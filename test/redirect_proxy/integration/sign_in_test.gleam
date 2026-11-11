//// End-to-end tests of signing in to the admin: sessions, throttling,
//// passwords, users and roles.

import gleam/erlang/process
import gleam/http
import gleam/http/response
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import integration_support.{
  admin_password, boot, cookie_of, csrf_token, get, location, login,
  login_with_role, post_form, send, session_cookie,
}
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import simplifile

pub fn admin_requires_authentication_test() {
  let env = boot(config.default())
  let resp = get(env.admin <> "/rules", [])
  assert resp.status == 303
  assert string.starts_with(location(resp), "/login")
  let resp = post_form(env, "/rules", "", [#("source", "/x")])
  assert resp.status == 401
  assert get(env.admin <> "/healthz", []).status == 200
  let metrics = get(env.admin <> "/metrics", [])
  assert string.contains(metrics.body, "redirect_proxy_rules 3")
}

pub fn security_headers_test() {
  let env = boot(config.default())
  let resp = get(env.admin <> "/login", [])
  assert resp.status == 200
  let assert Ok(csp) = response.get_header(resp, "content-security-policy")
  assert string.contains(csp, "frame-ancestors 'none'")
  assert response.get_header(resp, "x-frame-options") == Ok("DENY")
  assert response.get_header(resp, "x-content-type-options") == Ok("nosniff")
}

/// Failures from anywhere can block an account, but not in a browser where
/// it signed in before: guessing its password cannot lock its owner out.
pub fn known_device_is_not_locked_out_test() {
  let d = config.default()
  // its own address: the once per window audit of a 429 is per address
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let post = fn(cookie, fields) {
    send(
      http.Post,
      env.admin <> "/login",
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", env.admin),
        #("cookie", cookie),
        #("x-forwarded-for", "198.51.100.61"),
      ],
      uri.query_to_string(fields),
    )
  }
  let assert Ok(_) =
    users.create(
      users.Settings(
        path: env.dir <> "/users.json",
        audit_path: env.dir <> "/audit.jsonl",
      ),
      "device-user",
      password.hash_with("device-password-1", 1000),
      by: "test",
    )
  let sign_in = fn(cookie) {
    post(cookie, [
      #("username", "device-user"),
      #("password", "device-password-1"),
    ])
  }
  let first = sign_in("")
  assert first.status == 303
  let device = cookie_of(first, "rp_device")
  assert device != ""
  // as if 100 addresses had failed for this account
  list.each(list.repeat(Nil, 100), fn(_) {
    ratelimit.record_failure("login-user:device-user", 900)
  })
  assert sign_in("").status == 429
  assert sign_in(device).status == 303
  // the cookie is for this account only
  let assert Ok(_) =
    users.create(
      users.Settings(
        path: env.dir <> "/users.json",
        audit_path: env.dir <> "/audit.jsonl",
      ),
      "other-device-user",
      password.hash_with("device-password-2", 1000),
      by: "test",
    )
  list.each(list.repeat(Nil, 100), fn(_) {
    ratelimit.record_failure("login-user:other-device-user", 900)
  })
  let other =
    post(device, [
      #("username", "other-device-user"),
      #("password", "device-password-2"),
    ])
  assert other.status == 429
  ratelimit.reset("login-user:device-user")
  ratelimit.reset("login-user:other-device-user")
}

pub fn login_failures_are_throttled_test() {
  let env = boot(config.default())
  let attempt = fn() {
    post_form(env, "/login", "", [
      #("username", "throttled-user"),
      #("password", "wrong"),
    ]).status
  }
  let statuses = list.map(list.repeat(Nil, 11), fn(_) { attempt() })
  assert list.take(statuses, 10) == list.repeat(401, 10)
  assert list.last(statuses) == Ok(429)
  let resp =
    post_form(env, "/login", "", [
      #("username", "throttled-user"),
      #("password", "wrong"),
    ])
  let assert Ok(retry) = response.get_header(resp, "retry-after")
  let assert Ok(seconds) = int.parse(retry)
  assert seconds > 0 && seconds <= 900
  // an anonymous loop cannot flood the audit log: once per window
  let throttled =
    audit.tail(env.dir <> "/audit.jsonl", 100)
    |> list.filter(fn(e) { e.action == "auth.throttled" })
  assert list.length(throttled) == 1
}

/// Attempts are counted before the password is hashed: a burst of parallel
/// guesses gets no more than the limit (10 per account and address), and
/// the hashes running at once are bounded (503 beyond).
pub fn parallel_login_attempts_stay_within_the_limit_test() {
  let env = boot(config.default())
  // the address budget is shared with the other tests' failed logins
  let ip = ffi.throttle_address("127.0.0.1")
  ratelimit.reset("login-ip:" <> ip)
  let done = process.new_subject()
  let attempts = 30
  list.each(list.repeat(Nil, attempts), fn(_) {
    process.spawn(fn() {
      let status =
        post_form(env, "/login", "", [
          #("username", "parallel-user"),
          #("password", "wrong"),
        ]).status
      process.send(done, status)
    })
  })
  let statuses =
    list.map(list.repeat(Nil, attempts), fn(_) {
      let assert Ok(status) = process.receive(done, 30_000)
      status
    })
  let failed = list.count(statuses, fn(s) { s == 401 })
  assert failed >= 1 && failed <= 10
  assert list.all(statuses, fn(s) { s == 401 || s == 429 || s == 503 })
  // only real failures count: what is left of the budget is exact
  let left =
    list.repeat(Nil, 11)
    |> list.map(fn(_) {
      post_form(env, "/login", "", [
        #("username", "parallel-user"),
        #("password", "wrong"),
      ]).status
    })
    |> list.count(fn(s) { s == 401 })
  assert failed + left == 10
  ratelimit.reset("login:" <> ip <> " parallel-user")
  ratelimit.reset("login-ip:" <> ip)
  ratelimit.reset("login-user:parallel-user")
}

pub fn failures_elsewhere_do_not_lock_the_account_test() {
  // behind a trusted proxy, throttling uses the forwarded client address
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let from = fn(ip, pass) {
    send(
      http.Post,
      env.admin <> "/login",
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", env.admin),
        #("x-forwarded-for", ip),
      ],
      uri.query_to_string([#("username", "admin"), #("password", pass)]),
    ).status
  }
  let statuses =
    list.map(list.repeat(Nil, 11), fn(_) { from("198.51.100.7", "x") })
  assert list.last(statuses) == Ok(429)
  // the attacker's address is blocked, the account is not
  assert from("203.0.113.9", admin_password) == 303
}

pub fn oversized_login_input_is_refused_test() {
  let env = boot(config.default())
  let resp =
    post_form(env, "/login", "", [
      #("username", string.repeat("a", 65)),
      #("password", "x"),
    ])
  assert resp.status == 401
  // forms are small: a large body is refused before it is read
  let resp =
    post_form(env, "/login", "", [
      #("username", "admin"),
      #("password", string.repeat("x", 70_000)),
    ])
  assert resp.status == 413
}

pub fn sessions_end_when_the_user_changes_from_the_cli_test() {
  let env = boot(config.default())
  let settings =
    users.Settings(
      path: env.dir <> "/users.json",
      audit_path: env.dir <> "/audit.jsonl",
    )
  // a password change made by another process (the CLI) writes the file
  let #(cookie, _) = login(env)
  let assert Ok(Nil) =
    users.set_password(
      settings,
      "admin",
      password.hash_with("another-password", 1000),
      by: "cli",
    )
  let resp = get(env.admin <> "/rules", [#("cookie", cookie)])
  assert resp.status == 303
  assert string.starts_with(location(resp), "/login")

  // deleting the user ends their sessions too
  let assert Ok(Nil) =
    users.set_password(
      settings,
      "admin",
      password.hash_with(admin_password, 1000),
      by: "cli",
    )
  let #(cookie, _) = login(env)
  let assert Ok(_) =
    users.create(settings, "other", password.hash_with("pw", 1000), by: "cli")
  let assert Ok(Nil) = users.delete(settings, "admin", by: "cli")
  assert get(env.admin <> "/rules", [#("cookie", cookie)]).status == 303
}

pub fn own_password_change_keeps_the_current_session_test() {
  let env = boot(config.default())
  let #(first, csrf) = login(env)
  let #(second, _) = login(env)
  let resp =
    post_form(env, "/account/password", first, [
      #("csrf_token", csrf),
      #("password", "a-brand-new-password"),
      #("current_password", admin_password),
    ])
  assert resp.status == 303
  // the browser that changed it continues with a fresh session
  let fresh = session_cookie(resp)
  assert fresh != "" && fresh != first
  assert get(env.admin <> "/rules", [#("cookie", fresh)]).status == 200
  // every other session of the account ended, the old cookie too
  assert get(env.admin <> "/rules", [#("cookie", second)]).status == 303
  assert get(env.admin <> "/rules", [#("cookie", first)]).status == 303
}

pub fn users_file_is_private_test() {
  let env = boot(config.default())
  let assert Ok(info) = simplifile.file_info(env.dir <> "/users.json")
  assert simplifile.file_info_permissions_octal(info) == 0o600
}

pub fn https_admin_hardening_test() {
  // the admin behind a TLS-terminating proxy
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(..d.admin, public_url: "https://admin.test"),
      ),
    )
  let resp =
    send(
      http.Post,
      env.admin <> "/login",
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", env.admin),
        #("x-forwarded-proto", "https"),
      ],
      uri.query_to_string([
        #("username", "admin"),
        #("password", admin_password),
      ]),
    )
  assert resp.status == 303
  assert response.get_header(resp, "strict-transport-security")
    == Ok("max-age=31536000")
  let cookie = cookie_of(resp, "__Host-rp_session")
  assert cookie != ""
  assert cookie_of(resp, "rp_session") == ""
  let page =
    get(env.admin <> "/rules", [
      #("cookie", cookie),
      #("x-forwarded-proto", "https"),
    ])
  assert page.status == 200
}

pub fn sign_ins_are_audited_test() {
  let env = boot(config.default())
  // other tests spend the audit log's budget for failures
  ratelimit.reset("audit-failures")
  let assert 401 =
    post_form(env, "/login", "", [#("username", "admin"), #("password", "no")]).status
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/logout", cookie, [#("csrf_token", csrf)]).status
  let actions =
    audit.tail(env.dir <> "/audit.jsonl", 10)
    |> list.filter(fn(e) { string.starts_with(e.action, "auth.") })
    |> list.map(fn(e) { #(e.actor, e.action, e.target) })
  // newest first
  assert list.take(actions, 3)
    == [
      #("admin", "auth.logout", "local"),
      #("admin", "auth.login", "local"),
      #("admin", "auth.login_failed", "local"),
    ]
  // a name no account can have is not recorded as the actor
  let assert 401 =
    post_form(env, "/login", "", [
      #("username", "sso:alice"),
      #("password", "no"),
    ]).status
  let assert [failed, ..] = audit.tail(env.dir <> "/audit.jsonl", 1)
  assert #(failed.actor, failed.action) == #("", "auth.login_failed")
  assert string.contains(failed.details, "sso:alice")
}

pub fn password_changes_need_the_current_password_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let change = fn(current) {
    post_form(env, "/account/password", cookie, [
      #("csrf_token", csrf),
      #("username", "admin"),
      #("password", "a-brand-new-password"),
      #("current_password", current),
    ])
  }
  // other tests spend the audit log's budget for failures
  ratelimit.reset("audit-failures")
  let resp = change("not my password")
  assert resp.status == 422
  assert string.contains(resp.body, "current password is not correct")
  // audited like a failed sign-in: a stolen session guessing it
  let assert [failed, ..] = audit.tail(env.dir <> "/audit.jsonl", 1)
  assert #(failed.actor, failed.action, failed.target)
    == #("admin", "auth.password_check_failed", "local")
  assert change("").status == 422
  // nothing changed: the old password still signs in
  let #(_, _) = login(env)
}

/// Wrong current passwords count as failed logins: a stolen session cannot
/// guess the password through this form either.
pub fn password_changes_are_throttled_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  // its own client address, so that other tests' counters stay untouched
  let ip = "198.51.100.42"
  let post = fn(path, cookie, fields) {
    send(
      http.Post,
      env.admin <> path,
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", env.admin),
        #("x-forwarded-for", ip),
        #("cookie", cookie),
      ],
      uri.query_to_string(fields),
    )
  }
  let resp =
    post("/login", "", [#("username", "admin"), #("password", admin_password)])
  assert resp.status == 303
  let cookie = session_cookie(resp)
  let page =
    get(env.admin <> "/users", [#("cookie", cookie), #("x-forwarded-for", ip)])
  let csrf = csrf_token(page.body)
  let change = fn(current) {
    post("/account/password", cookie, [
      #("csrf_token", csrf),
      #("username", "admin"),
      #("password", "a-brand-new-password"),
      #("current_password", current),
    ])
  }
  let statuses =
    list.map(list.repeat(Nil, 10), fn(_) { change("not my password").status })
  assert statuses == list.repeat(422, 10)
  let blocked = change(admin_password)
  assert blocked.status == 429
  assert response.get_header(blocked, "retry-after") |> result.is_ok
  // the login form from that address is blocked for the account too
  let resp =
    post("/login", "", [#("username", "admin"), #("password", admin_password)])
  assert resp.status == 429
}

pub fn login_rejects_bad_password_test() {
  let env = boot(config.default())
  let resp =
    post_form(env, "/login", "", [#("username", "admin"), #("password", "nope")])
  assert resp.status == 401
  assert session_cookie(resp) == ""
}

pub fn login_next_is_not_an_open_redirect_test() {
  let env = boot(config.default())
  let try_next = fn(next) {
    send(
      http.Post,
      env.admin <> "/login?" <> uri.query_to_string([#("next", next)]),
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", env.admin),
      ],
      uri.query_to_string([
        #("username", "admin"),
        #("password", admin_password),
      ]),
    )
    |> location
  }
  assert try_next("/test?url=x") == "/test?url=x"
  assert try_next("//evil.test/") == "/rules"
  assert try_next("https://evil.test/") == "/rules"
  assert try_next("/\\evil.test") == "/rules"
  // browsers drop tabs and newlines in a Location: these would become
  // `//evil.test`, or split the response headers
  assert try_next("/\t/evil.test") == "/rules"
  assert try_next("/\n/evil.test") == "/rules"
  assert try_next("/\r\nx-evil: 1") == "/rules"
  assert try_next("/a\\b") == "/rules"
  assert try_next("/\u{7f}") == "/rules"
}

pub fn login_form_keeps_next_parameter_test() {
  let env = boot(config.default())
  let page = get(env.admin <> "/login?next=%2Faudit", [])
  // the form posts back to the current URL
  assert !string.contains(page.body, "action=\"/login\"")
  assert string.contains(page.body, "<form method=\"post\">")
}

pub fn csrf_protection_test() {
  let env = boot(config.default())
  let #(cookie, _csrf) = login(env)
  let fields = [
    #("source", "/csrf"),
    #("target", "/x"),
    #("match", "exact"),
    #("status", "301"),
  ]
  // missing token
  assert post_form(env, "/rules", cookie, fields).status == 403
  // forged token
  assert post_form(env, "/rules", cookie, [#("csrf_token", "forged"), ..fields]).status
    == 403
  // cross-origin request
  let resp =
    send(
      http.Post,
      env.admin <> "/rules",
      [
        #("content-type", "application/x-www-form-urlencoded"),
        #("origin", "https://evil.test"),
        #("cookie", cookie),
      ],
      uri.query_to_string(fields),
    )
  assert resp.status == 400
  assert get(env.redirect <> "/csrf", []).status == 404
}

pub fn user_management_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let resp =
    post_form(env, "/users", cookie, [
      #("csrf_token", csrf),
      #("username", "bob"),
      #("password", "short"),
    ])
  assert resp.status == 422
  let resp =
    post_form(env, "/users", cookie, [
      #("csrf_token", csrf),
      #("username", "bob"),
      #("password", "bob-password-long"),
    ])
  assert resp.status == 303
  // bob can sign in
  let resp =
    post_form(env, "/login", "", [
      #("username", "bob"),
      #("password", "bob-password-long"),
    ])
  assert resp.status == 303
  let bob_cookie = session_cookie(resp)
  // deleting bob revokes his session
  let resp =
    post_form(env, "/users/bob/delete", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.admin <> "/rules", [#("cookie", bob_cookie)]).status == 303
  // you cannot delete yourself
  let resp =
    post_form(env, "/users/admin/delete", cookie, [#("csrf_token", csrf)])
  assert resp.status == 422
}

pub fn logout_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let resp = post_form(env, "/logout", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.admin <> "/rules", [#("cookie", cookie)]).status == 303
}

/// Signing in again from a browser ends the session it held.
pub fn login_ends_the_previous_session_test() {
  let env = boot(config.default())
  let #(old, _) = login(env)
  let resp =
    post_form(env, "/login", old, [
      #("username", "admin"),
      #("password", admin_password),
    ])
  assert resp.status == 303
  let new = session_cookie(resp)
  assert new != old
  assert get(env.admin <> "/rules", [#("cookie", old)]).status == 303
  assert get(env.admin <> "/rules", [#("cookie", new)]).status == 200
}

pub fn viewer_role_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login_with_role(env, "vera", role.Viewer)
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]) }
  // reading
  let list = page("/rules")
  assert list.status == 200
  assert string.contains(list.body, "/old")
  assert !string.contains(list.body, "New redirection")
  assert !string.contains(list.body, "/toggle")
  assert !string.contains(list.body, "Users")
  assert page("/test?url=https://x.test/old").status == 200
  assert page("/export").status == 200
  // the rule details, read only
  let assert Ok(#(before, _)) = string.split_once(list.body, "/edit\"")
  let assert Ok(id) = string.split(before, "/rules/") |> list.last
  let details = page("/rules/" <> id <> "/edit")
  assert details.status == 200
  assert string.contains(details.body, "Read only")
  // no changes
  let create =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("source", "/nope"),
      #("target", "/x"),
    ])
  assert create.status == 403
  assert get(env.redirect <> "/nope", []).status == 404
  assert page("/rules/new").status == 403
  assert page("/import").status == 403
  assert post_form(env, "/reload", cookie, [#("csrf_token", csrf)]).status
    == 403
  // nor users, API clients or the audit log
  assert page("/users").status == 403
  assert page("/audit").status == 403
  assert page("/api-clients").status == 403
  // another user's password: no; their own: yes, from the account page
  let other =
    post_form(env, "/account/password", cookie, [
      #("csrf_token", csrf),
      #("username", "admin"),
      #("password", "a-brand-new-password"),
      #("current_password", admin_password),
    ])
  assert other.status == 403
  let own =
    post_form(env, "/account/password", cookie, [
      #("csrf_token", csrf),
      #("password", "a-brand-new-password"),
      #("current_password", admin_password),
    ])
  assert own.status == 303
  assert location(own) == "/account?flash=password_changed"
}

pub fn editor_role_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login_with_role(env, "eddie", role.Editor)
  let create =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/by-editor"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
    ])
  assert create.status == 303
  assert get(env.redirect <> "/by-editor", []).status == 301
  assert get(env.admin <> "/import", [#("cookie", cookie)]).status == 200
  assert get(env.admin <> "/users", [#("cookie", cookie)]).status == 403
  assert get(env.admin <> "/audit", [#("cookie", cookie)]).status == 403
}

/// An administrator changes roles on the users page; the last
/// administrator keeps theirs.
pub fn admins_change_roles_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let resp =
    post_form(env, "/users", cookie, [
      #("csrf_token", csrf),
      #("username", "newbie"),
      #("password", "a-long-enough-password"),
      #("role", "viewer"),
    ])
  assert resp.status == 303
  let users_page = get(env.admin <> "/users", [#("cookie", cookie)]).body
  assert string.contains(users_page, "action=\"/users/newbie/role\"")
  // newbie signs in as a viewer
  let newbie =
    post_form(env, "/login", "", [
      #("username", "newbie"),
      #("password", "a-long-enough-password"),
    ])
    |> session_cookie
  assert get(env.admin <> "/import", [#("cookie", newbie)]).status == 403
  let promote =
    post_form(env, "/users/newbie/role", cookie, [
      #("csrf_token", csrf),
      #("role", "editor"),
    ])
  assert promote.status == 303
  // the same session, with the new role: not signed out
  assert get(env.admin <> "/import", [#("cookie", newbie)]).status == 200
  let demote_self =
    post_form(env, "/users/admin/role", cookie, [
      #("csrf_token", csrf),
      #("role", "viewer"),
    ])
  assert demote_self.status == 422
  assert string.contains(demote_self.body, "last administrator")
}

/// Re-hashing a password at sign-in does not change it: the user's other
/// sessions go on (here one opened while the re-hash could not be saved).
pub fn a_password_rehash_keeps_the_other_sessions_test() {
  let env = boot(config.default())
  // the users file cannot be replaced: the first sign-in cannot re-hash
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o500)
  let #(first, _) = login(env)
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o700)
  let #(_, _) = login(env)
  let assert Ok(content) = simplifile.read(env.dir <> "/users.json")
  assert !string.contains(content, "$1000$")
  assert get(env.admin <> "/account", [#("cookie", first)]).status == 200
}
