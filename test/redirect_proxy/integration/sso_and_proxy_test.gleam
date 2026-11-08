//// End-to-end tests of single sign-on (OpenID Connect) and trusted proxy
//// headers.

import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import integration_support.{
  boot, cookie_of, csrf_token, get, location, oidc_env, post_form,
  session_cookie, sso_login, start_fake_idp,
}
import redirect_proxy/admin/auth/header
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import simplifile

/// Each SSO start holds a pending login attempt: one address cannot start
/// enough of them to block everyone else's SSO logins.
pub fn sso_starts_are_throttled_per_address_test() {
  let issuer = start_fake_idp("alice@example.com")
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
        oidc: config.OidcConfig(
          ..d.oidc,
          enabled: True,
          issuer:,
          client_id: "redirect-proxy",
          client_secret: "secret",
        ),
      ),
    )
  let start = fn(ip) {
    get(env.admin <> "/auth/oidc/start", [#("x-forwarded-for", ip)])
  }
  let flows_before = ffi.ets_size("redirect_proxy_oidc_flows")
  let statuses =
    list.map(list.repeat(Nil, 31), fn(_) { start("198.51.100.8").status })
  assert list.take(statuses, 30) == list.repeat(303, 30)
  let blocked = start("198.51.100.8")
  assert blocked.status == 429
  assert response.get_header(blocked, "retry-after") |> result.is_ok
  assert start("203.0.113.10").status == 303
  // logins in progress are kept by the browsers: starting them stores
  // nothing on the server, so no amount of them blocks anyone's SSO
  assert ffi.ets_size("redirect_proxy_oidc_flows") == flows_before
  // failed callbacks are throttled too
  let callbacks =
    list.map(list.repeat(Nil, 21), fn(_) {
      get(env.admin <> "/auth/oidc/callback?state=x&code=y", [
        #("x-forwarded-for", "198.51.100.9"),
      ]).status
    })
  assert list.take(callbacks, 20) == list.repeat(403, 20)
  assert list.last(callbacks) == Ok(429)
  // completed logins do not count: many people behind one address
  let login = fn() {
    let started = start("198.51.100.20")
    assert started.status == 303
    let authorize = get(location(started), [])
    let assert Ok(#(_, query)) = string.split_once(location(authorize), "?")
    get(env.admin <> "/auth/oidc/callback?" <> query, [
      #("cookie", cookie_of(started, "rp_oidc_state")),
      #("x-forwarded-for", "198.51.100.20"),
    ]).status
  }
  assert list.map(list.repeat(Nil, 35), fn(_) { login() })
    == list.repeat(303, 35)
}

pub fn sso_state_cookie_is_host_prefixed_over_https_test() {
  let issuer = start_fake_idp("alice@example.com")
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(..d.admin, public_url: "https://admin.test"),
        oidc: config.OidcConfig(
          ..d.oidc,
          enabled: True,
          issuer:,
          client_id: "redirect-proxy",
          client_secret: "secret",
        ),
      ),
    )
  let start =
    get(env.admin <> "/auth/oidc/start", [#("x-forwarded-proto", "https")])
  assert start.status == 303
  assert cookie_of(start, "__Host-rp_oidc_state") != ""
  assert cookie_of(start, "rp_oidc_state") == ""
}

pub fn sso_admins_cannot_change_local_passwords_test() {
  let issuer = start_fake_idp("alice@example.com")
  let env = oidc_env(issuer, ["example.com"])
  let resp = sso_login(env)
  let cookie = session_cookie(resp)
  let page = get(env.admin <> "/users", [#("cookie", cookie)])
  assert string.contains(page.body, "only local administrators can change")
  let csrf = csrf_token(page.body)
  let resp =
    post_form(env, "/account/password", cookie, [
      #("csrf_token", csrf),
      #("username", "admin"),
      #("password", "a-brand-new-password"),
      #("current_password", "anything"),
    ])
  assert resp.status == 403
}

pub fn header_auth_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        header_auth: config.HeaderAuthConfig(
          ..d.header_auth,
          enabled: True,
          trusted_proxies: ["127.0.0.1/32"],
        ),
      ),
    )
  let resp = get(env.admin <> "/rules", [#("x-forwarded-user", "Proxy-User")])
  assert resp.status == 200
  // without a role header, proxy users get the least role by default
  assert string.contains(resp.body, ">proxy-user (proxy, viewer)<")
  // names from the proxy cannot pass for a local user in the audit log
  let assert [login, ..] = audit.tail(env.dir <> "/audit.jsonl", 1)
  assert #(login.actor, login.action) == #("proxy:proxy-user", "auth.login")
  // a client that drops cookies keeps the same session: no new session nor
  // audit entry per request
  let first = session_cookie(resp)
  let again = get(env.admin <> "/rules", [#("x-forwarded-user", "proxy-user")])
  assert again.status == 200
  assert session_cookie(again) == first
  let logins =
    audit.tail(env.dir <> "/audit.jsonl", 100)
    |> list.filter(fn(e) { e.action == "auth.login" })
  assert list.length(logins) == 1
  // a forged header from an untrusted network is ignored
  let untrusted =
    boot(
      config.Config(
        ..d,
        header_auth: config.HeaderAuthConfig(
          ..d.header_auth,
          enabled: True,
          trusted_proxies: ["10.0.0.0/8"],
        ),
      ),
    )
  let resp =
    get(untrusted.admin <> "/rules", [#("x-forwarded-user", "mallory")])
  assert resp.status == 303
}

pub fn oidc_login_test() {
  let issuer = start_fake_idp("alice@example.com")
  let env = oidc_env(issuer, ["example.com"])
  let resp = sso_login(env)
  assert resp.status == 303
  assert location(resp) == "/rules"
  let cookie = session_cookie(resp)
  let page = get(env.admin <> "/rules", [#("cookie", cookie)])
  assert page.status == 200
  assert string.contains(page.body, ">alice@example.com (sso, admin)<")
  let assert [login, ..] = audit.tail(env.dir <> "/audit.jsonl", 1)
  assert #(login.actor, login.action)
    == #("sso:alice@example.com", "auth.login")
  // the role granted from the provider's groups is recorded
  let assert Ok(content) = simplifile.read(env.dir <> "/audit.jsonl")
  assert string.contains(content, "\"role\":\"admin\"")

  // a state can only be used once
  let start = get(env.admin <> "/auth/oidc/start", [])
  let state = [#("cookie", cookie_of(start, "rp_oidc_state"))]
  let authorize = get(location(start), [])
  let assert Ok(#(_, query)) = string.split_once(location(authorize), "?")
  assert get(env.admin <> "/auth/oidc/callback?" <> query, state).status == 303
  assert get(env.admin <> "/auth/oidc/callback?" <> query, state).status == 403
}

/// SSO comes back to the page that asked for a sign-in, like a password
/// login, and never to another site.
pub fn oidc_login_returns_to_next_test() {
  let issuer = start_fake_idp("alice@example.com")
  let env = oidc_env(issuer, ["example.com"])
  let page = get(env.admin <> "/login?next=%2Faudit%3Faction%3Drule", [])
  assert string.contains(
    page.body,
    "href=\"/auth/oidc/start?next=%2Faudit%3Faction%3Drule\"",
  )
  let via = fn(next) {
    let start =
      get(
        env.admin
          <> "/auth/oidc/start?"
          <> uri.query_to_string([#("next", next)]),
        [],
      )
    let state = cookie_of(start, "rp_oidc_state")
    let authorize = get(location(start), [])
    let assert Ok(#(_, query)) = string.split_once(location(authorize), "?")
    location(
      get(env.admin <> "/auth/oidc/callback?" <> query, [#("cookie", state)]),
    )
  }
  assert via("/audit?action=rule") == "/audit?action=rule"
  assert via("//evil.test/x") == "/rules"
  assert via("https://evil.test/") == "/rules"
  assert via("/\t/evil.test") == "/rules"
  assert via("/\r\nx-evil: 1") == "/rules"
}

/// With `logout_at_provider`, signing out of an SSO session also signs out
/// at the provider, which sends the browser back to the login page.
pub fn oidc_logout_at_provider_test() {
  let issuer = start_fake_idp("alice@example.com")
  let logout = fn(at_provider) {
    let d = config.default()
    let env =
      boot(
        config.Config(
          ..d,
          oidc: config.OidcConfig(
            ..d.oidc,
            enabled: True,
            issuer:,
            client_id: "redirect-proxy",
            client_secret: "secret",
            logout_at_provider: at_provider,
          ),
        ),
      )
    let cookie = session_cookie(sso_login(env))
    let page = get(env.admin <> "/rules", [#("cookie", cookie)])
    location(
      post_form(env, "/logout", cookie, [#("csrf_token", csrf_token(page.body))]),
    )
  }
  assert logout(False) == "/login"
  assert logout(True)
    == issuer
    <> "/logout?realm=x&client_id=redirect-proxy&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Flogin"
}

pub fn oidc_callback_from_another_browser_is_refused_test() {
  // login CSRF: an attacker sends their own callback link to a victim
  let issuer = start_fake_idp("alice@example.com")
  let env = oidc_env(issuer, ["example.com"])
  let start = get(env.admin <> "/auth/oidc/start", [])
  let authorize = get(location(start), [])
  let assert Ok(#(_, query)) = string.split_once(location(authorize), "?")
  let resp = get(env.admin <> "/auth/oidc/callback?" <> query, [])
  assert resp.status == 403
  assert session_cookie(resp) == ""
  // the victim's own login attempt has a different state
  let other = get(env.admin <> "/auth/oidc/start", [])
  let resp =
    get(env.admin <> "/auth/oidc/callback?" <> query, [
      #("cookie", cookie_of(other, "rp_oidc_state")),
    ])
  assert resp.status == 403
}

pub fn oidc_rejects_disallowed_users_test() {
  let issuer = start_fake_idp("mallory@evil.test")
  let env = oidc_env(issuer, ["example.com"])
  let resp = sso_login(env)
  assert resp.status == 403
  assert session_cookie(resp) == ""
  assert string.contains(resp.body, "not allowed")
}

pub fn oidc_login_page_shows_button_test() {
  let issuer = start_fake_idp("bob@example.com")
  let env = oidc_env(issuer, [])
  let page = get(env.admin <> "/login", [])
  assert string.contains(page.body, "Sign in with SSO")
  let _ = None
  let _ = Some(1)
}

pub fn header_session_ends_without_the_proxy_header_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        header_auth: config.HeaderAuthConfig(
          ..d.header_auth,
          enabled: True,
          trusted_proxies: ["127.0.0.1/32"],
        ),
      ),
    )
  let user = #(header.identity_header(d.header_auth), "alice")
  let resp = get(env.admin <> "/rules", [user])
  assert resp.status == 200
  let cookie = session_cookie(resp)
  assert cookie != ""
  // the proxy vouches for the user: the session holds
  assert get(env.admin <> "/rules", [user, #("cookie", cookie)]).status == 200
  // the cookie alone, without the proxy (signed out there, or replayed)
  let resp = get(env.admin <> "/rules", [#("cookie", cookie)])
  assert resp.status == 303
  assert string.starts_with(location(resp), "/login")
  // ... and the session is gone, not just skipped
  assert get(env.admin <> "/rules", [#("cookie", cookie)]).status == 303
}

/// With a role header, the proxy decides the role of each request, and the
/// session follows it.
pub fn proxy_role_header_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        header_auth: config.HeaderAuthConfig(
          ..d.header_auth,
          enabled: True,
          role_header: "x-forwarded-role",
        ),
      ),
    )
  let as_role = fn(r) {
    [#("x-forwarded-user", "pat"), #("x-forwarded-role", r)]
  }
  let first = get(env.admin <> "/users", as_role("viewer"))
  assert first.status == 403
  let cookie = session_cookie(first)
  // without a cookie, each role has its own session
  let as_editor = session_cookie(get(env.admin <> "/rules", as_role("editor")))
  assert as_editor != "" && as_editor != cookie
  assert session_cookie(get(env.admin <> "/rules", as_role("viewer"))) == cookie
  assert get(env.admin <> "/users", [#("cookie", cookie), ..as_role("admin")]).status
    == 200
  // no header: the least
  assert get(env.admin <> "/import", [#("x-forwarded-user", "sam")]).status
    == 403
}
