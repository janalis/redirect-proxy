//// End-to-end tests: the full application on ephemeral ports, driven over
//// real HTTP, plus a fake OpenID Connect provider.

import gleam/bit_array
import gleam/bytes_tree
import gleam/dynamic/decode
import gleam/erlang/charlist
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import mist
import redirect_proxy/admin/auth/header
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/app
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import simplifile
import support

const admin_password = "integration-password"

type Env {
  Env(redirect: String, admin: String, dir: String)
}

fn boot(cfg: config.Config) -> Env {
  let dir = support.temp_dir()
  let cfg =
    config.Config(
      ..cfg,
      server: config.ServerConfig(..cfg.server, listen: "127.0.0.1", port: 0),
      admin: config.AdminConfig(..cfg.admin, listen: "127.0.0.1", port: 0),
      storage: config.StorageConfig(
        ..config.default().storage,
        data_dir: dir,
        backups: 3,
        watch_interval: 0,
      ),
      access_log: {
        let al = cfg.access_log
        // tests can point a listener into the data dir with "{dir}"
        let in_dir = fn(l: config.ListenerLogConfig) {
          config.ListenerLogConfig(
            ..l,
            output: string.replace(l.output, "{dir}", dir),
          )
        }
        config.AccessLogConfig(
          ..al,
          output: dir <> "/logs/access.log",
          redirect: in_dir(al.redirect),
          admin: in_dir(al.admin),
          api: in_dir(al.api),
        )
      },
    )
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\": 1, \"rules\": [
        {\"source\": \"/old\", \"target\": \"https://example.com/new\"},
        {\"host\": \"docs.test\", \"match\": \"prefix\", \"source\": \"/v1/\", \"target\": \"https://docs.example.com/v2/$1\", \"status\": 302, \"preserve_query\": true},
        {\"match\": \"regex\", \"source\": \"^/blog/(\\\\d+)$\", \"target\": \"/articles/$1\", \"status\": 308}
      ]}",
    )
  let assert Ok(_) =
    users.create(
      app.users_settings(cfg),
      "admin",
      password.hash_with(admin_password, 1000),
      by: "test",
    )
  let assert Ok(running) = app.start(cfg)
  Env(
    redirect: "http://127.0.0.1:" <> int.to_string(running.redirect_port),
    admin: "http://127.0.0.1:" <> int.to_string(running.admin_port),
    dir:,
  )
}

fn send(
  method: http.Method,
  url: String,
  headers: List(#(String, String)),
  body: String,
) -> response.Response(String) {
  support.send(method, url, headers, body)
}

fn get(url: String, headers: List(#(String, String))) {
  send(http.Get, url, headers, "")
}

fn post_form(
  env: Env,
  path: String,
  cookie: String,
  fields: List(#(String, String)),
) -> response.Response(String) {
  send(
    http.Post,
    env.admin <> path,
    [
      #("content-type", "application/x-www-form-urlencoded"),
      #("origin", env.admin),
      #("cookie", cookie),
    ],
    uri.query_to_string(fields),
  )
}

fn location(resp: response.Response(a)) -> String {
  response.get_header(resp, "location") |> result.unwrap("")
}

fn session_cookie(resp: response.Response(a)) -> String {
  cookie_of(resp, "rp_session")
}

/// `name=value` of a cookie set by a response, "" when not set.
fn cookie_of(resp: response.Response(a), name: String) -> String {
  resp.headers
  |> list.filter_map(fn(h) {
    case h {
      #("set-cookie", value) ->
        case string.split_once(value, "=") {
          Ok(#(n, rest)) if n == name ->
            case string.split_once(rest, ";") {
              Ok(#(value, _)) -> Ok(name <> "=" <> value)
              Error(Nil) -> Ok(name <> "=" <> rest)
            }
          _ -> Error(Nil)
        }
      _ -> Error(Nil)
    }
  })
  |> list.first
  |> result.unwrap("")
}

fn csrf_token(html: String) -> String {
  let assert Ok(#(_, rest)) =
    string.split_once(html, "name=\"csrf_token\" type=\"hidden\" value=\"")
  let assert Ok(#(token, _)) = string.split_once(rest, "\"")
  token
}

fn login(env: Env) -> #(String, String) {
  let resp =
    post_form(env, "/login", "", [
      #("username", "admin"),
      #("password", admin_password),
    ])
  assert resp.status == 303
  let cookie = session_cookie(resp)
  assert cookie != ""
  let page = get(env.admin <> "/rules/new", [#("cookie", cookie)])
  assert page.status == 200
  #(cookie, csrf_token(page.body))
}

// --- redirect listener ------------------------------------------------------

pub fn redirect_listener_test() {
  let env = boot(config.default())

  let resp = get(env.redirect <> "/old", [#("host", "any.test")])
  assert resp.status == 301
  assert location(resp) == "https://example.com/new"
  assert response.get_header(resp, "cache-control")
    == Ok("public, max-age=3600")

  let resp =
    get(env.redirect <> "/v1/guide?lang=fr", [#("host", "docs.test:80")])
  assert resp.status == 302
  assert location(resp) == "https://docs.example.com/v2/guide?lang=fr"
  assert response.get_header(resp, "cache-control") == Ok("no-store")

  let resp = get(env.redirect <> "/v1/guide", [#("host", "other.test")])
  assert resp.status == 404

  let resp = get(env.redirect <> "/blog/42", [])
  assert resp.status == 308
  assert location(resp) == "/articles/42"

  let resp = send(http.Post, env.redirect <> "/old", [], "ignored body")
  assert resp.status == 301

  let resp = send(http.Head, env.redirect <> "/old", [], "")
  assert resp.status == 301

  let resp = send(http.Options, env.redirect <> "/old", [], "")
  assert resp.status == 204
  assert response.get_header(resp, "allow")
    == Ok("GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS")
}

pub fn access_log_test() {
  let env = boot(config.default())
  let _ =
    get(env.redirect <> "/old?email=someone@example.com", [
      #("referer", "https://ref.test/page?token=secret"),
      #("user-agent", "tester \"1\""),
    ])
  let _ = get(env.redirect <> "/missing", [])
  let lines = access_lines(env.dir, 2)
  let assert [hit, miss] = lines
  assert string.starts_with(hit, "127.0.0.0 - - [")
  assert string.contains(hit, "] \"GET /old HTTP/1.1\" 301 0 ")
  assert string.ends_with(
    hit,
    "\"https://ref.test/page\" \"tester \\x221\\x22\"",
  )
  assert !string.contains(hit, "someone")
  assert !string.contains(hit, "secret")
  assert string.contains(miss, "\"GET /missing HTTP/1.1\" 404 9 \"-\"")
}

pub fn access_log_json_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(
          ..d.access_log,
          format: "json",
          log_query: True,
          anonymize_ip: "none",
        ),
      ),
    )
  let _ = get(env.redirect <> "/blog/7?a=1", [])
  let assert [line] = access_lines(env.dir, 1)
  let decoder = {
    use addr <- decode.field("remote_addr", decode.string)
    use status <- decode.field("status", decode.int)
    use args <- decode.field("args", decode.string)
    use location <- decode.field("location", decode.string)
    use rule_id <- decode.field("rule_id", decode.string)
    decode.success(#(addr, status, args, location, rule_id))
  }
  let assert Ok(#("127.0.0.1", 308, "a=1", "/articles/7", rule_id)) =
    json.parse(line, decoder)
  assert rule_id != ""
}

pub fn access_log_admin_and_api_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(
          ..d.access_log,
          format: "$listener $request_method $uri $status",
          api: config.ListenerLogConfig(
            ..d.access_log.api,
            output: "{dir}/logs/api.log",
          ),
        ),
      ),
    )
  let _ = get(env.redirect <> "/old", [])
  let _ = get(env.admin <> "/login?next=/rules", [])
  let _ = get(env.admin <> "/api/openapi.json", [])
  let assert ["redirect GET /old 301", "admin GET /login 200"] =
    access_lines(env.dir, 2)
  let assert ["api GET /api/openapi.json 200"] =
    lines_of(env.dir <> "/logs/api.log", 1)
}

pub fn access_log_disabled_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, enabled: False),
      ),
    )
  let _ = get(env.redirect <> "/old", [])
  process.sleep(100)
  assert simplifile.read(env.dir <> "/logs/access.log")
    |> result.unwrap("")
    == ""
}

/// Waits for the access log handler to flush `count` lines.
fn access_lines(dir: String, count: Int) -> List(String) {
  lines_of(dir <> "/logs/access.log", count)
}

fn lines_of(path: String, count: Int) -> List(String) {
  access_lines_loop(path, count, 250)
}

fn access_lines_loop(path: String, count: Int, tries: Int) -> List(String) {
  let lines =
    simplifile.read(path)
    |> result.unwrap("")
    |> string.split("\n")
    |> list.filter(fn(l) { l != "" })
  case list.length(lines) >= count || tries == 0 {
    True -> lines
    False -> {
      process.sleep(20)
      access_lines_loop(path, count, tries - 1)
    }
  }
}

pub fn fallback_url_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(
          ..d.server,
          fallback_url: "https://home.test/",
        ),
      ),
    )
  let resp = get(env.redirect <> "/nothing", [])
  assert resp.status == 302
  assert location(resp) == "https://home.test/"
}

// --- admin ------------------------------------------------------------------

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
  let statuses =
    list.map(list.repeat(Nil, 31), fn(_) { start("198.51.100.8").status })
  assert list.take(statuses, 30) == list.repeat(303, 30)
  let blocked = start("198.51.100.8")
  assert blocked.status == 429
  assert response.get_header(blocked, "retry-after") |> result.is_ok
  assert start("203.0.113.10").status == 303
  // failed callbacks are throttled too
  let callbacks =
    list.map(list.repeat(Nil, 21), fn(_) {
      get(env.admin <> "/auth/oidc/callback?state=x&code=y", [
        #("x-forwarded-for", "198.51.100.9"),
      ]).status
    })
  assert list.take(callbacks, 20) == list.repeat(403, 20)
  assert list.last(callbacks) == Ok(429)
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

@external(erlang, "test_net_ffi", "raw_exchange")
fn raw_exchange(port: Int, chunks: List(BitArray)) -> BitArray

/// The redirect listener never reads request bodies: a body arriving after
/// the headers must not be parsed as a second request on the same connection.
pub fn unread_bodies_close_the_connection_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let smuggled = "GET /blog/7 HTTP/1.1\r\nhost: a.test\r\n\r\n"
  let headers =
    "POST /old HTTP/1.1\r\nhost: a.test\r\ncontent-length: "
    <> int.to_string(string.byte_size(smuggled))
    <> "\r\n\r\n"
  let assert Ok(received) =
    raw_exchange(port, [<<headers:utf8>>, <<smuggled:utf8>>])
    |> bit_array.to_string
  assert string.starts_with(received, "HTTP/1.1 301")
  assert string.contains(string.lowercase(received), "connection: close")
  assert !string.contains(received, "/articles/7")

  // without a body the connection stays open for the next request
  let assert Ok(received) =
    raw_exchange(port, [
      <<"GET /old HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
      <<"GET /blog/7 HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
    ])
    |> bit_array.to_string
  assert string.contains(received, "/articles/7")
}

pub fn draining_before_a_stop_test() {
  let env = boot(config.default())
  assert get(env.admin <> "/readyz", []).status == 200
  let resp = get(env.redirect <> "/old", [])
  assert response.get_header(resp, "connection") != Ok("close")
  // what SIGTERM does before the grace period ends
  support.set_draining(True)
  let ready = get(env.admin <> "/readyz", [])
  let resp = get(env.redirect <> "/old", [])
  support.set_draining(False)
  assert ready.status == 503
  assert resp.status == 301
  assert response.get_header(resp, "connection") == Ok("close")
}

/// `server.health_path` is answered before the rules, even by a catch-all
/// rule, and turns 503 while draining.
pub fn redirect_listener_health_path_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, health_path: "/_health"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/\", \"match\": \"prefix\", \"target\": \"https://elsewhere.test/\"}]",
    )
  let assert Ok(_) = reload_rules(env)
  assert get(env.redirect <> "/anything", []).status == 301
  let requests = metric(env, "redirect_proxy_requests_total")
  let resp = get(env.redirect <> "/_health", [])
  assert resp.status == 200
  assert resp.body == "ok"
  assert response.get_header(resp, "cache-control") == Ok("no-store")
  // probes are not counted as traffic
  assert metric(env, "redirect_proxy_requests_total") == requests
  support.set_draining(True)
  let draining = get(env.redirect <> "/_health", [])
  support.set_draining(False)
  assert draining.status == 503
}

/// `server.metrics_path`: a replica without an admin or API listener
/// serves its metrics on the redirect listener, before the rules, with the
/// metrics token.
pub fn redirect_listener_metrics_path_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(
          ..d.admin,
          metrics_token: "a-long-metrics-token",
        ),
        server: config.ServerConfig(..d.server, metrics_path: "/_metrics"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/\", \"match\": \"prefix\", \"target\": \"https://elsewhere.test/\"}]",
    )
  let assert Ok(_) = reload_rules(env)
  let denied = get(env.redirect <> "/_metrics", [])
  assert denied.status == 401
  assert !string.contains(denied.body, "redirect_proxy_")
  let resp =
    get(env.redirect <> "/_metrics", [
      #("authorization", "Bearer a-long-metrics-token"),
    ])
  assert resp.status == 200
  assert string.contains(resp.body, "redirect_proxy_requests_total")
  assert response.get_header(resp, "cache-control") == Ok("no-store")
  // other paths still go to the rules
  assert get(env.redirect <> "/_metrics/x", []).status == 301
}

/// Without a health path, the same path goes to the rules.
pub fn health_path_is_off_by_default_test() {
  let env = boot(config.default())
  assert get(env.redirect <> "/_health", []).status == 404
}

pub fn https_redirect_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(
          ..d.server,
          https_redirect: True,
          health_path: "/_health",
        ),
      ),
    )
  let resp = get(env.redirect <> "/old?a=1", [#("host", "Shop.Test:80")])
  assert resp.status == 301
  assert location(resp) == "https://shop.test/old?a=1"
  // other methods are repeated as they were
  let resp =
    send(http.Post, env.redirect <> "/form", [#("host", "shop.test")], "x=1")
  assert resp.status == 308
  assert location(resp) == "https://shop.test/form"
  // forwarded by a TLS proxy: the rules apply
  let resp =
    get(env.redirect <> "/old", [
      #("host", "shop.test"),
      #("x-forwarded-proto", "https"),
    ])
  assert resp.status == 301
  assert location(resp) == "https://example.com/new"
  assert get(env.redirect <> "/x", [#("x-forwarded-proto", "https")]).status
    == 404
  // a host that is not a host name is not redirected anywhere
  assert get(env.redirect <> "/old", [#("host", "evil.test/@x")]).status == 400
  // `_` is allowed, as in rule hosts
  let resp = get(env.redirect <> "/p", [#("host", "my_app.test")])
  assert resp.status == 301
  assert location(resp) == "https://my_app.test/p"
  // health probes are answered, not upgraded
  assert get(env.redirect <> "/_health", []).status == 200
}

pub fn overlong_paths_get_414_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, max_path_bytes: 300),
      ),
    )
  assert get(env.redirect <> "/" <> string.repeat("a", 299), []).status == 404
  let resp = get(env.redirect <> "/" <> string.repeat("a", 300), [])
  assert resp.status == 414
  let default_env = boot(d)
  assert get(default_env.redirect <> "/" <> string.repeat("a", 8192), []).status
    == 414
  assert get(default_env.redirect <> "/" <> string.repeat("a", 8191), []).status
    == 404
  // the query string does not count
  assert get(env.redirect <> "/old?" <> string.repeat("q", 400), []).status
    == 301
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

pub fn matching_features_over_http_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, trailing_slash: "ignore"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[
        {\"source\": \"/café\", \"target\": \"/coffee\"},
        {\"host\": \"*.example.test\", \"source\": \"/w\", \"target\": \"/wild\"},
        {\"match\": \"prefix\", \"source\": \"/docs/\", \"target\": \"/manual/$1\"},
        {\"source\": \"/slash\", \"target\": \"/no-slash\"}
      ]",
    )
  let assert Ok(_) = reload_rules(env)
  // a browser sends the UTF-8 path percent-encoded
  let resp = get(env.redirect <> "/caf%C3%A9", [])
  assert resp.status == 301
  assert location(resp) == "/coffee"
  // wildcard hosts match subdomains only
  assert location(get(env.redirect <> "/w", [#("host", "a.example.test")]))
    == "/wild"
  assert get(env.redirect <> "/w", [#("host", "example.test")]).status == 404
  // Location is ASCII even when the capture holds decoded characters
  assert location(get(env.redirect <> "/docs/%C3%A9t%C3%A9", []))
    == "/manual/%C3%A9t%C3%A9"
  // trailing_slash = "ignore"
  assert location(get(env.redirect <> "/slash/", [])) == "/no-slash"
  // unsupported methods name the supported ones (httpc cannot send TRACE)
  let headers =
    os_cmd(charlist.from_string(
      "curl -s -o /dev/null -D - -X TRACE " <> env.redirect <> "/x",
    ))
    |> charlist.to_string
    |> string.lowercase
  assert string.contains(headers, " 405")
  assert string.contains(
    headers,
    "allow: get, head, post, put, delete, patch, options",
  )
}

fn reload_rules(env: Env) -> Result(Nil, Nil) {
  let #(cookie, csrf) = login(env)
  case post_form(env, "/reload", cookie, [#("csrf_token", csrf)]).status {
    303 -> Ok(Nil)
    _ -> Error(Nil)
  }
}

pub fn admin_bulk_actions_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let ids =
    get(env.admin <> "/rules", [#("cookie", cookie)]).body
    |> string.split("name=\"ids\" type=\"checkbox\" value=\"")
    |> list.drop(1)
    |> list.filter_map(fn(chunk) {
      string.split_once(chunk, "\"") |> result.map(fn(p) { p.0 })
    })
  assert list.length(ids) == 3
  // disable two of them, coming back to a filtered list
  let back = "/rules?kind=exact&page=1"
  let resp =
    post_form(
      env,
      "/rules/bulk",
      cookie,
      list.flatten([
        [#("csrf_token", csrf), #("action", "disable"), #("return_to", back)],
        list.map(list.take(ids, 2), fn(id) { #("ids", id) }),
      ]),
    )
  assert resp.status == 303
  assert string.starts_with(
    location(resp),
    "/rules?kind=exact&page=1&flash=bulk",
  )
  let after = get(env.admin <> location(resp), [#("cookie", cookie)])
  assert string.contains(after.body, "Changed 2 redirection(s).")
  // every rule matching a filter, deleted after a confirmation
  let confirm =
    post_form(env, "/rules/bulk", cookie, [
      #("csrf_token", csrf),
      #("action", "delete"),
      #("all_matching", "on"),
      #("filter_kind", "regex"),
      #("return_to", "/rules"),
    ])
  assert confirm.status == 200
  assert string.contains(confirm.body, "1 redirection(s) will be removed")
  assert get(env.redirect <> "/blog/1", []).status == 308
  let resp =
    post_form(
      env,
      "/rules/bulk",
      cookie,
      list.flatten([
        [#("csrf_token", csrf), #("action", "delete"), #("confirm", "yes")],
        confirm.body
          |> string.split("name=\"ids\" type=\"hidden\" value=\"")
          |> list.drop(1)
          |> list.filter_map(fn(chunk) {
            string.split_once(chunk, "\"")
            |> result.map(fn(p) { #("ids", p.0) })
          }),
      ]),
    )
  assert resp.status == 303
  assert get(env.redirect <> "/blog/1", []).status == 404
}

/// A bulk action applies to the rules the page showed: when they changed
/// since, nothing is changed ("every matching rule" would otherwise take
/// in a rule nobody saw).
pub fn bulk_actions_refuse_a_changed_rule_set_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let bulk_version = fn() {
    let page = get(env.admin <> "/rules", [#("cookie", cookie)]).body
    let assert Ok(#(_, form)) = string.split_once(page, "id=\"bulk\"")
    hidden_value(form, "version")
  }
  let shown = bulk_version()
  // another admin adds a rule meanwhile
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/added-meanwhile"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let disable_all = fn(version) {
    post_form(env, "/rules/bulk", cookie, [
      #("csrf_token", csrf),
      #("action", "disable"),
      #("all_matching", "on"),
      #("version", version),
      #("return_to", "/rules"),
    ])
  }
  let resp = disable_all(shown)
  assert resp.status == 409
  assert string.contains(resp.body, "changed since this page was shown")
  assert get(env.redirect <> "/added-meanwhile", []).status == 301
  // from the current list, it applies
  assert disable_all(bulk_version()).status == 303
  assert get(env.redirect <> "/added-meanwhile", []).status == 404
}

pub fn toggle_keeps_the_list_filters_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = get(env.admin <> "/rules?q=old&sort=source", [#("cookie", cookie)])
  let assert Ok(#(_, rest)) = string.split_once(page.body, "/toggle\"")
  let assert Ok(#(before, _)) = string.split_once(page.body, "/toggle\"")
  let id = case string.split(before, "/rules/") |> list.last {
    Ok(id) -> id
    Error(Nil) -> ""
  }
  let assert Ok(#(_, version_rest)) =
    string.split_once(rest, "name=\"version\" type=\"hidden\" value=\"")
  let assert Ok(#(version, _)) = string.split_once(version_rest, "\"")
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("version", version),
      #("return_to", "/rules?q=old&sort=source&page=1"),
    ])
  assert resp.status == 303
  assert location(resp)
    == "/rules?q=old&sort=source&page=1&flash=disabled&id="
    <> uri.percent_encode(id)
  // the flash names the rule (looked up by id)
  let back = get(env.admin <> location(resp), [#("cookie", cookie)])
  assert string.contains(back.body, "Redirection * /old disabled.")
  // anything else than the rules list goes back to /rules
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("return_to", "https://evil.test/rules"),
    ])
  assert string.starts_with(location(resp), "/rules?")
}

pub fn audit_page_filters_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/audited"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let page = fn(query) {
    get(env.admin <> "/audit?" <> query, [#("cookie", cookie)]).body
  }
  // the action column renders <code>action</code>
  assert string.contains(page("action=rule."), "<code>rule.create</code>")
  assert !string.contains(page("action=rule."), "<code>auth.login</code>")
  assert string.contains(page("action=auth."), "<code>auth.login</code>")
  assert string.contains(page("actor=nobody"), "No audit entry matches.")
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
  let resp = change("not my password")
  assert resp.status == 422
  assert string.contains(resp.body, "current password is not correct")
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

pub fn destructive_actions_are_confirmed_test() {
  let env = boot(config.default())
  let #(cookie, _) = login(env)
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]) }
  let users = page("/users")
  // a link to a confirmation page, not a form posting at once
  assert !string.contains(users.body, "action=\"/users/admin/delete\"")
  let assert Ok(_) =
    users.create(
      users.Settings(
        path: env.dir <> "/users.json",
        audit_path: env.dir <> "/audit.jsonl",
      ),
      "bob",
      password.hash_with("bob-password-123", 1000),
      by: "test",
    )
  let confirm = page("/users/bob/delete")
  assert confirm.status == 200
  assert string.contains(confirm.body, "will be removed and signed out")
  assert string.contains(confirm.body, "action=\"/users/bob/delete\"")
}

pub fn admin_forms_and_exports_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]) }
  // every page starts with a skip link to the content
  assert string.contains(page("/rules").body, "href=\"#main\"")
  // field errors are next to the field, announced as such
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "no-slash"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "aria-invalid=\"true\"")
  assert string.contains(resp.body, "id=\"source-errors\"")
  assert string.contains(resp.body, "href=\"#source\"")
  // Duplicate opens the form filled from another rule
  // the id of the regex rule, from its edit link
  let list = page("/rules?kind=regex").body
  let assert Ok(#(before, _)) = string.split_once(list, "/edit\"")
  let assert Ok(id) = string.split(before, "/rules/") |> list.last
  let copy = page("/rules/new?from=" <> id)
  assert string.contains(copy.body, "^/blog/")
  assert string.contains(copy.body, "(copy)")
    || string.contains(copy.body, "Copy")
  // exports follow the filters, in the admin and the API
  let export = page("/export?kind=regex").body
  assert string.contains(export, "/blog/")
  assert !string.contains(export, "/old")
  // the filters are named as in the API (the old names above still work)
  let export = page("/export?match=regex&enabled=true").body
  assert string.contains(export, "/blog/")
  assert !string.contains(export, "/old")
  assert !string.contains(
    page("/export?match=regex&enabled=false").body,
    "/blog/",
  )
  let list = page("/rules?status=enabled").body
  assert string.contains(list, "<option selected value=\"true\">Enabled only")
    || string.contains(list, "value=\"true\" selected")
  // the list links and the bulk form carry the API names
  let list = page("/rules?kind=exact&status=enabled").body
  assert string.contains(
    list,
    "name=\"filter_match\" type=\"hidden\" value=\"exact\"",
  )
  assert string.contains(
    list,
    "name=\"filter_enabled\" type=\"hidden\" value=\"true\"",
  )
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

pub fn rule_crud_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)

  // create
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "307"),
      #("source", "/promo"),
      #("target", "https://shop.test/sale"),
      #("priority", "100"),
      #("enabled", "on"),
    ])
  assert resp.status == 303
  let redirect = get(env.redirect <> "/promo", [])
  assert redirect.status == 307
  assert location(redirect) == "https://shop.test/sale"

  // validation errors are shown
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("match", "regex"),
      #("status", "301"),
      #("source", "^/(a+)+$"),
      #("target", "/x"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "catastrophic backtracking")

  // the list shows it
  let list_page = get(env.admin <> "/rules?q=promo", [#("cookie", cookie)])
  assert string.contains(list_page.body, "https://shop.test/sale")

  // find its id in the persisted file
  let assert Ok(content) = simplifile.read(env.dir <> "/redirects.json")
  let assert Ok(#(_, after)) =
    string.split_once(content, "\"source\":\"/promo\"")
  let _ = after
  let id = find_id(content, "/promo")

  // update
  let resp =
    post_form(env, "/rules/" <> id, cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/promo"),
      #("target", "https://shop.test/summer"),
      #("enabled", "on"),
    ])
  assert resp.status == 303
  assert location(get(env.redirect <> "/promo", []))
    == "https://shop.test/summer"

  // toggle off
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.redirect <> "/promo", []).status == 404

  // delete
  let resp =
    post_form(env, "/rules/" <> id <> "/delete", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.admin <> "/rules/" <> id <> "/edit", [#("cookie", cookie)]).status
    == 404

  // audit trail
  let audit = get(env.admin <> "/audit", [#("cookie", cookie)])
  assert string.contains(audit.body, "rule.delete")
}

/// Two admins edit the same redirection: the second save is refused instead
/// of silently overwriting the first.
pub fn concurrent_admin_edits_are_detected_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert Ok(content) = simplifile.read(env.dir <> "/redirects.json")
  let id = find_id(content, "/old")
  let fields = fn(target, version) {
    [
      #("csrf_token", csrf),
      #("version", version),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/old"),
      #("target", target),
      #("enabled", "on"),
    ]
  }
  // both open the edit page
  let page = get(env.admin <> "/rules/" <> id <> "/edit", [#("cookie", cookie)])
  let version = hidden_value(page.body, "version")
  assert version != ""

  // the first one saves
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://first.test/", version),
    )
  assert resp.status == 303

  // the second one, based on the same version, is told and nothing changes
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://second.test/", version),
    )
  assert resp.status == 409
  assert string.contains(resp.body, "while you were working on it")
  assert string.contains(resp.body, "https://second.test/")
  assert location(get(env.redirect <> "/old", [])) == "https://first.test/"

  // saving the conflict form again (it carries the new version) overwrites
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://second.test/", hidden_value(resp.body, "version")),
    )
  assert resp.status == 303
  assert location(get(env.redirect <> "/old", [])) == "https://second.test/"

  // toggling and deleting from a stale page are refused too
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("version", version),
    ])
  assert resp.status == 409
  let resp =
    post_form(env, "/rules/" <> id <> "/delete", cookie, [
      #("csrf_token", csrf),
      #("version", version),
    ])
  assert resp.status == 409
  assert get(env.redirect <> "/old", []).status == 301
}

fn hidden_value(html: String, name: String) -> String {
  let assert Ok(#(_, rest)) =
    string.split_once(html, "name=\"" <> name <> "\" type=\"hidden\" value=\"")
  let assert Ok(#(value, _)) = string.split_once(rest, "\"")
  value
}

fn find_id(content: String, source: String) -> String {
  // rules are serialised as {"id":"...","host":...,"source":"<source>"...}
  let assert Ok(#(before, _)) =
    string.split_once(content, "\"source\":\"" <> source <> "\"")
  let assert Ok(last) = before |> string.split("\"id\":\"") |> list.last
  let assert Ok(#(id, _)) = string.split_once(last, "\"")
  id
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

pub fn import_export_and_tester_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let content =
    "[{\"source\": \"/imported\", \"target\": \"/landing\", \"status\": 302}]"
  // a replace is previewed first: nothing is written yet
  let preview =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("content", content),
    ])
  assert preview.status == 200
  assert string.contains(preview.body, "Import preview")
  assert string.contains(preview.body, "removed")
  assert get(env.redirect <> "/old", []).status == 301
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("step", "apply"),
      #("content", content),
    ])
  assert resp.status == 303
  assert location(get(env.redirect <> "/imported", [])) == "/landing"
  assert get(env.redirect <> "/old", []).status == 404

  let export = get(env.admin <> "/export", [#("cookie", cookie)])
  assert export.status == 200
  assert string.contains(export.body, "/imported")
  assert response.get_header(export, "content-disposition")
    |> result.map(string.contains(_, "redirects.json"))
    == Ok(True)

  let tester =
    get(
      env.admin
        <> "/test?"
        <> uri.query_to_string([#("url", "https://x.test/imported?a=1")]),
      [#("cookie", cookie)],
    )
  assert string.contains(tester.body, "/landing")

  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("content", "{broken"),
    ])
  assert resp.status == 422
}

/// Applying a previewed replace while the rules changed meanwhile shows the
/// updated preview instead of deleting rules that were never shown.
pub fn stale_import_preview_is_shown_again_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let content = "[{\"source\": \"/imported\", \"target\": \"/landing\"}]"
  let preview =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("content", content),
    ])
  let assert Ok(#(_, rest)) =
    string.split_once(preview.body, "name=\"version\" type=\"hidden\" value=\"")
  let assert Ok(#(version, _)) = string.split_once(rest, "\"")
  assert version != ""
  // another administrator adds a rule
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/added-meanwhile"),
      #("target", "/x"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("step", "apply"),
      #("version", version),
      #("content", content),
    ])
  assert resp.status == 200
  assert string.contains(resp.body, "were changed while you were reviewing")
  assert get(env.redirect <> "/added-meanwhile", []).status == 301
  assert get(env.redirect <> "/imported", []).status == 404
}

pub fn reload_from_disk_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/fresh\", \"target\": \"/reloaded\"}]",
    )
  let resp = post_form(env, "/reload", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert location(get(env.redirect <> "/fresh", [])) == "/reloaded"

  let assert Ok(Nil) = simplifile.write(env.dir <> "/redirects.json", "[{]")
  let resp = post_form(env, "/reload", cookie, [#("csrf_token", csrf)])
  assert resp.status == 422
  assert location(get(env.redirect <> "/fresh", [])) == "/reloaded"
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

// --- header authentication --------------------------------------------------

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

// --- OIDC -------------------------------------------------------------------

fn start_fake_idp(email: String) -> String {
  let #(jwks, key) = support.keypair()
  let port_key = "fake_idp_port_" <> email
  let handler = fn(req: request.Request(mist.Connection)) {
    let issuer =
      "http://127.0.0.1:"
      <> int.to_string(ffi.snapshot_get(port_key) |> result.unwrap(0))
    let json_response = fn(body) {
      response.new(200)
      |> response.set_header("content-type", "application/json")
      |> response.set_body(mist.Bytes(bytes_tree.from_string(body)))
    }
    case req.path {
      "/.well-known/openid-configuration" ->
        json.object([
          #("issuer", json.string(issuer)),
          #("authorization_endpoint", json.string(issuer <> "/authorize")),
          #("token_endpoint", json.string(issuer <> "/token")),
          #("jwks_uri", json.string(issuer <> "/jwks")),
          #("end_session_endpoint", json.string(issuer <> "/logout?realm=x")),
        ])
        |> json.to_string
        |> json_response
      "/jwks" -> json_response(jwks)
      "/authorize" -> {
        let query = request.get_query(req) |> result.unwrap([])
        let get = fn(k) { list.key_find(query, k) |> result.unwrap("") }
        // The code carries the nonce so that the token endpoint is stateless.
        let code = bit_array.base64_url_encode(<<get("nonce"):utf8>>, False)
        response.new(302)
        |> response.set_header(
          "location",
          get("redirect_uri")
            <> "?"
            <> uri.query_to_string([#("code", code), #("state", get("state"))]),
        )
        |> response.set_body(mist.Bytes(bytes_tree.new()))
      }
      "/token" -> {
        let assert Ok(req) = mist.read_body(req, 10_000)
        let assert Ok(body) = bit_array.to_string(req.body)
        let assert Ok(form) = uri.parse_query(body)
        let get = fn(k) { list.key_find(form, k) |> result.unwrap("") }
        let assert Ok(nonce) = bit_array.base64_url_decode(get("code"))
        let assert Ok(nonce) = bit_array.to_string(nonce)
        case get("client_secret") == "secret" && get("code_verifier") != "" {
          False ->
            response.new(401) |> response.set_body(mist.Bytes(bytes_tree.new()))
          True ->
            json.object([
              #(
                "id_token",
                json.string(support.sign(
                  key,
                  json.object([
                    #("iss", json.string(issuer)),
                    #("sub", json.string("user-123")),
                    #("aud", json.string("redirect-proxy")),
                    #("exp", json.int(ffi.now_seconds() + 300)),
                    #("iat", json.int(ffi.now_seconds())),
                    #("nonce", json.string(nonce)),
                    #("email", json.string(email)),
                    #("email_verified", json.bool(True)),
                    #("groups", json.array(["staff"], json.string)),
                  ])
                    |> json.to_string,
                )),
              ),
              #("token_type", json.string("Bearer")),
            ])
            |> json.to_string
            |> json_response
        }
      }
      _ -> response.new(404) |> response.set_body(mist.Bytes(bytes_tree.new()))
    }
  }
  let ready = process.new_subject()
  let assert Ok(_) =
    mist.new(handler)
    |> mist.bind("127.0.0.1")
    |> mist.port(0)
    |> mist.after_start(fn(port, _, _) {
      ffi.snapshot_put(port_key, port)
      process.send(ready, port)
    })
    |> mist.start
  let assert Ok(port) = process.receive(ready, 5000)
  "http://127.0.0.1:" <> int.to_string(port)
}

fn oidc_env(issuer: String, allowed_domains: List(String)) -> Env {
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
          allowed_domains:,
          default_role: "admin",
        ),
      ),
    )
  env
}

fn sso_login(env: Env) -> response.Response(String) {
  // public_url defaults to http://localhost:8081; the fake IdP simply sends
  // the browser back to whatever redirect_uri it received, so rewrite it.
  let start = get(env.admin <> "/auth/oidc/start", [])
  assert start.status == 303
  let state = cookie_of(start, "rp_oidc_state")
  assert state != ""
  let authorize = get(location(start), [])
  assert authorize.status == 302
  let callback = location(authorize)
  let assert Ok(#(_, query)) = string.split_once(callback, "?")
  get(env.admin <> "/auth/oidc/callback?" <> query, [#("cookie", state)])
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

// --- signals ----------------------------------------------------------------

@external(erlang, "os", "getpid")
fn os_pid() -> charlist.Charlist

@external(erlang, "os", "cmd")
fn os_cmd(command: charlist.Charlist) -> charlist.Charlist

pub fn sighup_reloads_rules_test() {
  let env = boot(config.default())
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/hup\", \"target\": \"/after-sighup\"}]",
    )
  let _ =
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  wait_until(fn() { get(env.redirect <> "/hup", []).status == 301 }, 50)
  assert location(get(env.redirect <> "/hup", [])) == "/after-sighup"
}

pub fn sighup_with_an_invalid_file_keeps_the_rules_test() {
  let env = boot(config.default())
  let failures = metric(env, "redirect_proxy_reload_failures_total")
  let assert Ok(Nil) =
    simplifile.write(env.dir <> "/redirects.json", "{ not json")
  let _ =
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  wait_until(
    fn() { metric(env, "redirect_proxy_reload_failures_total") > failures },
    50,
  )
  assert location(get(env.redirect <> "/old", [])) == "https://example.com/new"
}

/// A reload callback that crashes is logged; later signals still reach it.
pub fn sighup_survives_a_crashing_callback_test() {
  let calls = process.new_subject()
  ffi.on_sighup(fn() {
    process.send(calls, Nil)
    panic as "reload exploded"
  })
  let hup = fn() {
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  }
  let _ = hup()
  let first = process.receive(calls, 2000)
  let _ = hup()
  let second = process.receive(calls, 2000)
  // the next boot installs the application's own callback again
  ffi.on_sighup(fn() { Nil })
  assert first == Ok(Nil)
  assert second == Ok(Nil)
}

/// Signals other than SIGTERM keep OTP's default handling, and the drain
/// handler stays installed.
pub fn other_signals_are_left_to_otp_test() {
  let _ = boot(config.default())
  notify_signal("sigusr2")
  notify_signal("sigchld")
  assert !ffi.draining()
  assert list.contains(signal_handlers(), "redirect_proxy_sigterm")
  assert !list.contains(signal_handlers(), "erl_signal_handler")
}

@external(erlang, "test_signal_ffi", "notify")
fn notify_signal(signal: String) -> Nil

@external(erlang, "test_signal_ffi", "handlers")
fn signal_handlers() -> List(String)

pub fn request_counters_test() {
  let env = boot(config.default())
  let before = fn(name) { metric(env, name) }
  let requests = before("redirect_proxy_requests_total")
  let redirects = before("redirect_proxy_redirects_total")
  let not_found = before("redirect_proxy_not_found_total")
  assert get(env.redirect <> "/old", []).status == 301
  assert get(env.redirect <> "/blog/7", []).status == 308
  assert get(env.redirect <> "/nothing", []).status == 404
  // other tests may run requests concurrently: at least ours are counted
  assert metric(env, "redirect_proxy_requests_total") >= requests + 3
  assert metric(env, "redirect_proxy_redirects_total") >= redirects + 2
  assert metric(env, "redirect_proxy_not_found_total") >= not_found + 1
}

pub fn latency_and_response_metrics_test() {
  let env = boot(config.default())
  let count = fn() {
    metric(
      env,
      "redirect_proxy_request_duration_seconds_count{listener=\"redirect\"}",
    )
  }
  let redirects = metric(env, "redirect_proxy_responses_total{class=\"3xx\"}")
  let before = count()
  assert get(env.redirect <> "/old", []).status == 301
  assert get(env.redirect <> "/nothing", []).status == 404
  assert count() >= before + 2
  assert metric(env, "redirect_proxy_responses_total{class=\"3xx\"}")
    >= redirects + 1
  let body = get(env.admin <> "/metrics", []).body
  // cumulative buckets end with +Inf, equal to the count
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"+Inf\"}",
  )
  // buckets of microseconds, for redirects, written as decimals
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"0.000005\"}",
  )
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"0.0025\"}",
  )
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"1\"}",
  )
  assert !string.contains(body, "0e-")
  assert string.contains(body, "redirect_proxy_rules_by_kind{kind=\"exact\"} 1")
  assert string.contains(
    body,
    "redirect_proxy_rules_by_kind{kind=\"prefix\"} 1",
  )
  assert string.contains(body, "redirect_proxy_rules_by_kind{kind=\"regex\"} 1")
  assert metric(env, "redirect_proxy_last_reload_timestamp_seconds") > 0
}

/// Failures that need an operator are counted: an unwritable data directory
/// and an identity provider that cannot be reached.
pub fn failure_metrics_test() {
  let d = config.default()
  // nothing listens on the free port: SSO discovery fails
  let issuer = "http://127.0.0.1:" <> int.to_string(support.free_port())
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
        ),
      ),
    )
  let idp = metric(env, "redirect_proxy_idp_fetch_failures_total")
  assert get(env.admin <> "/auth/oidc/start", []).status == 303
  assert metric(env, "redirect_proxy_idp_fetch_failures_total") == idp + 1

  let #(cookie, csrf) = login(env)
  let writes = metric(env, "redirect_proxy_storage_write_failures_total")
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o500)
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/unsaved"),
      #("target", "/x"),
      #("priority", "100"),
      #("enabled", "on"),
    ])
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o700)
  assert resp.status == 422
  assert metric(env, "redirect_proxy_storage_write_failures_total") > writes
}

/// The value of an unlabelled metric in /metrics.
fn metric(env: Env, name: String) -> Int {
  let body = get(env.admin <> "/metrics", []).body
  body
  |> string.split("\n")
  |> list.find_map(fn(line) {
    case string.split_once(line, " ") {
      Ok(#(n, value)) if n == name -> int.parse(value)
      _ -> Error(Nil)
    }
  })
  |> result.unwrap(0)
}

fn wait_until(condition: fn() -> Bool, attempts: Int) -> Nil {
  case condition(), attempts {
    True, _ -> Nil
    False, 0 -> panic as "condition not met in time"
    False, _ -> {
      process.sleep(20)
      wait_until(condition, attempts - 1)
    }
  }
}

// --- API clients page -------------------------------------------------------

pub fn api_clients_page_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = get(env.admin <> "/api-clients", [#("cookie", cookie)])
  assert page.status == 200
  assert string.contains(page.body, "No API client yet.")

  // create: the secret is shown once
  let resp =
    post_form(env, "/api-clients", cookie, [
      #("csrf_token", csrf),
      #("name", "deploy"),
      #("scope", "redirects:read"),
      #("scope", "redirects:ops"),
    ])
  assert resp.status == 201
  let secret = between(resp.body, "rps_", "<")
  let client_id = between(resp.body, "rp_", "<")
  assert string.length(secret) > 20

  // the client can obtain a token
  let token_resp =
    send(
      http.Post,
      env.admin <> "/oauth/token",
      [#("content-type", "application/x-www-form-urlencoded")],
      uri.query_to_string([
        #("grant_type", "client_credentials"),
        #("client_id", "rp_" <> client_id),
        #("client_secret", "rps_" <> secret),
      ]),
    )
  assert token_resp.status == 200
  assert string.contains(token_resp.body, "redirects:read redirects:ops")

  // the listing no longer shows the secret
  let page = get(env.admin <> "/api-clients", [#("cookie", cookie)])
  assert !string.contains(page.body, secret)
  assert string.contains(page.body, "deploy")

  // invalid: no scope
  let resp =
    post_form(env, "/api-clients", cookie, [
      #("csrf_token", csrf),
      #("name", "noscope"),
    ])
  assert resp.status == 422

  // rotate shows a new secret, then delete
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/rotate", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 200
  assert between(resp.body, "rps_", "<") != secret
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/delete", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 303
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/delete", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 404
}

/// The text after the first `start` marker up to `stop`.
fn between(text: String, start: String, stop: String) -> String {
  let assert Ok(#(_, rest)) = string.split_once(text, start)
  let assert Ok(#(value, _)) = string.split_once(rest, stop)
  value
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

/// A replica serving a read-only volume (a Kubernetes ConfigMap): with the
/// admin disabled it starts, serves the rules and picks up a replaced file,
/// without writing to the data directory.
pub fn replica_on_a_read_only_data_dir_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"id\":\"r1\",\"source\":\"/ro\",\"target\":\"/one\"}]}",
    )
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o500)
  let d = config.default()
  let cfg =
    config.Config(
      ..d,
      server: config.ServerConfig(..d.server, listen: "127.0.0.1", port: 0),
      admin: config.AdminConfig(..d.admin, enabled: False),
      api: config.ApiConfig(..d.api, enabled: False),
      storage: config.StorageConfig(
        ..config.default().storage,
        data_dir: dir,
        backups: 3,
        watch_interval: 0,
      ),
      access_log: config.AccessLogConfig(..d.access_log, enabled: False),
    )
  let started = app.start(cfg)
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o700)
  let assert Ok(running) = started
  let resp =
    get(
      "http://127.0.0.1:" <> int.to_string(running.redirect_port) <> "/ro",
      [],
    )
  assert resp.status == 301
  assert location(resp) == "/one"
  // nothing was written: no cookie secret, no lock left behind
  let assert Ok(files) = simplifile.read_directory(dir)
  assert files == ["redirects.json"]
}

/// With `admin.metrics_token`, /metrics needs the bearer token; health
/// probes stay public.
pub fn metrics_token_test() {
  let d = config.default()
  let token = "a-metrics-token-of-some-length"
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(..d.admin, metrics_token: token),
      ),
    )
  let scrape = fn(headers) { get(env.admin <> "/metrics", headers) }
  let resp = scrape([])
  assert resp.status == 401
  assert response.get_header(resp, "www-authenticate")
    == Ok("Bearer realm=\"metrics\"")
  assert scrape([#("authorization", "Bearer wrong")]).status == 401
  assert scrape([#("authorization", "Basic " <> token)]).status == 401
  let resp = scrape([#("authorization", "Bearer " <> token)])
  assert resp.status == 200
  assert string.contains(resp.body, "redirect_proxy_build_info")
  assert scrape([#("authorization", "bearer " <> token)]).status == 200
  assert get(env.admin <> "/healthz", []).status == 200
}

pub fn admin_rule_tags_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/tagged"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
      #("tags", "Spring Sale, legacy"),
    ]).status
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]).body }
  let list = page("/rules?tag=legacy")
  assert string.contains(list, "/tagged")
  assert !string.contains(list, "/old")
  // each tag links to its filter
  assert string.contains(list, "href=\"/rules?tag=spring%20sale\"")
  assert !string.contains(page("/rules?tag=other"), "/tagged")
}

pub fn admin_csv_import_and_export_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "merge"),
      #("content", "source,target,status,tags\n/from-csv,/landing,302,sheet\n"),
    ])
  assert resp.status == 303
  let found = get(env.redirect <> "/from-csv", [])
  assert found.status == 302
  assert location(found) == "/landing"
  // errors name the line
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "merge"),
      #("content", "source,target,status\n/x,/y,moved\n"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "line 2: status: must be a number")
  let export =
    get(env.admin <> "/export?format=csv&tag=sheet", [#("cookie", cookie)])
  assert response.get_header(export, "content-type")
    == Ok("text/csv; charset=utf-8")
  assert string.contains(export.body, "/from-csv,/landing,302")
  assert !string.contains(export.body, "/old,")
}

/// Signs in a new local user with this role: the session cookie and CSRF
/// token.
fn login_with_role(env: Env, name: String, r: role.Role) -> #(String, String) {
  let assert Ok(_) =
    users.create_with_role(
      users.Settings(
        path: env.dir <> "/users.json",
        audit_path: env.dir <> "/audit.jsonl",
      ),
      name,
      password.hash_with(admin_password, 1000),
      r,
      by: "test",
    )
  let resp =
    post_form(env, "/login", "", [
      #("username", name),
      #("password", admin_password),
    ])
  assert resp.status == 303
  let cookie = session_cookie(resp)
  let page = get(env.admin <> "/account", [#("cookie", cookie)])
  assert page.status == 200
  #(cookie, csrf_token(page.body))
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
  assert get(env.admin <> "/users", [#("cookie", cookie), ..as_role("admin")]).status
    == 200
  // no header: the least
  assert get(env.admin <> "/import", [#("x-forwarded-user", "sam")]).status
    == 403
}

/// Dot segments are removed before matching: a capture cannot climb out of
/// the target path (`/v1/../../x` would give `https://docs.example.com/x`).
pub fn dot_segments_cannot_escape_the_target_path_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let exchange = fn(path) {
    let request =
      "GET "
      <> path
      <> " HTTP/1.1\r\nhost: docs.test\r\nconnection: close\r\n\r\n"
    let assert Ok(text) =
      bit_array.to_string(raw_exchange(port, [bit_array.from_string(request)]))
    text
  }
  assert string.starts_with(exchange("/v1/../../x"), "HTTP/1.1 404 ")
  assert string.starts_with(exchange("/v1/%2E%2E/%2e%2E/x"), "HTTP/1.1 404 ")
  assert string.contains(
    exchange("/v1/a/../b"),
    "\r\nlocation: https://docs.example.com/v2/b\r\n",
  )
  // browsers read `\` as `/`: a raw backslash never reaches the matcher
  assert !string.contains(exchange("/v1/..\\..\\x"), "location:")
}
