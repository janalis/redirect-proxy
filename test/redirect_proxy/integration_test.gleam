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
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import mist
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/password
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
      storage: config.StorageConfig(data_dir: dir, backups: 3),
      access_log: config.AccessLogConfig(
        ..cfg.access_log,
        output: dir <> "/logs/access.log",
      ),
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
  let assert Ok(req) = request.to(url)
  let req =
    list.fold(headers, request.set_method(req, method), fn(req, h) {
      request.set_header(req, h.0, h.1)
    })
    |> request.set_body(body)
  let assert Ok(resp) =
    httpc.configure() |> httpc.follow_redirects(False) |> httpc.dispatch(req)
  resp
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
  resp.headers
  |> list.filter_map(fn(h) {
    case h {
      #("set-cookie", "rp_session=" <> rest) ->
        case string.split_once(rest, ";") {
          Ok(#(value, _)) -> Ok("rp_session=" <> value)
          Error(Nil) -> Ok("rp_session=" <> rest)
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
  access_lines_loop(dir <> "/logs/access.log", count, 250)
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
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #(
        "content",
        "[{\"source\": \"/imported\", \"target\": \"/landing\", \"status\": 302}]",
      ),
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
  assert string.contains(resp.body, "proxy-user (proxy)")
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

@external(erlang, "test_jwt_ffi", "keypair")
fn keypair() -> #(String, Key)

@external(erlang, "test_jwt_ffi", "sign")
fn sign(key: Key, claims: String) -> String

type Key

fn start_fake_idp(email: String) -> String {
  let #(jwks, key) = keypair()
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
                json.string(sign(
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
  let authorize = get(location(start), [])
  assert authorize.status == 302
  let callback = location(authorize)
  let assert Ok(#(_, query)) = string.split_once(callback, "?")
  get(env.admin <> "/auth/oidc/callback?" <> query, [])
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
  assert string.contains(page.body, "alice@example.com (sso)")

  // a state can only be used once
  let start = get(env.admin <> "/auth/oidc/start", [])
  let authorize = get(location(start), [])
  let assert Ok(#(_, query)) = string.split_once(location(authorize), "?")
  assert get(env.admin <> "/auth/oidc/callback?" <> query, []).status == 303
  assert get(env.admin <> "/auth/oidc/callback?" <> query, []).status == 403
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
