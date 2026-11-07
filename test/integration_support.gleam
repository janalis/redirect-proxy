//// Shared by the end-to-end tests of test/redirect_proxy/integration/: the
//// full application on ephemeral ports, driven over real HTTP, plus a fake
//// OpenID Connect provider.

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/charlist
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import mist
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import simplifile
import support

pub const admin_password = "integration-password"

pub type Env {
  Env(redirect: String, admin: String, dir: String)
}

pub fn boot(cfg: config.Config) -> Env {
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

pub fn send(
  method: http.Method,
  url: String,
  headers: List(#(String, String)),
  body: String,
) -> response.Response(String) {
  support.send(method, url, headers, body)
}

pub fn get(url: String, headers: List(#(String, String))) {
  send(http.Get, url, headers, "")
}

pub fn post_form(
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

pub fn location(resp: response.Response(a)) -> String {
  response.get_header(resp, "location") |> result.unwrap("")
}

pub fn session_cookie(resp: response.Response(a)) -> String {
  cookie_of(resp, "rp_session")
}

/// `name=value` of a cookie set by a response, "" when not set.
pub fn cookie_of(resp: response.Response(a), name: String) -> String {
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

pub fn csrf_token(html: String) -> String {
  let assert Ok(#(_, rest)) =
    string.split_once(html, "name=\"csrf_token\" type=\"hidden\" value=\"")
  let assert Ok(#(token, _)) = string.split_once(rest, "\"")
  token
}

pub fn login(env: Env) -> #(String, String) {
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

/// Waits for the access log handler to flush `count` lines.
pub fn access_lines(dir: String, count: Int) -> List(String) {
  lines_of(dir <> "/logs/access.log", count)
}

pub fn lines_of(path: String, count: Int) -> List(String) {
  access_lines_loop(path, count, 250)
}

pub fn access_lines_loop(path: String, count: Int, tries: Int) -> List(String) {
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

@external(erlang, "test_net_ffi", "raw_exchange")
pub fn raw_exchange(port: Int, chunks: List(BitArray)) -> BitArray

pub fn reload_rules(env: Env) -> Result(Nil, Nil) {
  let #(cookie, csrf) = login(env)
  case post_form(env, "/reload", cookie, [#("csrf_token", csrf)]).status {
    303 -> Ok(Nil)
    _ -> Error(Nil)
  }
}

pub fn hidden_value(html: String, name: String) -> String {
  let assert Ok(#(_, rest)) =
    string.split_once(html, "name=\"" <> name <> "\" type=\"hidden\" value=\"")
  let assert Ok(#(value, _)) = string.split_once(rest, "\"")
  value
}

pub fn find_id(content: String, source: String) -> String {
  // rules are serialised as {"id":"...","host":...,"source":"<source>"...}
  let assert Ok(#(before, _)) =
    string.split_once(content, "\"source\":\"" <> source <> "\"")
  let assert Ok(last) = before |> string.split("\"id\":\"") |> list.last
  let assert Ok(#(id, _)) = string.split_once(last, "\"")
  id
}

pub fn start_fake_idp(email: String) -> String {
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
  let issuer = "http://127.0.0.1:" <> int.to_string(port)
  support.forget_provider(issuer)
  issuer
}

pub fn oidc_env(issuer: String, allowed_domains: List(String)) -> Env {
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

pub fn sso_login(env: Env) -> response.Response(String) {
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

@external(erlang, "os", "getpid")
pub fn os_pid() -> charlist.Charlist

@external(erlang, "os", "cmd")
pub fn os_cmd(command: charlist.Charlist) -> charlist.Charlist

@external(erlang, "test_signal_ffi", "notify")
pub fn notify_signal(signal: String) -> Nil

@external(erlang, "test_signal_ffi", "handlers")
pub fn signal_handlers() -> List(String)

/// The value of an unlabelled metric in /metrics.
pub fn metric(env: Env, name: String) -> Int {
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

pub fn wait_until(condition: fn() -> Bool, attempts: Int) -> Nil {
  case condition(), attempts {
    True, _ -> Nil
    False, 0 -> panic as "condition not met in time"
    False, _ -> {
      process.sleep(20)
      wait_until(condition, attempts - 1)
    }
  }
}

/// The text after the first `start` marker up to `stop`.
pub fn between(text: String, start: String, stop: String) -> String {
  let assert Ok(#(_, rest)) = string.split_once(text, start)
  let assert Ok(#(value, _)) = string.split_once(rest, stop)
  value
}

/// Signs in a new local user with this role: the session cookie and CSRF
/// token.
pub fn login_with_role(
  env: Env,
  name: String,
  r: role.Role,
) -> #(String, String) {
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
