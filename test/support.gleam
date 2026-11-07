//// Helpers shared by tests.

import envoy
import gleam/bytes_tree
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import mist
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/id
import simplifile

/// Creates a fresh, empty temporary directory.
pub fn temp_dir() -> String {
  let base = envoy.get("TMPDIR") |> result.unwrap("/tmp")
  let dir = base <> "/redirect-proxy-test-" <> id.token(9)
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  dir
}

pub type App {
  App(
    redirect: String,
    admin: String,
    /// Base URL of the API: the admin URL, or the dedicated API listener.
    api: String,
    dir: String,
    config: config.Config,
  )
}

/// Starts the whole application on ephemeral ports with an empty data dir.
pub fn boot(cfg: config.Config) -> App {
  let dir = temp_dir()
  let cfg =
    config.Config(
      ..cfg,
      server: config.ServerConfig(..cfg.server, listen: "127.0.0.1", port: 0),
      admin: config.AdminConfig(..cfg.admin, listen: "127.0.0.1", port: 0),
      // api.port 0 shares the admin listener; tests wanting the API on its
      // own port pass one from `free_port()`.
      api: config.ApiConfig(..cfg.api, listen: ""),
      storage: config.StorageConfig(
        ..config.default().storage,
        data_dir: dir,
        backups: 3,
        watch_interval: 0,
      ),
      // Keep access lines out of the test output unless a test picks a path.
      access_log: case cfg.access_log.output {
        "stdout" | "stderr" ->
          config.AccessLogConfig(..cfg.access_log, output: dir <> "/access.log")
        _ -> cfg.access_log
      },
    )
  let assert Ok(running) = app.start(cfg)
  let admin = "http://127.0.0.1:" <> int.to_string(running.admin_port)
  App(
    redirect: "http://127.0.0.1:" <> int.to_string(running.redirect_port),
    admin:,
    api: case config.api_dedicated(cfg) {
      True -> "http://127.0.0.1:" <> int.to_string(running.api_port)
      False -> admin
    },
    dir:,
    config: cfg,
  )
}

pub fn send(
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

@external(erlang, "test_net_ffi", "free_port")
pub fn free_port() -> Int

// --- fake OAuth 2.0 authorization server --------------------------------------

pub type Key

@external(erlang, "test_jwt_ffi", "keypair")
pub fn keypair() -> #(String, Key)

@external(erlang, "test_jwt_ffi", "sign")
pub fn sign(key: Key, claims: String) -> String

@external(erlang, "test_jwt_ffi", "sign_typed")
pub fn sign_typed(key: Key, typ: String, claims: String) -> String

/// Starts an authorization server publishing RFC 8414 metadata and a JWKS.
/// Returns its issuer URL and the signing key.
pub fn start_fake_authorization_server() -> #(String, Key) {
  let #(jwks, key) = keypair()
  let port_key = "fake_as_port_" <> id.token(6)
  let handler = fn(req: request.Request(mist.Connection)) {
    let issuer =
      "http://127.0.0.1:"
      <> int.to_string(ffi.snapshot_get(port_key) |> result.unwrap(0))
    let body = case req.path {
      "/.well-known/oauth-authorization-server" ->
        Ok(
          json.object([
            #("issuer", json.string(issuer)),
            #("token_endpoint", json.string(issuer <> "/token")),
            #("jwks_uri", json.string(issuer <> "/jwks")),
          ])
          |> json.to_string,
        )
      "/jwks" -> Ok(jwks)
      _ -> Error(Nil)
    }
    case body {
      Ok(body) ->
        response.new(200)
        |> response.set_header("content-type", "application/json")
        |> response.set_body(mist.Bytes(bytes_tree.from_string(body)))
      Error(Nil) ->
        response.new(404) |> response.set_body(mist.Bytes(bytes_tree.new()))
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
  #("http://127.0.0.1:" <> int.to_string(port), key)
}

/// Sets the flag a SIGTERM sets: the node drains before it stops.
@external(erlang, "redirect_proxy_sigterm", "set_draining")
pub fn set_draining(value: Bool) -> Nil

/// Runs `f` with the draining flag of a SIGTERM set, and always clears it
/// afterwards, even when `f` fails: the flag is node-wide, and left set it
/// would fail every later test that probes readiness.
pub fn with_draining(f: fn() -> a) -> a {
  set_draining(True)
  let result = ffi.rescue(f)
  set_draining(False)
  case result {
    Ok(value) -> value
    Error(reason) -> panic as reason
  }
}

/// Waits until `condition` holds, checking every 20 ms for at most
/// `timeout_ms`, and fails the test after that.
pub fn wait_until(condition: fn() -> Bool, timeout_ms: Int) -> Nil {
  case condition(), timeout_ms <= 0 {
    True, _ -> Nil
    False, True -> panic as "condition not met in time"
    False, False -> {
      process.sleep(20)
      wait_until(condition, timeout_ms - 20)
    }
  }
}
