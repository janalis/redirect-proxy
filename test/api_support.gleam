//// Shared by the tests of the REST API in test/redirect_proxy/api/: API
//// clients and tokens, requests, the fake authorization server.

import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/http.{Get, Post}
import gleam/http/response
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config
import support.{type App}

pub fn new_client(env: App, scopes: List(scope.Scope)) -> #(String, String) {
  let assert Ok(#(client, secret)) =
    clients.create(app.clients_settings(env.config), "test", scopes, by: "test")
  #(client.client_id, secret)
}

pub fn basic(id: String, secret: String) -> #(String, String) {
  #(
    "authorization",
    "Basic " <> bit_array.base64_encode(<<{ id <> ":" <> secret }:utf8>>, True),
  )
}

pub fn token_request(
  env: App,
  headers: List(#(String, String)),
  fields: List(#(String, String)),
) -> response.Response(String) {
  support.send(
    Post,
    env.api <> "/oauth/token",
    [#("content-type", "application/x-www-form-urlencoded"), ..headers],
    uri.query_to_string(fields),
  )
}

pub fn access_token(env: App, scopes: List(scope.Scope)) -> String {
  let #(id, secret) = new_client(env, scopes)
  let resp =
    token_request(env, [basic(id, secret)], [
      #("grant_type", "client_credentials"),
    ])
  assert resp.status == 200
  let assert Ok(token) =
    json.parse(resp.body, decode.at(["access_token"], decode.string))
  token
}

pub fn api(
  env: App,
  method: http.Method,
  path: String,
  token: String,
  body: String,
) -> response.Response(String) {
  support.send(
    method,
    env.api <> path,
    [
      #("authorization", "Bearer " <> token),
      #("content-type", "application/json"),
    ],
    body,
  )
}

pub fn field(body: String, path: List(String), d: decode.Decoder(a)) -> a {
  let assert Ok(value) = json.parse(body, decode.at(path, d))
  value
}

pub fn header(resp: response.Response(a), name: String) -> String {
  response.get_header(resp, name) |> result.unwrap("")
}

pub fn env_client(env: App) -> String {
  let assert Ok([first, ..]) = clients.list(app.clients_settings(env.config))
  first.client_id
}

pub fn dict_get(d: dict.Dict(String, a), key: String) -> Result(a, Nil) {
  dict.get(d, key)
}

pub fn external_env() -> #(App, String, support.Key) {
  let #(issuer, key) = support.start_fake_authorization_server()
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        api: config.ApiConfig(
          ..d.api,
          oauth: config.ApiOAuthConfig(
            ..d.api.oauth,
            enabled: True,
            issuer:,
            audience: "redirect-proxy",
            write_scope: "rp.write",
          ),
        ),
      ),
    )
  #(env, issuer, key)
}

/// An access token typed as such (RFC 9068), as `require_at_jwt` wants by
/// default.
pub fn jwt(key: support.Key, claims: List(#(String, json.Json))) -> String {
  support.sign_typed(key, "at+jwt", json.object(claims) |> json.to_string)
}

pub fn own_port(admin_enabled: Bool) -> App {
  let d = config.default()
  support.boot(
    config.Config(
      ..d,
      admin: config.AdminConfig(..d.admin, enabled: admin_enabled),
      // with the admin UI disabled, port 0 means an ephemeral port of its own
      api: config.ApiConfig(..d.api, port: case admin_enabled {
        True -> support.free_port()
        False -> 0
      }),
    ),
  )
}

pub fn import_set(
  env: App,
  token: String,
  rules: List(#(String, String, Bool)),
) {
  let body =
    rules
    |> list.map(fn(r) {
      json.object([
        #("id", json.string(r.0)),
        #("source", json.string(r.1)),
        #("target", json.string("/to" <> r.1)),
        #("enabled", json.bool(r.2)),
      ])
    })
    |> json.preprocessed_array
    |> json.to_string
  let resp = api(env, Post, "/api/redirects/import?mode=replace", token, body)
  assert resp.status == 200
}

pub fn get_rule_enabled(env: App, token: String, id: String) -> Bool {
  let resp = api(env, Get, "/api/redirects/" <> id, token, "")
  field(resp.body, ["enabled"], decode.bool)
}

pub fn compare_pairs(a: #(String, String), b: #(String, String)) {
  string.compare(a.1 <> " " <> a.0, b.1 <> " " <> b.0)
}
