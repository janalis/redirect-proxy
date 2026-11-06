//// REST API and OAuth token endpoint, end to end over HTTP.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/api/auth
import redirect_proxy/api/clients
import redirect_proxy/api/deprecation
import redirect_proxy/api/openapi
import redirect_proxy/api/problem
import redirect_proxy/api/routes
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/config/validate as config_validate
import redirect_proxy/ffi
import redirect_proxy/rule
import simplifile
import support.{type App}

// --- helpers ----------------------------------------------------------------

fn new_client(env: App, scopes: List(scope.Scope)) -> #(String, String) {
  let assert Ok(#(client, secret)) =
    clients.create(app.clients_settings(env.config), "test", scopes, by: "test")
  #(client.client_id, secret)
}

fn basic(id: String, secret: String) -> #(String, String) {
  #(
    "authorization",
    "Basic " <> bit_array.base64_encode(<<{ id <> ":" <> secret }:utf8>>, True),
  )
}

fn token_request(
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

fn access_token(env: App, scopes: List(scope.Scope)) -> String {
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

fn api(
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

fn field(body: String, path: List(String), d: decode.Decoder(a)) -> a {
  let assert Ok(value) = json.parse(body, decode.at(path, d))
  value
}

fn header(resp: response.Response(a), name: String) -> String {
  response.get_header(resp, name) |> result.unwrap("")
}

// --- token endpoint ---------------------------------------------------------

pub fn token_endpoint_test() {
  let env = support.boot(config.default())
  let #(id, secret) = new_client(env, [scope.Write, scope.Ops])
  let grant = [#("grant_type", "client_credentials")]

  // client_secret_basic
  let resp = token_request(env, [basic(id, secret)], grant)
  assert resp.status == 200
  assert header(resp, "cache-control") == "no-store"
  assert field(resp.body, ["token_type"], decode.string) == "Bearer"
  assert field(resp.body, ["expires_in"], decode.int) == 3600
  assert field(resp.body, ["scope"], decode.string)
    == "redirects:write redirects:ops"

  // client_secret_post and scope narrowing
  let resp =
    token_request(env, [], [
      #("client_id", id),
      #("client_secret", secret),
      #("scope", "redirects:read"),
      ..grant
    ])
  assert resp.status == 200
  assert field(resp.body, ["scope"], decode.string) == "redirects:read"

  // scope wider than granted
  let resp =
    token_request(env, [basic(id, secret)], [
      #("scope", "redirects:read bogus"),
      ..grant
    ])
  assert resp.status == 400
  assert field(resp.body, ["error"], decode.string) == "invalid_scope"

  // wrong secret
  let resp = token_request(env, [basic(id, "nope")], grant)
  assert resp.status == 401
  assert field(resp.body, ["error"], decode.string) == "invalid_client"
  assert string.starts_with(header(resp, "www-authenticate"), "Basic")

  // unknown client, unsupported grant
  assert token_request(env, [basic("rp_nobody", secret)], grant).status == 401
  let resp =
    token_request(env, [basic(id, secret)], [#("grant_type", "password")])
  assert resp.status == 400
  assert field(resp.body, ["error"], decode.string) == "unsupported_grant_type"
}

pub fn token_requests_are_audited_test() {
  let env = support.boot(config.default())
  let #(id, secret) = new_client(env, [scope.Read])
  let ok =
    token_request(env, [basic(id, secret)], [
      #("grant_type", "client_credentials"),
    ])
  assert ok.status == 200
  let bad =
    token_request(env, [basic(id, "wrong")], [
      #("grant_type", "client_credentials"),
    ])
  assert bad.status == 401
  let assert Ok(audit) = simplifile.read(config.audit_path(env.config))
  assert string.contains(audit, "\"action\":\"api.token_issued\"")
  assert string.contains(audit, "\"action\":\"api.token_rejected\"")
  assert string.contains(audit, "\"scope\":\"redirects:read\"")
}

pub fn plain_errors_become_json_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(..d, api: config.ApiConfig(..d.api, max_body_bytes: 1000)),
    )
  let token = access_token(env, [scope.Write])
  // malformed JSON
  let resp = api(env, Post, "/api/redirects", token, "{")
  assert resp.status == 400
  assert header(resp, "content-type") == "application/problem+json"
  assert field(resp.body, ["title"], decode.string) == "Bad Request"
  // larger than api.max_body_bytes
  let big = "{\"note\":\"" <> string.repeat("x", 2000) <> "\"}"
  let resp = api(env, Post, "/api/redirects", token, big)
  assert resp.status == 413
  assert header(resp, "content-type") == "application/problem+json"
  // the token endpoint answers with OAuth errors
  let resp =
    support.send(
      Post,
      env.api <> "/oauth/token",
      [#("content-type", "application/json")],
      "{}",
    )
  assert resp.status == 415
  assert field(resp.body, ["error"], decode.string) == "invalid_request"
}

pub fn token_endpoint_throttling_test() {
  let env = support.boot(config.default())
  let #(id, _) = new_client(env, [scope.Read])
  let statuses =
    list.repeat(Nil, 11)
    |> list.map(fn(_) {
      token_request(env, [basic(id, "wrong")], [
        #("grant_type", "client_credentials"),
      ]).status
    })
  assert list.take(statuses, 10) == list.repeat(401, 10)
  assert list.last(statuses) == Ok(429)
  let resp =
    token_request(env, [basic(id, "wrong")], [
      #("grant_type", "client_credentials"),
    ])
  let assert Ok(seconds) = int.parse(header(resp, "retry-after"))
  assert seconds > 0 && seconds <= 900
}

/// Failures from many addresses do not lock a client out: its secret is
/// too long to guess, a limit per client would only help a denial of
/// service.
pub fn token_client_is_not_locked_out_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, secret) = new_client(env, [scope.Read])
  let request = fn(secret, ip) {
    token_request(env, [basic(id, secret), #("x-forwarded-for", ip)], [
      #("grant_type", "client_credentials"),
    ]).status
  }
  list.each(int.range(1, 13, [], list.prepend), fn(n) {
    list.each(list.repeat(Nil, 10), fn(_) {
      assert request("wrong", "198.51.100." <> int.to_string(100 + n)) == 401
    })
  })
  assert request(secret, "198.51.100.200") == 200
}

/// One IPv6 host holds a whole /64: its addresses share their limits.
pub fn token_throttling_counts_ipv6_by_64_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, _) = new_client(env, [scope.Read])
  let statuses =
    int.range(1, 12, [], list.prepend)
    |> list.map(fn(n) {
      token_request(
        env,
        [
          basic(id, "wrong"),
          #("x-forwarded-for", "2001:db8:77:1::" <> int.to_string(n)),
        ],
        [#("grant_type", "client_credentials")],
      ).status
    })
  assert list.take(statuses, 10) == list.repeat(401, 10)
  assert list.last(statuses) == Ok(429)
}

/// Token requests are small: a large body is refused before it is read.
pub fn token_request_body_is_limited_test() {
  let env = support.boot(config.default())
  let resp =
    token_request(env, [], [
      #("grant_type", "client_credentials"),
      #("padding", string.repeat("x", 70_000)),
    ])
  assert resp.status == 413
}

/// A successful token request forgives that client's failures from that
/// address (a pipeline that recovered is not one failure from a 429).
pub fn token_success_resets_the_address_failures_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, secret) = new_client(env, [scope.Read])
  // its own address: the per address count must not block other tests
  let request = fn(secret) {
    token_request(
      env,
      [basic(id, secret), #("x-forwarded-for", "198.51.100.30")],
      [#("grant_type", "client_credentials")],
    ).status
  }
  assert list.map(list.repeat(Nil, 9), fn(_) { request("wrong") })
    == list.repeat(401, 9)
  assert request(secret) == 200
  assert list.map(list.repeat(Nil, 10), fn(_) { request("wrong") })
    == list.repeat(401, 10)
  assert request("wrong") == 429
}

// --- authentication ---------------------------------------------------------

pub fn bearer_required_test() {
  let env = support.boot(config.default())
  let resp = support.send(Get, env.api <> "/api/redirects", [], "")
  assert resp.status == 401
  assert header(resp, "www-authenticate") == "Bearer realm=\"redirect-proxy\""
  assert header(resp, "content-type") == "application/problem+json"

  let resp = api(env, Get, "/api/redirects", "rpat_garbage", "")
  assert resp.status == 401
  assert string.contains(header(resp, "www-authenticate"), "invalid_token")

  let resp = api(env, Get, "/api/redirects", "a.b.c", "")
  assert resp.status == 401
}

/// Checking a token signature costs CPU: an address sending invalid tokens
/// is throttled before its tokens are checked.
pub fn invalid_tokens_are_throttled_per_address_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let from = fn(ip, token) {
    support.send(
      Get,
      env.api <> "/api/redirects",
      [#("authorization", "Bearer " <> token), #("x-forwarded-for", ip)],
      "",
    )
  }
  let statuses =
    list.map(list.repeat(Nil, 101), fn(_) {
      from("198.51.100.20", "rpat_garbage").status
    })
  assert list.take(statuses, 100) == list.repeat(401, 100)
  assert list.last(statuses) == Ok(429)
  let blocked = from("198.51.100.20", "rpat_garbage")
  assert header(blocked, "retry-after") != ""
  assert header(blocked, "content-type") == "application/problem+json"
  // other addresses are not affected
  assert from("203.0.113.20", "rpat_garbage").status == 401
}

pub fn admin_session_cookie_does_not_authorize_api_test() {
  let env = support.boot(config.default())
  // a session cookie (even a forged one) is ignored by the API
  let resp =
    support.send(
      Get,
      env.api <> "/api/redirects",
      [#("cookie", "rp_session=whatever")],
      "",
    )
  assert resp.status == 401
}

pub fn scopes_are_enforced_test() {
  let env = support.boot(config.default())
  let read = access_token(env, [scope.Read])
  assert api(env, Get, "/api/redirects", read, "").status == 200
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      read,
      "{\"source\":\"/a\",\"target\":\"/b\"}",
    )
  assert resp.status == 403
  assert string.contains(header(resp, "www-authenticate"), "insufficient_scope")
  assert field(resp.body, ["required_scope"], decode.string)
    == "redirects:write"
  assert api(env, Post, "/api/reload", read, "").status == 403

  // write implies read, but not ops
  let write = access_token(env, [scope.Write])
  assert api(env, Get, "/api/redirects", write, "").status == 200
  assert api(env, Post, "/api/reload", write, "").status == 403
}

pub fn revocation_test() {
  let env = support.boot(config.default())
  let settings = app.clients_settings(env.config)
  let #(id, secret) = new_client(env, [scope.Read])
  let resp =
    token_request(env, [basic(id, secret)], [
      #("grant_type", "client_credentials"),
    ])
  let token = field(resp.body, ["access_token"], decode.string)
  assert api(env, Get, "/api/redirects", token, "").status == 200

  // rotating the secret (e.g. from the CLI) revokes issued tokens
  let assert Ok(_) = clients.rotate(settings, id, by: "test")
  assert api(env, Get, "/api/redirects", token, "").status == 401

  let token2 = access_token(env, [scope.Read])
  let assert Ok([_, other]) = clients.list(settings)
  let assert Ok(Nil) = clients.delete(settings, other.client_id, by: "test")
  assert api(env, Get, "/api/redirects", token2, "").status == 401
}

pub fn tokens_lose_scopes_the_client_loses_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read, scope.Ops])
  assert api(env, Post, "/api/reload", token, "").status == 200
  // the ops scope is removed from the clients file by hand
  let path = config.api_clients_path(env.config)
  let assert Ok(content) = simplifile.read(path)
  assert string.contains(content, ",\"redirects:ops\"")
  let assert Ok(Nil) =
    simplifile.write(path, string.replace(content, ",\"redirects:ops\"", ""))
  assert api(env, Post, "/api/reload", token, "").status == 403
  assert api(env, Get, "/api/redirects", token, "").status == 200
}

// --- redirections -----------------------------------------------------------

pub fn crud_round_trip_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])

  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/promo\",\"target\":\"https://shop.test/sale\",\"status\":307,\"unknown_field\":1}",
    )
  assert resp.status == 201
  let id = field(resp.body, ["id"], decode.string)
  let version = field(resp.body, ["version"], decode.string)
  assert header(resp, "location") == "/api/redirects/" <> id
  assert header(resp, "etag") == "\"" <> version <> "\""

  // it redirects
  let redirect = support.send(Get, env.redirect <> "/promo", [], "")
  assert redirect.status == 307
  assert header(redirect, "location") == "https://shop.test/sale"

  // get
  let resp = api(env, Get, "/api/redirects/" <> id, token, "")
  assert resp.status == 200
  assert field(resp.body, ["updated_by"], decode.string)
    == "client:" <> env_client(env)

  // put with a stale If-Match
  let put_body = "{\"source\":\"/promo\",\"target\":\"/summer\",\"status\":301}"
  let resp =
    support.send(
      Put,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/json"),
        #("if-match", "\"stale\""),
      ],
      put_body,
    )
  assert resp.status == 412
  assert header(resp, "etag") == "\"" <> version <> "\""

  // put with the current version
  let resp =
    support.send(
      Put,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/json"),
        #("if-match", "\"" <> version <> "\""),
      ],
      put_body,
    )
  assert resp.status == 200
  assert field(resp.body, ["status"], decode.int) == 301
  assert header(support.send(Get, env.redirect <> "/promo", [], ""), "location")
    == "/summer"

  // patch: absent fields kept, null resets to default
  let resp =
    support.send(
      Patch,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/merge-patch+json"),
      ],
      "{\"note\":\"hello\",\"status\":null}",
    )
  assert resp.status == 200
  assert field(resp.body, ["note"], decode.string) == "hello"
  assert field(resp.body, ["status"], decode.int) == 301
  assert field(resp.body, ["target"], decode.string) == "/summer"

  // validation errors
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"bad\",\"target\":\"/b\"}",
    )
  assert resp.status == 422
  assert field(
      resp.body,
      ["errors"],
      decode.list(decode.at(["field"], decode.string)),
    )
    == ["source"]
  assert api(env, Post, "/api/redirects", token, "[1]").status == 400
  let resp =
    support.send(
      Post,
      env.api <> "/api/redirects",
      [#("authorization", "Bearer " <> token), #("content-type", "text/plain")],
      "{}",
    )
  assert resp.status == 415
  assert header(resp, "content-type") == "application/problem+json"
  assert field(resp.body, ["status"], decode.int) == 415

  // delete
  assert api(env, Delete, "/api/redirects/" <> id, token, "").status == 204
  assert api(env, Get, "/api/redirects/" <> id, token, "").status == 404
  assert api(env, Delete, "/api/redirects/" <> id, token, "").status == 404
  assert support.send(Get, env.redirect <> "/promo", [], "").status == 404
}

fn env_client(env: App) -> String {
  let assert Ok([first, ..]) = clients.list(app.clients_settings(env.config))
  first.client_id
}

pub fn list_filters_and_pagination_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let rules =
    list.repeat(Nil, 25)
    |> list.index_map(fn(_, i) {
      let n = string.inspect(i)
      json.object([
        #("source", json.string("/page/" <> n)),
        #("target", json.string("/new/" <> n)),
        #("enabled", json.bool(i % 5 != 0)),
      ])
    })
    |> json.preprocessed_array
    |> json.to_string
  let resp = api(env, Post, "/api/redirects/import", token, rules)
  assert resp.status == 200
  assert field(resp.body, ["imported"], decode.int) == 25

  let resp = api(env, Get, "/api/redirects?per_page=10&page=3", token, "")
  assert field(resp.body, ["meta", "total"], decode.int) == 25
  assert list.length(field(resp.body, ["data"], decode.list(decode.dynamic)))
    == 5
  let resp = api(env, Get, "/api/redirects?enabled=false", token, "")
  assert field(resp.body, ["meta", "total"], decode.int) == 5
  let resp = api(env, Get, "/api/redirects?q=page/1", token, "")
  // /page/1 and /page/10..19
  assert field(resp.body, ["meta", "total"], decode.int) == 11
  let resp = api(env, Get, "/api/redirects?per_page=100000", token, "")
  assert field(resp.body, ["meta", "per_page"], decode.int) == 500
  // values that are not positive integers are refused, not guessed
  list.each(["page=abc", "page=0", "per_page=-1", "per_page=ten"], fn(query) {
    let resp = api(env, Get, "/api/redirects?" <> query, token, "")
    assert resp.status == 400
    assert header(resp, "content-type") == "application/problem+json"
  })
}

pub fn import_export_reload_and_tester_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write, scope.Ops])
  let one = "[{\"source\":\"/one\",\"target\":\"/1\"}]"
  assert api(env, Post, "/api/redirects/import", token, one).status == 200
  let resp =
    api(
      env,
      Post,
      "/api/redirects/import?mode=replace",
      token,
      "{\"version\":1,\"rules\":[{\"source\":\"/two\",\"target\":\"/2\"}]}",
    )
  assert field(resp.body, ["total"], decode.int) == 1
  // all or nothing
  let resp =
    api(
      env,
      Post,
      "/api/redirects/import",
      token,
      "[{\"source\":\"/ok\",\"target\":\"/x\"},{\"source\":\"bad\",\"target\":\"/y\"}]",
    )
  assert resp.status == 422
  assert api(env, Post, "/api/redirects/import?mode=nope", token, one).status
    == 400

  let resp = api(env, Get, "/api/redirects/export", token, "")
  assert resp.status == 200
  let assert Ok([exported]) = rule.file_from_string(resp.body)
  assert exported.source == "/two"

  let resp =
    api(
      env,
      Get,
      "/api/test?url=" <> uri.percent_encode("https://x.test/two"),
      token,
      "",
    )
  assert field(resp.body, ["matched"], decode.bool)
  assert field(resp.body, ["location"], decode.string) == "/2"
  let resp = api(env, Get, "/api/test?url=nope", token, "")
  assert resp.status == 400

  let assert Ok(Nil) =
    ffi.atomic_write(
      env.dir <> "/redirects.json",
      "[{\"source\":\"/disk\",\"target\":\"/3\"}]",
    )
  let resp = api(env, Post, "/api/reload", token, "")
  assert resp.status == 200
  assert field(resp.body, ["rules"], decode.int) == 1
  assert support.send(Get, env.redirect <> "/disk", [], "").status == 301
}

pub fn method_and_route_errors_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read])
  let resp = api(env, Delete, "/api/redirects", token, "")
  assert resp.status == 405
  assert header(resp, "allow") == "GET, POST"
  assert api(env, Get, "/api/nope", token, "").status == 404
  assert support.send(Get, env.api <> "/oauth/token", [], "").status == 405
}

pub fn api_can_be_disabled_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(..d, api: config.ApiConfig(..d.api, enabled: False)),
    )
  // falls through to the admin, which asks for a login
  assert support.send(Get, env.api <> "/api/redirects", [], "").status == 303
}

// --- OpenAPI and deprecations ----------------------------------------------

pub fn openapi_document_test() {
  let env = support.boot(config.default())
  let resp = support.send(Get, env.api <> "/api/openapi.json", [], "")
  assert resp.status == 200
  assert field(resp.body, ["openapi"], decode.string) == "3.1.0"
  let paths =
    field(resp.body, ["paths"], decode.dict(decode.string, decode.dynamic))
  [
    "/oauth/token", "/api/redirects", "/api/redirects/{id}",
    "/api/redirects/export", "/api/redirects/import", "/api/reload", "/api/test",
  ]
  |> list.each(fn(path) {
    let assert Ok(_) = dict_get(paths, path)
  })
  // no version prefix anywhere
  assert !string.contains(resp.body, "/v1/")
}

import gleam/dict
import redirect_proxy/api/rule_json as api_rule_json

fn dict_get(d: dict.Dict(String, a), key: String) -> Result(a, Nil) {
  dict.get(d, key)
}

pub fn deprecations_are_announced_test() {
  let registry = [
    deprecation.Deprecation(
      target: deprecation.Field("RuleInput", "note"),
      since: 1_767_225_600,
      sunset: Some("Wed, 01 Jul 2027 00:00:00 GMT"),
      replacement: "description",
    ),
    deprecation.Deprecation(
      target: deprecation.Route("get", "/api/test"),
      since: 1_760_000_000,
      sunset: None,
      replacement: "/api/resolve",
    ),
  ]
  let used = deprecation.for_fields(registry, "RuleInput", ["source", "note"])
  assert deprecation.headers(used)
    == [
      #("deprecation", "@1767225600"),
      #("sunset", "Wed, 01 Jul 2027 00:00:00 GMT"),
    ]
  assert deprecation.for_fields(registry, "RuleInput", ["source"]) == []
  assert deprecation.headers(deprecation.for_route(registry, "get", "/api/test"))
    == [#("deprecation", "@1760000000")]

  let doc = openapi.document(registry)
  let test_op =
    field(doc, ["paths", "/api/test", "get", "deprecated"], decode.bool)
  assert test_op
  assert field(
    doc,
    ["components", "schemas", "RuleInput", "properties", "note", "deprecated"],
    decode.bool,
  )
  assert !field(
    doc,
    ["paths", "/api/redirects", "get", "deprecated"],
    decode.bool,
  )
  // the production registry is empty: nothing is deprecated yet
  assert deprecation.registry() == []
}

// --- external authorization server ----------------------------------------

fn external_env() -> #(App, String, support.Key) {
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

fn jwt(key: support.Key, claims: List(#(String, json.Json))) -> String {
  support.sign(key, json.object(claims) |> json.to_string)
}

pub fn external_access_tokens_test() {
  let #(env, issuer, key) = external_env()
  let now = ffi.now_seconds()
  let base = fn(overrides: List(#(String, json.Json))) {
    let keys = list.map(overrides, fn(o) { o.0 })
    [
      #("iss", json.string(issuer)),
      #("sub", json.string("deploy-bot")),
      #("aud", json.array(["redirect-proxy", "other"], json.string)),
      #("exp", json.int(now + 300)),
      #("iat", json.int(now)),
      #("scope", json.string("openid rp.write")),
    ]
    |> list.filter(fn(c) { !list.contains(keys, c.0) })
    |> list.append(overrides)
  }

  let token = jwt(key, base([]))
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/ext\",\"target\":\"/e\"}",
    )
  assert resp.status == 201
  assert field(resp.body, ["updated_by"], decode.string) == "oauth:deploy-bot"

  // scp array claim also works
  let scp =
    jwt(
      key,
      base([
        #("scope", json.string("")),
        #("scp", json.array(["rp.write"], json.string)),
      ]),
    )
  assert api(env, Get, "/api/redirects", scp, "").status == 200

  // rejected tokens
  let rejected = [
    base([#("aud", json.string("someone-else"))]),
    base([#("iss", json.string("https://evil.test"))]),
    base([#("exp", json.int(now - 3600))]),
    base([#("nbf", json.int(now + 3600))]),
  ]
  list.each(rejected, fn(claims) {
    assert api(env, Get, "/api/redirects", jwt(key, claims), "").status == 401
  })
  // signed with another key
  let #(_, other_key) = support.keypair()
  assert api(env, Get, "/api/redirects", jwt(other_key, base([])), "").status
    == 401
  // valid but without the mapped scope
  let no_scope = jwt(key, base([#("scope", json.string("openid profile"))]))
  let resp = api(env, Get, "/api/redirects", no_scope, "")
  assert resp.status == 403
  // the hint uses the external scope name
  assert field(resp.body, ["required_scope"], decode.string) == "redirects:read"
}

// --- units ------------------------------------------------------------------

pub fn check_claims_unit_test() {
  let cfg =
    config.ApiOAuthConfig(
      ..config.default().api.oauth,
      enabled: True,
      issuer: "https://as.test",
      audience: "rp",
    )
  let claims = fn(extra) {
    json.object([
      #("iss", json.string("https://as.test/")),
      #("aud", json.string("rp")),
      #("exp", json.int(2000)),
      #("client_id", json.string("svc")),
      ..extra
    ])
    |> json.to_string
  }
  let assert Ok(p) =
    auth.check_claims(
      cfg,
      "https://as.test",
      claims([#("scope", json.string("redirects:read redirects:ops"))]),
      1000,
    )
  assert p.actor == "oauth:svc"
  assert p.scopes == [scope.Read, scope.Ops]
  let assert Error(_) = auth.check_claims(cfg, "https://as.test", "{}", 1000)
  let assert Error(_) =
    auth.check_claims(cfg, "https://as.test", claims([]), 5000)
  // an ID token (it has a nonce) is refused even with the API's audience
  let assert Error(reason) =
    auth.check_claims(
      cfg,
      "https://as.test",
      claims([#("nonce", json.string("n-1"))]),
      1000,
    )
  assert string.contains(reason, "ID token")
}

pub fn scope_unit_test() {
  assert scope.parse_list("redirects:read, redirects:write bogus")
    == [scope.Read, scope.Write]
  assert scope.allows([scope.Write], scope.Read)
  assert !scope.allows([scope.Read], scope.Write)
  assert !scope.allows([scope.Write], scope.Ops)
  assert scope.join([scope.Read, scope.Ops]) == "redirects:read redirects:ops"
}

pub fn problem_unit_test() {
  assert problem.parse_if_match("\"abc\"") == problem.Versions(["abc"])
  // weak tags never match with the strong comparison of If-Match
  assert problem.parse_if_match("W/\"abc\"") == problem.Versions([])
  assert problem.parse_if_match("\"a\", W/\"w\", \"b\"")
    == problem.Versions(["a", "b"])
  assert problem.parse_if_match(" * ") == problem.AnyVersion
  let listed = problem.parse_if_match("\"old\", \"current\"")
  assert problem.expected_version(listed, "current") == "current"
  assert problem.expected_version(listed, "newer") != "newer"
  assert problem.expected_version(problem.AnyVersion, "v") == "*"
}

pub fn patch_decoder_unit_test() {
  let base =
    rule.Rule(
      ..rule.blank(),
      source: "/a",
      target: "/b",
      status: 308,
      note: "keep",
    )
  let assert Ok(apply) =
    json.parse(
      "{\"target\":\"/c\",\"status\":null}",
      api_rule_json.patch_decoder(),
    )
  let patched = apply(base)
  assert patched.target == "/c"
  assert patched.status == 301
  assert patched.note == "keep"
  let assert Error(_) =
    json.parse("{\"match\":\"glob\"}", api_rule_json.patch_decoder())
}

pub fn clients_store_unit_test() {
  let dir = support.temp_dir()
  let settings =
    clients.Settings(
      path: dir <> "/api_clients.json",
      audit_path: dir <> "/audit.jsonl",
    )
  let assert Error(_) = clients.create(settings, "", [scope.Read], by: "t")
  let assert Error(_) = clients.create(settings, "x", [], by: "t")
  let assert Ok(#(c, secret)) =
    clients.create(settings, "ci", [scope.Read], by: "t")
  assert string.starts_with(c.client_id, "rp_")
  let assert Ok(_) = clients.authenticate(settings, c.client_id, secret)
  let assert Error(Nil) = clients.authenticate(settings, c.client_id, "x")
  let assert Ok(new_secret) = clients.rotate(settings, c.client_id, by: "t")
  let assert Error(Nil) = clients.authenticate(settings, c.client_id, secret)
  let assert Ok(_) = clients.authenticate(settings, c.client_id, new_secret)
  let assert Ok(Nil) = clients.delete(settings, c.client_id, by: "t")
  let assert Error(_) = clients.delete(settings, c.client_id, by: "t")
  let assert Error(_) = clients.rotate(settings, c.client_id, by: "t")
  // the secret hash never leaks in the public representation
  assert !string.contains(json.to_string(clients.public_json(c)), c.secret_hash)
}

// --- API on its own port ---------------------------------------------------

fn own_port(admin_enabled: Bool) -> App {
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

pub fn api_on_its_own_port_test() {
  let env = own_port(True)
  assert env.api != env.admin
  assert support.send(Get, env.api <> "/healthz", [], "").status == 200

  // the API and token endpoint live on the API port...
  let token = access_token(env, [scope.Write])
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/d\",\"target\":\"/e\"}",
    )
  assert resp.status == 201
  assert support.send(Get, env.redirect <> "/d", [], "").status == 301
  assert support.send(Get, env.api <> "/api/openapi.json", [], "").status == 200
  // ...and the admin UI is not served there
  assert support.send(Get, env.api <> "/rules", [], "").status == 404
  assert support.send(Get, env.api <> "/login", [], "").status == 404

  // the admin listener no longer serves the API
  let resp =
    support.send(
      Get,
      env.admin <> "/api/redirects",
      [#("authorization", "Bearer " <> token)],
      "",
    )
  assert resp.status == 303
  assert support.send(Post, env.admin <> "/oauth/token", [], "").status != 200
  // while the admin UI keeps working on its own port
  assert support.send(Get, env.admin <> "/login", [], "").status == 200

  let resp = support.send(Get, env.api <> "/healthz", [], "")
  assert header(resp, "x-content-type-options") == "nosniff"
  assert support.send(Get, env.api <> "/readyz", [], "").body == "ready"
  // the metrics stay on the admin listener
  assert support.send(Get, env.api <> "/metrics", [], "").status != 200
}

pub fn api_without_admin_ui_test() {
  let env = own_port(False)
  let token = access_token(env, [scope.Read])
  assert api(env, Get, "/api/redirects", token, "").status == 200
  // probes and metrics would be nowhere else
  assert support.send(Get, env.api <> "/readyz", [], "").status == 200
  let metrics = support.send(Get, env.api <> "/metrics", [], "")
  assert metrics.status == 200
  assert string.contains(metrics.body, "redirect_proxy_requests_total")
}

pub fn api_port_rules_test() {
  let d = config.default()
  let with_api = fn(api) { config.Config(..d, api:) }
  // default and explicit admin port: shared listener
  assert config.api_on_admin(d)
  assert !config.api_dedicated(d)
  let same = with_api(config.ApiConfig(..d.api, port: d.admin.port))
  assert config.api_on_admin(same)
  assert config.api_public_url(same) == d.admin.public_url
  // another port: own listener, inheriting admin.listen
  let other = with_api(config.ApiConfig(..d.api, port: 8082))
  assert config.api_dedicated(other)
  assert !config.api_on_admin(other)
  assert config.api_listen(other) == d.admin.listen
  assert config.api_public_url(other) == "http://localhost:8082"
  let assert Ok(_) = config_validate.validate(other)
  // admin disabled: the API keeps the admin port on its own listener
  let no_admin =
    config.Config(..d, admin: config.AdminConfig(..d.admin, enabled: False))
  assert config.api_dedicated(no_admin)
  assert config.api_port(no_admin) == d.admin.port
  // invalid combinations
  let assert Error(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, port: d.server.port),
    ))
  let assert Error(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, listen: "0.0.0.0"),
    ))
  let assert Ok(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, listen: "0.0.0.0", port: 8082),
    ))
}

/// The CLI holds api_clients.json.lock: client changes wait for it, while
/// authentication never waits (it only skips the last-use update).
pub fn clients_wait_for_another_process_test() {
  let dir = support.temp_dir()
  let s =
    clients.Settings(
      path: dir <> "/api_clients.json",
      audit_path: dir <> "/audit.jsonl",
    )
  let assert Ok(#(client, secret)) =
    clients.create(s, "ci", [scope.Read], by: "test")
  let lock = s.path <> ".lock"
  let assert Ok(Nil) = simplifile.write(lock, "4242 cli@host\n")
  let started = ffi.now_millis()
  let assert Ok(_) = clients.authenticate(s, client.client_id, secret)
  assert ffi.now_millis() - started < 1000
  process.spawn(fn() {
    process.sleep(300)
    let _ = simplifile.delete(lock)
  })
  let assert Ok(_) = clients.rotate(s, client.client_id, by: "test")
  assert ffi.now_millis() - started >= 250
}

// --- operator features -------------------------------------------------------

fn import_set(env: App, token: String, rules: List(#(String, String, Bool))) {
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

pub fn list_sort_links_and_invalid_filters_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [
    #("b", "/b", True),
    #("c", "/c", True),
    #("a", "/a", True),
  ])
  let ids = fn(resp: response.Response(String)) {
    field(resp.body, ["data"], decode.list(decode.at(["id"], decode.string)))
  }
  assert ids(api(env, Get, "/api/redirects?sort=source", token, ""))
    == ["a", "b", "c"]
  assert ids(api(env, Get, "/api/redirects?sort=-source", token, ""))
    == ["c", "b", "a"]
  // hits are part of the rule representation
  let resp = api(env, Get, "/api/redirects?per_page=1&page=2", token, "")
  assert field(
      resp.body,
      ["data"],
      decode.list(decode.at(["hits"], decode.int)),
    )
    == [0]
  assert field(resp.body, ["meta", "total_pages"], decode.int) == 3
  let link = header(resp, "link")
  assert string.contains(link, "page=3>; rel=\"next\"")
  assert string.contains(link, "page=1>; rel=\"prev\"")
  // invalid values are errors, not silently ignored
  assert api(env, Get, "/api/redirects?match=foo", token, "").status == 400
  assert api(env, Get, "/api/redirects?enabled=yes", token, "").status == 400
  assert api(env, Get, "/api/redirects?sort=colour", token, "").status == 400
}

pub fn bulk_changes_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [#("a", "/a", True), #("b", "/b", True)])
  let bulk = fn(body) { api(env, Post, "/api/redirects/bulk", token, body) }
  let resp = bulk("{\"ids\": [\"a\", \"b\"], \"action\": \"disable\"}")
  assert resp.status == 200
  assert field(resp.body, ["changed"], decode.int) == 2
  assert get_rule_enabled(env, token, "a") == False
  // already disabled: nothing changes
  let resp = bulk("{\"ids\": [\"a\"], \"action\": \"disable\"}")
  assert field(resp.body, ["changed"], decode.int) == 0
  // unknown ids and actions are refused, and nothing is changed
  assert bulk("{\"ids\": [\"a\", \"nope\"], \"action\": \"enable\"}").status
    == 422
  assert get_rule_enabled(env, token, "a") == False
  assert bulk("{\"ids\": [\"a\"], \"action\": \"explode\"}").status == 422
  let resp = bulk("{\"ids\": [\"b\"], \"action\": \"delete\"}")
  assert field(resp.body, ["changed"], decode.int) == 1
  assert api(env, Get, "/api/redirects/b", token, "").status == 404
}

fn get_rule_enabled(env: App, token: String, id: String) -> Bool {
  let resp = api(env, Get, "/api/redirects/" <> id, token, "")
  field(resp.body, ["enabled"], decode.bool)
}

pub fn import_dry_run_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [#("a", "/a", True), #("b", "/b", True)])
  let body =
    "[{\"id\": \"a\", \"source\": \"/a\", \"target\": \"/changed\"},
      {\"id\": \"c\", \"source\": \"/c\", \"target\": \"/new\"}]"
  let resp =
    api(
      env,
      Post,
      "/api/redirects/import?mode=replace&dry_run=true",
      token,
      body,
    )
  assert resp.status == 200
  assert field(resp.body, ["dry_run"], decode.bool)
  assert field(resp.body, ["added_ids"], decode.list(decode.string)) == ["c"]
  assert field(resp.body, ["removed_ids"], decode.list(decode.string)) == ["b"]
  assert field(resp.body, ["changed_ids"], decode.list(decode.string)) == ["a"]
  // nothing was written
  assert api(env, Get, "/api/redirects/b", token, "").status == 200
  assert api(env, Get, "/api/redirects/c", token, "").status == 404
}

/// The dry run's ETag applies exactly the previewed change: if the rules
/// changed in between, the import is refused with 412 and nothing is written.
pub fn import_applies_only_what_was_previewed_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [#("a", "/a", True)])
  let body = "[{\"id\": \"c\", \"source\": \"/c\", \"target\": \"/new\"}]"
  let with_if_match = fn(path, tag) {
    support.send(
      Post,
      env.api <> path,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/json"),
        #("if-match", tag),
      ],
      body,
    )
  }
  let preview =
    api(
      env,
      Post,
      "/api/redirects/import?mode=replace&dry_run=true",
      token,
      body,
    )
  let tag = header(preview, "etag")
  assert tag != ""
  // someone adds a rule after the preview
  let other = "{\"source\": \"/late\", \"target\": \"/x\"}"
  assert api(env, Post, "/api/redirects", token, other).status == 201
  let resp = with_if_match("/api/redirects/import?mode=replace", tag)
  assert resp.status == 412
  assert header(resp, "etag") != tag
  // nothing was written
  assert api(env, Get, "/api/redirects/c", token, "").status == 404
  // with the current version from the list, it applies
  let current = header(api(env, Get, "/api/redirects", token, ""), "etag")
  assert current == header(resp, "etag")
  let resp = with_if_match("/api/redirects/import?mode=replace", current)
  assert resp.status == 200
  // bulk changes take If-Match the same way
  let resp =
    support.send(
      Post,
      env.api <> "/api/redirects/bulk",
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/json"),
        #("if-match", current),
      ],
      "{\"ids\": [\"c\"], \"action\": \"disable\"}",
    )
  assert resp.status == 412
}

pub fn conditional_reads_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [#("a", "/a", True)])
  let get = fn(path, tag) {
    support.send(
      Get,
      env.api <> path,
      [#("authorization", "Bearer " <> token), #("if-none-match", tag)],
      "",
    )
  }
  // a rule always answers 200: its hit counts change without its ETag
  let tag = header(api(env, Get, "/api/redirects/a", token, ""), "etag")
  let resp = get("/api/redirects/a", tag)
  assert resp.status == 200
  assert header(resp, "etag") == tag
  assert get("/api/redirects/a", "*").status == 200
  let export = api(env, Get, "/api/redirects/export", token, "")
  assert get("/api/redirects/export", header(export, "etag")).status == 304
}

pub fn import_needs_a_json_body_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let resp =
    support.send(
      Post,
      env.api <> "/api/redirects/import",
      [#("authorization", "Bearer " <> token), #("content-type", "text/plain")],
      "[]",
    )
  assert resp.status == 415
}

pub fn tester_explains_the_resolution_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let body =
    "[{\"id\": \"exact\", \"source\": \"/docs/a\", \"target\": \"/exact\"},
      {\"id\": \"prefix\", \"match\": \"prefix\", \"source\": \"/docs/\", \"target\": \"/prefix/$1\"},
      {\"id\": \"off\", \"match\": \"prefix\", \"source\": \"/docs/a\", \"target\": \"/off\", \"enabled\": false},
      {\"id\": \"hop\", \"source\": \"/exact\", \"target\": \"/final\"}]"
  let resp = api(env, Post, "/api/redirects/import?mode=replace", token, body)
  assert resp.status == 200
  let resp =
    api(env, Get, "/api/test?url=https%3A%2F%2Fx.test%2Fdocs%2Fa", token, "")
  let verdicts =
    field(
      resp.body,
      ["candidates"],
      decode.list({
        use id <- decode.subfield(["rule", "id"], decode.string)
        use verdict <- decode.field("verdict", decode.string)
        decode.success(#(id, verdict))
      }),
    )
  assert verdicts
    == [#("exact", "applied"), #("off", "disabled"), #("prefix", "shadowed")]
  // the redirect chain: /exact is redirected again
  let chain =
    field(
      resp.body,
      ["chain"],
      decode.list(decode.at(["location"], decode.string)),
    )
  assert chain == ["/exact", "/final"]
  assert field(resp.body, ["loop"], decode.bool) == False
}

pub fn export_follows_filters_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  import_set(env, token, [#("a", "/a", True), #("b", "/b", False)])
  let resp = api(env, Get, "/api/redirects/export?enabled=false", token, "")
  assert resp.status == 200
  assert string.contains(resp.body, "\"/b\"")
  assert !string.contains(resp.body, "\"/a\"")
  assert api(env, Get, "/api/redirects/export?match=foo", token, "").status
    == 400
}

pub fn whole_segments_over_the_api_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/plain\",\"match\":\"prefix\",\"target\":\"/p$1\"}",
    )
  // always present in the API, false by default
  assert field(resp.body, ["whole_segments"], decode.bool) == False
  let id = field(resp.body, ["id"], decode.string)
  assert support.send(Get, env.redirect <> "/plainer", [], "").status == 301
  let resp =
    support.send(
      Patch,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/merge-patch+json"),
      ],
      "{\"whole_segments\": true}",
    )
  assert field(resp.body, ["whole_segments"], decode.bool)
  assert support.send(Get, env.redirect <> "/plainer", [], "").status == 404
  let resp = support.send(Get, env.redirect <> "/plain/x", [], "")
  assert header(resp, "location") == "/p/x"
  // refused on other kinds
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/e\",\"target\":\"/x\",\"whole_segments\":true}",
    )
  assert resp.status == 422
}

pub fn scheduled_rules_over_the_api_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/later\",\"target\":\"/x\",\"starts_at\":\"2999-01-01T00:00:00Z\"}",
    )
  assert resp.status == 201
  assert field(resp.body, ["starts_at"], decode.string)
    == "2999-01-01T00:00:00Z"
  assert field(resp.body, ["expires_at"], decode.string) == ""
  let id = field(resp.body, ["id"], decode.string)
  assert support.send(Get, env.redirect <> "/later", [], "").status == 404
  // the tester says why it does not apply
  let resp =
    api(env, Get, "/api/test?url=https%3A%2F%2Fx.test%2Flater", token, "")
  let verdicts =
    field(
      resp.body,
      ["candidates"],
      decode.list(decode.at(["verdict"], decode.string)),
    )
  assert verdicts == ["out_of_schedule"]
  // null removes the start: it applies at once
  let resp =
    support.send(
      Patch,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/merge-patch+json"),
      ],
      "{\"starts_at\": null}",
    )
  assert resp.status == 200
  assert support.send(Get, env.redirect <> "/later", [], "").status == 301
  // invalid dates are refused
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/bad\",\"target\":\"/x\",\"expires_at\":\"tomorrow\"}",
    )
  assert resp.status == 422
}

pub fn query_rules_over_http_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/page.php\",\"query\":\"id=42\",\"target\":\"/article-42\",\"preserve_query\":true}",
    )
  assert resp.status == 201
  assert field(resp.body, ["query"], decode.string) == "id=42"
  let resp = support.send(Get, env.redirect <> "/page.php?id=42&utm=x", [], "")
  assert resp.status == 301
  assert header(resp, "location") == "/article-42?id=42&utm=x"
  assert support.send(Get, env.redirect <> "/page.php?id=7", [], "").status
    == 404
  // refused on prefix rules
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/p\",\"match\":\"prefix\",\"query\":\"a=1\",\"target\":\"/x\"}",
    )
  assert resp.status == 422
}

/// The route table, the router and the OpenAPI document agree: every
/// documented operation is in the table and the other way round, each one
/// is routed (neither "no such endpoint" nor 405), and a 405 lists exactly
/// the table's methods.
pub fn routes_router_and_openapi_agree_test() {
  let methods = ["get", "post", "put", "patch", "delete"]
  let documented =
    json.parse(
      openapi.document([]),
      decode.at(
        ["paths"],
        decode.dict(decode.string, decode.dict(decode.string, decode.dynamic)),
      ),
    )
    |> result.unwrap(dict.new())
    |> dict.to_list
    |> list.filter(fn(entry) { string.starts_with(entry.0, "/api/") })
    |> list.flat_map(fn(entry) {
      dict.keys(entry.1)
      |> list.filter(list.contains(methods, _))
      |> list.map(fn(method) { #(method, entry.0) })
    })
  let table =
    list.map(routes.operations, fn(o) {
      #(string.lowercase(http.method_to_string(o.method)), o.template)
    })
  assert list.sort(documented, compare_pairs) == list.sort(table, compare_pairs)

  let env = support.boot(config.default())
  let token =
    access_token(env, [scope.Read, scope.Write, scope.Ops, scope.Audit])
  let created =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/r\",\"target\":\"/x\"}",
    )
  assert created.status == 201
  let id = field(created.body, ["id"], decode.string)
  // DELETE last: the other operations use the rule
  let #(deletes, others) =
    list.partition(routes.operations, fn(o) { o.method == Delete })
  list.each(list.append(others, deletes), fn(o) {
    let path = string.replace(o.template, "{id}", id)
    let path = case o.template {
      "/api/test" -> path <> "?url=https://x.test/r"
      _ -> path
    }
    let resp = api(env, o.method, path, token, "{}")
    assert resp.status != 405
    assert !string.contains(resp.body, "No such endpoint")
  })
  // a method the table does not list for a known path: `PUT
  // /api/redirects/export` used to reach `PUT /api/redirects/{id}` (404)
  let resp = api(env, Put, "/api/redirects/export", token, "{}")
  assert resp.status == 405
  assert header(resp, "allow") == "GET"
  list.each(
    list.unique(list.map(routes.operations, fn(o) { o.template })),
    fn(t) {
      let path = string.replace(t, "{id}", id)
      let unused =
        [Get, Post, Put, Patch, Delete]
        |> list.find(fn(m) {
          !list.contains(routes.operations, routes.Operation(m, t))
        })
      case unused {
        Error(Nil) -> Nil
        Ok(method) -> {
          let resp = api(env, method, path, token, "{}")
          assert resp.status == 405
          assert header(resp, "allow") == string.join(routes.allowed(t), ", ")
        }
      }
    },
  )
}

fn compare_pairs(a: #(String, String), b: #(String, String)) {
  string.compare(a.1 <> " " <> a.0, b.1 <> " " <> b.0)
}

pub fn rule_tags_over_the_api_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read, scope.Write])
  let created =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/t\",\"target\":\"/x\",\"tags\":[\"Legacy\",\"campaign\"]}",
    )
  assert created.status == 201
  assert field(created.body, ["tags"], decode.list(decode.string))
    == ["campaign", "legacy"]
  let id = field(created.body, ["id"], decode.string)
  // untagged rules show an empty list
  let plain =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/u\",\"target\":\"/x\"}",
    )
  assert field(plain.body, ["tags"], decode.list(decode.string)) == []
  // the list filters by tag
  let listed = api(env, Get, "/api/redirects?tag=legacy", token, "")
  assert field(listed.body, ["meta", "total"], decode.int) == 1
  // a merge patch replaces the tags
  let patched =
    support.send(
      Patch,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/merge-patch+json"),
      ],
      "{\"tags\":[\"done\"]}",
    )
  assert patched.status == 200
  assert field(patched.body, ["tags"], decode.list(decode.string)) == ["done"]
  let too_long =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/v\",\"target\":\"/x\",\"tags\":[\""
        <> string.repeat("x", 41)
        <> "\"]}",
    )
  assert too_long.status == 422
}

pub fn csv_import_and_export_over_the_api_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read, scope.Write])
  let send_csv = fn(path, body) {
    support.send(
      Post,
      env.api <> path,
      [#("authorization", "Bearer " <> token), #("content-type", "text/csv")],
      body,
    )
  }
  let resp =
    send_csv(
      "/api/redirects/import?mode=replace",
      "source,target,match\n/csv/,/to/$1,prefix\n",
    )
  assert resp.status == 200
  let export = api(env, Get, "/api/redirects/export?format=csv", token, "")
  assert export.status == 200
  assert header(export, "content-type") == "text/csv; charset=utf-8"
  assert string.starts_with(export.body, "id,host,match,source,target")
  assert string.contains(export.body, ",prefix,/csv/,/to/$1,")
  // the version of the rule set, as the JSON export: usable in If-Match
  let json_tag =
    header(api(env, Get, "/api/redirects/export", token, ""), "etag")
  assert header(export, "etag") == json_tag
  let guarded =
    support.send(
      Post,
      env.api <> "/api/redirects/import?mode=replace",
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "text/csv"),
        #("if-match", header(export, "etag")),
      ],
      export.body,
    )
  assert guarded.status == 200
  assert api(env, Get, "/api/redirects/export?format=xml", token, "").status
    == 400
  // CSV errors are validation errors with the line
  let bad = send_csv("/api/redirects/import", "source,target,status\n/a,/b,x\n")
  assert bad.status == 422
  assert string.contains(bad.body, "line 2: status: must be a number")
}

pub fn audit_over_the_api_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write, scope.Audit])
  list.each(["/a1", "/a2", "/a3"], fn(source) {
    let resp =
      api(
        env,
        Post,
        "/api/redirects",
        token,
        "{\"source\":\"" <> source <> "\",\"target\":\"/x\"}",
      )
    assert resp.status == 201
  })
  let resp =
    api(env, Get, "/api/audit?action=rule.create&per_page=2", token, "")
  assert resp.status == 200
  let actions =
    field(
      resp.body,
      ["data"],
      decode.list(decode.at(["action"], decode.string)),
    )
  assert actions == ["rule.create", "rule.create"]
  // entries are as recorded, with the rule after the change
  let sources =
    field(
      resp.body,
      ["data"],
      decode.list(decode.at(["after", "source"], decode.string)),
    )
  assert sources == ["/a3", "/a2"]
  assert field(resp.body, ["meta", "has_more"], decode.bool)
  assert string.contains(header(resp, "link"), "page=2")
  let next =
    api(env, Get, "/api/audit?action=rule.create&per_page=2&page=2", token, "")
  assert !field(next.body, ["meta", "has_more"], decode.bool)
  assert api(env, Get, "/api/audit?since=yesterday", token, "").status == 400
  // its own scope: not implied by any other (it holds sign-ins)
  let others = access_token(env, [scope.Read, scope.Write, scope.Ops])
  assert api(env, Get, "/api/audit", others, "").status == 403
}

pub fn audit_api_dates_and_paging_limits_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Audit])
  // an offset sent unencoded: `+` arrives as a space
  assert api(env, Get, "/api/audit?since=2000-01-01T00:00:00+00:00", token, "").status
    == 200
  assert api(env, Get, "/api/audit?page=1000&per_page=500", token, "").status
    == 400
}
