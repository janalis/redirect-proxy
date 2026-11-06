//// REST API and OAuth token endpoint, end to end over HTTP.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/http/response
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
import redirect_proxy/api/router
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config
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
  assert problem.parse_if_match("\"abc\"") == "abc"
  assert problem.parse_if_match("W/\"abc\"") == "abc"
  assert problem.parse_if_match("\"a\", \"b\"") == "a"
  assert problem.parse_if_match("*") == "*"
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
    json.parse("{\"target\":\"/c\",\"status\":null}", router.patch_decoder())
  let patched = apply(base)
  assert patched.target == "/c"
  assert patched.status == 301
  assert patched.note == "keep"
  let assert Error(_) =
    json.parse("{\"match\":\"glob\"}", router.patch_decoder())
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
}

pub fn api_without_admin_ui_test() {
  let env = own_port(False)
  let token = access_token(env, [scope.Read])
  assert api(env, Get, "/api/redirects", token, "").status == 200
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
  let assert Ok(_) = config.validate(other)
  // admin disabled: the API keeps the admin port on its own listener
  let no_admin =
    config.Config(..d, admin: config.AdminConfig(..d.admin, enabled: False))
  assert config.api_dedicated(no_admin)
  assert config.api_port(no_admin) == d.admin.port
  // invalid combinations
  let assert Error(_) =
    config.validate(with_api(config.ApiConfig(..d.api, port: d.server.port)))
  let assert Error(_) =
    config.validate(with_api(config.ApiConfig(..d.api, listen: "0.0.0.0")))
  let assert Ok(_) =
    config.validate(with_api(
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
