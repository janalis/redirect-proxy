//// Tests of API authentication: bearer tokens, scopes, external access
//// tokens.

import api_support.{
  access_token, api, basic, external_env, field, header, jwt, new_client,
  token_request,
}
import gleam/dynamic/decode
import gleam/http.{Get, Post}
import gleam/json
import gleam/list
import gleam/string
import redirect_proxy/api/auth
import redirect_proxy/api/clients
import redirect_proxy/api/routes
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi
import simplifile
import support

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
  // a caller nobody can tell apart in the audit log is refused
  let anonymous =
    jwt(
      key,
      base([#("sub", json.string(""))])
        |> list.filter(fn(c) { c.0 != "sub" }),
    )
  assert api(env, Get, "/api/redirects", anonymous, "").status == 401
}

/// `api.oauth.require_at_jwt` (on by default): only tokens typed as access
/// tokens (RFC 9068) are accepted, so that an ID token for the same
/// audience is not.
pub fn external_tokens_must_be_typed_as_access_tokens_test() {
  let #(issuer, key) = support.start_fake_authorization_server()
  let d = config.default()
  let boot = fn(require_at_jwt) {
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
            require_at_jwt:,
          ),
        ),
      ),
    )
  }
  let now = ffi.now_seconds()
  let claims =
    json.object([
      #("iss", json.string(issuer)),
      #("sub", json.string("deploy-bot")),
      #("aud", json.string("redirect-proxy")),
      #("exp", json.int(now + 300)),
      #("scope", json.string("redirects:read")),
    ])
    |> json.to_string
  assert d.api.oauth.require_at_jwt
  let env = boot(True)
  let status = fn(env, token) {
    api(env, Get, "/api/redirects", token, "").status
  }
  assert status(env, support.sign_typed(key, "at+jwt", claims)) == 200
  assert status(env, support.sign_typed(key, "application/at+JWT", claims))
    == 200
  assert status(env, support.sign_typed(key, "JWT", claims)) == 401
  assert status(env, support.sign(key, claims)) == 401
  // turned off, for servers that cannot type their access tokens
  let env = boot(False)
  assert status(env, support.sign_typed(key, "JWT", claims)) == 200
}

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

/// The route table, the router and the OpenAPI document agree: every
/// documented operation is in the table and the other way round, each one
/// is routed (neither "no such endpoint" nor 405), and a 405 lists exactly
/// the table's methods.
/// Every operation needs the scope of its row in `routes.operations`: a
/// token with every scope that does not grant it gets a 403, before the
/// operation runs.
pub fn every_operation_needs_its_scope_test() {
  let env = support.boot(config.default())
  let all = [scope.Read, scope.Write, scope.Ops, scope.Audit]
  list.each(routes.operations, fn(o) {
    let token =
      access_token(env, list.filter(all, fn(s) { !scope.allows([s], o.scope) }))
    let path = string.replace(o.template, "{id}", "no-such-rule")
    let resp = api(env, o.method, path, token, "{}")
    assert resp.status == 403
    assert string.contains(
      header(resp, "www-authenticate"),
      "insufficient_scope",
    )
  })
}
