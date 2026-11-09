//// Tests of the OpenAPI document and of deprecations.

import api_support.{access_token, api, compare_pairs, dict_get, field, header}
import gleam/dict
import gleam/dynamic/decode
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/api/deprecation
import redirect_proxy/api/openapi
import redirect_proxy/api/routes
import redirect_proxy/api/rule_json as api_rule_json
import redirect_proxy/api/scope
import redirect_proxy/config
import redirect_proxy/rule
import support

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
  // a body that is JSON but not an object is a 400 where an object is read
  let documented = fn(path, method, status) {
    field(
      resp.body,
      ["paths", path, method, "responses"],
      decode.dict(decode.string, decode.dynamic),
    )
    |> dict.has_key(status)
  }
  assert documented("/api/redirects", "post", "400")
  assert documented("/api/redirects/{id}", "put", "400")
  assert documented("/api/redirects/{id}", "patch", "400")
  assert documented("/api/redirects/bulk", "post", "400")
  assert documented("/oauth/token", "post", "413")
  assert documented("/oauth/token", "post", "415")
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

  let doc = openapi.document(registry, config.default().api.oauth)
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

/// The Rule schema of the OpenAPI document lists the fields the API sends,
/// no more and no fewer.
pub fn openapi_rule_schema_matches_the_rule_json_test() {
  let _ = support.boot(config.default())
  let keys = decode.dict(decode.string, decode.dynamic)
  let documented =
    json.parse(
      openapi.document([], config.default().api.oauth),
      decode.at(["components", "schemas", "Rule", "properties"], keys),
    )
    |> result.unwrap(dict.new())
    |> dict.keys
    |> list.sort(string.compare)
  let sent =
    rule.Rule(..rule.blank(), id: "x", source: "/a", target: "/b")
    |> api_rule_json.rule_json
    |> json.to_string
    |> json.parse(keys)
    |> result.unwrap(dict.new())
    |> dict.keys
    |> list.sort(string.compare)
  assert documented != []
  assert documented == sent
}

pub fn routes_router_and_openapi_agree_test() {
  let methods = ["get", "post", "put", "patch", "delete"]
  let documented =
    json.parse(
      openapi.document([], config.default().api.oauth),
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
  // each operation asks for the scope the router checks; the token endpoint
  // for none
  let doc = openapi.document([], config.default().api.oauth)
  let oauth_scopes = fn(method, path) {
    json.parse(
      doc,
      decode.at(
        ["paths", path, method, "security"],
        decode.list(decode.optional_field(
          "oauth2",
          [],
          decode.list(decode.string),
          decode.success,
        )),
      ),
    )
    |> result.unwrap([])
    |> list.flatten
  }
  list.each(routes.operations, fn(o) {
    let method = string.lowercase(http.method_to_string(o.method))
    assert oauth_scopes(method, o.template) == [scope.to_string(o.scope)]
  })
  assert oauth_scopes("post", "/oauth/token") == []

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
        |> list.find(fn(m) { result.is_error(routes.find(m, t)) })
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

/// With an external authorization server, the document gives the scope
/// names its tokens must carry.
pub fn openapi_names_external_scopes_test() {
  let d = config.default()
  let oauth =
    config.ApiOAuthConfig(
      ..d.api.oauth,
      enabled: True,
      issuer: "https://idp.test",
      read_scope: "api.read",
    )
  let doc = openapi.document([], oauth)
  let description =
    field(doc, ["paths", "/api/redirects", "get", "description"], decode.string)
  assert string.contains(description, "`redirects:read`")
  assert string.contains(description, "`api.read`")
  let bearer =
    field(
      doc,
      ["components", "securitySchemes", "bearer", "description"],
      decode.string,
    )
  assert string.contains(bearer, "https://idp.test")
  assert string.contains(bearer, "`api.read` for redirects:read")
  // unchanged names are not repeated
  let write =
    field(
      doc,
      ["paths", "/api/redirects", "post", "description"],
      decode.string,
    )
  assert write == "Requires the `redirects:write` scope."
}
