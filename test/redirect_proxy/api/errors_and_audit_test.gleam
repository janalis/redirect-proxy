//// Tests of API errors (problem details) and of the audit log over the API.

import api_support.{access_token, api, field, header}
import gleam/dynamic/decode
import gleam/http.{Delete, Get, Post}
import gleam/http/response
import gleam/list
import gleam/string
import redirect_proxy/api/problem
import redirect_proxy/api/scope
import redirect_proxy/config
import support

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

pub fn method_and_route_errors_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read])
  let resp = api(env, Delete, "/api/redirects", token, "")
  assert resp.status == 405
  assert header(resp, "allow") == "GET, POST"
  assert api(env, Get, "/api/nope", token, "").status == 404
  assert support.send(Get, env.api <> "/oauth/token", [], "").status == 405
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

/// Problems carry a stable `code`: clients tell them apart by it.
pub fn problems_have_a_stable_code_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Read, scope.Write])
  let code = fn(resp: response.Response(String)) {
    field(resp.body, ["code"], decode.string)
  }
  assert code(api(env, Get, "/api/redirects/nope", token, "")) == "not_found"
  assert code(api(env, Get, "/api/redirects", "", "")) == "missing_token"
  assert code(api(env, Get, "/api/redirects", "bogus", "")) == "invalid_token"
  let reader = access_token(env, [scope.Read])
  assert code(api(env, Post, "/api/reload", reader, "")) == "insufficient_scope"
  assert code(api(env, Post, "/api/redirects", token, "{\"source\":\"x\"}"))
    == "validation_failed"
  let body = "{\"id\":\"c1\",\"source\":\"/c\",\"target\":\"/d\"}"
  assert api(env, Post, "/api/redirects", token, body).status == 201
  assert code(api(env, Post, "/api/redirects", token, body)) == "already_exists"
  // pages say whether more follow, as in /api/audit
  let other = "{\"source\":\"/e\",\"target\":\"/f\"}"
  assert api(env, Post, "/api/redirects", token, other).status == 201
  let page = fn(n) {
    api(env, Get, "/api/redirects?per_page=1&page=" <> n, token, "").body
  }
  assert field(page("1"), ["meta", "has_more"], decode.bool)
  assert !field(page("2"), ["meta", "has_more"], decode.bool)
}

/// 422 responses name the invalid fields in `errors[].field`, taken from
/// the `field: message` convention of rule validation (`problem.validation`):
/// clients highlight form fields by these names. A message that names no
/// field (a JSON type error) has an empty one.
pub fn validation_errors_name_their_fields_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let fields = fn(body) {
    let resp = api(env, Post, "/api/redirects", token, body)
    assert resp.status == 422
    let errors =
      field(
        resp.body,
        ["errors"],
        decode.list({
          use name <- decode.field("field", decode.string)
          use message <- decode.field("message", decode.string)
          decode.success(#(name, message))
        }),
      )
    // the message is what follows the field name
    list.each(errors, fn(e) {
      assert e.1 != ""
      assert e.0 == "" || !string.starts_with(e.1, e.0 <> ":")
    })
    list.map(errors, fn(e) { e.0 }) |> list.unique |> list.sort(string.compare)
  }
  assert fields("{\"source\":\"\",\"target\":\"\",\"status\":999}")
    == ["source", "status", "target"]
  assert fields("{\"id\":\"a b\",\"source\":\"/a\",\"target\":\"/b\"}")
    == ["id"]
  assert fields(
      "{\"source\":\"/a\",\"target\":\"/b\",\"match\":\"prefix\",\"query\":\"a=1\"}",
    )
    == ["query"]
  assert fields(
      "{\"source\":\"/a\",\"target\":\"/b\",\"starts_at\":\"soon\",\"priority\":-1}",
    )
    == ["priority", "starts_at"]
  assert fields("{\"source\":1,\"target\":\"/b\"}") == [""]
}
