//// Tests of managing redirections over the API: CRUD, lists, imports,
//// bulk changes, the URL tester.

import api_support.{
  access_token, api, env_client, field, get_rule_enabled, header, import_set,
}
import gleam/dynamic/decode
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/http/response
import gleam/json
import gleam/list
import gleam/string
import gleam/uri
import redirect_proxy/api/rule_json as api_rule_json
import redirect_proxy/api/scope
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/rule
import support

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

/// A creation with an id chosen by the client can be retried safely: the
/// retry gets 409 (pointing to the rule) instead of creating a second one.
pub fn create_with_a_client_id_is_safe_to_retry_test() {
  let env = support.boot(config.default())
  let token = access_token(env, [scope.Write])
  let body =
    "{\"id\":\"deploy-42\",\"match\":\"prefix\",\"source\":\"/r/\",\"target\":\"/s/$1\"}"
  let first = api(env, Post, "/api/redirects", token, body)
  assert first.status == 201
  assert field(first.body, ["id"], decode.string) == "deploy-42"
  let retry = api(env, Post, "/api/redirects", token, body)
  assert retry.status == 409
  assert response.get_header(retry, "location")
    == Ok("/api/redirects/deploy-42")
  let listed = api(env, Get, "/api/redirects?q=/r/", token, "")
  assert field(listed.body, ["meta", "total"], decode.int) == 1
  // ids go in URLs
  let bad =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"id\":\"a/b\",\"source\":\"/x\",\"target\":\"/y\"}",
    )
  assert bad.status == 422
  // without an id, the server chooses one
  let generated =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/x\",\"target\":\"/y\"}",
    )
  assert generated.status == 201
  assert field(generated.body, ["id"], decode.string) != ""
}

/// With `api.require_if_match`, writes must name the version they change.
pub fn writes_can_require_if_match_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(..d, api: config.ApiConfig(..d.api, require_if_match: True)),
    )
  let token = access_token(env, [scope.Write])
  let created =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/m\",\"target\":\"/n\"}",
    )
  assert created.status == 201
  let id = field(created.body, ["id"], decode.string)
  let etag = header(created, "etag")
  let put = fn(headers) {
    support.send(
      Put,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/json"),
        ..headers
      ],
      "{\"source\":\"/m\",\"target\":\"/o\"}",
    )
  }
  let refused = put([])
  assert refused.status == 428
  assert field(refused.body, ["code"], decode.string) == "precondition_required"
  assert put([#("if-match", etag)]).status == 200
  // PATCH guards itself: no header needed
  let patch =
    support.send(
      Patch,
      env.api <> "/api/redirects/" <> id,
      [
        #("authorization", "Bearer " <> token),
        #("content-type", "application/merge-patch+json"),
      ],
      "{\"target\":\"/p\"}",
    )
  assert patch.status == 200
  assert api(env, Delete, "/api/redirects/" <> id, token, "").status == 428
}
