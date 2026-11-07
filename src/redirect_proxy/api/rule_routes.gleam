//// Handlers of the rule operations of the REST API (`/api/redirects`,
//// `/api/reload`, `/api/test`). The router dispatches to them once the
//// request is authenticated and its scope checked.

import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/http/request
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/api/auth.{type Principal}
import redirect_proxy/api/deprecation
import redirect_proxy/api/problem
import redirect_proxy/api/rule_json.{patch_decoder, rule_json} as _
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/config
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/rule_csv
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules
import wisp.{type Request, type Response}

import redirect_proxy/api/params

/// `GET /api/redirects/export`: the matching rules as JSON or CSV, with
/// the rule set's version as ETag.
pub fn export(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
  use #(rules, version) <- params.result_or_response(filtered_rules(ctx, get))
  use #(content_type, body, version) <- params.result_or_response(
    case get("format") {
      "" | "json" ->
        Ok(#("application/json", store_rules.export(rules), version))
      // the same ETag (the rule set's version), so that it can be sent
      // back in If-Match on an import; caches tell the formats apart by
      // their URL
      "csv" ->
        Ok(#("text/csv; charset=utf-8", rule_csv.to_string(rules), version))
      _ -> Error(problem.bad_request("format must be json or csv."))
    },
  )
  wisp.response(200)
  |> wisp.set_header("content-type", content_type)
  |> wisp.string_body(body)
  |> wisp.set_header("etag", problem.etag(version))
  |> unless_not_modified(req, version, _)
}

/// `GET /api/redirects/{id}`.
pub fn get_rule(ctx: Context, id: String) -> Response {
  case store.get(ctx.store, id) {
    // always 200: the body has live hit counts that the ETag (the
    // rule's version, for If-Match) does not cover, so a 304 would
    // keep stale counts in the client's copy
    Ok(r) -> rule_response(200, r)
    Error(Nil) -> rule_not_found(id)
  }
}

/// `POST /api/reload`: reads the redirections file again.
pub fn reload(ctx: Context, principal: Principal) -> Response {
  case store.reload(ctx.store, principal.actor) {
    Ok(count) ->
      problem.json_response(200, json.object([#("rules", json.int(count))]))
    Error(reason) ->
      problem.coded_problem(
        422,
        "reload_rejected",
        "Reload Rejected",
        "The redirections file is invalid; the current rules are kept. "
          <> reason,
        [],
      )
  }
}

fn rule_response(status: Int, r: Rule) -> Response {
  problem.json_response(status, rule_json(r))
  |> wisp.set_header("etag", problem.etag(rule.version(r)))
}

fn rule_not_found(id: String) -> Response {
  problem.not_found("No redirection with id " <> id <> ".")
}

pub fn list_rules(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
  use page <- params.result_or_response(params.positive_param(get, "page", 1))
  use per_page <- params.result_or_response(params.positive_param(
    get,
    "per_page",
    params.default_per_page,
  ))
  // larger pages are capped rather than refused
  let per_page = int.min(per_page, params.max_per_page)
  use #(matching, version) <- params.result_or_response(filtered_rules(ctx, get))
  case store_rules.sort(matching, get("sort"), metrics.hits, metrics.last_hit) {
    Error(Nil) ->
      problem.bad_request(
        "sort must be one of "
        <> string.join(store_rules.sort_fields, ", ")
        <> ", optionally prefixed with - (descending).",
      )
    Ok(sorted) -> {
      let total = list.length(sorted)
      let pages = int.max(1, { total + per_page - 1 } / per_page)
      let data =
        sorted |> list.drop({ page - 1 } * per_page) |> list.take(per_page)
      let link = fn(p, rel) {
        "<"
        <> "/api/redirects?"
        <> uri.query_to_string(
          query
          |> list.filter(fn(kv) { kv.0 != "page" })
          |> list.append([#("page", int.to_string(p))]),
        )
        <> ">; rel=\""
        <> rel
        <> "\""
      }
      let links =
        list.flatten([
          case page < pages {
            True -> [link(page + 1, "next")]
            False -> []
          },
          case page > 1 {
            True -> [link(int.min(page - 1, pages), "prev")]
            False -> []
          },
        ])
      let resp =
        problem.json_response(
          200,
          json.object([
            #("data", json.array(data, rule_json)),
            #(
              "meta",
              json.object([
                #("total", json.int(total)),
                #("page", json.int(page)),
                #("per_page", json.int(per_page)),
                #("total_pages", json.int(pages)),
                // as in /api/audit, where there is no total
                #("has_more", json.bool(page < pages)),
              ]),
            ),
          ]),
        )
      // the version of the whole rule set, for If-Match on import and bulk
      let resp = wisp.set_header(resp, "etag", problem.etag(version))
      case links {
        [] -> resp
        _ -> wisp.set_header(resp, "link", string.join(links, ", "))
      }
    }
  }
}

/// The rules matching the `q`, `host`, `match` and `enabled` filters (list
/// and export), and the version of the rule set they were read from.
/// Invalid filter values are a 400.
fn filtered_rules(
  ctx: Context,
  get: fn(String) -> String,
) -> Result(#(List(Rule), String), Response) {
  let kind = get("match")
  let enabled = get("enabled")
  // invalid filters are errors: silently ignoring them returns the wrong set
  use <- bool.guard(
    kind != "" && !list.contains(rule.kind_names(), kind),
    Error(problem.bad_request("match must be exact, prefix or regex.")),
  )
  use enabled <- result.try(case enabled {
    "" -> Ok(None)
    "true" -> Ok(Some(True))
    "false" -> Ok(Some(False))
    _ -> Error(problem.bad_request("enabled must be true or false."))
  })
  let #(rules, version) = store.versioned(ctx.store)
  let filter =
    store_rules.Filter(
      text: get("q"),
      host: get("host"),
      kind:,
      enabled:,
      tag: get("tag"),
    )
  Ok(#(store_rules.filter(rules, filter), version))
}

/// With `api.require_if_match`, a write must say which version it changes:
/// 428 without `If-Match` (RFC 6585).
fn require_precondition(
  req: Request,
  ctx: Context,
  next: fn() -> Response,
) -> Response {
  case
    ctx.config.api.require_if_match
    && request.get_header(req, "if-match") == Error(Nil)
  {
    True ->
      problem.problem(
        428,
        "Precondition Required",
        "Send If-Match with the ETag of what you change (api.require_if_match).",
        [],
      )
    False -> next()
  }
}

/// The version `If-Match` requires of the whole rule set (import, bulk), if
/// the header is set.
fn collection_if_match(req: Request, ctx: Context) -> Option(String) {
  case request.get_header(req, "if-match") {
    Error(Nil) -> None
    Ok(value) -> {
      let #(_, current) = store.versioned(ctx.store)
      Some(problem.expected_version(problem.parse_if_match(value), current))
    }
  }
}

fn set_change_error(error: store.SetChangeError) -> Response {
  case error {
    store.Stale(current) -> problem.precondition_failed(current)
    store.Rejected(errors) -> problem.validation(errors)
  }
}

/// 304 when `If-None-Match` lists the current version (or is `*`).
fn unless_not_modified(
  req: Request,
  version: String,
  resp: Response,
) -> Response {
  case request.get_header(req, "if-none-match") {
    Error(Nil) -> resp
    Ok(value) -> {
      let unchanged = case problem.parse_if_none_match(value) {
        problem.AnyVersion -> True
        problem.Versions(versions) -> list.contains(versions, version)
      }
      case unchanged {
        False -> resp
        True ->
          wisp.response(304)
          |> wisp.set_header("etag", problem.etag(version))
          |> wisp.set_header("cache-control", "no-store")
      }
    }
  }
}

pub fn bulk(req: Request, ctx: Context, principal: Principal) -> Response {
  use <- require_precondition(req, ctx)
  use body, _ <- require_json_object(req)
  let decoder = {
    use ids <- decode.field("ids", decode.list(decode.string))
    use action <- decode.field("action", decode.string)
    decode.success(#(ids, action))
  }
  case json.parse(body, decoder) {
    Error(e) -> problem.validation([rule.describe_json_error(e)])
    Ok(#(ids, action)) ->
      case store.bulk_action_from_string(action) {
        Error(Nil) ->
          problem.validation(["action: must be enable, disable or delete"])
        Ok(action) ->
          case
            store.bulk_versioned(
              ctx.store,
              ids,
              action,
              collection_if_match(req, ctx),
              principal.actor,
            )
          {
            Ok(count) ->
              problem.json_response(
                200,
                json.object([#("changed", json.int(count))]),
              )
            Error(error) -> set_change_error(error)
          }
      }
  }
}

/// Reads an import body: JSON, or CSV sent as `text/csv` (`True`).
fn require_import_body(
  req: Request,
  next: fn(String, Bool) -> Response,
) -> Response {
  let content_type =
    request.get_header(req, "content-type") |> result.unwrap("")
  case string.starts_with(string.lowercase(content_type), "text/csv") {
    True -> wisp.require_string_body(req, fn(body) { next(body, True) })
    False -> require_json_body(req, fn(body) { next(body, False) })
  }
}

/// Reads a body sent as JSON (415 otherwise).
fn require_json_body(req: Request, next: fn(String) -> Response) -> Response {
  let content_type =
    request.get_header(req, "content-type") |> result.unwrap("")
  use <- bool.lazy_guard(
    !string.starts_with(content_type, "application/json")
      && !string.starts_with(content_type, "application/merge-patch+json"),
    fn() {
      problem.problem(
        415,
        "Unsupported Media Type",
        "Send application/json.",
        [],
      )
    },
  )
  wisp.require_string_body(req, next)
}

/// Reads a JSON object body. Returns the parsed value with the list of
/// top-level keys used (for field deprecations).
fn require_json_object(
  req: Request,
  next: fn(String, List(String)) -> Response,
) -> Response {
  use body <- require_json_body(req)
  case json.parse(body, decode.dict(decode.string, decode.dynamic)) {
    Ok(fields) -> next(body, dict.keys(fields))
    Error(_) -> problem.bad_request("The body must be a JSON object.")
  }
}

pub fn create_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
) -> Response {
  use body, used <- require_json_object(req)
  let deprecated = deprecation.for_fields(ctx.deprecations, "RuleInput", used)
  case json.parse(body, rule.decoder()) {
    Error(e) -> problem.validation([rule.describe_json_error(e)])
    Ok(input) -> {
      // an id chosen by the client makes a retry safe: the second request
      // gets 409 instead of creating a second rule
      let id = string.trim(input.id)
      case valid_client_id(id) {
        False ->
          problem.validation([
            "id: up to 128 letters, digits, '.', '_', '~' or '-', and not "
            <> string.join(rule.reserved_ids, ", "),
          ])
        True ->
          case
            store.create(ctx.store, rule.Rule(..input, id:), principal.actor)
          {
            Ok(created) ->
              rule_response(201, created)
              |> wisp.set_header("location", "/api/redirects/" <> created.id)
            Error(["id: already exists"]) ->
              problem.conflict("A redirection with this id already exists.")
              |> wisp.set_header("location", "/api/redirects/" <> id)
            Error(errors) -> problem.validation(errors)
          }
      }
    }
  }
  |> params.add_deprecation_headers(deprecated)
}

/// An id given at creation ("" lets the server choose one): it goes in
/// URLs, so only unreserved URL characters.
fn valid_client_id(id: String) -> Bool {
  id == ""
  || {
    !rule.is_reserved_id(id)
    && string.byte_size(id) <= 128
    && string.to_utf_codepoints(id)
    |> list.all(fn(c) {
      let c = string.utf_codepoint_to_int(c)
      { c >= 0x30 && c <= 0x39 }
      || { c >= 0x41 && c <= 0x5A }
      || { c >= 0x61 && c <= 0x7A }
      || c == 0x2E
      || c == 0x5F
      || c == 0x7E
      || c == 0x2D
    })
  }
}

/// The version `If-Match` requires of rule `id`, if the header is set. With a
/// list of tags, any of them may be the current version.
fn if_match(req: Request, ctx: Context, id: String) -> Option(String) {
  case request.get_header(req, "if-match") {
    Error(Nil) -> None
    Ok(value) -> {
      let current = case store.get(ctx.store, id) {
        Ok(r) -> rule.version(r)
        Error(Nil) -> ""
      }
      Some(problem.expected_version(problem.parse_if_match(value), current))
    }
  }
}

fn change_response(result: Result(Rule, store.ChangeError), id: String) {
  case result {
    Ok(r) -> rule_response(200, r)
    Error(store.NotFound) -> rule_not_found(id)
    Error(store.Conflict(current)) ->
      problem.precondition_failed(rule.version(current))
    Error(store.Invalid(errors)) -> problem.validation(errors)
  }
}

pub fn replace_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
  use <- require_precondition(req, ctx)
  use body, used <- require_json_object(req)
  let deprecated = deprecation.for_fields(ctx.deprecations, "RuleInput", used)
  case json.parse(body, rule.decoder()) {
    Error(e) -> problem.validation([rule.describe_json_error(e)])
    Ok(input) ->
      store.update_versioned(
        ctx.store,
        rule.Rule(..input, id:),
        if_match(req, ctx, id),
        principal.actor,
      )
      |> change_response(id)
  }
  |> params.add_deprecation_headers(deprecated)
}

pub fn patch_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
  use body, used <- require_json_object(req)
  let deprecated = deprecation.for_fields(ctx.deprecations, "RuleInput", used)
  case store.get(ctx.store, id), json.parse(body, patch_decoder()) {
    Error(Nil), _ -> rule_not_found(id)
    _, Error(e) -> problem.validation([rule.describe_json_error(e)])
    Ok(existing), Ok(apply) -> {
      // When no If-Match is given, still guard against a concurrent change
      // between our read and the update.
      let expected = case if_match(req, ctx, id) {
        Some(v) -> Some(v)
        None -> Some(rule.version(existing))
      }
      store.update_versioned(
        ctx.store,
        apply(existing),
        expected,
        principal.actor,
      )
      |> change_response(id)
    }
  }
  |> params.add_deprecation_headers(deprecated)
}

pub fn delete_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
  use <- require_precondition(req, ctx)
  case
    store.delete_versioned(
      ctx.store,
      id,
      if_match(req, ctx, id),
      principal.actor,
    )
  {
    Ok(_) -> wisp.no_content()
    Error(store.NotFound) -> rule_not_found(id)
    Error(store.Conflict(current)) ->
      problem.precondition_failed(rule.version(current))
    Error(store.Invalid(errors)) -> problem.validation(errors)
  }
}

pub fn import_rules(
  req: Request,
  ctx: Context,
  principal: Principal,
) -> Response {
  let mode = case list.key_find(wisp.get_query(req), "mode") {
    Ok(mode) -> store.import_mode_from_string(mode)
    Error(Nil) -> Ok(store.Merge)
  }
  let dry_run = list.key_find(wisp.get_query(req), "dry_run") == Ok("true")
  // a rules file may be an array of rules: not `require_json_object`
  use body, csv <- require_import_body(req)
  let incoming = case csv {
    True -> rule_csv.parse(body)
    False -> rule.file_from_string(body) |> result.map_error(fn(e) { [e] })
  }
  case mode, incoming {
    Error(Nil), _ -> problem.bad_request("mode must be merge or replace.")
    _, Error(errors) -> problem.validation(errors)
    Ok(mode), Ok(incoming) if dry_run ->
      case store.preview_import(ctx.store, incoming, mode, principal.actor) {
        Ok(#(d, version)) ->
          problem.json_response(
            200,
            json.object([
              #("dry_run", json.bool(True)),
              ..store_rules.diff_to_json(d)
            ]),
          )
          // send it back in If-Match to apply exactly this change
          |> wisp.set_header("etag", problem.etag(version))
        Error(errors) -> problem.validation(errors)
      }
    Ok(mode), Ok(incoming) -> {
      use <- require_precondition(req, ctx)
      case
        store.import_rules_versioned(
          ctx.store,
          incoming,
          mode,
          collection_if_match(req, ctx),
          principal.actor,
        )
      {
        Ok(count) ->
          problem.json_response(
            200,
            json.object([
              #("imported", json.int(count)),
              #("total", json.int(list.length(store.all(ctx.store)))),
            ]),
          )
        Error(error) -> set_change_error(error)
      }
    }
  }
}

pub fn test_url(req: Request, ctx: Context) -> Response {
  let url = list.key_find(wisp.get_query(req), "url") |> result.unwrap("")
  let tolerant = config.ignore_trailing_slash(ctx.config)
  // one read of the published rules for the result and its explanation
  let current = snapshot.current()
  case matcher.resolve_url(current, url, tolerant) {
    matcher.BadUrl ->
      problem.bad_request(
        "url must be an absolute URL, e.g. https://host/path.",
      )
    resolution -> {
      let explanation =
        explain.explain(current, store.all(ctx.store), url, tolerant)
      let details = case explanation {
        Ok(e) -> [
          #(
            "candidates",
            json.array(e.candidates, fn(c) {
              json.object([
                #("verdict", json.string(verdict_string(c.verdict))),
                #("rule", rule_json(c.rule)),
              ])
            }),
          ),
          #(
            "chain",
            json.array(e.chain, fn(hop) {
              json.object([
                #("location", json.string(hop.location)),
                #("status", json.int(hop.status)),
                #("rule_id", json.string(hop.rule_id)),
              ])
            }),
          ),
          #("loop", json.bool(e.loops)),
        ]
        Error(Nil) -> []
      }
      case resolution {
        matcher.Redirected(m, location) ->
          problem.json_response(
            200,
            json.object([
              #("matched", json.bool(True)),
              #("status", json.int(m.rule.status)),
              #("location", json.string(location)),
              #("rule", rule_json(m.rule)),
              ..details
            ]),
          )
        _ ->
          problem.json_response(
            200,
            json.object([#("matched", json.bool(False)), ..details]),
          )
      }
    }
  }
}

fn verdict_string(verdict: explain.Verdict) -> String {
  case verdict {
    explain.Applied -> "applied"
    explain.Shadowed -> "shadowed"
    explain.Disabled -> "disabled"
    explain.OutOfSchedule -> "out_of_schedule"
  }
}
