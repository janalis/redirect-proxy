//// REST API (`/api/...`) and OAuth2 token endpoint (`/oauth/token`), served
//// by the admin listener. There is no version prefix: see
//// `api/deprecation.gleam` for how the API evolves.

import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/http/request
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/api/auth.{type Principal}
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/api/openapi
import redirect_proxy/api/problem
import redirect_proxy/api/routes
import redirect_proxy/api/rule_json.{patch_decoder, rule_json} as _
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/api/token_endpoint.{token_endpoint} as _
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
import redirect_proxy/metrics
import redirect_proxy/metrics_endpoint
import redirect_proxy/rule.{type Rule}
import redirect_proxy/rule_csv
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules
import wisp.{type Request, type Response}

const max_per_page = 500

const default_per_page = 100

/// Entry point of the API's own listener (when `api.port` differs from
/// `admin.port`, or the admin UI is disabled).
pub fn handle_dedicated(req: Request, ctx: Context) -> Response {
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  let plain = fn(status, body) {
    wisp.response(status)
    |> wisp.set_header("content-type", "text/plain; charset=utf-8")
    |> wisp.set_header("cache-control", "no-store")
    |> wisp.string_body(body)
  }
  case wisp.path_segments(req) {
    ["healthz"] -> plain(200, "ok")
    // 503 while draining before a stop, like the admin's
    ["readyz"] ->
      case ffi.draining() {
        True -> plain(503, "draining")
        False -> plain(200, "ready")
      }
    // the admin serves the metrics; without it, they would be nowhere
    ["metrics"] if !ctx.config.admin.enabled ->
      metrics_endpoint.respond(req, ctx.config.admin.metrics_token)
    _ -> handle(req, ctx)
  }
  |> wisp.set_header("x-content-type-options", "nosniff")
  |> wisp.set_header("x-frame-options", "DENY")
  |> wisp.set_header("referrer-policy", "no-referrer")
}

const max_token_request_bytes = 65_536

/// Entry point for `/oauth/*` and `/api/*` requests.
pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.ApiRequests)
  let oauth = case wisp.path_segments(req) {
    ["oauth", ..] -> True
    _ -> False
  }
  // token requests are small and unauthenticated: anything larger is
  // refused before it is read
  let req = case oauth {
    True -> wisp.set_max_body_size(req, max_token_request_bytes)
    False -> wisp.set_max_body_size(req, ctx.config.api.max_body_bytes)
  }
  {
    use <- wisp.rescue_crashes
    dispatch(req, ctx)
  }
  |> problem.from_plain_error(oauth)
}

fn dispatch(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    ["oauth", "token"] ->
      case req.method {
        Post -> token_endpoint(req, ctx)
        _ -> problem.method_not_allowed(["POST"])
      }
    ["api", "openapi.json"] ->
      case req.method {
        Get ->
          wisp.response(200)
          |> wisp.set_header("content-type", "application/json")
          |> wisp.set_header("access-control-allow-origin", "*")
          |> wisp.string_body(openapi.document(ctx.deprecations))
        _ -> problem.method_not_allowed(["GET"])
      }
    ["api", ..rest] -> {
      use principal <- authenticated(req, ctx)
      route(req, ctx, principal, rest)
    }
    _ -> problem.not_found("No such endpoint.")
  }
}

fn route(
  req: Request,
  ctx: Context,
  principal: Principal,
  segments: List(String),
) -> Response {
  let template = routes.template(segments)
  use <- known_method(req, template)
  let response = case req.method, segments {
    Get, ["redirects"] -> {
      use <- require(principal, scope.Read, ctx)
      list_rules(req, ctx)
    }
    Post, ["redirects"] -> {
      use <- require(principal, scope.Write, ctx)
      create_rule(req, ctx, principal)
    }
    Get, ["redirects", "export"] -> {
      use <- require(principal, scope.Read, ctx)
      let query = wisp.get_query(req)
      let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
      use #(rules, version) <- result_or_response(filtered_rules(ctx, get))
      use #(content_type, body, version) <- result_or_response(
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
    Post, ["redirects", "import"] -> {
      use <- require(principal, scope.Write, ctx)
      import_rules(req, ctx, principal)
    }
    Post, ["redirects", "bulk"] -> {
      use <- require(principal, scope.Write, ctx)
      bulk(req, ctx, principal)
    }
    Get, ["redirects", id] -> {
      use <- require(principal, scope.Read, ctx)
      case store.get(ctx.store, id) {
        // always 200: the body has live hit counts that the ETag (the
        // rule's version, for If-Match) does not cover, so a 304 would
        // keep stale counts in the client's copy
        Ok(r) -> rule_response(200, r)
        Error(Nil) -> rule_not_found(id)
      }
    }
    Put, ["redirects", id] -> {
      use <- require(principal, scope.Write, ctx)
      replace_rule(req, ctx, principal, id)
    }
    Patch, ["redirects", id] -> {
      use <- require(principal, scope.Write, ctx)
      patch_rule(req, ctx, principal, id)
    }
    Delete, ["redirects", id] -> {
      use <- require(principal, scope.Write, ctx)
      delete_rule(req, ctx, principal, id)
    }
    Post, ["reload"] -> {
      use <- require(principal, scope.Ops, ctx)
      case store.reload(ctx.store, principal.actor) {
        Ok(count) ->
          problem.json_response(200, json.object([#("rules", json.int(count))]))
        Error(reason) ->
          problem.problem(
            422,
            "Reload Rejected",
            "The redirections file is invalid; the current rules are kept. "
              <> reason,
            [],
          )
      }
    }
    Get, ["test"] -> {
      use <- require(principal, scope.Read, ctx)
      test_url(req, ctx)
    }
    Get, ["audit"] -> {
      use <- require(principal, scope.Audit, ctx)
      audit_log(req, ctx)
    }
    _, _ -> problem.not_found("No such endpoint.")
  }
  with_route_deprecations(response, ctx, req, template)
}

/// A known path with a method it does not have is a 405, before the
/// dispatch: `PUT /api/redirects/export` must not reach `PUT {id}`.
fn known_method(
  req: Request,
  template: Result(String, Nil),
  next: fn() -> Response,
) -> Response {
  case template {
    Ok(template) ->
      case
        list.contains(routes.operations, routes.Operation(req.method, template))
      {
        True -> next()
        False -> problem.method_not_allowed(routes.allowed(template))
      }
    // unknown paths are a 404 from the dispatch
    Error(Nil) -> next()
  }
}

fn with_route_deprecations(
  response: Response,
  ctx: Context,
  req: Request,
  template: Result(String, Nil),
) -> Response {
  case template {
    Error(Nil) -> response
    Ok(template) -> {
      let method = string.lowercase(http.method_to_string(req.method))
      deprecation.for_route(ctx.deprecations, method, template)
      |> add_deprecation_headers(response, _)
    }
  }
}

fn add_deprecation_headers(
  response: Response,
  used: List(Deprecation),
) -> Response {
  list.fold(deprecation.headers(used), response, fn(resp, header) {
    wisp.set_header(resp, header.0, header.1)
  })
}

fn authenticated(
  req: Request,
  ctx: Context,
  next: fn(Principal) -> Response,
) -> Response {
  // checked before the token: verifying a signature costs CPU
  let ip_key = "api-ip:" <> ffi.throttle_address(ctx.client_ip)
  use <- api_throttle(ip_key)
  case auth.authenticate(req, ctx.config.api.oauth, ctx.clients) {
    Ok(principal) -> next(principal)
    Error(auth.MissingToken) -> {
      metrics.incr(metrics.ApiAuthFailures)
      problem.unauthorized("", "A bearer access token is required.")
    }
    Error(auth.InvalidToken(reason)) -> {
      metrics.incr(metrics.ApiAuthFailures)
      ratelimit.record_failure(ip_key, invalid_token_window)
      log.warning("API token rejected from " <> ctx.client_ip <> ": " <> reason)
      problem.unauthorized("invalid_token", reason)
    }
  }
}

/// Invalid tokens accepted from one address in a window before it gets 429.
const invalid_token_limit = 100

const invalid_token_window = 900

fn api_throttle(key: String, next: fn() -> Response) -> Response {
  case ratelimit.blocked_for(key, invalid_token_limit) {
    Error(Nil) -> next()
    Ok(seconds) ->
      problem.problem(
        429,
        "Too Many Requests",
        "Too many invalid access tokens from this address, retry later.",
        [],
      )
      |> wisp.set_header("retry-after", int.to_string(seconds))
  }
}

fn require(
  principal: Principal,
  required: Scope,
  ctx: Context,
  next: fn() -> Response,
) -> Response {
  case scope.allows(principal.scopes, required) {
    True -> next()
    False -> {
      let name = case string.starts_with(principal.actor, "client:") {
        True -> scope.to_string(required)
        False -> scope.external_name(ctx.config.api.oauth, required)
      }
      problem.insufficient_scope(name)
    }
  }
}

fn rule_response(status: Int, r: Rule) -> Response {
  problem.json_response(status, rule_json(r))
  |> wisp.set_header("etag", problem.etag(rule.version(r)))
}

fn rule_not_found(id: String) -> Response {
  problem.not_found("No redirection with id " <> id <> ".")
}

fn list_rules(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
  use page <- result_or_response(positive_param(get, "page", 1))
  use per_page <- result_or_response(positive_param(
    get,
    "per_page",
    default_per_page,
  ))
  // larger pages are capped rather than refused
  let per_page = int.min(per_page, max_per_page)
  use #(matching, version) <- result_or_response(filtered_rules(ctx, get))
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

/// A positive integer query parameter, or `default` when it is not set.
fn positive_param(
  get: fn(String) -> String,
  name: String,
  default: Int,
) -> Result(Int, Response) {
  case get(name) {
    "" -> Ok(default)
    value ->
      case int.parse(value) {
        Ok(n) if n >= 1 -> Ok(n)
        _ -> Error(problem.bad_request(name <> " must be a positive integer."))
      }
  }
}

const max_audit_entries = 100_000

/// `GET /api/audit`: the audit entries as recorded (newest first), filtered,
/// in pages. `has_more` (and a `Link: rel="next"`) tells whether older
/// entries match, without counting them all.
fn audit_log(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) {
    list.key_find(query, key) |> result.unwrap("") |> string.trim
  }
  let time = fn(name) {
    case get(name) {
      "" -> Ok(0)
      value ->
        // `+01:00` sent unencoded arrives as ` 01:00`
        ffi.parse_rfc3339(string.replace(value, " ", "+"))
        |> result.replace_error(problem.bad_request(
          name <> " must be an RFC 3339 date-time (2026-11-06T12:00:00Z).",
        ))
    }
  }
  use page <- result_or_response(positive_param(get, "page", 1))
  use per_page <- result_or_response(positive_param(
    get,
    "per_page",
    default_per_page,
  ))
  let per_page = int.min(per_page, max_per_page)
  // each page reads the files up to it: older entries are for `until`
  use <- bool.guard(
    page * per_page > max_audit_entries,
    problem.bad_request(
      "page: at most the "
      <> int.to_string(max_audit_entries)
      <> " most recent matching entries are paged through; use until for older ones.",
    ),
  )
  use since <- result_or_response(time("since"))
  use until <- result_or_response(time("until"))
  let filter =
    audit.Filter(
      actor: get("actor"),
      action: get("action"),
      target: get("target"),
      since:,
      until:,
    )
  let found =
    audit.search(config.audit_path(ctx.config), filter, page * per_page + 1)
  let has_more = list.length(found) > page * per_page
  let lines =
    found
    |> list.drop({ page - 1 } * per_page)
    |> list.take(per_page)
    |> list.map(fn(e) { e.details })
  let meta =
    json.object([
      #("page", json.int(page)),
      #("per_page", json.int(per_page)),
      #("has_more", json.bool(has_more)),
    ])
  // entries are sent as recorded: each line is a JSON object
  let body =
    "{\"data\":["
    <> string.join(lines, ",")
    <> "],\"meta\":"
    <> json.to_string(meta)
    <> "}"
  let resp =
    wisp.response(200)
    |> wisp.set_header("content-type", "application/json")
    |> wisp.set_header("cache-control", "no-store")
    |> wisp.string_body(body)
  case has_more {
    False -> resp
    True ->
      wisp.set_header(
        resp,
        "link",
        "</api/audit?"
          <> uri.query_to_string(
          query
          |> list.filter(fn(kv) { kv.0 != "page" })
          |> list.append([#("page", int.to_string(page + 1))]),
        )
          <> ">; rel=\"next\"",
      )
  }
}

fn result_or_response(
  result: Result(a, Response),
  next: fn(a) -> Response,
) -> Response {
  case result {
    Ok(value) -> next(value)
    Error(response) -> response
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
    !list.contains(["", "exact", "prefix", "regex"], kind),
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

fn bulk(req: Request, ctx: Context, principal: Principal) -> Response {
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

fn create_rule(req: Request, ctx: Context, principal: Principal) -> Response {
  use body, used <- require_json_object(req)
  let deprecated = deprecation.for_fields(ctx.deprecations, "RuleInput", used)
  case json.parse(body, rule.decoder()) {
    Error(e) -> problem.validation([rule.describe_json_error(e)])
    Ok(input) ->
      case
        store.create(ctx.store, rule.Rule(..input, id: ""), principal.actor)
      {
        Ok(created) ->
          rule_response(201, created)
          |> wisp.set_header("location", "/api/redirects/" <> created.id)
        Error(errors) -> problem.validation(errors)
      }
  }
  |> add_deprecation_headers(deprecated)
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

fn replace_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
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
  |> add_deprecation_headers(deprecated)
}

fn patch_rule(
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
  |> add_deprecation_headers(deprecated)
}

fn delete_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
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

fn import_rules(req: Request, ctx: Context, principal: Principal) -> Response {
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
    Ok(mode), Ok(incoming) ->
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

fn test_url(req: Request, ctx: Context) -> Response {
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
