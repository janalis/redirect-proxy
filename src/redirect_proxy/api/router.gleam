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
import redirect_proxy/api/auth.{type Principal}
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/api/openapi
import redirect_proxy/api/problem
import redirect_proxy/api/rule_json.{patch_decoder, rule_json} as _
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/api/token_endpoint.{token_endpoint} as _
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/config
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
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
  case wisp.path_segments(req) {
    ["healthz"] ->
      wisp.response(200)
      |> wisp.set_header("content-type", "text/plain; charset=utf-8")
      |> wisp.string_body("ok")
    _ -> handle(req, ctx)
  }
  |> wisp.set_header("x-content-type-options", "nosniff")
  |> wisp.set_header("x-frame-options", "DENY")
  |> wisp.set_header("referrer-policy", "no-referrer")
}

/// Entry point for `/oauth/*` and `/api/*` requests.
pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.ApiRequests)
  let req = wisp.set_max_body_size(req, ctx.config.api.max_body_bytes)
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
      wisp.response(200)
      |> wisp.set_header("content-type", "application/json")
      |> wisp.string_body(store_rules.export(store.all(ctx.store)))
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
    _, ["redirects"] -> problem.method_not_allowed(["GET", "POST"])
    _, ["redirects", "export"] -> problem.method_not_allowed(["GET"])
    _, ["redirects", "import"] -> problem.method_not_allowed(["POST"])
    _, ["redirects", "bulk"] -> problem.method_not_allowed(["POST"])
    _, ["redirects", _] ->
      problem.method_not_allowed(["GET", "PUT", "PATCH", "DELETE"])
    _, ["reload"] -> problem.method_not_allowed(["POST"])
    _, ["test"] -> problem.method_not_allowed(["GET"])
    _, _ -> problem.not_found("No such endpoint.")
  }
  with_route_deprecations(response, ctx, req, segments)
}

fn with_route_deprecations(
  response: Response,
  ctx: Context,
  req: Request,
  segments: List(String),
) -> Response {
  let template = case segments {
    ["redirects", id] if id != "export" && id != "import" && id != "bulk" ->
      "/api/redirects/{id}"
    _ -> "/api/" <> string.join(segments, "/")
  }
  let method = string.lowercase(http.method_to_string(req.method))
  deprecation.for_route(ctx.deprecations, method, template)
  |> add_deprecation_headers(response, _)
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
  case auth.authenticate(req, ctx.config.api.oauth, ctx.clients) {
    Ok(principal) -> next(principal)
    Error(auth.MissingToken) -> {
      metrics.incr(metrics.ApiAuthFailures)
      problem.unauthorized("", "A bearer access token is required.")
    }
    Error(auth.InvalidToken(reason)) -> {
      metrics.incr(metrics.ApiAuthFailures)
      log.warning("API token rejected from " <> ctx.peer_ip <> ": " <> reason)
      problem.unauthorized("invalid_token", reason)
    }
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
  let page = int.parse(get("page")) |> result.unwrap(1) |> int.max(1)
  let per_page =
    int.parse(get("per_page"))
    |> result.unwrap(default_per_page)
    |> int.clamp(1, max_per_page)
  let needle = string.lowercase(string.trim(get("q")))
  let host = case get("host") {
    "" -> ""
    h -> rule.normalise_host(h)
  }
  let kind = get("match")
  let enabled = get("enabled")
  // invalid filters are errors: silently ignoring them returns the wrong set
  use <- bool.lazy_guard(
    !list.contains(["", "exact", "prefix", "regex"], kind),
    fn() { problem.bad_request("match must be exact, prefix or regex.") },
  )
  use <- bool.lazy_guard(!list.contains(["", "true", "false"], enabled), fn() {
    problem.bad_request("enabled must be true or false.")
  })
  let matching =
    store.all(ctx.store)
    |> list.filter(fn(r) {
      { needle == "" || text_matches(r, needle) }
      && { host == "" || r.host == host }
      && { kind == "" || rule.kind_to_string(r.kind) == kind }
      && case enabled {
        "true" -> r.enabled
        "false" -> !r.enabled
        _ -> True
      }
    })
  case store_rules.sort(matching, get("sort"), metrics.hits) {
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
      case links {
        [] -> resp
        _ -> wisp.set_header(resp, "link", string.join(links, ", "))
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
          case store.bulk(ctx.store, ids, action, principal.actor) {
            Ok(count) ->
              problem.json_response(
                200,
                json.object([#("changed", json.int(count))]),
              )
            Error(errors) -> problem.validation(errors)
          }
      }
  }
}

fn text_matches(r: Rule, needle: String) -> Bool {
  list.any([r.host, r.source, r.target, r.note, r.id], fn(field) {
    string.contains(string.lowercase(field), needle)
  })
}

/// Reads a JSON object body. Returns the parsed value with the list of
/// top-level keys used (for field deprecations).
fn require_json_object(
  req: Request,
  next: fn(String, List(String)) -> Response,
) -> Response {
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
  use body <- wisp.require_string_body(req)
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
  use body <- wisp.require_string_body(req)
  case mode, rule.file_from_string(body) {
    Error(Nil), _ -> problem.bad_request("mode must be merge or replace.")
    _, Error(reason) -> problem.validation([reason])
    Ok(mode), Ok(incoming) if dry_run ->
      case store.preview_import(ctx.store, incoming, mode, principal.actor) {
        Ok(d) ->
          problem.json_response(
            200,
            json.object([
              #("dry_run", json.bool(True)),
              ..store_rules.diff_to_json(d)
            ]),
          )
        Error(errors) -> problem.validation(errors)
      }
    Ok(mode), Ok(incoming) ->
      case store.import_rules(ctx.store, incoming, mode, principal.actor) {
        Ok(count) ->
          problem.json_response(
            200,
            json.object([
              #("imported", json.int(count)),
              #("total", json.int(list.length(store.all(ctx.store)))),
            ]),
          )
        Error(errors) -> problem.validation(errors)
      }
  }
}

fn test_url(req: Request, ctx: Context) -> Response {
  let url = list.key_find(wisp.get_query(req), "url") |> result.unwrap("")
  let tolerant = config.ignore_trailing_slash(ctx.config)
  case matcher.resolve_url(snapshot.current(), url, tolerant) {
    matcher.BadUrl ->
      problem.bad_request(
        "url must be an absolute URL, e.g. https://host/path.",
      )
    resolution -> {
      let explanation =
        explain.explain(snapshot.current(), store.all(ctx.store), url, tolerant)
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
  }
}
