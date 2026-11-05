//// REST API (`/api/...`) and OAuth2 token endpoint (`/oauth/token`), served
//// by the admin listener. There is no version prefix: see
//// `api/deprecation.gleam` for how the API evolves.

import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/http/request
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/api/auth.{type Principal}
import redirect_proxy/api/clients
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/api/openapi
import redirect_proxy/api/problem
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/api/token
import redirect_proxy/config.{type Config}
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store.{type Store}
import wisp.{type Request, type Response}

pub type Context {
  Context(
    config: Config,
    store: Store,
    clients: clients.Settings,
    peer_ip: String,
    deprecations: List(Deprecation),
  )
}

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
      |> wisp.string_body(store.export(store.all(ctx.store)))
    }
    Post, ["redirects", "import"] -> {
      use <- require(principal, scope.Write, ctx)
      import_rules(req, ctx, principal)
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
      test_url(req)
    }
    _, ["redirects"] -> problem.method_not_allowed(["GET", "POST"])
    _, ["redirects", "export"] -> problem.method_not_allowed(["GET"])
    _, ["redirects", "import"] -> problem.method_not_allowed(["POST"])
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
    ["redirects", id] if id != "export" && id != "import" ->
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

// --- authentication ---------------------------------------------------------

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

// --- token endpoint (RFC 6749 §4.4) ------------------------------------------

fn token_endpoint(req: Request, ctx: Context) -> Response {
  use form <- wisp.require_form(req)
  let field = fn(name) { list.key_find(form.values, name) |> result.unwrap("") }
  let basic = basic_credentials(req)
  let #(client_id, secret) = case basic {
    Ok(credentials) -> credentials
    Error(Nil) -> #(field("client_id"), field("client_secret"))
  }
  let ip_key = "token-ip:" <> ctx.peer_ip
  let client_key = "token-client:" <> client_id
  use <- bool.lazy_guard(
    ratelimit.is_blocked(ip_key, 30) || ratelimit.is_blocked(client_key, 10),
    fn() {
      oauth_error(429, "slow_down", "Too many failed attempts, retry later.")
    },
  )
  use <- bool.lazy_guard(field("grant_type") != "client_credentials", fn() {
    oauth_error(
      400,
      "unsupported_grant_type",
      "Only the client_credentials grant is supported.",
    )
  })
  case client_id, clients.authenticate(ctx.clients, client_id, secret) {
    "", _ | _, Error(Nil) -> {
      ratelimit.record_failure(ip_key, 900)
      ratelimit.record_failure(client_key, 900)
      metrics.incr(metrics.ApiAuthFailures)
      log.warning(
        "token request rejected for client="
        <> client_id
        <> " ip="
        <> ctx.peer_ip,
      )
      let resp =
        oauth_error(401, "invalid_client", "Client authentication failed.")
      case basic {
        Ok(_) ->
          wisp.set_header(
            resp,
            "www-authenticate",
            "Basic realm=\"redirect-proxy\"",
          )
        Error(Nil) -> resp
      }
    }
    _, Ok(client) -> {
      let requested = case string.trim(field("scope")) {
        "" -> Ok(client.scopes)
        value -> {
          let names =
            value |> string.split(" ") |> list.filter(fn(s) { s != "" })
          let parsed = list.filter_map(names, scope.from_string)
          case
            list.length(parsed) == list.length(names)
            && list.all(parsed, scope.allows(client.scopes, _))
          {
            True -> Ok(list.unique(parsed))
            False -> Error(Nil)
          }
        }
      }
      case requested {
        Error(Nil) ->
          oauth_error(
            400,
            "invalid_scope",
            "The requested scope exceeds the scopes granted to the client.",
          )
        Ok(scopes) -> {
          ratelimit.reset(client_key)
          let ttl = ctx.config.api.token_ttl
          let access_token =
            token.issue(client.client_id, client.secret_hash, scopes, ttl)
          metrics.incr(metrics.TokensIssued)
          problem.json_response(
            200,
            json.object([
              #("access_token", json.string(access_token)),
              #("token_type", json.string("Bearer")),
              #("expires_in", json.int(ttl)),
              #("scope", json.string(scope.join(scopes))),
            ]),
          )
          |> wisp.set_header("pragma", "no-cache")
        }
      }
    }
  }
}

/// `Authorization: Basic` client credentials, form-urlencoded per RFC 6749
/// §2.3.1.
fn basic_credentials(req: Request) -> Result(#(String, String), Nil) {
  use value <- result.try(request.get_header(req, "authorization"))
  use #(scheme, encoded) <- result.try(string.split_once(
    string.trim(value),
    " ",
  ))
  use <- bool.guard(string.lowercase(scheme) != "basic", Error(Nil))
  use bits <- result.try(bit_array.base64_decode(string.trim(encoded)))
  use decoded <- result.try(bit_array.to_string(bits))
  use #(id, secret) <- result.try(string.split_once(decoded, ":"))
  let unescape = fn(v) { uri.percent_decode(v) |> result.unwrap(v) }
  Ok(#(unescape(id), unescape(secret)))
}

fn oauth_error(status: Int, error: String, description: String) -> Response {
  problem.json_response(
    status,
    json.object([
      #("error", json.string(error)),
      #("error_description", json.string(description)),
    ]),
  )
  |> wisp.set_header("pragma", "no-cache")
}

// --- redirections -----------------------------------------------------------

pub fn rule_json(r: Rule) -> Json {
  json.object([
    #("id", json.string(r.id)),
    #("host", json.string(r.host)),
    #("source", json.string(r.source)),
    #("match", json.string(rule.kind_to_string(r.kind))),
    #("target", json.string(r.target)),
    #("status", json.int(r.status)),
    #("preserve_query", json.bool(r.preserve_query)),
    #("case_insensitive", json.bool(r.case_insensitive)),
    #("priority", json.int(r.priority)),
    #("enabled", json.bool(r.enabled)),
    #("note", json.string(r.note)),
    #("created_at", json.string(r.created_at)),
    #("updated_at", json.string(r.updated_at)),
    #("updated_by", json.string(r.updated_by)),
    #("version", json.string(rule.version(r))),
  ])
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
  let total = list.length(matching)
  let data =
    matching |> list.drop({ page - 1 } * per_page) |> list.take(per_page)
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
        ]),
      ),
    ]),
  )
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

fn if_match(req: Request) -> Option(String) {
  case request.get_header(req, "if-match") {
    Ok(value) -> Some(problem.parse_if_match(value))
    Error(Nil) -> None
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
        if_match(req),
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
      let expected = case if_match(req) {
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

fn field(
  name: String,
  inner: decode.Decoder(a),
  next: fn(Option(Option(a))) -> decode.Decoder(b),
) -> decode.Decoder(b) {
  decode.optional_field(
    name,
    None,
    decode.optional(inner) |> decode.map(Some),
    next,
  )
}

fn pick(patch: Option(Option(a)), current: a, default: a) -> a {
  case patch {
    None -> current
    Some(None) -> default
    Some(Some(value)) -> value
  }
}

/// JSON merge patch (RFC 7396) of the writable rule fields: absent fields are
/// kept, `null` resets a field to its default, other values replace it.
pub fn patch_decoder() -> decode.Decoder(fn(Rule) -> Rule) {
  let defaults = rule.blank()
  let kind_decoder = {
    use value <- decode.then(decode.string)
    case rule.kind_from_string(value) {
      Ok(kind) -> decode.success(kind)
      Error(Nil) -> decode.failure(rule.Exact, "exact | prefix | regex")
    }
  }
  use host <- field("host", decode.string)
  use kind <- field("match", kind_decoder)
  use source <- field("source", decode.string)
  use target <- field("target", decode.string)
  use status <- field("status", decode.int)
  use preserve_query <- field("preserve_query", decode.bool)
  use case_insensitive <- field("case_insensitive", decode.bool)
  use priority <- field("priority", decode.int)
  use enabled <- field("enabled", decode.bool)
  use note <- field("note", decode.string)
  decode.success(fn(r: Rule) {
    rule.Rule(
      ..r,
      host: pick(host, r.host, defaults.host),
      kind: pick(kind, r.kind, defaults.kind),
      source: pick(source, r.source, defaults.source),
      target: pick(target, r.target, defaults.target),
      status: pick(status, r.status, defaults.status),
      preserve_query: pick(
        preserve_query,
        r.preserve_query,
        defaults.preserve_query,
      ),
      case_insensitive: pick(
        case_insensitive,
        r.case_insensitive,
        defaults.case_insensitive,
      ),
      priority: pick(priority, r.priority, defaults.priority),
      enabled: pick(enabled, r.enabled, defaults.enabled),
      note: pick(note, r.note, defaults.note),
    )
  })
}

fn delete_rule(
  req: Request,
  ctx: Context,
  principal: Principal,
  id: String,
) -> Response {
  case store.delete_versioned(ctx.store, id, if_match(req), principal.actor) {
    Ok(_) -> wisp.no_content()
    Error(store.NotFound) -> rule_not_found(id)
    Error(store.Conflict(current)) ->
      problem.precondition_failed(rule.version(current))
    Error(store.Invalid(errors)) -> problem.validation(errors)
  }
}

fn import_rules(req: Request, ctx: Context, principal: Principal) -> Response {
  let mode = case list.key_find(wisp.get_query(req), "mode") {
    Ok("replace") -> Ok(store.Replace)
    Ok("merge") | Error(Nil) -> Ok(store.Merge)
    Ok(_) -> Error(Nil)
  }
  use body <- wisp.require_string_body(req)
  case mode, rule.file_from_string(body) {
    Error(Nil), _ -> problem.bad_request("mode must be merge or replace.")
    _, Error(reason) -> problem.validation([reason])
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

fn test_url(req: Request) -> Response {
  let url = list.key_find(wisp.get_query(req), "url") |> result.unwrap("")
  case matcher.resolve_url(snapshot.current(), url) {
    matcher.BadUrl ->
      problem.bad_request(
        "url must be an absolute URL, e.g. https://host/path.",
      )
    matcher.NotMatched ->
      problem.json_response(200, json.object([#("matched", json.bool(False))]))
    matcher.Redirected(m, location) ->
      problem.json_response(
        200,
        json.object([
          #("matched", json.bool(True)),
          #("status", json.int(m.rule.status)),
          #("location", json.string(location)),
          #("rule", rule_json(m.rule)),
        ]),
      )
  }
}
