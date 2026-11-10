//// REST API (`/api/...`) and OAuth2 token endpoint (`/oauth/token`), served
//// by the admin listener. There is no version prefix: see
//// `api/deprecation.gleam` for how the API evolves.
////
//// This module authenticates requests, throttles invalid tokens, checks
//// the scope of each operation (`api/routes.gleam`) and dispatches; the
//// handlers are in `rule_routes` and `audit_routes`.

import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/api/audit_routes
import redirect_proxy/api/auth.{type Principal}
import redirect_proxy/api/deprecation
import redirect_proxy/api/openapi
import redirect_proxy/api/params
import redirect_proxy/api/problem
import redirect_proxy/api/routes
import redirect_proxy/api/rule_routes
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/api/token_endpoint.{token_endpoint} as _
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/health
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/metrics_endpoint
import wisp.{type Request, type Response}

/// Entry point of the API's own listener (when `api.port` differs from
/// `admin.port`, or the admin UI is disabled).
pub fn handle_dedicated(req: Request, ctx: Context) -> Response {
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  case wisp.path_segments(req) {
    ["healthz"] -> health.live()
    ["readyz"] -> health.ready()
    // the admin serves the metrics; without it, they would be nowhere
    ["metrics"] if !ctx.config.admin.enabled ->
      metrics_endpoint.respond(req, ctx.config.admin.metrics_token)
    _ -> handle(req, ctx)
  }
  |> wisp.set_header("x-content-type-options", "nosniff")
  |> wisp.set_header("x-frame-options", "DENY")
  |> wisp.set_header("referrer-policy", "no-referrer")
  |> fn(resp) {
    // as the admin: clients must not fall back to HTTP once they used HTTPS
    case
      string.starts_with(
        string.lowercase(config.api_public_url(ctx.config)),
        "https://",
      )
    {
      True ->
        wisp.set_header(resp, "strict-transport-security", "max-age=31536000")
      False -> resp
    }
  }
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
          |> wisp.set_header("content-type", "application/json; charset=utf-8")
          |> wisp.set_header("access-control-allow-origin", "*")
          |> wisp.string_body(openapi.document(
            ctx.deprecations,
            ctx.config.api.oauth,
          ))
        _ -> problem.method_not_allowed(["GET"])
      }
    ["api", ..rest] -> {
      use principal <- authenticated(req, ctx)
      // rule ids are percent-encoded in URLs: `/api/redirects/a%20b`
      let rest =
        list.map(rest, fn(s) { uri.percent_decode(s) |> result.unwrap(s) })
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
  use <- required_scope(req, ctx, principal, template)
  let response = case req.method, segments {
    Get, ["redirects"] -> {
      rule_routes.list_rules(req, ctx)
    }
    Post, ["redirects"] -> {
      rule_routes.create_rule(req, ctx, principal)
    }
    Get, ["redirects", "export"] -> rule_routes.export(req, ctx)
    Post, ["redirects", "import"] -> {
      rule_routes.import_rules(req, ctx, principal)
    }
    Post, ["redirects", "bulk"] -> {
      rule_routes.bulk(req, ctx, principal)
    }
    Get, ["redirects", id] -> rule_routes.get_rule(ctx, id)
    Put, ["redirects", id] -> {
      rule_routes.replace_rule(req, ctx, principal, id)
    }
    Patch, ["redirects", id] -> {
      rule_routes.patch_rule(req, ctx, principal, id)
    }
    Delete, ["redirects", id] -> {
      rule_routes.delete_rule(req, ctx, principal, id)
    }
    Post, ["reload"] -> rule_routes.reload(ctx, principal)
    Get, ["test"] -> {
      rule_routes.test_url(req, ctx)
    }
    Get, ["audit"] -> {
      audit_routes.audit_log(req, ctx)
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
      case routes.find(req.method, template) {
        Ok(_) -> next()
        Error(Nil) -> problem.method_not_allowed(routes.allowed(template))
      }
    // unknown paths are a 404 from the dispatch
    Error(Nil) -> next()
  }
}

/// The scope of the operation (`routes.operations`), for every operation:
/// the dispatch does not check scopes itself.
fn required_scope(
  req: Request,
  ctx: Context,
  principal: Principal,
  template: Result(String, Nil),
  next: fn() -> Response,
) -> Response {
  case result.try(template, routes.find(req.method, _)) {
    Ok(operation) -> require(principal, operation.scope, ctx, next)
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
      |> params.add_deprecation_headers(response, _)
    }
  }
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
