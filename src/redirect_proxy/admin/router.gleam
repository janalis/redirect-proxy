//// Administration backend: entry point and routing.

import gleam/http.{Get, Post}
import redirect_proxy/admin/routes/auth.{
  login, login_page, logout, oidc_callback, oidc_start, require_session,
} as _
import redirect_proxy/admin/routes/clients.{
  api_clients_page, create_api_client, delete_api_client, rotate_api_client,
} as _
import redirect_proxy/admin/routes/rules.{
  audit_page, confirm_delete, create_rule, delete_rule, edit_rule, export,
  import_page, import_rules, list_rules, new_rule, reload, test_url, toggle_rule,
  update_rule,
} as _
import redirect_proxy/admin/routes/users.{
  change_password, create_user, delete_user, list_users,
} as _
import redirect_proxy/admin/web.{
  type Context, limit_body, not_found, plain, security_headers,
  strict_transport_security,
} as _
import redirect_proxy/api/deprecation
import redirect_proxy/api/router as api_router
import redirect_proxy/api/web as api_web
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/metrics
import wisp.{type Request, type Response}

pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.AdminRequests)
  use <- strict_transport_security(ctx)
  use <- security_headers
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  use <- wisp.serve_static(req, under: "/static", from: ctx.static_dir)
  // The REST API is bearer-token only (no cookies): route it before the
  // session and CSRF machinery.
  use <- api_dispatch(req, ctx)
  let req = limit_body(req, ctx)
  use req <- wisp.csrf_known_header_protection(req)

  case req.method, wisp.path_segments(req) {
    // Public endpoints
    Get, ["healthz"] -> plain(200, "ok")
    // 503 while draining before a stop, so that load balancers move away
    Get, ["readyz"] ->
      case ffi.draining() {
        True -> plain(503, "draining")
        False -> plain(200, "ready")
      }
    Get, ["metrics"] ->
      wisp.response(200)
      |> wisp.set_header("content-type", "text/plain; version=0.0.4")
      |> wisp.string_body(metrics.render_prometheus())
    Get, ["login"] -> login_page(req, ctx)
    Post, ["login"] -> login(req, ctx)
    Get, ["auth", "oidc", "start"] -> oidc_start(req, ctx)
    Get, ["auth", "oidc", "callback"] -> oidc_callback(req, ctx)
    Get, ["favicon.ico"] -> wisp.redirect("/static/favicon.svg")

    // Everything else requires an authenticated administrator
    _, _ -> authenticated(req, ctx)
  }
}

fn api_dispatch(
  req: Request,
  ctx: Context,
  next: fn() -> Response,
) -> Response {
  case config.api_on_admin(ctx.config), wisp.path_segments(req) {
    True, ["api", ..] | True, ["oauth", ..] ->
      api_router.handle(
        req,
        api_web.Context(
          config: ctx.config,
          store: ctx.store,
          clients: ctx.clients,
          peer_ip: ctx.peer_ip,
          client_ip: ctx.client_ip,
          deprecations: deprecation.registry(),
        ),
      )
    _, _ -> next()
  }
}

fn authenticated(req: Request, ctx: Context) -> Response {
  use s, set_cookie <- require_session(req, ctx)
  let resp = case req.method, wisp.path_segments(req) {
    Get, [] -> wisp.redirect("/rules")
    Post, ["logout"] -> logout(req, ctx, s)
    Get, ["rules"] -> list_rules(req, ctx, s)
    Get, ["rules", "new"] -> new_rule(req, ctx, s)
    Post, ["rules"] -> create_rule(req, ctx, s)
    Get, ["rules", id, "edit"] -> edit_rule(ctx, s, id)
    Post, ["rules", id] -> update_rule(req, ctx, s, id)
    Get, ["rules", id, "delete"] -> confirm_delete(ctx, s, id)
    Post, ["rules", id, "delete"] -> delete_rule(req, ctx, s, id)
    Post, ["rules", id, "toggle"] -> toggle_rule(req, ctx, s, id)
    Post, ["reload"] -> reload(req, ctx, s)
    Get, ["test"] -> test_url(req, ctx, s)
    Get, ["export"] -> export(ctx)
    Get, ["import"] -> import_page(req, ctx, s)
    Post, ["import"] -> import_rules(req, ctx, s)
    Get, ["users"] -> list_users(req, ctx, s)
    Post, ["users"] -> create_user(req, ctx, s)
    Post, ["users", username, "delete"] -> delete_user(req, ctx, s, username)
    Post, ["account", "password"] -> change_password(req, ctx, s)
    Get, ["audit"] -> audit_page(ctx, s)
    Get, ["api-clients"] -> api_clients_page(req, ctx, s)
    Post, ["api-clients"] -> create_api_client(req, ctx, s)
    Post, ["api-clients", client_id, "rotate"] ->
      rotate_api_client(req, ctx, s, client_id)
    Post, ["api-clients", client_id, "delete"] ->
      delete_api_client(req, ctx, s, client_id)
    _, _ -> not_found(ctx, s)
  }
  set_cookie(resp)
}
