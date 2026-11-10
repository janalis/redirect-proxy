//// Administration backend: entry point and routing.

import gleam/bool
import gleam/http.{Get, Post}
import gleam/list
import gleam/result
import gleam/uri
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/routes/audit.{audit_page} as _
import redirect_proxy/admin/routes/auth.{
  login, login_page, logout, oidc_callback, oidc_start, require_session,
} as _
import redirect_proxy/admin/routes/clients.{
  api_clients_page, confirm_client_action, create_api_client, delete_api_client,
  rotate_api_client,
} as _
import redirect_proxy/admin/routes/import_export.{import_page, import_rules} as _
import redirect_proxy/admin/routes/rules.{
  bulk, confirm_delete, create_rule, delete_rule, edit_rule, export, list_rules,
  new_rule, reload, test_url, toggle_rule, update_rule,
} as _
import redirect_proxy/admin/routes/users.{
  account_page, change_password, confirm_delete_user, create_user, delete_user,
  list_users, set_user_role,
} as _
import redirect_proxy/admin/web.{
  type Context, error_page, limit_body, not_found, security_headers,
  strict_transport_security,
} as _
import redirect_proxy/api/deprecation
import redirect_proxy/api/router as api_router
import redirect_proxy/api/web as api_web
import redirect_proxy/config
import redirect_proxy/health
import redirect_proxy/metrics
import redirect_proxy/metrics_endpoint
import redirect_proxy/role.{type Role}
import redirect_proxy/store
import wisp.{type Request, type Response}

pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.AdminRequests)
  use <- strict_transport_security(ctx)
  use <- security_headers(ctx)
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
    Get, ["healthz"] -> health.live()
    Get, ["readyz"] -> health.ready()
    Get, ["metrics"] ->
      metrics_endpoint.respond_on(
        req,
        ctx.config.admin.metrics_token,
        ctx.config.admin.listen,
      )
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

/// The role a route needs (see `role`). Reading is for every role; changing
/// rules for editors; users, API clients and the audit log (sign-ins, with
/// client addresses) for admins. A route that is not listed needs the admin
/// role, so that a new page is not open to everyone by mistake.
pub fn required_role(method: http.Method, segments: List(String)) -> Role {
  case method, segments {
    // own password and session: anyone (other users' passwords: checked in
    // `change_password`)
    Get, ["account"] | Post, ["account", "password"] | Post, ["logout"] ->
      role.Viewer
    // a rule's details are on its edit page
    Get, [] | Get, ["rules"] | Get, ["rules", _, "edit"] -> role.Viewer
    Get, ["test"] | Get, ["export"] -> role.Viewer
    // changing rules, or the pages that lead to a change
    Get, ["rules", "new"]
    | Post, ["rules"]
    | Post, ["rules", "bulk"]
    | Post, ["rules", _]
    | Get, ["rules", _, "delete"]
    | Post, ["rules", _, "delete"]
    | Post, ["rules", _, "toggle"]
    | Post, ["reload"]
    | Get, ["import"]
    | Post, ["import"]
    -> role.Editor
    // users, API clients, the audit log and anything new
    _, _ -> role.Admin
  }
}

fn authenticated(req: Request, ctx: Context) -> Response {
  use s, set_cookie <- require_session(req, ctx)
  // rule ids and usernames are percent-encoded in links: `/rules/a%20b`
  let segments = list.map(wisp.path_segments(req), decode_segment)
  use <- bool.lazy_guard(
    !role.allows(s.role, required_role(req.method, segments)),
    fn() {
      error_page(
        ctx,
        s,
        403,
        "Not allowed",
        "Your role (" <> role.to_string(s.role) <> ") does not allow this.",
      )
      |> set_cookie
    },
  )
  use <- store_available(ctx, s, req.method, set_cookie)
  let resp = case req.method, segments {
    Get, [] -> wisp.redirect("/rules")
    Post, ["logout"] -> logout(req, ctx, s)
    Get, ["rules"] -> list_rules(req, ctx, s)
    Get, ["rules", "new"] -> new_rule(req, ctx, s)
    Post, ["rules"] -> create_rule(req, ctx, s)
    Post, ["rules", "bulk"] -> bulk(req, ctx, s)
    Get, ["rules", id, "edit"] -> edit_rule(ctx, s, id)
    Post, ["rules", id] -> update_rule(req, ctx, s, id)
    Get, ["rules", id, "delete"] -> confirm_delete(req, ctx, s, id)
    Post, ["rules", id, "delete"] -> delete_rule(req, ctx, s, id)
    Post, ["rules", id, "toggle"] -> toggle_rule(req, ctx, s, id)
    Post, ["reload"] -> reload(req, ctx, s)
    Get, ["test"] -> test_url(req, ctx, s)
    Get, ["export"] -> export(req, ctx)
    Get, ["import"] -> import_page(req, ctx, s)
    Post, ["import"] -> import_rules(req, ctx, s)
    Get, ["users"] -> list_users(req, ctx, s)
    Post, ["users"] -> create_user(req, ctx, s)
    Get, ["users", username, "delete"] -> confirm_delete_user(ctx, s, username)
    Post, ["users", username, "delete"] -> delete_user(req, ctx, s, username)
    Get, ["account"] -> account_page(req, ctx, s)
    Post, ["account", "password"] -> change_password(req, ctx, s)
    Post, ["users", username, "role"] -> set_user_role(req, ctx, s, username)
    Get, ["audit"] -> audit_page(req, ctx, s)
    Get, ["api-clients"] -> api_clients_page(req, ctx, s)
    Post, ["api-clients"] -> create_api_client(req, ctx, s)
    Get, ["api-clients", client_id, "rotate"] ->
      confirm_client_action(ctx, s, client_id, "rotate")
    Get, ["api-clients", client_id, "delete"] ->
      confirm_client_action(ctx, s, client_id, "delete")
    Post, ["api-clients", client_id, "rotate"] ->
      rotate_api_client(req, ctx, s, client_id)
    Post, ["api-clients", client_id, "delete"] ->
      delete_api_client(req, ctx, s, client_id)
    _, _ -> not_found(ctx, s)
  }
  set_cookie(resp)
}

/// A 503 page when the rules store does not answer in time (changes queued,
/// or waiting for the file lock another process holds), rather than a crash
/// (500). A change that timed out is skipped by the store: it was not made.
fn store_available(
  ctx: Context,
  s: Session,
  method: http.Method,
  set_cookie: fn(Response) -> Response,
  handler: fn() -> Response,
) -> Response {
  use <- store.or_unavailable(handler)
  let message = case method {
    Get | http.Head ->
      "The rules are busy with other changes (another process may hold the lock). Retry in a moment."
    _ ->
      "The rules are busy with other changes (another process may hold the lock): your change was not made. Retry in a moment."
  }
  error_page(ctx, s, 503, "Rules busy", message)
  |> wisp.set_header("retry-after", "1")
  |> set_cookie
}

fn decode_segment(segment: String) -> String {
  uri.percent_decode(segment) |> result.unwrap(segment)
}
