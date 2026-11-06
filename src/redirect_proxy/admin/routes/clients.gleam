//// REST API clients.

import gleam/bool
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, html, not_found,
  require_csrf_form,
} as _
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/api/token
import redirect_proxy/config
import wisp.{type Request, type Response}

fn render_api_clients(
  ctx: Context,
  s: Session,
  status: Int,
  flash: Option(layout.Flash),
  issued: Option(pages.IssuedSecret),
  errors: List(String),
) -> Response {
  case clients.list(ctx.clients) {
    Ok(all) ->
      html(
        status,
        pages.api_clients(
          s,
          features(ctx),
          flash,
          all,
          issued,
          errors,
          config.api_public_url(ctx.config),
        ),
      )
    Error(reason) -> error_page(ctx, s, 500, "API clients unavailable", reason)
  }
}

pub fn api_clients_page(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!ctx.config.api.enabled, fn() { not_found(ctx, s) })
  render_api_clients(ctx, s, 200, flash_from_query(req), None, [])
}

pub fn create_api_client(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!ctx.config.api.enabled, fn() { not_found(ctx, s) })
  use form <- require_csrf_form(req, s)
  let name = list.key_find(form.values, "name") |> result.unwrap("")
  let scopes =
    form.values
    |> list.filter(fn(pair) { pair.0 == "scope" })
    |> list.filter_map(fn(pair) { scope.from_string(pair.1) })
  case clients.create(ctx.clients, name, scopes, s.username) {
    Ok(#(client, secret)) ->
      render_api_clients(
        ctx,
        s,
        201,
        Some(layout.Success("API client created.")),
        Some(pages.IssuedSecret(client.client_id, secret)),
        [],
      )
    Error(reason) -> render_api_clients(ctx, s, 422, None, None, [reason])
  }
}

pub fn rotate_api_client(
  req: Request,
  ctx: Context,
  s: Session,
  client_id: String,
) -> Response {
  use <- bool.lazy_guard(!ctx.config.api.enabled, fn() { not_found(ctx, s) })
  use _form <- require_csrf_form(req, s)
  case clients.rotate(ctx.clients, client_id, s.username) {
    Ok(secret) -> {
      token.revoke_client(client_id)
      render_api_clients(
        ctx,
        s,
        200,
        Some(layout.Success("Secret rotated; previous tokens are revoked.")),
        Some(pages.IssuedSecret(client_id, secret)),
        [],
      )
    }
    Error(reason) -> render_api_clients(ctx, s, 404, None, None, [reason])
  }
}

pub fn delete_api_client(
  req: Request,
  ctx: Context,
  s: Session,
  client_id: String,
) -> Response {
  use <- bool.lazy_guard(!ctx.config.api.enabled, fn() { not_found(ctx, s) })
  use _form <- require_csrf_form(req, s)
  case clients.delete(ctx.clients, client_id, s.username) {
    Ok(Nil) -> {
      token.revoke_client(client_id)
      wisp.redirect("/api-clients?flash=client_deleted")
    }
    Error(reason) -> render_api_clients(ctx, s, 404, None, None, [reason])
  }
}
