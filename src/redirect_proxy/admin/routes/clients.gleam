//// REST API clients.

import gleam/bool
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/uri
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/clients as clients_view
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, form_value, html,
  not_found, require_csrf_form,
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
  issued: Option(clients_view.IssuedSecret),
  errors: List(String),
) -> Response {
  case clients.list(ctx.clients) {
    Ok(all) ->
      html(
        status,
        clients_view.api_clients(
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
  let name = form_value(form, "name")
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
        Some(clients_view.IssuedSecret(client.client_id, secret)),
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
        Some(clients_view.IssuedSecret(client_id, secret)),
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

pub fn confirm_client_action(
  ctx: Context,
  s: Session,
  client_id: String,
  action: String,
) -> Response {
  let path = "/api-clients/" <> uri.percent_encode(client_id) <> "/" <> action
  case action {
    "rotate" ->
      html(
        200,
        pages.confirm(
          s,
          features(ctx),
          layout.NavClients,
          "Rotate a client secret",
          "A new secret is generated for "
            <> client_id
            <> ". The current secret stops working at once and the tokens issued with it are revoked.",
          path,
          "Rotate the secret",
          "/api-clients",
        ),
      )
    _ ->
      html(
        200,
        pages.confirm(
          s,
          features(ctx),
          layout.NavClients,
          "Delete an API client",
          "The client "
            <> client_id
            <> " will be removed and its tokens revoked at once.",
          path,
          "Delete " <> client_id,
          "/api-clients",
        ),
      )
  }
}
