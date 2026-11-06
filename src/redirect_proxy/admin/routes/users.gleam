//// Local administrator accounts.

import gleam/bool
import gleam/list
import gleam/option.{type Option, None}
import gleam/result
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, html, not_found,
  require_csrf_form, set_session_cookie, show_users,
} as _
import redirect_proxy/password
import redirect_proxy/users
import wisp.{type Request, type Response}

fn users_page(
  ctx: Context,
  s: Session,
  status: Int,
  flash: Option(layout.Flash),
  errors: List(String),
) -> Response {
  case users.list(ctx.users) {
    Ok(all) -> html(status, pages.users(s, features(ctx), flash, all, errors))
    Error(reason) -> error_page(ctx, s, 500, "Users unavailable", reason)
  }
}

pub fn list_users(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  users_page(ctx, s, 200, flash_from_query(req), [])
}

pub fn create_user(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  use form <- require_csrf_form(req, s)
  let username = list.key_find(form.values, "username") |> result.unwrap("")
  let pass = list.key_find(form.values, "password") |> result.unwrap("")
  let result = {
    use Nil <- result.try(users.validate_username(users.normalise(username)))
    use Nil <- result.try(password.validate_strength(pass))
    users.create(ctx.users, username, password.hash(pass), s.username)
  }
  case result {
    Ok(_) -> wisp.redirect("/users?flash=user_created")
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}

pub fn delete_user(
  req: Request,
  ctx: Context,
  s: Session,
  username: String,
) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  use _form <- require_csrf_form(req, s)
  use <- bool.lazy_guard(users.normalise(username) == s.username, fn() {
    users_page(ctx, s, 422, None, ["You cannot delete your own account."])
  })
  case users.delete(ctx.users, username, s.username) {
    Ok(Nil) -> {
      session.destroy_user(users.normalise(username))
      wisp.redirect("/users?flash=user_deleted")
    }
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}

pub fn change_password(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  use form <- require_csrf_form(req, s)
  let username =
    list.key_find(form.values, "username")
    |> result.unwrap(s.username)
    |> users.normalise
  let pass = list.key_find(form.values, "password") |> result.unwrap("")
  let result = {
    use Nil <- result.try(password.validate_strength(pass))
    users.set_password(ctx.users, username, password.hash(pass), s.username)
  }
  case result {
    Ok(Nil) -> {
      // Every session of that user ends (their fingerprint no longer
      // matches); when it is our own account, continue in a fresh session.
      session.destroy_user(username)
      let resp = wisp.redirect("/users?flash=password_changed")
      case username == s.username && s.method == session.Local {
        False -> resp
        True ->
          case users.get(ctx.users, username) {
            Ok(user) ->
              session.create(
                username,
                session.Local,
                ctx.config.admin.session_ttl,
                session.user_fingerprint(user.password_hash, user.updated_at),
              )
              |> set_session_cookie(resp, req, ctx, _)
            Error(Nil) -> resp
          }
      }
    }
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}
