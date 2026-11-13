//// Local administrator accounts.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None}
import gleam/result
import gleam/uri
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/routes/auth
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/views/users as users_view
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, form_value, html,
  not_found, require_csrf_form, set_session_cookie, show_users,
} as _
import redirect_proxy/password
import redirect_proxy/role
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
    Ok(all) ->
      html(status, users_view.users(s, features(ctx), flash, all, errors))
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
  let username = form_value(form, "username")
  let pass = form_value(form, "password")
  let result = {
    use Nil <- result.try(users.validate_username(users.normalise(username)))
    // forms from before roles send none: they created administrators
    use new_role <- result.try(case form_value(form, "role") {
      "" -> Ok(role.Admin)
      value ->
        role.from_string(value)
        |> result.replace_error("role: must be viewer, editor or admin")
    })
    use Nil <- result.try(password.validate_strength(pass))
    users.create_with_role(
      ctx.users,
      username,
      password.hash(pass),
      new_role,
      s.username,
    )
  }
  case result {
    Ok(_) -> wisp.redirect("/users?flash=user_created")
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}

/// Changes the role of a local user (the last administrator keeps theirs).
pub fn set_user_role(
  req: Request,
  ctx: Context,
  s: Session,
  username: String,
) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  use form <- require_csrf_form(req, s)
  let result = {
    use new_role <- result.try(
      role.from_string(form_value(form, "role"))
      |> result.replace_error("role: must be viewer, editor or admin"),
    )
    users.set_role(ctx.users, username, new_role, s.username)
  }
  case result {
    Ok(Nil) -> wisp.redirect("/users?flash=role_changed")
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}

/// The account page: every role can change its own password there.
pub fn account_page(req: Request, ctx: Context, s: Session) -> Response {
  html(200, users_view.account(s, features(ctx), flash_from_query(req), []))
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

pub fn confirm_delete_user(
  ctx: Context,
  s: Session,
  username: String,
) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  case users.get(ctx.users, username) {
    Error(Nil) -> not_found(ctx, s)
    Ok(user) ->
      html(
        200,
        pages.confirm(
          s,
          features(ctx),
          layout.NavUsers,
          "Delete a user",
          "The user "
            <> user.username
            <> " will be removed and signed out everywhere.",
          "/users/" <> uri.percent_encode(user.username) <> "/delete",
          "Delete " <> user.username,
          "/users",
        ),
      )
  }
}

/// Changing a local password, yours or another user's, needs a local session
/// and your current password: a stolen session or an SSO account cannot take
/// over local accounts.
/// Too many wrong current passwords: 429 until the window ends.
fn throttled(
  req: Request,
  ctx: Context,
  s: Session,
  next: fn(List(ratelimit.Receipt)) -> Response,
) -> Response {
  case auth.start_password_check(req, ctx, s.username) {
    Ok(receipts) -> next(receipts)
    Error(seconds) ->
      error_page(
        ctx,
        s,
        429,
        "Too many attempts",
        "Too many wrong passwords. Try again in a few minutes.",
      )
      |> wisp.set_header("retry-after", int.to_string(seconds))
  }
}

/// The password check did not run: the attempt is taken back.
fn busy_or(
  ctx: Context,
  s: Session,
  receipts: List(ratelimit.Receipt),
  checked: Result(Bool, Nil),
  next: fn(Bool) -> Response,
) -> Response {
  case checked {
    Ok(ok) -> next(ok)
    Error(Nil) -> {
      auth.end_password_check(ctx, s.username, receipts, auth.NotRun)
      error_page(
        ctx,
        s,
        503,
        "Server busy",
        "Too many password checks are running. Try again in a moment.",
      )
      |> wisp.set_header("retry-after", "1")
    }
  }
}

pub fn change_password(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  use form <- require_csrf_form(req, s)
  use <- bool.lazy_guard(s.method != session.Local, fn() {
    error_page(
      ctx,
      s,
      403,
      "Not allowed",
      "Only local administrators can change local passwords.",
    )
  })
  let username =
    list.key_find(form.values, "username")
    |> result.unwrap(s.username)
    |> users.normalise
  let pass = form_value(form, "password")
  let admin = role.allows(s.role, role.Admin)
  use <- bool.lazy_guard(username != s.username && !admin, fn() {
    error_page(
      ctx,
      s,
      403,
      "Not allowed",
      "Only administrators can change another user's password.",
    )
  })
  // where the form was: the users page (administrators) or the account page
  let back = case admin {
    True -> "/users"
    False -> "/account"
  }
  let failed = fn(reason) {
    case admin {
      True -> users_page(ctx, s, 422, None, [reason])
      False -> html(422, users_view.account(s, features(ctx), None, [reason]))
    }
  }
  use receipts <- throttled(req, ctx, s)
  let checked =
    auth.hashing_password(fn() {
      case users.get(ctx.users, s.username) {
        Ok(me) ->
          password.verify(
            form_value(form, "current_password"),
            me.password_hash,
          )
        Error(Nil) -> False
      }
    })
  use current_ok <- busy_or(ctx, s, receipts, checked)
  auth.record_password_check(ctx, s.username, receipts, current_ok)
  let result = {
    use <- bool.guard(
      !current_ok,
      Error("Your current password is not correct."),
    )
    use Nil <- result.try(password.validate_strength(pass))
    users.set_password(ctx.users, username, password.hash(pass), s.username)
  }
  case result {
    Ok(Nil) -> {
      // Every session of that user ends (their fingerprint no longer
      // matches); when it is our own account, continue in a fresh session.
      session.destroy_user(username)
      let resp = wisp.redirect(back <> "?flash=password_changed")
      case username == s.username && s.method == session.Local {
        False -> resp
        True ->
          case users.get(ctx.users, username) {
            Ok(user) ->
              session.create(
                username,
                session.Local,
                ctx.config.admin.session_ttl,
                users.fingerprint(user),
                user.role,
              )
              |> set_session_cookie(resp, req, ctx, _)
            Error(Nil) -> resp
          }
      }
    }
    Error(reason) -> failed(reason)
  }
}
