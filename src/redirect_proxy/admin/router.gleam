//// Administration backend: routing, middleware and request handlers.

import gleam/bool
import gleam/bytes_tree
import gleam/http.{Get, Post}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/header
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/views/rules as rules_view
import redirect_proxy/api/clients
import redirect_proxy/api/deprecation
import redirect_proxy/api/router as api_router
import redirect_proxy/api/scope
import redirect_proxy/api/token
import redirect_proxy/audit
import redirect_proxy/config.{type Config}
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/password
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store.{type Store}
import redirect_proxy/users
import simplifile
import wisp.{type Request, type Response}

pub const session_cookie = "rp_session"

/// Binds an SSO login in progress to the browser that started it.
const oidc_state_cookie = "rp_oidc_state"

/// Failed logins allowed per window for one account from one client, for
/// one client (all accounts), and for one account (all clients). The last
/// one bounds distributed guessing without letting anyone lock a user out
/// cheaply.
const login_pair_limit = 10

const login_ip_limit = 20

const login_user_limit = 100

/// Longer usernames are refused before they become a throttling key or a log
/// line.
const max_username_bytes = 64

const login_window = 900

pub type Context {
  Context(
    config: Config,
    store: Store,
    users: users.Settings,
    clients: clients.Settings,
    static_dir: String,
    /// TCP peer address of the current request.
    peer_ip: String,
    /// Client address, forwarded by a trusted proxy (`access_log.trusted_proxies`)
    /// or the peer address. Used for throttling.
    client_ip: String,
  )
}

// --- entry point ------------------------------------------------------------

pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.AdminRequests)
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
        api_router.Context(
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
    Post, ["logout"] -> logout(req, s)
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

// --- middleware -------------------------------------------------------------

/// Admin forms are small: anything larger is refused before it is read, so
/// that unauthenticated requests (login) cannot make the server buffer
/// megabytes. Imports carry a rules file and get the API's limit.
const max_form_bytes = 65_536

fn limit_body(req: Request, ctx: Context) -> Request {
  case wisp.path_segments(req) {
    ["import"] ->
      req
      |> wisp.set_max_body_size(ctx.config.api.max_body_bytes)
      |> wisp.set_max_files_size(ctx.config.api.max_body_bytes)
    _ ->
      req
      |> wisp.set_max_body_size(max_form_bytes)
      |> wisp.set_max_files_size(0)
  }
}

fn security_headers(next: fn() -> Response) -> Response {
  next()
  |> wisp.set_header(
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
      <> "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  )
  |> wisp.set_header("x-frame-options", "DENY")
  |> wisp.set_header("x-content-type-options", "nosniff")
  |> wisp.set_header("referrer-policy", "same-origin")
  |> wisp.set_header("cross-origin-opener-policy", "same-origin")
  |> wisp.set_header(
    "permissions-policy",
    "camera=(), microphone=(), geolocation=()",
  )
}

/// Resolves the current session from the session cookie, or from trusted
/// proxy headers. `next` receives the session and a function that must be
/// applied to the response (it may set a fresh session cookie).
fn require_session(
  req: Request,
  ctx: Context,
  next: fn(Session, fn(Response) -> Response) -> Response,
) -> Response {
  let from_cookie = current_session(req, ctx)
  let proxy_user = header.identify(ctx.config.header_auth, req, ctx.peer_ip)

  case from_cookie, proxy_user {
    // Header auth: the proxy is authoritative, the session must follow it.
    Ok(s), Ok(user) if s.method == session.Header && s.username != user -> {
      session.destroy(s.token)
      start_header_session(req, ctx, user, next)
    }
    Ok(s), _ -> next(s, fn(resp) { resp })
    Error(Nil), Ok(user) -> start_header_session(req, ctx, user, next)
    Error(Nil), Error(Nil) ->
      case req.method {
        Get -> {
          let path = case req.query {
            Some(q) -> req.path <> "?" <> q
            None -> req.path
          }
          wisp.redirect("/login?" <> uri.query_to_string([#("next", path)]))
        }
        _ -> wisp.response(401) |> wisp.string_body("Authentication required")
      }
  }
}

/// The live session of the request's cookie. A local account's session ends
/// once the user is deleted or changes password, including from the CLI,
/// which runs in another process and cannot reach this server's sessions.
fn current_session(req: Request, ctx: Context) -> Result(Session, Nil) {
  use token <- result.try(wisp.get_cookie(req, session_cookie, wisp.Signed))
  use s <- result.try(session.get(token, ctx.config.admin.session_idle_timeout))
  case s.method {
    session.Local ->
      case users.get(ctx.users, s.username) {
        Ok(user) ->
          case
            session.user_fingerprint(user.password_hash, user.updated_at)
            == s.fingerprint
          {
            True -> Ok(s)
            False -> end_session(s)
          }
        Error(Nil) -> end_session(s)
      }
    session.Oidc | session.Header -> Ok(s)
  }
}

fn end_session(s: Session) -> Result(Session, Nil) {
  session.destroy(s.token)
  Error(Nil)
}

fn start_header_session(
  req: Request,
  ctx: Context,
  user: String,
  next: fn(Session, fn(Response) -> Response) -> Response,
) -> Response {
  log.info(
    "proxy-authenticated session for "
    <> log_value(user)
    <> " from "
    <> ctx.peer_ip,
  )
  let s = session.create(user, session.Header, ctx.config.admin.session_ttl, "")
  next(s, set_session_cookie(_, req, ctx, s))
}

fn set_session_cookie(
  resp: Response,
  req: Request,
  ctx: Context,
  s: Session,
) -> Response {
  wisp.set_cookie(
    resp,
    req,
    session_cookie,
    s.token,
    wisp.Signed,
    ctx.config.admin.session_ttl,
  )
}

/// Parses the form and verifies the CSRF token of the session.
fn require_csrf_form(
  req: Request,
  s: Session,
  next: fn(wisp.FormData) -> Response,
) -> Response {
  use form <- wisp.require_form(req)
  let token = list.key_find(form.values, "csrf_token") |> result.unwrap("")
  case session_token_matches(s, token) {
    True -> next(form)
    False -> {
      log.warning("CSRF token mismatch for " <> s.username)
      wisp.response(403) |> wisp.string_body("Invalid CSRF token")
    }
  }
}

fn session_token_matches(s: Session, token: String) -> Bool {
  token != "" && ffi.secure_compare(<<token:utf8>>, <<s.csrf_token:utf8>>)
}

// --- authentication ---------------------------------------------------------

fn sso_label(ctx: Context) -> Option(String) {
  case ctx.config.oidc.enabled {
    True -> Some(ctx.config.oidc.button_label)
    False -> None
  }
}

fn login_page(req: Request, ctx: Context) -> Response {
  // Already signed in?
  case current_session(req, ctx) {
    Ok(_) -> wisp.redirect("/rules")
    Error(Nil) -> {
      // a code, never text from the link: the page must not display
      // arbitrary messages to whoever follows a crafted URL
      let error = case list.key_find(wisp.get_query(req), "error") {
        Ok("sso_unavailable") ->
          Some("Single sign-on is currently unavailable.")
        _ -> None
      }
      html(
        200,
        pages.login(error, ctx.config.local_auth.enabled, sso_label(ctx), ""),
      )
    }
  }
}

fn login(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.local_auth.enabled, fn() {
    wisp.not_found()
  })
  use form <- wisp.require_form(req)
  let username =
    list.key_find(form.values, "username")
    |> result.unwrap("")
    |> users.normalise
  let pass = list.key_find(form.values, "password") |> result.unwrap("")
  let fail = fn(message: String, status: Int, username: String) {
    html(
      status,
      pages.login(
        Some(message),
        ctx.config.local_auth.enabled,
        sso_label(ctx),
        username,
      ),
    )
  }
  let ip_key = "login-ip:" <> ctx.client_ip
  use <- bool.lazy_guard(string.byte_size(username) > max_username_bytes, fn() {
    ratelimit.record_failure(ip_key, login_window)
    fail("Invalid username or password.", 401, "")
  })
  let pair_key = "login:" <> ctx.client_ip <> " " <> username
  let user_key = "login-user:" <> username
  let who = log_value(username) <> " ip=" <> ctx.client_ip

  case
    ratelimit.is_blocked(pair_key, login_pair_limit)
    || ratelimit.is_blocked(ip_key, login_ip_limit)
    || ratelimit.is_blocked(user_key, login_user_limit)
  {
    True -> {
      log.warning("login throttled for user=" <> who)
      fail(
        "Too many failed attempts. Try again in a few minutes.",
        429,
        username,
      )
    }
    False -> {
      let user = case users.get(ctx.users, username) {
        Ok(user) ->
          case pass != "" && password.verify(pass, user.password_hash) {
            True -> Ok(user)
            False -> Error(Nil)
          }
        Error(Nil) -> {
          password.dummy_verify()
          Error(Nil)
        }
      }
      case user {
        Ok(user) -> {
          ratelimit.reset(pair_key)
          log.info("login: " <> who)
          let user = rehash_if_needed(ctx, user, pass)
          let s =
            session.create(
              username,
              session.Local,
              ctx.config.admin.session_ttl,
              session.user_fingerprint(user.password_hash, user.updated_at),
            )
          let next = list.key_find(wisp.get_query(req), "next")
          wisp.redirect(safe_next(next))
          |> set_session_cookie(req, ctx, s)
        }
        Error(Nil) -> {
          ratelimit.record_failure(pair_key, login_window)
          ratelimit.record_failure(ip_key, login_window)
          ratelimit.record_failure(user_key, login_window)
          metrics.incr(metrics.LoginFailures)
          log.warning("failed login for user=" <> who)
          fail("Invalid username or password.", 401, username)
        }
      }
    }
  }
}

/// Re-hashes a password stored with fewer iterations than the current
/// default, now that it is known. Returns the user as stored.
fn rehash_if_needed(
  ctx: Context,
  user: users.User,
  pass: String,
) -> users.User {
  case password.needs_rehash(user.password_hash) {
    False -> user
    True -> {
      let stored =
        users.set_password(
          ctx.users,
          user.username,
          password.hash(pass),
          user.username,
        )
        |> result.try(fn(_) {
          users.get(ctx.users, user.username) |> result.replace_error("")
        })
      case stored {
        Ok(updated) -> updated
        Error(reason) -> {
          log.warning(
            "could not re-hash the password of "
            <> user.username
            <> ": "
            <> reason,
          )
          user
        }
      }
    }
  }
}

/// A user-supplied value in a log line: line breaks are escaped, so that a
/// crafted value cannot forge log lines.
fn log_value(value: String) -> String {
  ffi.escape_newlines(value)
}

/// Only allow local, absolute-path redirects after login (no open redirect).
fn safe_next(next: Result(String, Nil)) -> String {
  case next {
    Ok("/" <> rest) ->
      case string.starts_with(rest, "/") || string.starts_with(rest, "\\") {
        True -> "/rules"
        False -> "/" <> rest
      }
    _ -> "/rules"
  }
}

fn logout(req: Request, s: Session) -> Response {
  use _form <- require_csrf_form(req, s)
  session.destroy(s.token)
  log.info("logout: " <> s.username)
  wisp.redirect("/login")
  |> wisp.set_cookie(req, session_cookie, "", wisp.Signed, 0)
}

fn oidc_start(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  case oidc.begin(ctx.config.oidc, ctx.config.admin.public_url) {
    Ok(#(url, state)) ->
      wisp.redirect(url)
      |> wisp.set_cookie(
        req,
        oidc_state_cookie,
        state,
        wisp.Signed,
        oidc.flow_ttl,
      )
    Error(reason) -> {
      log.error("OIDC start failed: " <> reason)
      wisp.redirect(
        "/login?" <> uri.query_to_string([#("error", "sso_unavailable")]),
      )
    }
  }
}

fn oidc_callback(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  let outcome =
    oidc.complete(
      ctx.config.oidc,
      ctx.config.admin.public_url,
      wisp.get_query(req),
      wisp.get_cookie(req, oidc_state_cookie, wisp.Signed),
    )
  let clear_state = wisp.set_cookie(
    _,
    req,
    oidc_state_cookie,
    "",
    wisp.Signed,
    0,
  )
  case outcome {
    Ok(identity) -> {
      log.info(
        "SSO login: "
        <> log_value(identity.username)
        <> " ("
        <> log_value(identity.subject)
        <> ")",
      )
      let s =
        session.create(
          identity.username,
          session.Oidc,
          ctx.config.admin.session_ttl,
          "",
        )
      wisp.redirect("/rules")
      |> set_session_cookie(req, ctx, s)
      |> clear_state
    }
    Error(failure) -> {
      metrics.incr(metrics.LoginFailures)
      // provider errors and internal URLs stay in the log
      let #(logged, shown) = case failure {
        oidc.Denied(reason) -> #(reason, "Single sign-on failed: " <> reason)
        oidc.Failed(reason) -> #(
          reason,
          "Single sign-on failed. Try again, or contact your administrator if it keeps failing.",
        )
      }
      log.warning("SSO login rejected: " <> log_value(logged))
      html(
        403,
        pages.login(
          Some(shown),
          ctx.config.local_auth.enabled,
          sso_label(ctx),
          "",
        ),
      )
      |> clear_state
    }
  }
}

// --- redirections -----------------------------------------------------------

fn show_users(ctx: Context) -> Bool {
  ctx.config.local_auth.enabled
}

fn features(ctx: Context) -> layout.Features {
  layout.Features(
    users: ctx.config.local_auth.enabled,
    api: ctx.config.api.enabled,
  )
}

fn flash_from_query(req: Request) -> Option(layout.Flash) {
  let query = wisp.get_query(req)
  case list.key_find(query, "flash") {
    Ok("created") -> Some(layout.Success("Redirection created."))
    Ok("updated") -> Some(layout.Success("Redirection updated."))
    Ok("deleted") -> Some(layout.Success("Redirection deleted."))
    Ok("toggled") -> Some(layout.Success("Redirection updated."))
    Ok("reloaded") ->
      Some(layout.Success(
        "Reloaded "
        <> { list.key_find(query, "count") |> result.unwrap("0") }
        <> " redirection(s) from disk.",
      ))
    Ok("imported") ->
      Some(layout.Success(
        "Imported "
        <> { list.key_find(query, "count") |> result.unwrap("0") }
        <> " redirection(s).",
      ))
    Ok("user_created") -> Some(layout.Success("User created."))
    Ok("user_deleted") -> Some(layout.Success("User deleted."))
    Ok("password_changed") -> Some(layout.Success("Password changed."))
    Ok("client_deleted") ->
      Some(layout.Success("API client deleted; its tokens are revoked."))
    _ -> None
  }
}

fn list_rules(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
  let filters =
    rules_view.Filters(
      query: string.trim(get("q")),
      kind: get("kind"),
      status: get("status"),
      page: int.parse(get("page")) |> result.unwrap(1),
    )
  let all = store.all(ctx.store)
  let rows =
    all
    |> list.filter(matches_filters(_, filters))
    |> list.map(fn(r) { rules_view.Row(rule: r, hits: metrics.hits(r.id)) })
  html(
    200,
    rules_view.index(
      s,
      features(ctx),
      flash_from_query(req),
      rows,
      list.length(all),
      filters,
    ),
  )
}

fn matches_filters(r: Rule, f: rules_view.Filters) -> Bool {
  let needle = string.lowercase(f.query)
  let text_ok =
    needle == ""
    || list.any([r.host, r.source, r.target, r.note, r.id], fn(field) {
      string.contains(string.lowercase(field), needle)
    })
  let kind_ok = f.kind == "" || rule.kind_to_string(r.kind) == f.kind
  let status_ok = case f.status {
    "enabled" -> r.enabled
    "disabled" -> !r.enabled
    _ -> True
  }
  text_ok && kind_ok && status_ok
}

fn new_rule(_req: Request, ctx: Context, s: Session) -> Response {
  html(200, rules_view.form(s, features(ctx), rule.blank(), [], True, ""))
}

fn create_rule(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  case rule_from_form(form.values, rule.blank()) {
    Error(#(r, errors)) ->
      html(422, rules_view.form(s, features(ctx), r, errors, True, ""))
    Ok(r) ->
      case store.create(ctx.store, rule.Rule(..r, id: ""), s.username) {
        Ok(_) -> wisp.redirect("/rules?flash=created")
        Error(errors) ->
          html(422, rules_view.form(s, features(ctx), r, errors, True, ""))
      }
  }
}

fn edit_rule(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) ->
      html(
        200,
        rules_view.form(s, features(ctx), r, [], False, rule.version(r)),
      )
    Error(Nil) -> not_found(ctx, s)
  }
}

fn update_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use form <- require_csrf_form(req, s)
  let version = form_version(form.values)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(existing) -> {
      let render = fn(status, r, errors, version) {
        html(
          status,
          rules_view.form(s, features(ctx), r, errors, False, version),
        )
      }
      let submitted_version = option.unwrap(version, rule.version(existing))
      case rule_from_form(form.values, existing) {
        Error(#(r, errors)) -> render(422, r, errors, submitted_version)
        Ok(r) ->
          case store.update_versioned(ctx.store, r, version, s.username) {
            Ok(_) -> wisp.redirect("/rules?flash=updated")
            Error(store.NotFound) -> not_found(ctx, s)
            // Keep the submitted values; saving again overwrites knowingly.
            Error(store.Conflict(current)) ->
              render(
                409,
                r,
                [
                  conflict_message(current)
                  <> " Your changes are shown below; saving again replaces theirs.",
                ],
                rule.version(current),
              )
            Error(store.Invalid(errors)) ->
              render(422, r, errors, submitted_version)
          }
      }
    }
  }
}

fn confirm_delete(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) -> html(200, rules_view.confirm_delete(s, features(ctx), r))
    Error(Nil) -> not_found(ctx, s)
  }
}

fn delete_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use form <- require_csrf_form(req, s)
  let version = form_version(form.values)
  case store.delete_versioned(ctx.store, id, version, s.username) {
    Ok(_) -> wisp.redirect("/rules?flash=deleted")
    Error(store.Conflict(current)) ->
      error_page(
        ctx,
        s,
        409,
        "Not deleted",
        conflict_message(current) <> " Review it, then delete it again.",
      )
    Error(error) ->
      error_page(
        ctx,
        s,
        404,
        "Cannot delete",
        string.join(store.describe_change_error(error), " "),
      )
  }
}

fn toggle_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use form <- require_csrf_form(req, s)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(r) ->
      case
        store.update_versioned(
          ctx.store,
          rule.Rule(..r, enabled: !r.enabled),
          form_version(form.values),
          s.username,
        )
      {
        Ok(_) -> wisp.redirect("/rules?flash=toggled")
        Error(store.Conflict(current)) ->
          error_page(
            ctx,
            s,
            409,
            "Not changed",
            conflict_message(current) <> " Review it, then try again.",
          )
        Error(error) ->
          error_page(
            ctx,
            s,
            422,
            "Cannot update",
            string.join(store.describe_change_error(error), " "),
          )
      }
  }
}

/// The rule version a form was rendered from (`None` for old forms).
fn form_version(values: List(#(String, String))) -> Option(String) {
  case list.key_find(values, "version") |> result.map(string.trim) {
    Ok("") | Error(Nil) -> None
    Ok(version) -> Some(version)
  }
}

fn conflict_message(current: Rule) -> String {
  "This redirection was changed by "
  <> current.updated_by
  <> " at "
  <> current.updated_at
  <> " while you were working on it, so nothing was saved."
}

fn reload(req: Request, ctx: Context, s: Session) -> Response {
  use _form <- require_csrf_form(req, s)
  case store.reload(ctx.store, s.username) {
    Ok(count) ->
      wisp.redirect("/rules?flash=reloaded&count=" <> int.to_string(count))
    Error(reason) ->
      error_page(
        ctx,
        s,
        422,
        "Reload rejected",
        "The file on disk is invalid; the current redirections are kept. "
          <> reason,
      )
  }
}

/// Builds a rule from submitted form values on top of `base`.
pub fn rule_from_form(
  values: List(#(String, String)),
  base: Rule,
) -> Result(Rule, #(Rule, List(String))) {
  let get = fn(key) { list.key_find(values, key) |> result.unwrap("") }
  let checked = fn(key) { get(key) == "on" || get(key) == "true" }
  let kind = rule.kind_from_string(get("match"))
  let status = int.parse(string.trim(get("status")))
  let priority = case string.trim(get("priority")) {
    "" -> Ok(rule.default_priority)
    p -> int.parse(p)
  }
  let r =
    rule.Rule(
      ..base,
      host: get("host"),
      source: get("source"),
      kind: result.unwrap(kind, rule.Exact),
      target: get("target"),
      status: result.unwrap(status, 301),
      preserve_query: checked("preserve_query"),
      case_insensitive: checked("case_insensitive"),
      priority: result.unwrap(priority, rule.default_priority),
      enabled: checked("enabled"),
      note: get("note"),
    )
  let errors =
    list.flatten([
      case kind {
        Ok(_) -> []
        Error(_) -> ["match: must be exact, prefix or regex"]
      },
      case status {
        Ok(_) -> []
        Error(_) -> ["status: must be a number"]
      },
      case priority {
        Ok(_) -> []
        Error(_) -> ["priority: must be a number"]
      },
    ])
  case errors {
    [] ->
      case rule.validate(r) {
        Ok(valid) -> Ok(valid)
        Error(errors) -> Error(#(r, errors))
      }
    _ -> Error(#(r, errors))
  }
}

// --- tester -----------------------------------------------------------------

fn test_url(req: Request, ctx: Context, s: Session) -> Response {
  let url = list.key_find(wisp.get_query(req), "url") |> result.unwrap("")
  let result = case string.trim(url) {
    "" -> pages.NotTested
    url ->
      case matcher.resolve_url(snapshot.current(), url) {
        matcher.Redirected(m, location) -> pages.Matched(m.rule, location)
        matcher.NotMatched -> pages.NoMatch
        matcher.BadUrl -> pages.InvalidUrl
      }
  }
  html(200, pages.test_url(s, features(ctx), url, result))
}

// --- import / export --------------------------------------------------------

fn export(ctx: Context) -> Response {
  let body = store.export(store.all(ctx.store))
  wisp.ok()
  |> wisp.set_header("content-type", "application/json")
  |> wisp.file_download_from_memory(
    named: "redirects.json",
    containing: bytes_tree.from_string(body),
  )
}

fn import_page(req: Request, ctx: Context, s: Session) -> Response {
  html(200, pages.import_export(s, features(ctx), flash_from_query(req), []))
}

fn import_rules(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  let pasted = list.key_find(form.values, "content") |> result.unwrap("")
  let uploaded = case list.key_find(form.files, "file") {
    Ok(file) ->
      simplifile.read(file.path)
      |> result.unwrap("")
    Error(Nil) -> ""
  }
  let content = case string.trim(uploaded) {
    "" -> pasted
    _ -> uploaded
  }
  let mode = case list.key_find(form.values, "mode") {
    Ok("replace") -> store.Replace
    _ -> store.Merge
  }
  let fail = fn(errors) {
    html(422, pages.import_export(s, features(ctx), None, errors))
  }
  case string.trim(content) {
    "" -> fail(["Provide a JSON file or paste JSON content."])
    _ ->
      case rule.file_from_string(content) {
        Error(reason) -> fail([reason])
        Ok(incoming) ->
          case store.import_rules(ctx.store, incoming, mode, s.username) {
            Ok(count) ->
              wisp.redirect(
                "/rules?flash=imported&count=" <> int.to_string(count),
              )
            Error(errors) -> fail(errors)
          }
      }
  }
}

// --- users ------------------------------------------------------------------

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

fn list_users(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!show_users(ctx), fn() { not_found(ctx, s) })
  users_page(ctx, s, 200, flash_from_query(req), [])
}

fn create_user(req: Request, ctx: Context, s: Session) -> Response {
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

fn delete_user(
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

fn change_password(req: Request, ctx: Context, s: Session) -> Response {
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

// --- API clients ------------------------------------------------------------

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

fn api_clients_page(req: Request, ctx: Context, s: Session) -> Response {
  use <- bool.lazy_guard(!ctx.config.api.enabled, fn() { not_found(ctx, s) })
  render_api_clients(ctx, s, 200, flash_from_query(req), None, [])
}

fn create_api_client(req: Request, ctx: Context, s: Session) -> Response {
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

fn rotate_api_client(
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

fn delete_api_client(
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

// --- audit ------------------------------------------------------------------

fn audit_page(ctx: Context, s: Session) -> Response {
  let entries = audit.tail(config.audit_path(ctx.config), 200)
  html(200, pages.audit_log(s, features(ctx), entries))
}

// --- helpers ----------------------------------------------------------------

fn html(status: Int, body: String) -> Response {
  wisp.html_response(body, status)
  |> wisp.set_header("cache-control", "no-store")
}

fn plain(status: Int, body: String) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "text/plain; charset=utf-8")
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.string_body(body)
}

fn not_found(ctx: Context, s: Session) -> Response {
  error_page(ctx, s, 404, "Not found", "This page does not exist.")
}

fn error_page(
  ctx: Context,
  s: Session,
  status: Int,
  title: String,
  message: String,
) -> Response {
  html(status, pages.error(Some(s), features(ctx), title, message))
}
