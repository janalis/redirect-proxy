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
import redirect_proxy/audit
import redirect_proxy/config.{type Config}
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

const login_ip_limit = 20

const login_user_limit = 10

const login_window = 900

pub type Context {
  Context(
    config: Config,
    store: Store,
    users: users.Settings,
    static_dir: String,
    /// TCP peer address of the current request.
    peer_ip: String,
  )
}

// --- entry point ------------------------------------------------------------

pub fn handle(req: Request, ctx: Context) -> Response {
  metrics.incr(metrics.AdminRequests)
  use <- security_headers
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  use <- wisp.serve_static(req, under: "/static", from: ctx.static_dir)
  use req <- wisp.csrf_known_header_protection(req)

  case req.method, wisp.path_segments(req) {
    // Public endpoints
    Get, ["healthz"] -> plain(200, "ok")
    Get, ["readyz"] -> plain(200, "ready")
    Get, ["metrics"] ->
      wisp.response(200)
      |> wisp.set_header("content-type", "text/plain; version=0.0.4")
      |> wisp.string_body(metrics.render_prometheus())
    Get, ["login"] -> login_page(req, ctx)
    Post, ["login"] -> login(req, ctx)
    Get, ["auth", "oidc", "start"] -> oidc_start(ctx)
    Get, ["auth", "oidc", "callback"] -> oidc_callback(req, ctx)
    Get, ["favicon.ico"] -> wisp.redirect("/static/favicon.svg")

    // Everything else requires an authenticated administrator
    _, _ -> authenticated(req, ctx)
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
    _, _ -> not_found(ctx, s)
  }
  set_cookie(resp)
}

// --- middleware -------------------------------------------------------------

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
  let from_cookie =
    wisp.get_cookie(req, session_cookie, wisp.Signed)
    |> result.try(session.get)
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

fn start_header_session(
  req: Request,
  ctx: Context,
  user: String,
  next: fn(Session, fn(Response) -> Response) -> Response,
) -> Response {
  log.info(
    "proxy-authenticated session for " <> user <> " from " <> ctx.peer_ip,
  )
  let s = session.create(user, session.Header, ctx.config.admin.session_ttl)
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
  token != "" && token == s.csrf_token
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
  case
    wisp.get_cookie(req, session_cookie, wisp.Signed) |> result.try(session.get)
  {
    Ok(_) -> wisp.redirect("/rules")
    Error(Nil) -> {
      let error =
        list.key_find(wisp.get_query(req), "error") |> option.from_result
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
  let ip_key = "login-ip:" <> ctx.peer_ip
  let user_key = "login-user:" <> username
  let fail = fn(message: String, status: Int) {
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

  case
    ratelimit.is_blocked(ip_key, login_ip_limit)
    || ratelimit.is_blocked(user_key, login_user_limit)
  {
    True -> {
      log.warning(
        "login throttled for user=" <> username <> " ip=" <> ctx.peer_ip,
      )
      fail("Too many failed attempts. Try again in a few minutes.", 429)
    }
    False -> {
      let verified = case users.get(ctx.users, username) {
        Ok(user) -> password.verify(pass, user.password_hash)
        Error(Nil) -> {
          password.dummy_verify()
          False
        }
      }
      case verified && pass != "" {
        True -> {
          ratelimit.reset(user_key)
          log.info("login: " <> username <> " from " <> ctx.peer_ip)
          let s =
            session.create(
              username,
              session.Local,
              ctx.config.admin.session_ttl,
            )
          let next = list.key_find(wisp.get_query(req), "next")
          wisp.redirect(safe_next(next))
          |> set_session_cookie(req, ctx, s)
        }
        False -> {
          ratelimit.record_failure(ip_key, login_window)
          ratelimit.record_failure(user_key, login_window)
          metrics.incr(metrics.LoginFailures)
          log.warning(
            "failed login for user=" <> username <> " ip=" <> ctx.peer_ip,
          )
          fail("Invalid username or password.", 401)
        }
      }
    }
  }
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

fn oidc_start(ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  case oidc.begin(ctx.config.oidc, ctx.config.admin.public_url) {
    Ok(url) -> wisp.redirect(url)
    Error(reason) -> {
      log.error("OIDC start failed: " <> reason)
      wisp.redirect(
        "/login?"
        <> uri.query_to_string([
          #("error", "Single sign-on is currently unavailable."),
        ]),
      )
    }
  }
}

fn oidc_callback(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  case
    oidc.complete(
      ctx.config.oidc,
      ctx.config.admin.public_url,
      wisp.get_query(req),
    )
  {
    Ok(identity) -> {
      log.info(
        "SSO login: " <> identity.username <> " (" <> identity.subject <> ")",
      )
      let s =
        session.create(
          identity.username,
          session.Oidc,
          ctx.config.admin.session_ttl,
        )
      wisp.redirect("/rules") |> set_session_cookie(req, ctx, s)
    }
    Error(reason) -> {
      metrics.incr(metrics.LoginFailures)
      log.warning("SSO login rejected: " <> reason)
      html(
        403,
        pages.login(
          Some("Single sign-on failed: " <> reason),
          ctx.config.local_auth.enabled,
          sso_label(ctx),
          "",
        ),
      )
    }
  }
}

// --- redirections -----------------------------------------------------------

fn show_users(ctx: Context) -> Bool {
  ctx.config.local_auth.enabled
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
      show_users(ctx),
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
  html(200, rules_view.form(s, show_users(ctx), rule.blank(), [], True))
}

fn create_rule(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  case rule_from_form(form.values, rule.blank()) {
    Error(#(r, errors)) ->
      html(422, rules_view.form(s, show_users(ctx), r, errors, True))
    Ok(r) ->
      case store.create(ctx.store, rule.Rule(..r, id: ""), s.username) {
        Ok(_) -> wisp.redirect("/rules?flash=created")
        Error(errors) ->
          html(422, rules_view.form(s, show_users(ctx), r, errors, True))
      }
  }
}

fn edit_rule(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) -> html(200, rules_view.form(s, show_users(ctx), r, [], False))
    Error(Nil) -> not_found(ctx, s)
  }
}

fn update_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use form <- require_csrf_form(req, s)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(existing) ->
      case rule_from_form(form.values, existing) {
        Error(#(r, errors)) ->
          html(422, rules_view.form(s, show_users(ctx), r, errors, False))
        Ok(r) ->
          case store.update(ctx.store, r, s.username) {
            Ok(_) -> wisp.redirect("/rules?flash=updated")
            Error(errors) ->
              html(422, rules_view.form(s, show_users(ctx), r, errors, False))
          }
      }
  }
}

fn confirm_delete(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) -> html(200, rules_view.confirm_delete(s, show_users(ctx), r))
    Error(Nil) -> not_found(ctx, s)
  }
}

fn delete_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use _form <- require_csrf_form(req, s)
  case store.delete(ctx.store, id, s.username) {
    Ok(_) -> wisp.redirect("/rules?flash=deleted")
    Error(reason) -> error_page(ctx, s, 404, "Cannot delete", reason)
  }
}

fn toggle_rule(req: Request, ctx: Context, s: Session, id: String) -> Response {
  use _form <- require_csrf_form(req, s)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(r) ->
      case
        store.update(ctx.store, rule.Rule(..r, enabled: !r.enabled), s.username)
      {
        Ok(_) -> wisp.redirect("/rules?flash=toggled")
        Error(errors) ->
          error_page(ctx, s, 422, "Cannot update", string.join(errors, " "))
      }
  }
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
      case uri.parse(url) {
        Ok(uri.Uri(host: Some(host), path: path, query: query, ..)) -> {
          let path = case path {
            "" -> "/"
            p -> p
          }
          case matcher.lookup(snapshot.current(), host, path) {
            Ok(m) ->
              pages.Matched(
                m.rule,
                matcher.location(m, option.to_result(query, Nil)),
              )
            Error(Nil) -> pages.NoMatch
          }
        }
        _ -> pages.InvalidUrl
      }
  }
  html(200, pages.test_url(s, show_users(ctx), url, result))
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
  html(200, pages.import_export(s, show_users(ctx), flash_from_query(req), []))
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
    html(422, pages.import_export(s, show_users(ctx), None, errors))
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
    Ok(all) -> html(status, pages.users(s, flash, all, errors))
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
      // Revoke other sessions of that user
      case username == s.username {
        True -> Nil
        False -> session.destroy_user(username)
      }
      wisp.redirect("/users?flash=password_changed")
    }
    Error(reason) -> users_page(ctx, s, 422, None, [reason])
  }
}

// --- audit ------------------------------------------------------------------

fn audit_page(ctx: Context, s: Session) -> Response {
  let entries = audit.tail(config.audit_path(ctx.config), 200)
  html(200, pages.audit_log(s, show_users(ctx), entries))
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
  html(status, pages.error(Some(s), show_users(ctx), title, message))
}
