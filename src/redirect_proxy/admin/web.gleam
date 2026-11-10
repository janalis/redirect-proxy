//// Shared pieces of the administration backend: request context, security
//// headers, body limits, session cookies, CSRF checks and responses.

import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/api/clients
import redirect_proxy/config.{type Config}
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/store.{type Store}
import redirect_proxy/users
import wisp.{type Request, type Response}

pub const session_cookie = "rp_session"

/// With the `__Host-` prefix, browsers only accept the cookie when it is
/// `Secure`, set by this host (no `Domain`) for every path, so that a
/// sibling subdomain cannot set or shadow it.
const secure_session_cookie = "__Host-rp_session"

/// The session cookie name: prefixed when the admin is served over HTTPS and
/// the cookie is `Secure` (wisp sends it without `Secure` only for plain
/// HTTP on localhost).
pub fn session_cookie_name(req: Request, ctx: Context) -> String {
  case host_prefixed(req, ctx) {
    True -> secure_session_cookie
    False -> session_cookie
  }
}

/// Binds an SSO login in progress to the browser that started it. Prefixed
/// like the session cookie, so that a sibling subdomain cannot plant its own
/// login attempt in a victim's browser (login CSRF).
pub fn oidc_state_cookie_name(req: Request, ctx: Context) -> String {
  case host_prefixed(req, ctx) {
    True -> "__Host-" <> oidc_state_cookie
    False -> oidc_state_cookie
  }
}

const oidc_state_cookie = "rp_oidc_state"

/// Marks a browser where an account signed in with its password. Failed
/// logins from anywhere can block an account; this browser is let through
/// that limit (still not past the limits of its own address), so that
/// guessing a password cannot lock its owner out (OWASP "device cookies").
/// Signed, so that it cannot be made up.
const device_cookie = "rp_device"

/// How long a browser stays known after a sign-in, in seconds (90 days).
const device_cookie_max_age = 7_776_000

fn device_cookie_name(req: Request, ctx: Context) -> String {
  case host_prefixed(req, ctx) {
    True -> "__Host-" <> device_cookie
    False -> device_cookie
  }
}

/// True when this browser signed in as `username` with its password before.
pub fn known_device(req: Request, ctx: Context, username: String) -> Bool {
  wisp.get_cookie(req, device_cookie_name(req, ctx), wisp.Signed)
  == Ok(username)
}

pub fn set_device_cookie(
  resp: Response,
  req: Request,
  ctx: Context,
  username: String,
) -> Response {
  wisp.set_cookie(
    resp,
    req,
    device_cookie_name(req, ctx),
    username,
    wisp.Signed,
    device_cookie_max_age,
  )
}

fn host_prefixed(req: Request, ctx: Context) -> Bool {
  let local_http =
    req.scheme == http.Http
    && list.contains(["localhost", "127.0.0.1", "[::1]"], req.host)
    && result.is_error(request.get_header(req, "x-forwarded-proto"))
  https_admin(ctx) && !local_http
}

fn https_admin(ctx: Context) -> Bool {
  string.starts_with(string.lowercase(ctx.config.admin.public_url), "https://")
}

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

/// Admin forms are small: anything larger is refused before it is read, so
/// that unauthenticated requests (login) cannot make the server buffer
/// megabytes. Imports carry a rules file and get the API's limit.
const max_form_bytes = 65_536

pub fn limit_body(req: Request, ctx: Context) -> Request {
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

/// When the admin is served over HTTPS, browsers must not fall back to HTTP.
pub fn strict_transport_security(
  ctx: Context,
  next: fn() -> Response,
) -> Response {
  case https_admin(ctx) {
    True ->
      next()
      |> wisp.set_header("strict-transport-security", "max-age=31536000")
    False -> next()
  }
}

pub fn security_headers(next: fn() -> Response) -> Response {
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

/// Sets the cookie of session `s`, ending the session the browser held
/// until then (an earlier login's would otherwise stay valid until it
/// expires).
pub fn set_session_cookie(
  resp: Response,
  req: Request,
  ctx: Context,
  s: Session,
) -> Response {
  let name = session_cookie_name(req, ctx)
  case wisp.get_cookie(req, name, wisp.Signed) {
    Ok(old) if old != s.token -> session.destroy(old)
    _ -> Nil
  }
  wisp.set_cookie(
    resp,
    req,
    name,
    s.token,
    wisp.Signed,
    ctx.config.admin.session_ttl,
  )
}

/// Where to go back after an action on the rules list, keeping its filters,
/// sort and page: `return_to` when it is a local `/rules` URL, otherwise
/// `/rules`, with `flash` set (and any previous flash parameters dropped).
pub fn return_to(value: String, flash: List(#(String, String))) -> String {
  let #(path, query) = case string.split_once(value, "?") {
    Ok(#(path, query)) -> #(path, query)
    Error(Nil) -> #(value, "")
  }
  let path = case path == "/rules" {
    True -> path
    False -> "/rules"
  }
  let kept =
    uri.parse_query(query)
    |> result.unwrap([])
    |> list.filter(fn(kv) { kv.0 != "flash" && kv.0 != "count" && kv.0 != "id" })
  path <> "?" <> uri.query_to_string(list.append(kept, flash))
}

/// A form field, "" when absent.
pub fn form_value(form: wisp.FormData, name: String) -> String {
  list.key_find(form.values, name) |> result.unwrap("")
}

/// Parses the form and verifies the CSRF token of the session.
pub fn require_csrf_form(
  req: Request,
  s: Session,
  next: fn(wisp.FormData) -> Response,
) -> Response {
  use form <- wisp.require_form(req)
  let token = form_value(form, "csrf_token")
  case session_token_matches(s, token) {
    True -> next(form)
    False -> {
      log.warning("CSRF token mismatch for " <> log_value(s.username))
      wisp.response(403) |> wisp.string_body("Invalid CSRF token")
    }
  }
}

fn session_token_matches(s: Session, token: String) -> Bool {
  token != "" && ffi.secure_compare(<<token:utf8>>, <<s.csrf_token:utf8>>)
}

/// A user-supplied value in a log line: line breaks are escaped, so that a
/// crafted value cannot forge log lines.
pub fn log_value(value: String) -> String {
  ffi.escape_newlines(value)
}

pub fn show_users(ctx: Context) -> Bool {
  ctx.config.local_auth.enabled
}

pub fn features(ctx: Context) -> layout.Features {
  layout.Features(
    users: ctx.config.local_auth.enabled,
    api: ctx.config.api.enabled,
  )
}

pub fn flash_from_query(req: Request) -> Option(layout.Flash) {
  let query = wisp.get_query(req)
  // a number, never text from the link
  let count =
    list.key_find(query, "count")
    |> result.try(int.parse)
    |> result.unwrap(0)
    |> int.to_string
  case list.key_find(query, "flash") {
    Ok("bulk") ->
      Some(layout.Success("Changed " <> count <> " redirection(s)."))
    Ok("created") -> Some(layout.Success("Redirection created."))
    Ok("updated") -> Some(layout.Success("Redirection updated."))
    Ok("deleted") -> Some(layout.Success("Redirection deleted."))
    Ok("toggled") -> Some(layout.Success("Redirection updated."))
    Ok("enabled") -> Some(layout.Success("Redirection enabled."))
    Ok("disabled") -> Some(layout.Success("Redirection disabled."))
    Ok("reloaded") ->
      Some(layout.Success("Reloaded " <> count <> " redirection(s) from disk."))
    Ok("imported") ->
      Some(layout.Success("Imported " <> count <> " redirection(s)."))
    Ok("user_created") -> Some(layout.Success("User created."))
    Ok("user_deleted") -> Some(layout.Success("User deleted."))
    Ok("password_changed") -> Some(layout.Success("Password changed."))
    Ok("role_changed") -> Some(layout.Success("Role changed."))
    Ok("client_deleted") ->
      Some(layout.Success("API client deleted; its tokens are revoked."))
    _ -> None
  }
}

pub fn html(status: Int, body: String) -> Response {
  wisp.html_response(body, status)
  |> wisp.set_header("cache-control", "no-store")
}

pub fn plain(status: Int, body: String) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "text/plain; charset=utf-8")
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.string_body(body)
}

pub fn not_found(ctx: Context, s: Session) -> Response {
  error_page(ctx, s, 404, "Not found", "This page does not exist.")
}

pub fn error_page(
  ctx: Context,
  s: Session,
  status: Int,
  title: String,
  message: String,
) -> Response {
  html(status, pages.error(Some(s), features(ctx), title, message))
}
