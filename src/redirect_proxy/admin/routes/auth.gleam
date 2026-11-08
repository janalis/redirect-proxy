//// Sign-in: sessions, local login, single sign-on, proxy headers, logout.

import gleam/bool
import gleam/http.{Get}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/header
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/login as login_view
import redirect_proxy/admin/web.{
  type Context, form_value, html, known_device, log_value,
  oidc_state_cookie_name, require_csrf_form, session_cookie_name,
  set_device_cookie, set_session_cookie,
} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import wisp.{type Request, type Response}

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

/// SSO logins started from one address in a window. A login in progress is
/// kept by the browser, not here: this only bounds what one address makes
/// the provider's discovery and the log go through.
const sso_start_ip_limit = 30

/// Failed SSO callbacks from one address in a window.
const sso_callback_ip_limit = 20

/// Resolves the current session from the session cookie, or from trusted
/// proxy headers. `next` receives the session and a function that must be
/// applied to the response (it may set a fresh session cookie).
pub fn require_session(
  req: Request,
  ctx: Context,
  next: fn(Session, fn(Response) -> Response) -> Response,
) -> Response {
  let from_cookie = current_session(req, ctx)
  let proxy_user = header.identify(ctx.config.header_auth, req, ctx.peer_ip)

  // the name a header session acts as, to compare with the cookie's session
  let proxy_actor =
    result.map(proxy_user, session.actor(session.Header, _))
    |> result.unwrap("")
  let proxy_role = header.role(ctx.config.header_auth, req)
  case from_cookie, proxy_user {
    // Header auth: the proxy is authoritative, the session must follow it
    // (the user and their role).
    Ok(s), Ok(user)
      if s.method == session.Header
      && { s.username != proxy_actor || s.role != proxy_role }
    -> {
      session.destroy(s.token)
      start_header_session(req, ctx, user, next)
    }
    // ... and ends when the proxy no longer vouches for the user (signed out
    // there, or the cookie replayed past the proxy)
    Ok(s), Error(Nil) if s.method == session.Header -> {
      session.destroy(s.token)
      unauthenticated(req)
    }
    Ok(s), _ -> next(s, fn(resp) { resp })
    Error(Nil), Ok(user) -> start_header_session(req, ctx, user, next)
    Error(Nil), Error(Nil) -> unauthenticated(req)
  }
}

fn unauthenticated(req: Request) -> Response {
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

/// The live session of the request's cookie. A local account's session ends
/// once the user is deleted or changes password, including from the CLI,
/// which runs in another process and cannot reach this server's sessions.
fn current_session(req: Request, ctx: Context) -> Result(Session, Nil) {
  use token <- result.try(wisp.get_cookie(
    req,
    session_cookie_name(req, ctx),
    wisp.Signed,
  ))
  use s <- result.try(session.get(token, ctx.config.admin.session_idle_timeout))
  case s.method {
    session.Local ->
      case users.get(ctx.users, s.username) {
        Ok(user) ->
          case
            session.user_fingerprint(user.password_hash, user.updated_at)
            == s.fingerprint
          {
            // the role as stored now: a demotion applies at once
            True -> Ok(session.Session(..s, role: user.role))
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
  let #(s, created) =
    session.header_session(
      user,
      header.role(ctx.config.header_auth, req),
      ctx.config.admin.session_ttl,
      ctx.config.admin.session_idle_timeout,
    )
  case created {
    True -> {
      log.info(
        "proxy-authenticated session for "
        <> log_value(user)
        <> " from "
        <> ctx.peer_ip,
      )
      audit_auth(ctx, s.username, "auth.login", "proxy")
    }
    False -> Nil
  }
  next(s, set_session_cookie(_, req, ctx, s))
}

fn sso_label(ctx: Context) -> Option(String) {
  case ctx.config.oidc.enabled {
    True -> Some(ctx.config.oidc.button_label)
    False -> None
  }
}

pub fn login_page(req: Request, ctx: Context) -> Response {
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
        login_view.login(
          error,
          ctx.config.local_auth.enabled,
          sso_label(ctx),
          "",
          next_param(req),
        ),
      )
    }
  }
}

/// Starts a password check (login form, or the current password asked by
/// the change-password form, so that a stolen session gets no more guesses
/// than the login form gives). It is counted as a failure for the client,
/// the address and the account before the password is hashed: checked and
/// counted in one step, so that concurrent attempts cannot all pass the
/// limits. `Error` holds the seconds to wait while blocked. A started check
/// ends with `end_password_check`.
pub fn start_password_check(
  req: Request,
  ctx: Context,
  username: String,
) -> Result(Nil, Int) {
  let known = known_device(req, ctx, username)
  use Nil <- result.try(ratelimit.take_all(
    login_checks(ctx.client_ip, username, known),
    login_window,
  ))
  // a known device is not held back by the account's limit, but its
  // failures count towards it
  case known {
    True -> ratelimit.record_failure(login_user_check(username).0, login_window)
    False -> Nil
  }
  Ok(Nil)
}

pub type PasswordCheck {
  /// The password was right: the attempt is taken back, and the client's
  /// earlier failures forgiven.
  Passed
  /// The password was wrong: the attempt stays counted.
  Failed
  /// The password was not checked (the server was busy).
  NotRun
}

pub fn end_password_check(
  ctx: Context,
  username: String,
  outcome: PasswordCheck,
) -> Nil {
  let pair_key = login_pair_key(ctx.client_ip, username)
  let others = [login_ip_key(ctx.client_ip), login_user_check(username).0]
  case outcome {
    Failed -> metrics.incr(metrics.LoginFailures)
    Passed -> {
      ratelimit.reset(pair_key)
      list.each(others, ratelimit.forgive)
    }
    NotRun -> list.each([pair_key, ..others], ratelimit.forgive)
  }
}

/// Runs a password hash (`password.verify`, `password.dummy_verify`) unless
/// as many as the server allows are already running: each one takes a CPU
/// for a fraction of a second, and a burst of logins must not starve the
/// redirect listener. `Error` when busy: answer 503.
pub fn hashing_password(work: fn() -> a) -> Result(a, Nil) {
  ratelimit.bounded("password", ffi.password_check_slots(), work)
}

pub fn record_password_check(ctx: Context, username: String, ok: Bool) -> Nil {
  case ok {
    True -> end_password_check(ctx, username, Passed)
    False -> {
      end_password_check(ctx, username, Failed)
      log.warning(
        "wrong current password for user="
        <> log_value(username)
        <> " ip="
        <> ctx.client_ip,
      )
    }
  }
}

fn login_pair_key(ip: String, username: String) -> String {
  "login:" <> ffi.throttle_address(ip) <> " " <> username
}

fn login_ip_key(ip: String) -> String {
  "login-ip:" <> ffi.throttle_address(ip)
}

/// The limits a login attempt is checked against. A browser where the
/// account signed in before (`known_device`) is not held back by the
/// account's limit, which failures from anywhere count towards.
fn login_checks(
  ip: String,
  username: String,
  known_device: Bool,
) -> List(#(String, Int)) {
  let checks = [
    #(login_pair_key(ip, username), login_pair_limit),
    #(login_ip_key(ip), login_ip_limit),
  ]
  case known_device {
    True -> checks
    False -> [login_user_check(username), ..checks]
  }
}

fn login_user_check(username: String) -> #(String, Int) {
  #("login-user:" <> username, login_user_limit)
}

pub fn login(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.local_auth.enabled, fn() {
    wisp.not_found()
  })
  use form <- wisp.require_form(req)
  let username =
    form_value(form, "username")
    |> users.normalise
  let pass = form_value(form, "password")
  let fail = fn(message: String, status: Int, username: String) {
    html(
      status,
      login_view.login(
        Some(message),
        ctx.config.local_auth.enabled,
        sso_label(ctx),
        username,
        next_param(req),
      ),
    )
  }
  let ip_key = login_ip_key(ctx.client_ip)
  use <- bool.lazy_guard(string.byte_size(username) > max_username_bytes, fn() {
    ratelimit.record_failure(ip_key, login_window)
    fail("Invalid username or password.", 401, "")
  })
  let who = log_value(username) <> " ip=" <> ctx.client_ip

  case start_password_check(req, ctx, username) {
    Error(seconds) -> {
      log.warning("login throttled for user=" <> who)
      audit_once_per_window(ctx.client_ip, seconds, fn() {
        audit_auth(ctx, username, "auth.throttled", "local")
      })
      fail(
        "Too many failed attempts. Try again in a few minutes.",
        429,
        username,
      )
      |> wisp.set_header("retry-after", int.to_string(seconds))
    }
    Ok(Nil) -> {
      let checked =
        hashing_password(fn() {
          case users.get(ctx.users, username) {
            Ok(user) ->
              case pass {
                // as slow as a wrong password: the timing must not tell that
                // the user exists
                "" -> {
                  password.dummy_verify()
                  Error(Nil)
                }
                _ ->
                  case password.verify(pass, user.password_hash) {
                    True -> Ok(user)
                    False -> Error(Nil)
                  }
              }
            Error(Nil) -> {
              password.dummy_verify()
              Error(Nil)
            }
          }
        })
      case checked {
        Error(Nil) -> {
          end_password_check(ctx, username, NotRun)
          log.warning("login refused, too many password checks running")
          fail("The server is busy. Try again in a moment.", 503, username)
          |> wisp.set_header("retry-after", "1")
        }
        Ok(Ok(user)) -> {
          end_password_check(ctx, username, Passed)
          log.info("login: " <> who)
          audit_auth(ctx, username, "auth.login", "local")
          let user = rehash_if_needed(ctx, user, pass)
          let s =
            session.create(
              username,
              session.Local,
              ctx.config.admin.session_ttl,
              session.user_fingerprint(user.password_hash, user.updated_at),
              user.role,
            )
          let next = list.key_find(wisp.get_query(req), "next")
          wisp.redirect(safe_next(next))
          |> set_session_cookie(req, ctx, s)
          |> set_device_cookie(req, ctx, user.username)
        }
        Ok(Error(Nil)) -> {
          end_password_check(ctx, username, Failed)
          log.warning("failed login for user=" <> who)
          audit_login_failure(
            ctx,
            "local",
            case users.validate_username(username) {
              Ok(Nil) -> #(username, [])
              // not a possible account: the name typed goes in the details,
              // so that it cannot pass for an actor (`system`, `sso:...`)
              Error(_) -> #("", [#("username", json.string(username))])
            },
          )
          fail("Invalid username or password.", 401, username)
        }
      }
    }
  }
}

/// Re-hashes a password stored with fewer iterations than the current
/// default, now that it is known. Returns the user as stored, or as it was
/// checked when its password changed meanwhile: the session then belongs to
/// the old password, and ends at once.
fn rehash_if_needed(
  ctx: Context,
  user: users.User,
  pass: String,
) -> users.User {
  case password.needs_rehash(user.password_hash) {
    False -> user
    True -> {
      let stored =
        users.rehash_password(
          ctx.users,
          user.username,
          user.password_hash,
          password.hash(pass),
        )
        |> result.try(fn(rehashed) {
          case rehashed {
            False -> Ok(user)
            True ->
              users.get(ctx.users, user.username) |> result.replace_error("")
          }
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

/// Records a sign-in event in the audit trail, with the client address.
fn audit_auth(ctx: Context, actor: String, action: String, method: String) {
  audit_auth_with(ctx, actor, action, method, [])
}

/// A failed sign-in: needs no credentials, so it goes through the audit
/// log's budget for failures (`audit.record_failure`).
fn audit_login_failure(
  ctx: Context,
  method: String,
  who: #(String, List(#(String, json.Json))),
) -> Nil {
  let #(actor, details) = who
  audit.record_failure(
    config.audit_path(ctx.config),
    actor,
    "auth.login_failed",
    method,
    json.object([#("client_ip", json.string(ctx.client_ip)), ..details]),
  )
}

fn audit_auth_with(
  ctx: Context,
  actor: String,
  action: String,
  method: String,
  details: List(#(String, json.Json)),
) {
  audit.record(
    config.audit_path(ctx.config),
    actor,
    action,
    method,
    None,
    Some(json.object([#("client_ip", json.string(ctx.client_ip)), ..details])),
  )
}

/// The `next` query parameter of the login page ("" when absent), passed on
/// to the SSO link.
fn next_param(req: Request) -> String {
  list.key_find(wisp.get_query(req), "next") |> result.unwrap("")
}

/// Only allow local, absolute-path redirects after login (no open redirect).
/// Control characters are refused anywhere: browsers drop tabs and newlines
/// when they parse a `Location` (`/\t/evil` becomes `//evil`), and CR/LF
/// would split the response headers. `\` is refused anywhere too, browsers
/// read it as `/`.
fn safe_next(next: Result(String, Nil)) -> String {
  case next {
    Ok("/" <> rest) ->
      case
        string.starts_with(rest, "/")
        || string.contains(rest, "\\")
        || has_control_character(rest)
      {
        True -> "/rules"
        False -> "/" <> rest
      }
    _ -> "/rules"
  }
}

/// C0 controls, DEL and C1 controls.
fn has_control_character(value: String) -> Bool {
  string.to_utf_codepoints(value)
  |> list.any(fn(c) {
    let n = string.utf_codepoint_to_int(c)
    n < 0x20 || { n >= 0x7f && n <= 0x9f }
  })
}

pub fn logout(req: Request, ctx: Context, s: Session) -> Response {
  use _form <- require_csrf_form(req, s)
  session.destroy(s.token)
  log.info("logout: " <> s.username)
  audit_auth(ctx, s.username, "auth.logout", session.method_to_string(s.method))
  wisp.redirect(after_logout(ctx, s))
  |> wisp.set_cookie(req, session_cookie_name(req, ctx), "", wisp.Signed, 0)
}

/// The login page, or for an SSO session with `logout_at_provider`, the
/// provider's logout endpoint, which sends the browser back to the login
/// page.
fn after_logout(ctx: Context, s: Session) -> String {
  let cfg = ctx.config.oidc
  let login = "/login"
  case s.method == session.Oidc && cfg.enabled && cfg.logout_at_provider {
    False -> login
    True ->
      case oidc.end_session_url(cfg, ctx.config.admin.public_url) {
        Ok(url) -> url
        Error(reason) -> {
          log.warning("SSO logout at the provider skipped: " <> reason)
          login
        }
      }
  }
}

pub fn oidc_start(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  let start_key = "sso-start-ip:" <> ffi.throttle_address(ctx.client_ip)
  use <- sso_throttle(ctx, start_key, sso_start_ip_limit)
  ratelimit.record_failure(start_key, login_window)
  let next = safe_next(list.key_find(wisp.get_query(req), "next"))
  case oidc.begin(ctx.config.oidc, ctx.config.admin.public_url, next) {
    Ok(#(url, flow)) ->
      wisp.redirect(url)
      |> wisp.set_cookie(
        req,
        oidc_state_cookie_name(req, ctx),
        flow,
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

pub fn oidc_callback(req: Request, ctx: Context) -> Response {
  use <- bool.lazy_guard(!ctx.config.oidc.enabled, fn() { wisp.not_found() })
  let failure_key = "sso-callback-ip:" <> ffi.throttle_address(ctx.client_ip)
  use <- sso_throttle(ctx, failure_key, sso_callback_ip_limit)
  let outcome =
    oidc.complete(
      ctx.config.oidc,
      ctx.config.admin.public_url,
      wisp.get_query(req),
      wisp.get_cookie(req, oidc_state_cookie_name(req, ctx), wisp.Signed),
    )
  let clear_state = wisp.set_cookie(
    _,
    req,
    oidc_state_cookie_name(req, ctx),
    "",
    wisp.Signed,
    0,
  )
  case outcome {
    Ok(#(identity, next)) -> {
      log.info(
        "SSO login: "
        <> log_value(identity.username)
        <> " ("
        <> log_value(identity.subject)
        <> ")",
      )
      let granted = oidc.role_for(ctx.config.oidc, identity)
      // the username may be editable at the provider: keep who it really is;
      // the role comes from the provider's groups at this sign-in
      audit_auth_with(
        ctx,
        session.actor(session.Oidc, identity.username),
        "auth.login",
        "sso",
        [
          #("issuer", json.string(ctx.config.oidc.issuer)),
          #("subject", json.string(identity.subject)),
          #("role", json.string(role.to_string(granted))),
        ],
      )
      let s =
        session.create(
          identity.username,
          session.Oidc,
          ctx.config.admin.session_ttl,
          "",
          granted,
        )
      // checked by `safe_next` when the login started
      wisp.redirect(next)
      |> set_session_cookie(req, ctx, s)
      |> clear_state
    }
    Error(failure) -> {
      ratelimit.record_failure(failure_key, login_window)
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
      audit_login_failure(
        ctx,
        "sso",
        #("", [
          #(
            "reason",
            json.string(case failure {
              oidc.Denied(reason) -> reason
              oidc.Failed(_) -> "provider error (see the server log)"
            }),
          ),
        ]),
      )
      html(
        403,
        login_view.login(
          Some(shown),
          ctx.config.local_auth.enabled,
          sso_label(ctx),
          "",
          "",
        ),
      )
      |> clear_state
    }
  }
}

/// Answers 429 while `key` is blocked. The audit log records it once per
/// window and address, so that an anonymous loop cannot flood it.
fn sso_throttle(
  ctx: Context,
  key: String,
  limit: Int,
  next: fn() -> Response,
) -> Response {
  case ratelimit.blocked_for(key, limit) {
    Error(Nil) -> next()
    Ok(seconds) -> {
      log.warning("SSO throttled for ip=" <> ctx.client_ip)
      audit_once_per_window(ctx.client_ip, seconds, fn() {
        audit_auth(ctx, "", "auth.throttled", "sso")
      })
      html(
        429,
        login_view.login(
          Some("Too many sign-in attempts. Try again in a few minutes."),
          ctx.config.local_auth.enabled,
          sso_label(ctx),
          "",
          "",
        ),
      )
      |> wisp.set_header("retry-after", int.to_string(seconds))
    }
  }
}

/// Runs `write` (an audit entry about throttling) at most once per address
/// while it stays throttled.
fn audit_once_per_window(client_ip: String, seconds: Int, write: fn() -> Nil) {
  let key = "throttle-audited:" <> ffi.throttle_address(client_ip)
  case ratelimit.is_blocked(key, 1) {
    True -> Nil
    False -> {
      ratelimit.record_failure(key, seconds)
      write()
    }
  }
}
