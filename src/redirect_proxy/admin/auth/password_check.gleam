//// Password checks of the admin (the login form, and the current password
//// asked to change one): throttled per client, address and account, and
//// bounded in how many hashes run at once.

import gleam/json
import gleam/list
import gleam/result
import redirect_proxy/admin/web.{type Context, known_device, log_value} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/ratelimit
import wisp.{type Request}

/// Failed logins allowed per window for one account from one client, for
/// one client (all accounts), and for one account (all clients). The last
/// one bounds distributed guessing without letting anyone lock a user out
/// cheaply.
const login_pair_limit = 10

const login_ip_limit = 20

const login_user_limit = 100

/// Seconds a failed attempt counts for (the SSO limits use it too).
pub const login_window = 900

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
) -> Result(List(ratelimit.Receipt), Int) {
  let known = known_device(req, ctx, username)
  use receipts <- result.try(ratelimit.take_all(
    login_checks(ctx.client_ip, username, known),
    login_window,
  ))
  // a known device is not held back by the account's limit, but its
  // failures count towards it
  let receipts = case known {
    True -> [
      ratelimit.record(login_user_check(username).0, login_window),
      ..receipts
    ]
    False -> receipts
  }
  Ok(receipts)
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
  receipts: List(ratelimit.Receipt),
  outcome: PasswordCheck,
) -> Nil {
  let pair_key = login_pair_key(ctx.client_ip, username)
  let others = list.filter(receipts, fn(receipt) { receipt.key != pair_key })
  case outcome {
    Failed -> metrics.incr(metrics.LoginFailures)
    Passed -> {
      ratelimit.reset(pair_key)
      list.each(others, ratelimit.forgive)
    }
    NotRun -> list.each(receipts, ratelimit.forgive)
  }
}

/// Runs a password hash (`password.verify`, `password.dummy_verify`) unless
/// as many as the server allows are already running: each one takes a CPU
/// for a fraction of a second, and a burst of logins must not starve the
/// redirect listener. `Error` when busy: answer 503.
pub fn hashing_password(work: fn() -> a) -> Result(a, Nil) {
  ratelimit.bounded("password", ffi.password_check_slots(), work)
}

pub fn record_password_check(
  ctx: Context,
  username: String,
  receipts: List(ratelimit.Receipt),
  ok: Bool,
) -> Nil {
  case ok {
    True -> end_password_check(ctx, username, receipts, Passed)
    False -> {
      end_password_check(ctx, username, receipts, Failed)
      // a stolen session guessing the password: audited like a failed
      // sign-in, within the same budget
      audit.record_failure(
        config.audit_path(ctx.config),
        username,
        "auth.password_check_failed",
        "local",
        json.object([#("client_ip", json.string(ctx.client_ip))]),
      )
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

pub fn login_ip_key(ip: String) -> String {
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
