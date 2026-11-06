//// Fixed-window failure counters used to throttle login attempts.

import gleam/int
import gleam/list
import gleam/result
import redirect_proxy/ffi

const table = "redirect_proxy_ratelimit"

pub fn init() -> Nil {
  ffi.ets_new(table)
}

/// True when `key` has reached `limit` failures in the current window.
pub fn is_blocked(key: String, limit: Int) -> Bool {
  blocked_for(key, limit) |> result.is_ok
}

/// The seconds left until `key` is no longer blocked.
pub fn blocked_for(key: String, limit: Int) -> Result(Int, Nil) {
  let now = ffi.now_seconds()
  case ffi.window_get(table, key) {
    Ok(#(window_end, count)) if window_end > now && count >= limit ->
      Ok(window_end - now)
    _ -> Error(Nil)
  }
}

/// The longest wait among the blocked `#(key, limit)` checks (for a
/// `Retry-After` header), or an error when none is blocked.
pub fn retry_after(checks: List(#(String, Int))) -> Result(Int, Nil) {
  checks
  |> list.filter_map(fn(check) { blocked_for(check.0, check.1) })
  |> list.max(int.compare)
}

/// Counts a failure, atomically: concurrent failures are all counted.
pub fn record_failure(key: String, window: Int) -> Nil {
  ffi.window_record(table, key, ffi.now_seconds(), window)
}

/// Counts one use of `key` when it is under `limit` in the current window:
/// True when it was, False (nothing counted) when the budget is spent.
pub fn take(key: String, limit: Int, window: Int) -> Bool {
  case is_blocked(key, limit) {
    True -> False
    False -> {
      record_failure(key, window)
      True
    }
  }
}

pub fn reset(key: String) -> Nil {
  ffi.ets_delete(table, key)
}

pub fn purge_expired() -> Int {
  ffi.window_purge(table, ffi.now_seconds())
}
