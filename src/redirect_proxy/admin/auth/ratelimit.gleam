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
  case ffi.ets_get(table, key) {
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

pub fn record_failure(key: String, window: Int) -> Nil {
  let now = ffi.now_seconds()
  let entry = case ffi.ets_get(table, key) {
    Ok(#(window_end, count)) if window_end > now -> #(window_end, count + 1)
    _ -> #(now + window, 1)
  }
  ffi.ets_put(table, key, entry)
}

pub fn reset(key: String) -> Nil {
  ffi.ets_delete(table, key)
}

pub fn purge_expired() -> Int {
  ffi.ets_delete_older(table, ffi.now_seconds())
}
