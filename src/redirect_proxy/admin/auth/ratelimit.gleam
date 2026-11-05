//// Fixed-window failure counters used to throttle login attempts.

import redirect_proxy/ffi

const table = "redirect_proxy_ratelimit"

pub fn init() -> Nil {
  ffi.ets_new(table)
}

/// True when `key` has reached `limit` failures in the current window.
pub fn is_blocked(key: String, limit: Int) -> Bool {
  case ffi.ets_get(table, key) {
    Ok(#(window_end, count)) -> window_end > ffi.now_seconds() && count >= limit
    Error(Nil) -> False
  }
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
