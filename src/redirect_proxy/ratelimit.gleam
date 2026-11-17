//// Fixed-window failure counters and bounded work slots, shared by the
//// sign-in, API token and audit throttles.

import gleam/int
import gleam/list
import gleam/result
import redirect_proxy/ffi/ets as ets_ffi
import redirect_proxy/ffi/system as system_ffi

const table = "redirect_proxy_ratelimit"

/// Slots of work that runs a bounded number of times at once.
const slots = "redirect_proxy_slots"

pub type Receipt {
  Receipt(key: String, generation: Int)
}

/// Records an attempt that may later be refunded.
pub fn record(key: String, window: Int) -> Receipt {
  let assert Ok(generation) =
    ets_ffi.window_record_receipt(table, key, system_ffi.now_seconds(), window)
  Receipt(key, generation)
}

pub fn init() -> Nil {
  ets_ffi.ets_new(table)
  ets_ffi.ets_new(slots)
}

/// True when `key` has reached `limit` failures in the current window.
pub fn is_blocked(key: String, limit: Int) -> Bool {
  blocked_for(key, limit) |> result.is_ok
}

/// The seconds left until `key` is no longer blocked.
pub fn blocked_for(key: String, limit: Int) -> Result(Int, Nil) {
  let now = system_ffi.now_seconds()
  case ets_ffi.window_get(table, key) {
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
  ets_ffi.window_record(table, key, system_ffi.now_seconds(), window)
}

/// Counts one use of `key` when it is under `limit` in the current window:
/// True when it was, False (nothing counted) when the budget is spent.
pub fn take(key: String, limit: Int, window: Int) -> Bool {
  ets_ffi.window_take(table, key, system_ffi.now_seconds(), window, limit)
  |> result.is_ok
}

/// `take` for every `#(key, limit)` check, all or nothing: when one is spent,
/// the uses already counted are taken back and the longest wait is returned
/// (for a `Retry-After` header). Counting before the work, not after it
/// failed, is what keeps concurrent attempts within the limits.
pub fn take_all(
  checks: List(#(String, Int)),
  window: Int,
) -> Result(List(Receipt), Int) {
  do_take_all(checks, window, system_ffi.now_seconds(), [])
}

fn do_take_all(
  checks: List(#(String, Int)),
  window: Int,
  now: Int,
  taken: List(Receipt),
) -> Result(List(Receipt), Int) {
  case checks {
    [] -> Ok(list.reverse(taken))
    [#(key, limit), ..rest] ->
      case ets_ffi.window_take_receipt(table, key, now, window, limit) {
        Ok(generation) ->
          do_take_all(rest, window, now, [Receipt(key, generation), ..taken])
        Error(seconds) -> {
          list.each(taken, forgive)
          Error(
            retry_after(rest)
            |> result.map(int.max(_, seconds))
            |> result.unwrap(seconds),
          )
        }
      }
  }
}

/// Takes back a use counted by `take_all` or `record`, only while the
/// receipt's original window still exists.
pub fn forgive(receipt: Receipt) -> Nil {
  ets_ffi.window_forgive(table, receipt.key, receipt.generation)
}

/// Runs `work` unless `max` runs of the `name` work are already under way:
/// an error then, at once (for a 503), rather than a queue.
pub fn bounded(name: String, max: Int, work: fn() -> a) -> Result(a, Nil) {
  ets_ffi.with_slot(slots, name, max, work)
}

pub fn reset(key: String) -> Nil {
  ets_ffi.ets_delete(table, key)
}

pub fn purge_expired() -> Int {
  ets_ffi.window_purge(table, system_ffi.now_seconds())
}
