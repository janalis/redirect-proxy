import gleam/erlang/process
import gleam/int
import gleam/list
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/ffi

fn key(name: String) -> String {
  name <> "-" <> int.to_string(ffi.now_micros())
}

pub fn blocks_at_the_limit_and_resets_test() {
  ratelimit.init()
  let k = key("limit")
  ratelimit.record_failure(k, 60)
  ratelimit.record_failure(k, 60)
  assert !ratelimit.is_blocked(k, 3)
  ratelimit.record_failure(k, 60)
  assert ratelimit.is_blocked(k, 3)
  let assert Ok(wait) = ratelimit.blocked_for(k, 3)
  assert wait > 0 && wait <= 60
  assert ratelimit.retry_after([#(k, 3), #(key("other"), 1)]) == Ok(wait)
  ratelimit.reset(k)
  assert !ratelimit.is_blocked(k, 1)
}

/// An ended window starts over instead of adding to the old count.
pub fn an_ended_window_starts_over_test() {
  ratelimit.init()
  let k = key("window")
  // a window of 0 seconds has ended by the next failure
  ratelimit.record_failure(k, 0)
  ratelimit.record_failure(k, 0)
  ratelimit.record_failure(k, 60)
  assert !ratelimit.is_blocked(k, 2)
  assert ratelimit.is_blocked(k, 1)
}

/// Failures recorded at the same time are all counted (a read-then-write
/// would lose some, letting parallel guesses past the limit).
pub fn concurrent_failures_are_all_counted_test() {
  ratelimit.init()
  let k = key("parallel")
  let done = process.new_subject()
  let attempts = 500
  list.repeat(Nil, attempts)
  |> list.each(fn(_) {
    process.spawn(fn() {
      ratelimit.record_failure(k, 60)
      process.send(done, Nil)
    })
  })
  list.each(list.repeat(Nil, attempts), fn(_) {
    let assert Ok(Nil) = process.receive(done, 5000)
  })
  assert ratelimit.is_blocked(k, attempts)
  assert !ratelimit.is_blocked(k, attempts + 1)
}

pub fn ended_windows_are_purged_test() {
  ratelimit.init()
  let k = key("purge")
  ratelimit.record_failure(k, 0)
  assert ratelimit.purge_expired() >= 1
  ratelimit.record_failure(k, 60)
  assert ratelimit.is_blocked(k, 1)
}
