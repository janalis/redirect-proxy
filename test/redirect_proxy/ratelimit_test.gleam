import gleam/erlang/process
import gleam/int
import gleam/list
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/ffi
import support

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

/// `take` checks and counts in one step: of many concurrent attempts, only
/// the limit get through (a check made before counting lets them all pass).
pub fn concurrent_takes_stay_within_the_limit_test() {
  ratelimit.init()
  let k = key("take")
  let done = process.new_subject()
  let attempts = 200
  list.each(list.repeat(Nil, attempts), fn(_) {
    process.spawn(fn() { process.send(done, ratelimit.take(k, 10, 60)) })
  })
  let passed =
    list.repeat(Nil, attempts)
    |> list.filter(fn(_) {
      let assert Ok(taken) = process.receive(done, 5000)
      taken
    })
  assert list.length(passed) == 10
  assert ratelimit.is_blocked(k, 10)
  assert !ratelimit.is_blocked(k, 11)
}

/// All or nothing: a spent check takes back the uses counted for the others.
pub fn take_all_counts_nothing_when_one_is_spent_test() {
  ratelimit.init()
  let open = key("open")
  let spent = key("spent")
  ratelimit.record_failure(spent, 60)
  let assert Error(wait) = ratelimit.take_all([#(open, 5), #(spent, 1)], 60)
  assert wait > 0 && wait <= 60
  assert !ratelimit.is_blocked(open, 1)
  assert ratelimit.take_all([#(open, 1)], 60) == Ok(Nil)
  assert ratelimit.is_blocked(open, 1)
  ratelimit.forgive(open)
  assert !ratelimit.is_blocked(open, 1)
  // never below zero
  ratelimit.forgive(open)
  ratelimit.forgive(key("missing"))
  assert ratelimit.take_all([#(open, 1)], 60) == Ok(Nil)
}

pub fn bounded_work_refuses_beyond_the_limit_test() {
  ratelimit.init()
  let name = key("slots")
  let started = process.new_subject()
  process.spawn(fn() {
    let release = process.new_subject()
    ratelimit.bounded(name, 1, fn() {
      process.send(started, release)
      process.receive(release, 5000)
    })
  })
  let assert Ok(release) = process.receive(started, 5000)
  assert ratelimit.bounded(name, 1, fn() { Nil }) == Error(Nil)
  process.send(release, Nil)
  // the slot is given back, even by work that crashes
  support_wait(fn() { ratelimit.bounded(name, 1, fn() { Nil }) == Ok(Nil) })
  let _ = ffi.rescue(fn() { ratelimit.bounded(name, 1, fn() { panic }) })
  assert ratelimit.bounded(name, 1, fn() { 7 }) == Ok(7)
}

fn support_wait(condition: fn() -> Bool) -> Nil {
  support.wait_until(condition, 2000)
}

/// A process killed while it holds a slot (no `after` runs then) does not
/// keep it: the next caller removes the dead holder.
pub fn a_killed_holder_gives_its_slot_back_test() {
  ratelimit.init()
  let name = key("killed")
  let started = process.new_subject()
  let holder =
    process.spawn_unlinked(fn() {
      ratelimit.bounded(name, 1, fn() {
        process.send(started, Nil)
        process.sleep(10_000)
      })
    })
  let assert Ok(Nil) = process.receive(started, 5000)
  assert ratelimit.bounded(name, 1, fn() { Nil }) == Error(Nil)
  process.kill(holder)
  support_wait(fn() { !process.is_alive(holder) })
  assert ratelimit.bounded(name, 1, fn() { 7 }) == Ok(7)
}
