//// The published rule set. The snapshot is global: each test puts back
//// what was published before it, for the tests that run after.

import gleam/erlang/process
import gleam/result
import redirect_proxy/ffi
import redirect_proxy/matcher.{type Matcher}
import redirect_proxy/rule.{Rule}
import redirect_proxy/snapshot

@external(erlang, "test_snapshot_ffi", "unpublish")
fn unpublish() -> Nil

fn with_snapshot_restored(run: fn() -> Nil) -> Nil {
  let previous: Result(Matcher, Nil) = ffi.snapshot_get("matcher")
  run()
  case previous {
    Ok(m) -> snapshot.publish(m)
    Error(Nil) -> unpublish()
  }
}

fn rules_to(target: String) -> Matcher {
  matcher.build([Rule(..rule.blank(), id: "a", source: "/a", target:)])
}

fn location(m: Matcher) -> Result(String, Nil) {
  matcher.lookup(m, "h.test", "/a") |> result.map(fn(found) { found.location })
}

pub fn current_is_what_was_last_published_test() {
  use <- with_snapshot_restored
  snapshot.publish(rules_to("/first"))
  assert location(snapshot.current()) == Ok("/first")
  snapshot.publish(rules_to("/second"))
  assert location(snapshot.current()) == Ok("/second")
  snapshot.publish(matcher.empty())
  assert matcher.size(snapshot.current()) == 0
}

/// Other processes read the same rule set, without asking the publisher.
pub fn other_processes_read_the_published_rules_test() {
  use <- with_snapshot_restored
  snapshot.publish(rules_to("/shared"))
  let reply = process.new_subject()
  process.spawn(fn() { process.send(reply, location(snapshot.current())) })
  assert process.receive(reply, 5000) == Ok(Ok("/shared"))
}

/// Before anything is published, the rule set is empty, and reading it does
/// not publish that empty one (it could replace the first real one).
pub fn empty_until_published_test() {
  use <- with_snapshot_restored
  unpublish()
  let current = snapshot.current()
  assert matcher.size(current) == 0
  assert location(current) == Error(Nil)
  let still: Result(Matcher, Nil) = ffi.snapshot_get("matcher")
  assert result.is_error(still)
}
