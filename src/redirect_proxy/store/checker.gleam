//// Logs what is wrong with the published rules: redirect loops, and rules
//// that can never apply. Going over every rule takes about half a second at
//// 50 000 rules, and it only logs, so it runs in a process of its own, after
//// a change is answered, rather than in the store's, before. A burst of
//// changes is checked once, on the rules as they are when the checker gets
//// to it.

import gleam/erlang/process.{type Subject}
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store/rules.{warn_loops, warn_problems}

/// The checker of each store, by rules path.
const table = "redirect_proxy_store_checkers"

/// What to log about the rules now published: only redirect loops (a change
/// that may uncover one elsewhere), or also the rules that can never apply
/// (a whole new rule set).
pub type Check {
  Loops
  Problems
}

/// Creates the table of checkers. Called by the process starting the store.
pub fn init() -> Nil {
  ffi.ets_new(table)
}

/// Starts the checker of the store of `rules_path`, linked to the calling
/// process (the store: they stop together). `fetch` reads the rules as
/// published.
pub fn start(
  rules_path: String,
  ignore_trailing_slash: Bool,
  fetch: fn() -> List(Rule),
) -> Nil {
  let ready = process.new_subject()
  process.spawn(fn() {
    let checks = process.new_subject()
    process.send(ready, checks)
    loop(checks, fetch, ignore_trailing_slash)
  })
  let assert Ok(checks) = process.receive(ready, 5000)
  ffi.ets_put(table, rules_path, checks)
}

/// Asks the checker of the store of `rules_path` to check the rules now
/// published.
pub fn request(rules_path: String, check: Check) -> Nil {
  case ffi.ets_get(table, rules_path) {
    Ok(checks) -> process.send(checks, check)
    Error(Nil) -> Nil
  }
}

fn loop(
  checks: Subject(Check),
  fetch: fn() -> List(Rule),
  ignore_trailing_slash: Bool,
) -> Nil {
  let check = pending(checks, process.receive_forever(checks))
  let outcome =
    ffi.rescue(fn() {
      // the rules as published: the snapshot is their matcher
      let rules = fetch()
      let built = snapshot.current()
      case check {
        Problems -> warn_problems(built, rules, ignore_trailing_slash)
        Loops -> warn_loops(built, rules, ignore_trailing_slash)
      }
    })
  case outcome {
    Ok(_) -> Nil
    Error(reason) -> log.warning("checking the rules failed: " <> reason)
  }
  loop(checks, fetch, ignore_trailing_slash)
}

/// The checks requested meanwhile, as one: `Problems` covers `Loops`.
fn pending(checks: Subject(Check), check: Check) -> Check {
  case process.receive(checks, 0) {
    Ok(next) ->
      pending(checks, case check, next {
        Problems, _ | _, Problems -> Problems
        Loops, Loops -> Loops
      })
    Error(Nil) -> check
  }
}
