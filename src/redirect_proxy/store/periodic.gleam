//// The store's work each second: republishing the rules when a scheduled
//// one starts or expires, and saving the hit counts.

import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/log
import redirect_proxy/rule
import redirect_proxy/store/checker
import redirect_proxy/store/commit
import redirect_proxy/store/hits
import redirect_proxy/store/state.{type State, State, save_hits}

/// Republishes the rules when one started or expired since the last check.
pub fn schedule(state: State) -> State {
  let now = system_ffi.now_seconds()
  // computed again when the rules changed (another term: comparing
  // the same term is immediate)
  let next = case state.next_boundary {
    #(rules, next) if rules == state.rules -> next
    _ -> rule.next_boundary(state.rules, state.checked_at)
  }
  // a change since the last check rebuilt the matcher already: then
  // this rebuild is redundant, but harmless
  let crossed = next <= now
  case crossed {
    False -> Nil
    True -> {
      log.info("a scheduled rule starts or expires: rules republished")
      commit.loaded(
        state.config.target,
        state.rules,
        state.fingerprint,
        checker.Loops,
      )
    }
  }
  let next = case crossed {
    True -> rule.next_boundary(state.rules, now)
    False -> next
  }
  State(..state, checked_at: now, next_boundary: #(state.rules, next))
}

/// Saves the hit counts when due (`hits.interval`) or when the node starts
/// draining before a stop.
pub fn save_hits_if_due(state: State) -> State {
  let now = system_ffi.now_seconds()
  let draining = system_ffi.draining()
  case
    now - state.hits_saved_at >= hits.interval
    || { draining && !state.hits_saved_draining }
  {
    False -> state
    True -> {
      let hits_written = save_hits(state)
      State(
        ..state,
        hits_saved_at: now,
        hits_saved_draining: draining,
        hits_written:,
      )
    }
  }
}

/// Saves the hit counts now.
pub fn flush_hits(state: State) -> State {
  let hits_written = save_hits(state)
  State(..state, hits_saved_at: system_ffi.now_seconds(), hits_written:)
}
