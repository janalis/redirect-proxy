//// How the store applies a change of the rules: holding the cross-process
//// file lock, on rules refreshed from disk when another process changed
//// the file, and only while its caller still waits for it.

import gleam/bool
import gleam/erlang/process.{type Subject}
import redirect_proxy/ffi/file as file_ffi
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/reload
import redirect_proxy/store/state.{
  type State, in_effect, lock_timeout, save_hits_if_removed,
}

/// What a change that was not made is reported as (`store.ChangeError`).
pub type Errors(e) {
  Errors(
    /// Another process holds the lock of the file past the wait, or the
    /// caller stopped waiting.
    busy: fn(String) -> e,
    /// The file could not be read, written or refreshed.
    storage: fn(String) -> e,
  )
}

/// Runs `change` and replies with its outcome: the new state. `change`
/// returns the reply, the new rules and the fingerprint of the written
/// file.
///
/// A change whose caller stopped waiting while it was queued (it timed out,
/// or exited) is skipped: nothing is written, audited or published.
pub fn run(
  state: State,
  reply: Subject(Result(a, e)),
  errors: Errors(e),
  change: fn(State) -> Result(#(a, List(Rule), String), e),
) -> State {
  use <- bool.lazy_guard(abandoned(reply), fn() {
    log.warning("a change was skipped: its caller stopped waiting for it")
    state
  })
  let outcome =
    file_ffi.with_file_lock_detailed(
      state.config.rules_path,
      lock_timeout,
      fn() {
        // the lock may have taken long enough for the caller to give up
        use <- bool.lazy_guard(abandoned(reply), fn() {
          log.warning("a change was skipped: its caller stopped waiting for it")
          #(state, Error(errors.busy("the caller stopped waiting")))
        })
        case reload.refresh(state) {
          Error(reason) -> #(state, Error(errors.storage(reason)))
          Ok(state) ->
            case change(state) {
              Ok(#(value, rules, fingerprint)) -> {
                let changed = in_effect(state, rules, fingerprint)
                #(save_hits_if_removed(state.rules, changed), Ok(value))
              }
              Error(error) -> #(state, Error(error))
            }
        }
      },
    )
  case outcome {
    Ok(#(state, result)) -> {
      process.send(reply, result)
      state
    }
    Error(failure) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("redirections not saved: " <> failure.message)
      process.send(
        reply,
        Error(case failure {
          file_ffi.Held(reason) -> errors.busy(reason)
          file_ffi.CannotCreate(reason) -> errors.storage(reason)
        }),
      )
      state
    }
  }
}

/// Whether nobody waits for the reply any more.
fn abandoned(reply: Subject(a)) -> Bool {
  case process.subject_owner(reply) {
    Ok(owner) -> !process.is_alive(owner)
    Error(Nil) -> False
  }
}
