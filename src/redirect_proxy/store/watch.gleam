//// The watcher of the redirections file: at each tick, reloads it when
//// another process changed it, and says once why a change of it does not
//// load.

import gleam/bool
import gleam/option.{None, Some}
import gleam/string
import redirect_proxy/ffi/file as file_ffi
import redirect_proxy/log
import redirect_proxy/store/file as store_file
import redirect_proxy/store/reload
import redirect_proxy/store/state.{type State, State, in_effect}
import simplifile

/// Looks at the file: the state once any change of it is loaded, or
/// noted as one that does not load.
pub fn tick(state: State) -> State {
  let stamp = file_ffi.file_stamp(state.config.rules_path)
  case stamp == state.stamp && !file_ffi.stamp_is_recent(stamp) {
    True -> state
    False -> {
      let content = simplifile.read_bits(state.config.rules_path)
      // still being written (truncated, then filled): look again at the
      // next tick, or the content read now would be taken again for a
      // change once the stamp settles (an invalid file reported twice)
      use <- bool.lazy_guard(
        file_ffi.file_stamp(state.config.rules_path) != stamp,
        fn() { state },
      )
      // the store's own writes leave the fingerprint unchanged
      case content {
        Ok(content) if content != <<>> ->
          changed(state, stamp, store_file.fingerprint(content))
        Error(simplifile.Enoent) | Ok(_) -> State(..state, stamp:)
        // reported once per change of the file (its stamp stays
        // recent for a few ticks, read again at each)
        Error(e) -> {
          let unreadable = "unreadable " <> string.inspect(stamp)
          case state.unreadable == unreadable {
            True -> Nil
            False ->
              log.error(
                "the redirections file cannot be read, keeping current rules: "
                <> simplifile.describe_error(e),
              )
          }
          State(..state, stamp:, unreadable:)
        }
      }
    }
  }
}

/// The file, at `stamp`, has a content of fingerprint `found`.
fn changed(state: State, stamp: file_ffi.FileStamp, found: String) -> State {
  // the same content, of the write refused (its time may have
  // moved since), not of a write made since
  let skipped = case state.rejected {
    Some(#(at, refused)) -> refused == found && file_ffi.same_write(at, stamp)
    None -> False
  }
  case found == state.fingerprint || skipped {
    // the content in effect (reverted, or loaded by a change
    // made meanwhile): nothing rejected left to skip
    True if found == state.fingerprint ->
      State(..in_effect(state, state.rules, state.fingerprint), stamp:)
    True -> State(..state, stamp:)
    False -> {
      let #(reloaded, outcome) =
        reload.reload(State(..state, stamp:), "watch", report_busy: False)
      case outcome {
        Ok(_) -> reloaded
        // the lock held by another process: the next tick
        // tries again (said once per write of the file: a
        // lock never released keeps the file from loading)
        Error(store_file.LockHeld(reason)) -> {
          case reloaded.busy == Some(stamp) {
            True -> Nil
            False ->
              log.warning(
                "reload of the redirections file waits for its lock: " <> reason,
              )
          }
          State(..reloaded, stamp: state.stamp, busy: Some(stamp))
        }
        // a file that does not load (invalid, its ids not
        // written, the lock not created) is reported once:
        // tried again when it is written again (a new stamp),
        // or on SIGHUP
        Error(failure) ->
          State(
            ..reloaded,
            // the write and content the load read, which may
            // be newer than this tick's (else this tick's)
            rejected: Some(case failure {
              store_file.Content(store_file.Invalid(read:, ..))
                | store_file.Content(store_file.IdsNotWritten(read:, ..))
                if read != ""
              -> #(file_ffi.file_stamp(state.config.rules_path), read)
              _ -> #(stamp, found)
            }),
          )
      }
    }
  }
}
