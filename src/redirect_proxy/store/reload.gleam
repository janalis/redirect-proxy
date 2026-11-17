//// Reloads of the redirections file: asked for (`SIGHUP`, the admin, the
//// API), seen changed by the watcher, or found changed by another process
//// before a change is applied.

import gleam/int
import gleam/list
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/audit_entries
import redirect_proxy/store/checker
import redirect_proxy/store/commit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/state.{type State, files, in_effect, lock_timeout}
import simplifile

/// Reads the file again, holding its lock: the new state, and the number
/// of rules or why the file was refused. Without `report_busy`, a lock held
/// by another process is left to the caller to report (the watcher says it
/// once per write, and tries again at its next tick).
pub fn reload(
  state: State,
  actor_name: String,
  report_busy report_busy: Bool,
) -> #(State, Result(Int, store_file.LoadFailure)) {
  case
    store_file.load_locked_or_busy(
      files(state.config),
      store_file.Reloading,
      lock_timeout,
    )
  {
    // timed from when the lock was taken: waiting for another process is
    // not part of the load
    Ok(#(rules, fingerprint, started)) -> {
      let reloaded = loaded(state, rules, fingerprint, actor_name, started)
      log.info("reloaded " <> int.to_string(list.length(rules)) <> " rule(s)")
      #(reloaded, Ok(list.length(rules)))
    }
    Error(store_file.LockHeld(_) as failure) if !report_busy -> #(
      state,
      Error(failure),
    )
    // the file was not read: nothing was refused, the caller answers busy
    Error(store_file.LockHeld(reason) as failure) -> {
      log.warning("reload not done, the file is busy: " <> reason)
      #(state, Error(failure))
    }
    Error(failure) -> {
      let reason = store_file.reason(failure)
      metrics.incr(metrics.ReloadFailures)
      log.error("reload failed, keeping current rules: " <> reason)
      audit_entries.reload_failed(state, actor_name, reason)
      #(state, Error(failure))
    }
  }
}

/// Reloads the rules when the file was changed by another process since it
/// was last read or written, before a change is applied (the file lock
/// held). A missing file keeps the current rules (they are written back by
/// the change).
pub fn refresh(state: State) -> Result(State, String) {
  case simplifile.read_bits(state.config.rules_path) {
    Error(simplifile.Enoent) -> Ok(state)
    // not a missing file: one this process cannot read must not be
    // overwritten as if it were
    Error(e) ->
      Error(
        "the redirections file cannot be read ("
        <> simplifile.describe_error(e)
        <> "), so it was not overwritten. Fix its permissions, then retry.",
      )
    Ok(content) ->
      case store_file.fingerprint(content) == state.fingerprint {
        True -> Ok(state)
        False -> {
          // like `reload`, the time counted includes loading the file
          let started = system_ffi.monotonic_micros()
          case
            store_file.load_failing(files(state.config), store_file.Reloading)
          {
            Error(store_file.IdsNotWritten(reason:, ..)) ->
              Error(
                "the redirections file was changed outside the server, and the ids of its rules without one could not be written, so it was not overwritten. Free space or fix the permissions, then retry. "
                <> reason,
              )
            Error(store_file.Invalid(reason:, ..)) ->
              Error(
                "the redirections file was changed outside the server and is invalid, so it was not overwritten. Fix it, then retry. "
                <> reason,
              )
            Ok(#(rules, fingerprint)) -> {
              let reloaded =
                loaded(state, rules, fingerprint, "external", started)
              log.warning(
                state.config.rules_path
                <> " was changed outside the server: reloaded "
                <> int.to_string(list.length(rules))
                <> " rule(s) before applying the change",
              )
              Ok(reloaded)
            }
          }
        }
      }
  }
}

/// Puts the `rules` read from the file of `fingerprint` in effect: publishes
/// them, counts the reload (and its time since `started`) and audits it.
fn loaded(
  state: State,
  rules: List(Rule),
  fingerprint: String,
  actor_name: String,
  started: Int,
) -> State {
  commit.loaded(state.config.target, rules, fingerprint, checker.Problems)
  metrics.incr(metrics.Reloads)
  metrics.reloaded(system_ffi.monotonic_micros() - started)
  audit_entries.rules_change(
    state,
    actor_name,
    "rules.reload",
    int.to_string(list.length(rules)) <> " rule(s)",
    rules,
    fingerprint,
  )
  in_effect(state, rules, fingerprint)
}
