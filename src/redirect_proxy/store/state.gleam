//// The state of the store actor, shared by the modules that handle its
//// messages (`redirect_proxy/store` is the public interface).

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set.{type Set}
import redirect_proxy/ffi/file as file_ffi
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/commit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits
import simplifile

/// How long a change or a reload waits for another process to release the
/// file lock.
pub const lock_timeout = 5000

/// What the store was started with (`store.Settings`), in the form its
/// work uses.
pub type Config {
  Config(
    /// The files and how loops are followed, for `commit`.
    target: commit.Target,
    rules_path: String,
    audit_path: String,
    /// Milliseconds between checks of the file for outside changes (0: off).
    watch_interval: Int,
    /// Where hit counts are kept across restarts ("": not kept).
    hits_path: String,
  )
}

pub fn files(config: Config) -> store_file.Files {
  config.target.files
}

pub type State {
  State(
    config: Config,
    rules: List(Rule),
    /// SHA-256 of the file content last read or written.
    fingerprint: String,
    /// The file's stamp at the last `Watch` tick.
    stamp: file_ffi.FileStamp,
    /// The write of the file (its stamp) the watcher last could not load,
    /// and the fingerprint of its content: reported once, not at every tick
    /// that reads it again, and tried again when the file is written again
    /// (or on `SIGHUP`).
    rejected: Option(#(file_ffi.FileStamp, String)),
    /// The write of the file the watcher last waited for the lock to load:
    /// said once.
    busy: Option(file_ffi.FileStamp),
    /// The stamp of the file the watcher last could not read, for the same
    /// reason.
    unreadable: String,
    /// When the hit counts were last saved.
    hits_saved_at: Int,
    /// Whether they were saved since draining began.
    hits_saved_draining: Bool,
    /// What is in the hits file: an unchanged content is not written again
    /// (no write and fsync a minute while idle).
    hits_written: hits.Written,
    /// The file's stamp at the last save of the hit counts, and the ids of
    /// its rules when another process wrote it (a command line import)
    /// since it was last loaded: only their counts are saved, or the counts
    /// of rules it removed would be written back until a reload.
    disk_ids: Option(#(file_ffi.FileStamp, Option(Set(String)))),
    /// When the published rules were last checked against the rules'
    /// `starts_at`/`expires_at` (`Schedule`).
    checked_at: Int,
    /// The next `starts_at` or `expires_at` after `checked_at`, and the rules
    /// it was found in: while the rules are the same term, the check each
    /// second compares two numbers instead of reading every rule's dates.
    next_boundary: #(List(Rule), Int),
  )
}

/// The state of a store that loaded `rules`; `before` is the time and the
/// file stamp taken before the load started. The schedule is checked from
/// that time: a rule starting or expiring while a large file loads would
/// otherwise wait for an unrelated change. A write landing during the load
/// changes the stamp, so the watcher reads the file again.
pub fn initial(
  config: Config,
  rules: List(Rule),
  fingerprint: String,
  before: #(Int, file_ffi.FileStamp),
) -> State {
  let #(loaded_at, stamp) = before
  State(
    config:,
    rules:,
    fingerprint:,
    stamp:,
    rejected: None,
    busy: None,
    unreadable: "",
    hits_saved_at: system_ffi.now_seconds(),
    hits_saved_draining: False,
    hits_written: hits.nothing_written,
    disk_ids: None,
    checked_at: loaded_at,
    next_boundary: #(rules, rule.next_boundary(rules, loaded_at)),
  )
}

/// The rules in effect are now `rules`, from the file of `fingerprint`:
/// nothing the watcher rejected is left to skip.
pub fn in_effect(
  state: State,
  rules: List(Rule),
  fingerprint: String,
) -> State {
  State(..state, rules:, fingerprint:, rejected: None, busy: None)
}

/// Saves the hit counts at once when a change removed rules: the saved
/// counts of a deleted rule would otherwise stay in the file until the next
/// save, and a crash meanwhile would restore them onto a new rule created
/// with the same id.
pub fn save_hits_if_removed(before: List(Rule), after: State) -> State {
  let kept = set.from_list(list.map(after.rules, fn(r) { r.id }))
  case list.any(before, fn(r) { !set.contains(kept, r.id) }) {
    True -> save_hits(after)
    False -> after
  }
}

/// Saves the hit counts of the rules in effect that are still in the file.
pub fn save_hits(state: State) -> State {
  case state.config.hits_path {
    "" -> state
    path -> {
      let state = look_at_disk(state)
      let ids = list.map(state.rules, fn(r) { r.id })
      let ids = case state.disk_ids {
        Some(#(_, Some(on_disk))) -> list.filter(ids, set.contains(on_disk, _))
        _ -> ids
      }
      State(..state, hits_written: hits.save(path, ids, state.hits_written))
    }
  }
}

/// `disk_ids` for the file as it is now: read again only when its stamp
/// changed (one `stat` a save otherwise).
fn look_at_disk(state: State) -> State {
  let path = state.config.rules_path
  let stamp = file_ffi.file_stamp(path)
  case state.disk_ids {
    Some(#(seen, _)) if seen == stamp ->
      case file_ffi.stamp_is_recent(stamp) {
        False -> state
        True -> State(..state, disk_ids: Some(#(stamp, read_ids(state, path))))
      }
    _ -> State(..state, disk_ids: Some(#(stamp, read_ids(state, path))))
  }
}

/// The ids of the rules in the file, when it is not the content in effect
/// (`None`: it is, or it cannot be read: the rules in effect are kept).
fn read_ids(state: State, path: String) -> Option(Set(String)) {
  case simplifile.read_bits(path) {
    Ok(content) ->
      case store_file.fingerprint(content) == state.fingerprint {
        True -> None
        False ->
          case bit_array.to_string(content) {
            Ok(text) ->
              case rule.file_from_string(text) {
                Ok(rules) ->
                  Some(set.from_list(list.map(rules, fn(r) { r.id })))
                Error(_) -> None
              }
            Error(Nil) -> None
          }
      }
    Error(_) -> None
  }
}
