//// The state of the store actor, shared by the modules that handle its
//// messages (`redirect_proxy/store` is the public interface).

import gleam/list
import gleam/option.{type Option, None}
import gleam/set
import redirect_proxy/ffi/file as file_ffi
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/commit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits

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
    True -> State(..after, hits_written: save_hits(after))
    False -> after
  }
}

pub fn save_hits(state: State) -> hits.Written {
  hits.save(
    state.config.hits_path,
    list.map(state.rules, fn(r) { r.id }),
    state.hits_written,
  )
}
