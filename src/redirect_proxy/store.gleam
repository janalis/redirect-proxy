//// The rule store: a single OTP actor serialising every mutation.
////
//// Each successful mutation:
////   1. validates the rule(s),
////   2. rebuilds the compiled matcher,
////   3. backs up then atomically rewrites the redirections file,
////   4. publishes the matcher to `persistent_term`,
////   5. appends an entry to the audit log.
////
//// Reads on the hot path never touch this actor.
////
//// Other OS processes (the CLI, editors, scripts) may write the file too.
//// Every mutation holds the cross-process `<file>.lock` and, when the file
//// changed on disk since it was last read or written, reloads it first, so
//// that outside changes are never silently overwritten.

import gleam/bool
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import gleam/set
import gleam/string
import redirect_proxy/audit
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/checker
import redirect_proxy/store/commit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits
import redirect_proxy/store/rules.{merge, prepare_import} as store_rules
import simplifile

/// Milliseconds between checks for rules starting or expiring.
const schedule_interval = 1000

/// How long a mutation waits for another process to release the file lock.
const lock_timeout = 5000

/// At start the lock is waited for longer than the 10 seconds after which a
/// lock left by a crashed process is broken, so that start never fails on it.
const start_lock_timeout = 15_000

/// How long callers wait for the store. Mutations queue behind each other and
/// each one may wait `lock_timeout` for the file lock, then rebuild the
/// matcher. A caller that stops waiting raises `ffi.store_timeout` (see
/// `or_unavailable`), and its change is skipped unless the store had begun it.
const timeout = 30_000

/// Calls the store, waiting up to `waiting` milliseconds (unless a test
/// shortened it) for the reply.
///
/// The reply goes to a process linked to the caller, which forwards it: when
/// the caller times out (or exits), that process is gone, and `mutate` skips a
/// change nobody waits for any more, rather than make one reported as failed.
fn call(
  store: Store,
  waiting default: Int,
  sending make: fn(Subject(reply)) -> Message,
) -> reply {
  let store_pid = store_pid(store)
  let caller = process.self()
  let forwarded = process.new_subject()
  let forwarder =
    process.spawn(fn() {
      let reply = process.new_subject()
      process.send(store, make(reply))
      let value = process.receive_forever(reply)
      // no exit message for a caller trapping exits
      process.unlink(caller)
      process.send(forwarded, value)
    })
  let forwarder_down = process.monitor(forwarder)
  let store_down = process.monitor(store_pid)
  let outcome =
    process.new_selector()
    |> process.select_map(forwarded, Ok)
    |> process.select_specific_monitor(store_down, fn(_) { Error(True) })
    |> process.selector_receive(ffi.tunable("store_call_timeout", default))
    |> result.unwrap(Error(False))
  process.demonitor_process(store_down)
  case outcome {
    Ok(value) -> {
      process.demonitor_process(forwarder_down)
      value
    }
    Error(store_exited) -> {
      process.unlink(forwarder)
      process.kill(forwarder)
      // a reply sent before the kill arrives before the forwarder's exit
      let late =
        process.new_selector()
        |> process.select_map(forwarded, Ok)
        |> process.select_specific_monitor(forwarder_down, fn(_) { Error(Nil) })
        |> process.selector_receive_forever
      process.demonitor_process(forwarder_down)
      case late, store_exited {
        Ok(value), _ -> value
        Error(Nil), True -> panic as "the store exited before replying"
        Error(Nil), False -> ffi.store_timeout()
      }
    }
  }
}

/// Calls the store for a read, waiting up to `waiting` milliseconds: the
/// reply comes straight back (a read has nothing to skip, and the rule list
/// is not copied twice). A reply arriving after the timeout stays in the
/// caller's mailbox, as with `process.call`; callers are request processes.
fn read(
  store: Store,
  waiting default: Int,
  sending make: fn(Subject(reply)) -> Message,
) -> reply {
  let store_down = process.monitor(store_pid(store))
  let reply = process.new_subject()
  process.send(store, make(reply))
  let outcome =
    process.new_selector()
    |> process.select_map(reply, Ok)
    |> process.select_specific_monitor(store_down, fn(_) { Error(True) })
    |> process.selector_receive(ffi.tunable("store_call_timeout", default))
    |> result.unwrap(Error(False))
  process.demonitor_process(store_down)
  case outcome {
    Ok(value) -> value
    Error(True) -> panic as "the store exited before replying"
    Error(False) -> ffi.store_timeout()
  }
}

/// The store's process; while the supervisor restarts it, the store is
/// unavailable, as when it is too busy.
fn store_pid(store: Store) -> process.Pid {
  case process.subject_owner(store) {
    Ok(pid) -> pid
    Error(Nil) -> ffi.store_timeout()
  }
}

/// Runs `run`, or `unavailable` when a store call in it timed out: the store
/// was busy, with changes queued or waiting for the file lock another process
/// holds.
pub fn or_unavailable(run: fn() -> a, unavailable: fn() -> a) -> a {
  ffi.rescue_store_timeout(run, unavailable)
}

pub type Settings {
  Settings(
    rules_path: String,
    backups_dir: String,
    backups: Int,
    audit_path: String,
    /// `server.trailing_slash = "ignore"`: loops are followed the way the
    /// redirect listener answers.
    ignore_trailing_slash: Bool,
    /// Milliseconds between checks of the file for outside changes (0: off).
    watch_interval: Int,
    /// Where hit counts are kept across restarts ("": not kept).
    hits_path: String,
  )
}

pub type ImportMode {
  /// Replace every rule with the imported ones.
  Replace
  /// Add imported rules; rules with an existing id are updated.
  Merge
}

/// `merge` or `replace`, as given to the admin form and the API.
pub fn import_mode_from_string(mode: String) -> Result(ImportMode, Nil) {
  case mode {
    "merge" -> Ok(Merge)
    "replace" -> Ok(Replace)
    _ -> Error(Nil)
  }
}

/// Why a versioned change was refused.
pub type ChangeError {
  NotFound
  /// The rule changed since the version the caller based its change on.
  Conflict(current: Rule)
  Invalid(List(String))
}

/// Why a change to the whole rule set (an import, a bulk change) was refused.
/// What an import would make of the rule set, before the checks of the
/// rules it changes (done by the caller, not to block the store).
type Preview {
  Preview(
    diff: store_rules.Diff,
    fingerprint: String,
    rules: List(Rule),
    ignore_trailing_slash: Bool,
  )
}

pub type SetChangeError {
  /// The rule set changed since the version (`versioned`) the caller based
  /// its change on, such as an import preview: nothing was written.
  Stale(current: String)
  Rejected(List(String))
}

pub fn describe_set_change_error(error: SetChangeError) -> List(String) {
  case error {
    Stale(_) -> [
      "version: the rules were changed since they were read: review the changes and retry",
    ]
    Rejected(errors) -> errors
  }
}

pub opaque type Message {
  All(reply: Subject(List(Rule)))
  Versioned(reply: Subject(#(List(Rule), String)))
  Get(id: String, reply: Subject(Result(Rule, Nil)))
  Create(rule: Rule, actor: String, reply: Subject(Result(Rule, List(String))))
  Update(
    rule: Rule,
    expected: Option(String),
    actor: String,
    reply: Subject(Result(Rule, ChangeError)),
  )
  Delete(
    id: String,
    expected: Option(String),
    actor: String,
    reply: Subject(Result(Rule, ChangeError)),
  )
  /// `rules` are already prepared and validated by `import_rules`.
  Import(
    rules: List(Rule),
    mode: ImportMode,
    expected: Option(String),
    actor: String,
    reply: Subject(Result(Int, SetChangeError)),
  )
  /// `rules` are prepared and validated, as for `Import`.
  PreviewImport(
    rules: List(Rule),
    mode: ImportMode,
    reply: Subject(Result(Preview, List(String))),
  )
  Bulk(
    ids: List(String),
    action: BulkAction,
    expected: Option(String),
    actor: String,
    reply: Subject(Result(Int, SetChangeError)),
  )
  Reload(actor: String, reply: Subject(Result(Int, String)))
  ReloadInBackground(actor: String)
  /// `watch_interval` tick: reloads the file if it changed on disk.
  Watch(self: Subject(Message))
  /// Every second: saves the hit counts when due (`hits.interval`) or when
  /// the node starts draining before a stop.
  SaveHits(self: Subject(Message))
  /// Saves the hit counts now: right before the node stops.
  FlushHits(reply: Subject(Nil))

  /// Every second: republishes the rules when one starts or expires.
  Schedule(self: Subject(Message))
}

/// What a bulk change does to the rules it names.
pub type BulkAction {
  Enable
  Disable
  Remove
}

pub fn bulk_action_from_string(action: String) -> Result(BulkAction, Nil) {
  case action {
    "enable" -> Ok(Enable)
    "disable" -> Ok(Disable)
    "delete" -> Ok(Remove)
    _ -> Error(Nil)
  }
}

pub fn bulk_action_to_string(action: BulkAction) -> String {
  case action {
    Enable -> "enable"
    Disable -> "disable"
    Remove -> "delete"
  }
}

type State {
  State(
    settings: Settings,
    rules: List(Rule),
    /// SHA-256 of the file content last read or written.
    fingerprint: String,
    /// The file's stamp at the last `Watch` tick.
    stamp: ffi.FileStamp,
    /// The fingerprint of the content the watcher last could not load: it
    /// is reported once, not at every tick that reads it again. Content that
    /// may load later as it is (`rejected_retry`: valid, but its ids could
    /// not be written, or the lock not created) is tried again, quietly,
    /// every minute (`retry_rejected`), until it loads.
    rejected: String,
    rejected_at: Int,
    rejected_retry: Bool,
    /// Whether its content was read (not only the lock refused): tried
    /// again, it is reported only if not.
    rejected_read: Bool,
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

pub type Store =
  Subject(Message)

/// Starts the store. Fails if the redirections file exists but is invalid, so
/// that a broken file never silently replaces the configuration.
/// The state of a store that just loaded `rules`.
/// The state of a store that loaded `rules`; `before` is the time and the
/// file stamp taken before the load started. The schedule is checked from
/// that time: a rule starting or expiring while a large file loads would
/// otherwise wait for an unrelated change. A write landing during the load
/// changes the stamp, so the watcher reads the file again.
fn initial_state(
  settings: Settings,
  rules: List(Rule),
  fingerprint: String,
  before: #(Int, ffi.FileStamp),
) -> State {
  let #(loaded_at, stamp) = before
  State(
    settings:,
    rules:,
    fingerprint:,
    stamp:,
    rejected: "",
    rejected_at: 0,
    rejected_retry: False,
    rejected_read: False,
    unreadable: "",
    hits_saved_at: ffi.now_seconds(),
    hits_saved_draining: False,
    hits_written: hits.nothing_written,
    checked_at: loaded_at,
    next_boundary: #(rules, rule.next_boundary(rules, loaded_at)),
  )
}

pub fn start(
  settings: Settings,
  name: Name(Message),
) -> Result(actor.Started(Store), actor.StartError) {
  commit.init()
  checker.init()
  actor.new_with_initialiser(30_000, fn(subject) {
    checker.start(settings.rules_path, settings.ignore_trailing_slash, fn() {
      all(subject)
    })
    let started = ffi.monotonic_micros()
    let before = #(ffi.now_seconds(), ffi.file_stamp(settings.rules_path))
    use state <- result.try(
      case
        store_file.load_locked(
          files(settings),
          store_file.FirstStart,
          ffi.tunable("start_lock_timeout", start_lock_timeout),
        )
      {
        Ok(#(rules, fingerprint)) -> {
          commit.loaded(target(settings), rules, checker.Problems)
          metrics.reloaded(ffi.monotonic_micros() - started)
          log.info(
            "loaded "
            <> int.to_string(list.length(rules))
            <> " redirection rule(s) from "
            <> settings.rules_path,
          )
          Ok(initial_state(settings, rules, fingerprint, before))
        }
        Error(reason) ->
          // A restart after a crash: the last good rules are still being
          // served. Keep them rather than failing again until the supervisor
          // gives up and stops the whole node. The empty fingerprint makes
          // the next change re-read the file first (and refuse while it is
          // invalid).
          case commit.last_good(settings.rules_path) {
            Ok(rules) -> {
              metrics.incr(metrics.ReloadFailures)
              log.error(
                "store restarted with an invalid redirections file, keeping the "
                <> int.to_string(list.length(rules))
                <> " rule(s) loaded before: "
                <> reason,
              )
              Ok(initial_state(settings, rules, "", before))
            }
            Error(Nil) -> Error(reason)
          }
      },
    )
    schedule_watch(settings, subject)
    hits.load(settings.hits_path)
    process.send_after(subject, 1000, SaveHits(subject))

    process.send_after(subject, schedule_interval, Schedule(subject))
    actor.initialised(state)
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

pub fn all(store: Store) -> List(Rule) {
  read(store, timeout, All)
}

/// Every rule and the version of the rule set (the fingerprint of the file
/// last read or written), for `import_rules_versioned` and `bulk_versioned`.
pub fn versioned(store: Store) -> #(List(Rule), String) {
  read(store, timeout, Versioned)
}

pub fn get(store: Store, id: String) -> Result(Rule, Nil) {
  read(store, timeout, Get(id, _))
}

pub fn create(
  store: Store,
  rule: Rule,
  by actor_name: String,
) -> Result(Rule, List(String)) {
  call(store, timeout, Create(rule, actor_name, _))
}

pub fn update(
  store: Store,
  rule: Rule,
  by actor_name: String,
) -> Result(Rule, List(String)) {
  update_versioned(store, rule, None, actor_name)
  |> result.map_error(describe_change_error)
}

/// Updates a rule only if its current version equals `expected` (when given).
pub fn update_versioned(
  store: Store,
  rule: Rule,
  expected: Option(String),
  by actor_name: String,
) -> Result(Rule, ChangeError) {
  call(store, timeout, Update(rule, expected, actor_name, _))
}

pub fn delete(
  store: Store,
  id: String,
  by actor_name: String,
) -> Result(Rule, String) {
  delete_versioned(store, id, None, actor_name)
  |> result.map_error(fn(e) { string.join(describe_change_error(e), "; ") })
}

/// Deletes a rule only if its current version equals `expected` (when given).
pub fn delete_versioned(
  store: Store,
  id: String,
  expected: Option(String),
  by actor_name: String,
) -> Result(Rule, ChangeError) {
  call(store, timeout, Delete(id, expected, actor_name, _))
}

pub fn describe_change_error(error: ChangeError) -> List(String) {
  case error {
    NotFound -> ["id: rule not found"]
    Conflict(_) -> ["version: the rule was modified concurrently"]
    Invalid(errors) -> errors
  }
}

/// `expected` (when given, `*` for any) must be the current version of the
/// rule set.
fn check_collection_version(
  state: State,
  expected: Option(String),
) -> Result(Nil, SetChangeError) {
  case expected {
    Some(v) if v != "*" && v != state.fingerprint ->
      Error(Stale(state.fingerprint))
    _ -> Ok(Nil)
  }
}

fn check_version(
  existing: Rule,
  expected: Option(String),
) -> Result(Nil, ChangeError) {
  case expected {
    Some(v) if v != "*" ->
      case rule.version(existing) == v {
        True -> Ok(Nil)
        False -> Error(Conflict(existing))
      }
    _ -> Ok(Nil)
  }
}

pub fn import_rules(
  store: Store,
  rules: List(Rule),
  mode: ImportMode,
  by actor_name: String,
) -> Result(Int, List(String)) {
  import_rules_versioned(store, rules, mode, None, actor_name)
  |> result.map_error(describe_set_change_error)
}

/// Imports only if the rule set is still at version `expected` (when
/// given): the one a preview was shown for, or read with `versioned`.
pub fn import_rules_versioned(
  store: Store,
  rules: List(Rule),
  mode: ImportMode,
  expected: Option(String),
  by actor_name: String,
) -> Result(Int, SetChangeError) {
  // Validation is done here, in the caller's process, so that the store
  // does not hold the file lock (nor block other callers) while it runs.
  use prepared <- result.try(
    prepare_import(rules, actor_name) |> result.map_error(Rejected),
  )
  call(store, 60_000, Import(prepared, mode, expected, actor_name, _))
}

/// What an import would change, without writing anything: rules added,
/// removed and changed (by id), and the version of the rule set it was
/// computed against (to apply exactly this with `import_rules_versioned`).
/// Fails like `import_rules` would.
pub fn preview_import(
  store: Store,
  rules: List(Rule),
  mode: ImportMode,
  by actor_name: String,
) -> Result(#(store_rules.Diff, String), List(String)) {
  use prepared <- result.try(prepare_import(rules, actor_name))
  use preview <- result.try(
    read(store, 60_000, PreviewImport(prepared, mode, _)),
  )
  let changed_ids =
    set.from_list(list.append(preview.diff.added, preview.diff.changed))
  use Nil <- result.try(store_rules.check_changed(
    matcher.build(preview.rules),
    preview.rules,
    list.filter(preview.rules, fn(r) { set.contains(changed_ids, r.id) }),
    preview.ignore_trailing_slash,
  ))
  Ok(#(preview.diff, preview.fingerprint))
}

/// Enables, disables or deletes several rules in one write, recorded as one
/// audit entry, only if the rule set is still at version `expected` (when
/// given). Every id must exist. Returns the number of rules changed.
pub fn bulk_versioned(
  store: Store,
  ids: List(String),
  action: BulkAction,
  expected: Option(String),
  by actor_name: String,
) -> Result(Int, SetChangeError) {
  call(store, timeout, Bulk(list.unique(ids), action, expected, actor_name, _))
}

pub fn reload(store: Store, by actor_name: String) -> Result(Int, String) {
  call(store, 60_000, Reload(actor_name, _))
}

/// Saves the hit counts and waits for the write, so that the hits counted
/// while draining before a stop are kept.
pub fn flush_hits(store: Store) -> Nil {
  call(store, 10_000, FlushHits)
}

/// Reload without waiting for the result (used by the SIGHUP handler).
pub fn reload_async(store: Store) -> Nil {
  process.send(store, ReloadInBackground("signal:SIGHUP"))
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    All(reply) -> {
      process.send(reply, state.rules)
      actor.continue(state)
    }

    Versioned(reply) -> {
      process.send(reply, #(state.rules, state.fingerprint))
      actor.continue(state)
    }

    Get(id, reply) -> {
      process.send(reply, list.find(state.rules, fn(r) { r.id == id }))
      actor.continue(state)
    }

    Create(input, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { [e] })
      let now = ffi.now_rfc3339()
      let new_id = case string.trim(input.id) {
        "" -> id.uuid()
        given -> given
      }
      let candidate =
        rule.Rule(
          ..input,
          id: new_id,
          created_at: now,
          updated_at: now,
          updated_by: actor_name,
        )
      {
        use <- bool.guard(
          list.any(state.rules, fn(r) { r.id == new_id }),
          Error(["id: already exists"]),
        )
        use valid <- result.try(rule.validate(candidate))
        let rules = list.append(state.rules, [valid])
        // a new rule only adds matches: a loop it makes goes through it
        use fingerprint <- result.try(commit.one(
          target(state.settings),
          valid,
          None,
          rules,
          uncovers: False,
        ))
        audit.record(
          state.settings.audit_path,
          actor_name,
          "rule.create",
          valid.id,
          None,
          Some(rule.to_json(valid)),
        )
        Ok(#(valid, rules, fingerprint))
      }
    }

    Update(input, expected, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { Invalid([e]) })
      {
        use existing <- result.try(
          list.find(state.rules, fn(r) { r.id == input.id })
          |> result.replace_error(NotFound),
        )
        use Nil <- result.try(check_version(existing, expected))
        let candidate =
          rule.Rule(
            ..input,
            created_at: existing.created_at,
            updated_at: ffi.now_rfc3339(),
            updated_by: actor_name,
          )
        use valid <- result.try(
          rule.validate(candidate) |> result.map_error(Invalid),
        )
        let rules =
          list.map(state.rules, fn(r) {
            case r.id == valid.id {
              True -> valid
              False -> r
            }
          })
        // the old version may have shadowed a rule that loops
        use fingerprint <- result.try(
          commit.one(
            target(state.settings),
            valid,
            Some(existing),
            rules,
            uncovers: True,
          )
          |> result.map_error(Invalid),
        )
        audit.record(
          state.settings.audit_path,
          actor_name,
          "rule.update",
          valid.id,
          Some(rule.to_json(existing)),
          Some(rule.to_json(valid)),
        )
        Ok(#(valid, rules, fingerprint))
      }
    }

    Delete(rule_id, expected, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { Invalid([e]) })
      {
        use existing <- result.try(
          list.find(state.rules, fn(r) { r.id == rule_id })
          |> result.replace_error(NotFound),
        )
        use Nil <- result.try(check_version(existing, expected))
        let rules = list.filter(state.rules, fn(r) { r.id != rule_id })
        // removing a rule adds no conflict (and a file with conflicts can
        // still lose rules); it may uncover a loop it was shadowing
        use fingerprint <- result.try(
          commit.many(
            target(state.settings),
            rules,
            changed: [],
            check_conflicts: False,
          )
          |> result.map_error(Invalid),
        )
        audit.record(
          state.settings.audit_path,
          actor_name,
          "rule.delete",
          rule_id,
          Some(rule.to_json(existing)),
          None,
        )
        Ok(#(existing, rules, fingerprint))
      }
    }

    Import(prepared, mode, expected, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { Rejected([e]) })
      {
        let prepared = store_rules.resolve_ids(state.rules, prepared)
        use Nil <- result.try(check_collection_version(state, expected))
        use Nil <- result.try(
          store_rules.check_new_ids(state.rules, prepared)
          |> result.map_error(Rejected),
        )
        let rules =
          case mode {
            Replace -> prepared
            Merge -> merge(state.rules, prepared)
          }
          |> store_rules.keep_created_at(state.rules, _)
          |> store_rules.keep_unchanged(state.rules, _)
        let action = case mode {
          Replace -> "rules.import.replace"
          Merge -> "rules.import.merge"
        }
        let outcome =
          commit.many(
            target(state.settings),
            rules,
            changed: store_rules.changed_rules(state.rules, rules),
            check_conflicts: True,
          )
        case outcome {
          Ok(fingerprint) -> {
            audit_rules_change(
              state,
              actor_name,
              action,
              int.to_string(list.length(prepared)) <> " rule(s)",
              rules,
              fingerprint,
            )
            Ok(#(list.length(prepared), rules, fingerprint))
          }
          Error(errors) -> {
            audit.record(
              state.settings.audit_path,
              actor_name,
              action <> "_failed",
              int.to_string(list.length(prepared)) <> " rule(s)",
              None,
              Some(json.object([#("errors", json.array(errors, json.string))])),
            )
            Error(Rejected(errors))
          }
        }
      }
    }

    PreviewImport(prepared, mode, reply) -> {
      let prepared = store_rules.resolve_ids(state.rules, prepared)
      // creation dates do not matter here: diff ignores them
      let rules = case mode {
        Replace -> prepared
        Merge -> merge(state.rules, prepared)
      }
      process.send(reply, {
        use Nil <- result.try(store_rules.check_new_ids(state.rules, prepared))
        use Nil <- result.try(store_rules.check_conflicts(rules))
        Ok(Preview(
          diff: store_rules.diff(state.rules, rules),
          fingerprint: state.fingerprint,
          rules:,
          ignore_trailing_slash: state.settings.ignore_trailing_slash,
        ))
      })
      actor.continue(state)
    }

    Bulk(ids, action, expected, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { Rejected([e]) })
      use Nil <- result.try(check_collection_version(state, expected))
      result.map_error(_, Rejected)({
        let known = list.map(state.rules, fn(r) { r.id }) |> set.from_list
        let wanted = set.from_list(ids)
        use <- bool.guard(ids == [], Error(["ids: select at least one rule"]))
        use <- bool.guard(
          !list.all(ids, set.contains(known, _)),
          Error([
            "ids: unknown rule "
            <> {
              list.filter(ids, fn(id) { !set.contains(known, id) })
              |> string.join(", ")
            },
          ]),
        )
        let now = ffi.now_rfc3339()
        let change = fn(r: Rule, enabled: Bool) {
          case set.contains(wanted, r.id) && r.enabled != enabled {
            True ->
              rule.Rule(..r, enabled:, updated_at: now, updated_by: actor_name)
            False -> r
          }
        }
        let rules = case action {
          Remove ->
            list.filter(state.rules, fn(r) { !set.contains(wanted, r.id) })
          Enable -> list.map(state.rules, change(_, True))
          Disable -> list.map(state.rules, change(_, False))
        }
        // enabling may bring two exact rules for one path back together, or
        // rules that loop or can never apply
        use fingerprint <- result.try(commit.many(
          target(state.settings),
          rules,
          changed: case action {
            Enable -> store_rules.changed_rules(state.rules, rules)
            Disable | Remove -> []
          },
          check_conflicts: True,
        ))
        let d = store_rules.diff(state.rules, rules)
        let count = list.length(d.removed) + list.length(d.changed)
        audit_rules_change(
          state,
          actor_name,
          "rules.bulk." <> bulk_action_to_string(action),
          int.to_string(count) <> " rule(s)",
          rules,
          fingerprint,
        )
        Ok(#(count, rules, fingerprint))
      })
    }

    FlushHits(reply) -> {
      let hits_written = save_hits(state)
      process.send(reply, Nil)
      actor.continue(
        State(..state, hits_saved_at: ffi.now_seconds(), hits_written:),
      )
    }
    SaveHits(self) -> {
      process.send_after(self, 1000, SaveHits(self))
      let now = ffi.now_seconds()
      let draining = ffi.draining()
      case
        now - state.hits_saved_at >= hits.interval
        || { draining && !state.hits_saved_draining }
      {
        False -> actor.continue(state)
        True -> {
          let hits_written = save_hits(state)
          actor.continue(
            State(
              ..state,
              hits_saved_at: now,
              hits_saved_draining: draining,
              hits_written:,
            ),
          )
        }
      }
    }

    Schedule(self) -> {
      process.send_after(self, schedule_interval, Schedule(self))
      let now = ffi.now_seconds()
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
          commit.loaded(target(state.settings), state.rules, checker.Loops)
        }
      }
      let next = case crossed {
        True -> rule.next_boundary(state.rules, now)
        False -> next
      }
      actor.continue(
        State(..state, checked_at: now, next_boundary: #(state.rules, next)),
      )
    }

    Watch(self) -> {
      schedule_watch(state.settings, self)
      let stamp = ffi.file_stamp(state.settings.rules_path)
      let retry = retry_rejected(state)
      case stamp == state.stamp && !ffi.stamp_is_recent(stamp) && !retry {
        True -> actor.continue(state)
        False -> {
          let content = simplifile.read_bits(state.settings.rules_path)
          // still being written (truncated, then filled): look again at the
          // next tick, or the content read now would be taken again for a
          // change once the stamp settles (an invalid file reported twice)
          use <- bool.lazy_guard(
            ffi.file_stamp(state.settings.rules_path) != stamp,
            fn() { actor.continue(state) },
          )
          // the store's own writes leave the fingerprint unchanged
          case content {
            Ok(content) if content != <<>> -> {
              let found = store_file.fingerprint(content)
              case
                found == state.fingerprint
                || { found == state.rejected && !retry }
              {
                // the content in effect (reverted, or loaded by a change
                // made meanwhile): nothing left to try again
                True if found == state.fingerprint ->
                  actor.continue(
                    State(
                      ..in_effect(state, state.rules, state.fingerprint),
                      stamp:,
                    ),
                  )
                True -> actor.continue(State(..state, stamp:))
                False -> {
                  // trying again content already reported: quietly
                  let #(reloaded, outcome) =
                    reload_file_or_busy(
                      State(..state, stamp:),
                      "watch",
                      quiet: found == state.rejected && state.rejected_read,
                    )
                  case outcome {
                    Ok(_) -> actor.continue(reloaded)
                    // the lock held by another process: the next tick
                    // tries again
                    Error(store_file.LockHeld(_)) ->
                      actor.continue(State(..reloaded, stamp: state.stamp))
                    // a file that does not load (invalid, or without ids
                    // a read-only replica cannot write) is reported once
                    // (the content load read, which may be newer)
                    // a file that does not load is reported once (the
                    // content load read, which may be newer); one that may
                    // load later as it is is tried again by the minute,
                    // quietly if its content was read
                    Error(failure) -> {
                      let #(read, retry, was_read) = case failure {
                        store_file.LockNotCreated(_) -> #("", True, False)
                        store_file.IdsNotWritten(read:, ..) -> #(
                          read,
                          True,
                          True,
                        )
                        store_file.Invalid(read:, ..) -> #(read, False, True)
                        store_file.LockHeld(_) -> #("", False, False)
                      }
                      actor.continue(
                        State(
                          ..reloaded,
                          rejected: case read {
                            "" -> found
                            read -> read
                          },
                          rejected_at: ffi.now_seconds(),
                          rejected_retry: retry,
                          rejected_read: was_read,
                        ),
                      )
                    }
                  }
                }
              }
            }
            Error(simplifile.Enoent) | Ok(_) ->
              actor.continue(State(..state, stamp:))
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
              actor.continue(State(..state, stamp:, unreadable:))
            }
          }
        }
      }
    }

    ReloadInBackground(actor_name) -> {
      let #(state, _) = reload_file(state, actor_name)
      actor.continue(state)
    }

    Reload(actor_name, reply) -> {
      let #(state, outcome) = reload_file(state, actor_name)
      process.send(reply, outcome)
      actor.continue(state)
    }
  }
}

/// Reads the file again (`SIGHUP`, the admin, the API, the watcher): the
/// new state, and the number of rules or why the file was refused.
fn reload_file(
  state: State,
  actor_name: String,
) -> #(State, Result(Int, String)) {
  let #(state, outcome) = reload_file_or_busy(state, actor_name, quiet: False)
  #(state, result.map_error(outcome, fn(failure) { failure.reason }))
}

/// The rules in effect are now `rules`, from the file of `fingerprint`:
/// nothing the watcher rejected is left to try or to skip.
fn in_effect(state: State, rules: List(Rule), fingerprint: String) -> State {
  State(
    ..state,
    rules:,
    fingerprint:,
    rejected: "",
    rejected_retry: False,
    rejected_read: False,
  )
}

/// Whether the content the watcher could not load was valid, and failed a
/// minute ago or more: writing its ids may succeed now (a disk no longer
/// full).
fn retry_rejected(state: State) -> Bool {
  state.rejected_retry
  && ffi.now_seconds() - state.rejected_at
  >= ffi.tunable("rejected_retry_seconds", 60)
}

/// `reload_file`, saying why it failed (`store_file.LoadFailure`).
/// `quiet`, a failure is not reported (content tried again).
fn reload_file_or_busy(
  state: State,
  actor_name: String,
  quiet quiet: Bool,
) -> #(State, Result(Int, store_file.LoadFailure)) {
  let started = ffi.monotonic_micros()
  case
    store_file.load_locked_or_busy(
      files(state.settings),
      store_file.Reloading,
      lock_timeout,
    )
  {
    Ok(#(rules, fingerprint)) -> {
      commit.loaded(target(state.settings), rules, checker.Problems)
      metrics.incr(metrics.Reloads)
      metrics.reloaded(ffi.monotonic_micros() - started)
      audit_rules_change(
        state,
        actor_name,
        "rules.reload",
        int.to_string(list.length(rules)) <> " rule(s)",
        rules,
        fingerprint,
      )
      log.info("reloaded " <> int.to_string(list.length(rules)) <> " rule(s)")
      #(in_effect(state, rules, fingerprint), Ok(list.length(rules)))
    }
    Error(failure) if quiet -> #(state, Error(failure))
    Error(failure) -> {
      let reason = failure.reason
      metrics.incr(metrics.ReloadFailures)
      log.error("reload rejected, keeping current rules: " <> reason)
      audit.record(
        state.settings.audit_path,
        actor_name,
        "rules.reload_failed",
        state.settings.rules_path,
        None,
        Some(json.object([#("error", json.string(reason))])),
      )
      #(state, Error(failure))
    }
  }
}

/// Audits a new rule set: the file fingerprints before and after, and the
/// rules added, removed and changed.
fn audit_rules_change(
  state: State,
  actor_name: String,
  action: String,
  target: String,
  rules: List(Rule),
  fingerprint: String,
) -> Nil {
  audit.record(
    state.settings.audit_path,
    actor_name,
    action,
    target,
    Some(json.object([#("fingerprint", json.string(state.fingerprint))])),
    Some(
      json.object([
        #("fingerprint", json.string(fingerprint)),
        ..store_rules.diff_to_json(store_rules.diff(state.rules, rules))
      ]),
    ),
  )
}

/// Runs a mutation holding the cross-process file lock, on rules refreshed
/// from disk when another process changed the file. `change` returns the
/// reply, the new rules and the fingerprint of the written file.
///
/// A change whose caller stopped waiting while it was queued (it timed out,
/// or exited) is skipped: nothing is written, audited or published.
fn mutate(
  state: State,
  reply: Subject(Result(a, e)),
  to_error: fn(String) -> e,
  change: fn(State) -> Result(#(a, List(Rule), String), e),
) -> actor.Next(State, Message) {
  use <- bool.lazy_guard(abandoned(reply), fn() {
    log.warning("a change was skipped: its caller stopped waiting for it")
    actor.continue(state)
  })
  let outcome =
    ffi.with_file_lock(state.settings.rules_path, lock_timeout, fn() {
      // the lock may have taken long enough for the caller to give up
      use <- bool.lazy_guard(abandoned(reply), fn() {
        log.warning("a change was skipped: its caller stopped waiting for it")
        #(state, Error(to_error("the caller stopped waiting")))
      })
      case refresh(state) {
        Error(reason) -> #(state, Error(to_error(reason)))
        Ok(state) ->
          case change(state) {
            Ok(#(value, rules, fingerprint)) -> {
              let changed = in_effect(state, rules, fingerprint)
              #(save_hits_if_removed(state.rules, changed), Ok(value))
            }
            Error(error) -> #(state, Error(error))
          }
      }
    })
  case outcome {
    Ok(#(state, result)) -> {
      process.send(reply, result)
      actor.continue(state)
    }
    Error(reason) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("redirections not saved: " <> reason)
      process.send(reply, Error(to_error("storage: " <> reason)))
      actor.continue(state)
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

/// Reloads the rules when the file was changed by another process since it
/// was last read or written. A missing file keeps the current rules (they
/// are written back by the mutation).
fn refresh(state: State) -> Result(State, String) {
  case simplifile.read_bits(state.settings.rules_path) {
    Error(simplifile.Enoent) -> Ok(state)
    // not a missing file: one this process cannot read must not be
    // overwritten as if it were
    Error(e) ->
      Error(
        "storage: the redirections file cannot be read ("
        <> simplifile.describe_error(e)
        <> "), so it was not overwritten. Fix its permissions, then retry.",
      )
    Ok(content) ->
      case store_file.fingerprint(content) == state.fingerprint {
        True -> Ok(state)
        False ->
          case
            store_file.load_failing(files(state.settings), store_file.Reloading)
          {
            Error(store_file.IdsNotWritten(reason:, ..)) ->
              Error(
                "storage: the redirections file was changed outside the server, and the ids of its rules without one could not be written, so it was not overwritten. Free space or fix the permissions, then retry. "
                <> reason,
              )
            Error(failure) -> {
              let reason = failure.reason
              Error(
                "storage: the redirections file was changed outside the server and is invalid, so it was not overwritten. Fix it, then retry. "
                <> reason,
              )
            }
            Ok(#(rules, fingerprint)) -> {
              let started = ffi.monotonic_micros()
              commit.loaded(target(state.settings), rules, checker.Problems)
              metrics.incr(metrics.Reloads)
              metrics.reloaded(ffi.monotonic_micros() - started)
              audit_rules_change(
                state,
                "external",
                "rules.reload",
                int.to_string(list.length(rules)) <> " rule(s)",
                rules,
                fingerprint,
              )
              log.warning(
                state.settings.rules_path
                <> " was changed outside the server: reloaded "
                <> int.to_string(list.length(rules))
                <> " rule(s) before applying the change",
              )
              Ok(in_effect(state, rules, fingerprint))
            }
          }
      }
  }
}

fn files(settings: Settings) -> store_file.Files {
  store_file.Files(
    rules_path: settings.rules_path,
    backups_dir: settings.backups_dir,
    backups: settings.backups,
  )
}

/// Saves the hit counts at once when a change removed rules: the saved
/// counts of a deleted rule would otherwise stay in the file until the next
/// save, and a crash meanwhile would restore them onto a new rule created
/// with the same id.
fn save_hits_if_removed(before: List(Rule), after: State) -> State {
  let kept = set.from_list(list.map(after.rules, fn(r) { r.id }))
  case list.any(before, fn(r) { !set.contains(kept, r.id) }) {
    True -> State(..after, hits_written: save_hits(after))
    False -> after
  }
}

fn save_hits(state: State) -> hits.Written {
  hits.save(
    state.settings.hits_path,
    list.map(state.rules, fn(r) { r.id }),
    state.hits_written,
  )
}

fn schedule_watch(settings: Settings, self: Subject(Message)) -> Nil {
  case settings.watch_interval > 0 {
    True -> {
      process.send_after(self, settings.watch_interval, Watch(self))
      Nil
    }
    False -> Nil
  }
}

fn target(settings: Settings) -> commit.Target {
  commit.Target(
    files: files(settings),
    ignore_trailing_slash: settings.ignore_trailing_slash,
  )
}
