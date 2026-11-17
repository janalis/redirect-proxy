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
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/id
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/call.{call, read}
import redirect_proxy/store/checker
import redirect_proxy/store/commit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits
import redirect_proxy/store/rules/check
import redirect_proxy/store/rules/diff
import redirect_proxy/store/rules/imports
import redirect_proxy/store/rules/validate
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

/// Why a change was refused: nothing was written.
pub type ChangeError {
  /// The rule to change does not exist.
  NotFound
  /// A rule already has the id given to a new one (a retried creation).
  AlreadyExists
  /// The rule changed since the version the caller based its change on.
  Conflict(current: Rule)
  /// The rule set changed since the version (`versioned`) the caller based
  /// its change of the whole set (an import, a bulk change) on, such as an
  /// import preview.
  Stale(current: String)
  /// The change is invalid.
  Invalid(List(FieldError))
  /// Another process holds the lock of the redirections file past the
  /// wait: retrying soon may succeed.
  Busy(reason: String)
  /// The redirections file could not be read or written (permissions, a
  /// full disk), or was changed outside the server into a file that does
  /// not load.
  Storage(reason: String)
}

/// What an import would make of the rule set, before the checks of the
/// rules it changes (done by the caller, not to block the store).
type Preview {
  Preview(
    diff: diff.Diff,
    fingerprint: String,
    rules: List(Rule),
    ignore_trailing_slash: Bool,
  )
}

pub opaque type Message {
  All(reply: Subject(List(Rule)))
  Versioned(reply: Subject(#(List(Rule), String)))
  Get(id: String, reply: Subject(Result(Rule, Nil)))
  Create(rule: Rule, actor: String, reply: Subject(Result(Rule, ChangeError)))
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
    reply: Subject(Result(Int, ChangeError)),
  )
  /// `rules` are prepared and validated, as for `Import`.
  PreviewImport(
    rules: List(Rule),
    mode: ImportMode,
    reply: Subject(Result(Preview, List(FieldError))),
  )
  Bulk(
    ids: List(String),
    action: BulkAction,
    expected: Option(String),
    actor: String,
    reply: Subject(Result(Int, ChangeError)),
  )
  Reload(actor: String, reply: Subject(Result(Int, ReloadError)))
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

fn bulk_action_to_string(action: BulkAction) -> String {
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
    /// The write of the file (its stamp) the watcher last could not load,
    /// and the fingerprint of its content: reported once, not at every tick
    /// that reads it again, and tried again when the file is written again
    /// (or on `SIGHUP`).
    rejected: Option(#(ffi.FileStamp, String)),
    /// The write of the file the watcher last waited for the lock to load:
    /// said once.
    busy: Option(ffi.FileStamp),
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
    rejected: None,
    busy: None,
    unreadable: "",
    hits_saved_at: ffi.now_seconds(),
    hits_saved_draining: False,
    hits_written: hits.nothing_written,
    checked_at: loaded_at,
    next_boundary: #(rules, rule.next_boundary(rules, loaded_at)),
  )
}

/// Starts the store. Fails if the redirections file exists but is invalid, so
/// that a broken file never silently replaces the configuration.
pub fn start(
  settings: Settings,
  name: Name(Message),
) -> Result(actor.Started(Store), actor.StartError) {
  // for a store started alone: in the application, the table owner
  // (`tables`) created them, and these do nothing
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
          commit.loaded(target(settings), rules, fingerprint, checker.Problems)
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
              // read with the version of the state: the next change
              // re-reads the file
              commit.set_view(settings.rules_path, rules, "")
              Ok(initial_state(settings, rules, "", before))
            }
            Error(Nil) -> Error(reason)
          }
      },
    )
    commit.register(subject, settings.rules_path)
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

/// `all` and `versioned` do not wait for a change in progress: while the
/// store runs, they get the rules in effect (`commit.view`). Before it has
/// started, or while it restarts, they ask it (unavailable then, as any
/// call).
pub fn all(store: Store) -> List(Rule) {
  case view(store) {
    Ok(#(rules, _)) -> rules
    Error(Nil) -> read(store, timeout, All)
  }
}

fn view(store: Store) -> Result(#(List(Rule), String), Nil) {
  case process.subject_owner(store) {
    Ok(_) -> commit.view(store)
    Error(Nil) -> Error(Nil)
  }
}

/// Every rule and the version of the rule set (the fingerprint of the file
/// last read or written), for `import_rules_versioned` and `bulk_versioned`.
pub fn versioned(store: Store) -> #(List(Rule), String) {
  case view(store) {
    Ok(view) -> view
    Error(Nil) -> read(store, timeout, Versioned)
  }
}

/// Asks the store, which sends back the one rule: reading the rules in
/// effect would copy them all into the caller.
pub fn get(store: Store, id: String) -> Result(Rule, Nil) {
  read(store, timeout, Get(id, _))
}

pub fn create(
  store: Store,
  rule: Rule,
  by actor_name: String,
) -> Result(Rule, ChangeError) {
  call(store, timeout, Create(rule, actor_name, _))
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

/// Deletes a rule only if its current version equals `expected` (when given).
pub fn delete_versioned(
  store: Store,
  id: String,
  expected: Option(String),
  by actor_name: String,
) -> Result(Rule, ChangeError) {
  call(store, timeout, Delete(id, expected, actor_name, _))
}

/// `expected` (when given, `*` for any) must be the current version of the
/// rule set.
fn check_collection_version(
  state: State,
  expected: Option(String),
) -> Result(Nil, ChangeError) {
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
) -> Result(Int, ChangeError) {
  import_rules_versioned(store, rules, mode, None, actor_name)
}

/// `import_rules` without a running store, for the `rules import` command:
/// the same validation and checks, file lock, backup and atomic write,
/// audit entry and hit counts kept, in the calling process. Nothing is
/// published: a server serving the file applies the change when it reloads
/// it. Fails with the reasons, among them the lock held by another process
/// past the wait.
pub fn import_into_file(
  settings: Settings,
  rules: List(Rule),
  mode: ImportMode,
  by actor_name: String,
) -> Result(Int, ChangeError) {
  use prepared <- result.try(
    imports.prepare_import(rules, actor_name) |> result.map_error(Invalid),
  )
  let files = files(settings)
  let locked =
    ffi.with_file_lock_detailed(
      settings.rules_path,
      ffi.tunable("start_lock_timeout", start_lock_timeout),
      fn() {
        use #(existing, before) <- result.try(
          store_file.load_failing(files, store_file.FirstStart)
          |> result.map_error(fn(failure) { Storage(failure.reason) }),
        )
        use #(prepared, rules) <- result.try(
          imported(existing, prepared, mode) |> result.map_error(Invalid),
        )
        let action = case mode {
          Replace -> "rules.import.replace"
          Merge -> "rules.import.merge"
        }
        let summary = int.to_string(list.length(prepared)) <> " rule(s)"
        let outcome = {
          use _ <- result.try(
            commit.check_many(
              target(settings),
              rules,
              diff.changed_rules(existing, rules),
              check_conflicts: True,
            )
            |> result.map_error(commit.Refused),
          )
          commit.persist(target(settings), rules)
          |> result.map_error(commit.NotWritten)
        }
        case outcome {
          Ok(fingerprint) -> {
            audit_rule_set(
              settings.audit_path,
              #(existing, before),
              actor_name,
              action,
              summary,
              rules,
              fingerprint,
            )
            hits.keep_only(settings.hits_path, list.map(rules, fn(r) { r.id }))
            Ok(list.length(prepared))
          }
          Error(refusal) -> {
            audit.record(
              settings.audit_path,
              actor_name,
              action <> "_failed",
              summary,
              None,
              Some(refusal_json(refusal)),
            )
            Error(refused(refusal))
          }
        }
      },
    )
  case locked {
    Ok(outcome) -> outcome
    Error(ffi.Held(reason)) -> Error(Busy(reason))
    Error(ffi.CannotCreate(reason)) -> Error(Storage(reason))
  }
}

/// Imports only if the rule set is still at version `expected` (when
/// given): the one a preview was shown for, or read with `versioned`.
pub fn import_rules_versioned(
  store: Store,
  rules: List(Rule),
  mode: ImportMode,
  expected: Option(String),
  by actor_name: String,
) -> Result(Int, ChangeError) {
  // Validation is done here, in the caller's process, so that the store
  // does not hold the file lock (nor block other callers) while it runs.
  use prepared <- result.try(
    imports.prepare_import(rules, actor_name) |> result.map_error(Invalid),
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
) -> Result(#(diff.Diff, String), List(FieldError)) {
  use prepared <- result.try(imports.prepare_import(rules, actor_name))
  use preview <- result.try(
    read(store, 60_000, PreviewImport(prepared, mode, _)),
  )
  let changed_ids =
    set.from_list(list.append(preview.diff.added, preview.diff.changed))
  use Nil <- result.try(check.check_changed(
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
) -> Result(Int, ChangeError) {
  call(store, timeout, Bulk(list.unique(ids), action, expected, actor_name, _))
}

/// What the admin and the API say of a reload that failed, before its
/// reason.
pub const reload_rejected =
  "The redirections file is invalid; the current redirections are kept."

/// Why a reload changed nothing.
pub type ReloadError {
  /// Another process holds the lock of the redirections file past the
  /// wait: retrying soon may succeed.
  ReloadBusy(reason: String)
  /// The file was refused (invalid, unreadable, or its new ids could not be
  /// written): the current rules are kept.
  ReloadRejected(reason: String)
}

pub fn reload(store: Store, by actor_name: String) -> Result(Int, ReloadError) {
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
      use state <- mutate(state, reply)
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
          Error(AlreadyExists),
        )
        use valid <- result.try(
          rule.validate(candidate) |> result.map_error(Invalid),
        )
        let rules = list.append(state.rules, [valid])
        // a new rule only adds matches: a loop it makes goes through it
        use fingerprint <- result.try(
          commit.one(
            target(state.settings),
            valid,
            None,
            rules,
            uncovers: False,
          )
          |> result.map_error(refused),
        )
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
      use state <- mutate(state, reply)
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
          |> result.map_error(refused),
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
      use state <- mutate(state, reply)
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
          |> result.map_error(refused),
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
      use state <- mutate(state, reply)
      {
        use Nil <- result.try(check_collection_version(state, expected))
        use #(prepared, rules) <- result.try(
          imported(state.rules, prepared, mode) |> result.map_error(Invalid),
        )
        let action = case mode {
          Replace -> "rules.import.replace"
          Merge -> "rules.import.merge"
        }
        let outcome =
          commit.many(
            target(state.settings),
            rules,
            changed: diff.changed_rules(state.rules, rules),
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
          Error(refusal) -> {
            audit.record(
              state.settings.audit_path,
              actor_name,
              action <> "_failed",
              int.to_string(list.length(prepared)) <> " rule(s)",
              None,
              Some(refusal_json(refusal)),
            )
            Error(refused(refusal))
          }
        }
      }
    }

    PreviewImport(prepared, mode, reply) -> {
      process.send(reply, {
        use #(_, rules) <- result.try(imported(state.rules, prepared, mode))
        use Nil <- result.try(validate.check_conflicts(rules))
        Ok(Preview(
          diff: diff.diff(state.rules, rules),
          fingerprint: state.fingerprint,
          rules:,
          ignore_trailing_slash: state.settings.ignore_trailing_slash,
        ))
      })
      actor.continue(state)
    }

    Bulk(ids, action, expected, actor_name, reply) -> {
      use state <- mutate(state, reply)
      use Nil <- result.try(check_collection_version(state, expected))
      {
        let known = list.map(state.rules, fn(r) { r.id }) |> set.from_list
        let wanted = set.from_list(ids)
        use <- bool.guard(
          ids == [],
          Error(Invalid([FieldError("ids", "select at least one rule")])),
        )
        use <- bool.guard(
          !list.all(ids, set.contains(known, _)),
          Error(
            Invalid([
              FieldError(
                "ids",
                "unknown rule "
                  <> {
                  list.filter(ids, fn(id) { !set.contains(known, id) })
                  |> string.join(", ")
                },
              ),
            ]),
          ),
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
        use fingerprint <- result.try(
          commit.many(
            target(state.settings),
            rules,
            changed: case action {
              Enable -> diff.changed_rules(state.rules, rules)
              Disable | Remove -> []
            },
            check_conflicts: True,
          )
          |> result.map_error(refused),
        )
        let d = diff.diff(state.rules, rules)
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
      }
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
          commit.loaded(
            target(state.settings),
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
      actor.continue(
        State(..state, checked_at: now, next_boundary: #(state.rules, next)),
      )
    }

    Watch(self) -> {
      schedule_watch(state.settings, self)
      let stamp = ffi.file_stamp(state.settings.rules_path)
      case stamp == state.stamp && !ffi.stamp_is_recent(stamp) {
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
              // the same content, of the write refused (its time may have
              // moved since), not of a write made since
              let skipped = case state.rejected {
                Some(#(at, refused)) ->
                  refused == found && ffi.same_write(at, stamp)
                None -> False
              }
              case found == state.fingerprint || skipped {
                // the content in effect (reverted, or loaded by a change
                // made meanwhile): nothing rejected left to skip
                True if found == state.fingerprint ->
                  actor.continue(
                    State(
                      ..in_effect(state, state.rules, state.fingerprint),
                      stamp:,
                    ),
                  )
                True -> actor.continue(State(..state, stamp:))
                False -> {
                  let #(reloaded, outcome) =
                    reload_file_or_busy(
                      State(..state, stamp:),
                      "watch",
                      report_busy: False,
                    )
                  case outcome {
                    Ok(_) -> actor.continue(reloaded)
                    // the lock held by another process: the next tick
                    // tries again (said once per write of the file: a
                    // lock never released keeps the file from loading)
                    Error(store_file.LockHeld(reason)) -> {
                      case reloaded.busy == Some(stamp) {
                        True -> Nil
                        False ->
                          log.warning(
                            "reload of the redirections file waits for its lock: "
                            <> reason,
                          )
                      }
                      actor.continue(
                        State(..reloaded, stamp: state.stamp, busy: Some(stamp)),
                      )
                    }
                    // a file that does not load (invalid, its ids not
                    // written, the lock not created) is reported once:
                    // tried again when it is written again (a new stamp),
                    // or on SIGHUP
                    Error(failure) ->
                      actor.continue(
                        State(
                          ..reloaded,
                          // the write and content the load read, which may
                          // be newer than this tick's (else this tick's)
                          rejected: Some(case failure {
                            store_file.Content(store_file.Invalid(read:, ..))
                              | store_file.Content(store_file.IdsNotWritten(
                                read:,
                                ..,
                              ))
                              if read != ""
                            -> #(
                              ffi.file_stamp(state.settings.rules_path),
                              read,
                            )
                            _ -> #(stamp, found)
                          }),
                        ),
                      )
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
) -> #(State, Result(Int, ReloadError)) {
  let #(state, outcome) =
    reload_file_or_busy(state, actor_name, report_busy: True)
  #(
    state,
    result.map_error(outcome, fn(failure) {
      case failure {
        store_file.LockHeld(reason) -> ReloadBusy(reason)
        _ -> ReloadRejected(store_file.reason(failure))
      }
    }),
  )
}

/// The rules an import of `prepared` leaves, and `prepared` with its ids
/// resolved against the `existing` rules: the same for an import and its
/// preview. Rules imported again unchanged are kept as they were.
fn imported(
  existing: List(Rule),
  prepared: List(Rule),
  mode: ImportMode,
) -> Result(#(List(Rule), List(Rule)), List(FieldError)) {
  imports.apply(existing, prepared, replace: mode == Replace)
}

/// The rules in effect are now `rules`, from the file of `fingerprint`:
/// nothing the watcher rejected is left to skip.
fn in_effect(state: State, rules: List(Rule), fingerprint: String) -> State {
  State(..state, rules:, fingerprint:, rejected: None, busy: None)
}

/// `reload_file`, saying why it failed (`store_file.LoadFailure`). Without
/// `report_busy`, a lock held by another process is left to the caller to
/// report (the watcher says it once per write, and tries again at its next
/// tick).
fn reload_file_or_busy(
  state: State,
  actor_name: String,
  report_busy report_busy: Bool,
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
      commit.loaded(
        target(state.settings),
        rules,
        fingerprint,
        checker.Problems,
      )
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
    Error(store_file.LockHeld(_) as failure) if !report_busy -> #(
      state,
      Error(failure),
    )
    Error(failure) -> {
      let reason = store_file.reason(failure)
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
  audit_rule_set(
    state.settings.audit_path,
    #(state.rules, state.fingerprint),
    actor_name,
    action,
    target,
    rules,
    fingerprint,
  )
}

/// `audit_rules_change`, from the rules and fingerprint `before`.
fn audit_rule_set(
  audit_path: String,
  before: #(List(Rule), String),
  actor_name: String,
  action: String,
  target: String,
  rules: List(Rule),
  fingerprint: String,
) -> Nil {
  audit.record(
    audit_path,
    actor_name,
    action,
    target,
    Some(json.object([#("fingerprint", json.string(before.1))])),
    Some(
      json.object([
        #("fingerprint", json.string(fingerprint)),
        ..diff.to_json(diff.diff(before.0, rules))
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
  reply: Subject(Result(a, ChangeError)),
  change: fn(State) -> Result(#(a, List(Rule), String), ChangeError),
) -> actor.Next(State, Message) {
  use <- bool.lazy_guard(abandoned(reply), fn() {
    log.warning("a change was skipped: its caller stopped waiting for it")
    actor.continue(state)
  })
  let outcome =
    ffi.with_file_lock_detailed(state.settings.rules_path, lock_timeout, fn() {
      // the lock may have taken long enough for the caller to give up
      use <- bool.lazy_guard(abandoned(reply), fn() {
        log.warning("a change was skipped: its caller stopped waiting for it")
        #(state, Error(Busy("the caller stopped waiting")))
      })
      case refresh(state) {
        Error(reason) -> #(state, Error(Storage(reason)))
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
    Error(failure) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("redirections not saved: " <> failure.message)
      process.send(
        reply,
        Error(case failure {
          ffi.Held(reason) -> Busy(reason)
          ffi.CannotCreate(reason) -> Storage(reason)
        }),
      )
      actor.continue(state)
    }
  }
}

/// A change `commit` refused.
fn refused(refusal: commit.Refusal) -> ChangeError {
  case refusal {
    commit.Refused(errors) -> Invalid(errors)
    commit.NotWritten(reason) -> Storage(reason)
  }
}

/// The errors of a change `commit` refused, for its audit entry.
fn refusal_json(refusal: commit.Refusal) -> json.Json {
  let errors = case refusal {
    commit.Refused(errors) -> field_error.to_strings(errors)
    commit.NotWritten(reason) -> ["storage: " <> reason]
  }
  json.object([#("errors", json.array(errors, json.string))])
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
        "the redirections file cannot be read ("
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
                "the redirections file was changed outside the server, and the ids of its rules without one could not be written, so it was not overwritten. Free space or fix the permissions, then retry. "
                <> reason,
              )
            Error(store_file.Invalid(reason:, ..)) ->
              Error(
                "the redirections file was changed outside the server and is invalid, so it was not overwritten. Fix it, then retry. "
                <> reason,
              )
            Ok(#(rules, fingerprint)) -> {
              let started = ffi.monotonic_micros()
              commit.loaded(
                target(state.settings),
                rules,
                fingerprint,
                checker.Problems,
              )
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
