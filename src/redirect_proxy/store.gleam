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
////
//// This module is the store's interface and its actor. What a change asks
//// for and why one is refused are in `store/rule_change`, shared with its
//// callers. The actor's work is in `store/*`: how callers wait (`call`),
//// how a change is applied (`mutate`) and what it makes of the rules
//// (`edit`), reloads (`reload`), the file watcher (`watch`), the work each
//// second (`periodic`) and the audit entries (`audit_entries`).

import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None}
import gleam/otp/actor
import gleam/result
import gleam/set
import redirect_proxy/ffi/file as file_ffi
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/field_error.{type FieldError}
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store/audit_entries
import redirect_proxy/store/call.{call, read, rescue_store_timeout}
import redirect_proxy/store/checker
import redirect_proxy/store/commit
import redirect_proxy/store/edit
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits
import redirect_proxy/store/mutate
import redirect_proxy/store/periodic
import redirect_proxy/store/reload
import redirect_proxy/store/rule_change.{
  type BulkAction, type ChangeError, type ImportMode, Busy, Invalid, Storage,
}
import redirect_proxy/store/rules/check
import redirect_proxy/store/rules/diff
import redirect_proxy/store/rules/imports
import redirect_proxy/store/state.{
  type Config, type State, Config, initial as initial_state,
}
import redirect_proxy/store/watch

/// Milliseconds between checks for rules starting or expiring.
const schedule_interval = 1000

/// At start the lock is waited for longer than the 10 seconds after which a
/// lock left by a crashed process is broken, so that start never fails on it.
const start_lock_timeout = 15_000

/// How long callers wait for the store. Mutations queue behind each other and
/// each one may wait `state.lock_timeout` for the file lock, then rebuild the
/// matcher. A caller that stops waiting raises `call.store_timeout` (see
/// `or_unavailable`), and its change is skipped unless the store had begun it.
const timeout = 30_000

/// Runs `run`, or `unavailable` when a store call in it timed out: the store
/// was busy, with changes queued or waiting for the file lock another process
/// holds.
pub fn or_unavailable(run: fn() -> a, unavailable: fn() -> a) -> a {
  rescue_store_timeout(run, unavailable)
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
    reply: Subject(Result(edit.Preview, List(FieldError))),
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

pub type Store =
  Subject(Message)

/// The settings in the form the actor's work uses.
fn config(settings: Settings) -> Config {
  Config(
    target: target(settings),
    rules_path: settings.rules_path,
    audit_path: settings.audit_path,
    watch_interval: settings.watch_interval,
    hits_path: settings.hits_path,
  )
}

fn target(settings: Settings) -> commit.Target {
  commit.Target(
    files: store_file.Files(
      rules_path: settings.rules_path,
      backups_dir: settings.backups_dir,
      backups: settings.backups,
    ),
    ignore_trailing_slash: settings.ignore_trailing_slash,
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
  let config = config(settings)
  actor.new_with_initialiser(30_000, fn(subject) {
    checker.start(settings.rules_path, settings.ignore_trailing_slash, fn() {
      all(subject)
    })
    let started = system_ffi.monotonic_micros()
    let before = #(
      system_ffi.now_seconds(),
      file_ffi.file_stamp(settings.rules_path),
    )
    use state <- result.try(
      case
        store_file.load_locked(
          config.target.files,
          store_file.FirstStart,
          file_ffi.tunable("start_lock_timeout", start_lock_timeout),
        )
      {
        Ok(#(rules, fingerprint)) -> {
          commit.loaded(config.target, rules, fingerprint, checker.Problems)
          metrics.reloaded(system_ffi.monotonic_micros() - started)
          log.info(
            "loaded "
            <> int.to_string(list.length(rules))
            <> " redirection rule(s) from "
            <> settings.rules_path,
          )
          Ok(initial_state(config, rules, fingerprint, before))
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
              Ok(initial_state(config, rules, "", before))
            }
            Error(Nil) -> Error(reason)
          }
      },
    )
    commit.register(subject, settings.rules_path)
    schedule_watch(config, subject)
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

/// The published matcher and the rules it was built from (the URL
/// testers: a match is shown with its rule, and explained from the same
/// rules). Read again while a change is published between the two reads.
pub fn published(store: Store) -> #(matcher.Matcher, List(Rule)) {
  published_within(store, 5)
}

fn published_within(
  store: Store,
  tries: Int,
) -> #(matcher.Matcher, List(Rule)) {
  let current = snapshot.current()
  let #(rules, version) = versioned(store)
  case matcher.version(current) == version || tries <= 1 {
    True -> #(current, rules)
    False -> {
      process.sleep(1)
      published_within(store, tries - 1)
    }
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
  let target = target(settings)
  let locked =
    file_ffi.with_file_lock_detailed(
      settings.rules_path,
      file_ffi.tunable("start_lock_timeout", start_lock_timeout),
      fn() {
        use #(existing, before) <- result.try(
          store_file.load_failing(target.files, store_file.FirstStart)
          |> result.map_error(fn(failure) { Storage(failure.reason) }),
        )
        use #(prepared, rules) <- result.try(
          edit.imported(existing, prepared, mode) |> result.map_error(Invalid),
        )
        let action = edit.import_action(mode)
        let summary = int.to_string(list.length(prepared)) <> " rule(s)"
        let outcome = {
          use _ <- result.try(
            commit.check_many(
              target,
              rules,
              diff.changed_rules(existing, rules),
              check_conflicts: True,
            )
            |> result.map_error(commit.Refused),
          )
          commit.persist(target, rules)
          |> result.map_error(commit.NotWritten)
        }
        case outcome {
          Ok(fingerprint) -> {
            audit_entries.rule_set(
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
            audit_entries.refused(
              settings.audit_path,
              actor_name,
              action,
              summary,
              refusal,
            )
            Error(edit.refused(refusal))
          }
        }
      },
    )
  case locked {
    Ok(outcome) -> outcome
    Error(file_ffi.Held(reason)) -> Error(Busy(reason))
    Error(file_ffi.CannotCreate(reason)) -> Error(Storage(reason))
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
  /// The file was refused (invalid or unreadable): the current rules are
  /// kept.
  ReloadRejected(reason: String)
  /// The file is valid, but its lock could not be created or the ids given
  /// to its rules without one could not be written (a full disk, missing
  /// permissions): the current rules are kept.
  ReloadStorage(reason: String)
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
    Create(input, actor_name, reply) ->
      apply_change(state, reply, edit.create(_, input, actor_name))
    Update(input, expected, actor_name, reply) ->
      apply_change(state, reply, edit.update(_, input, expected, actor_name))
    Delete(rule_id, expected, actor_name, reply) ->
      apply_change(state, reply, edit.delete(_, rule_id, expected, actor_name))
    Import(prepared, mode, expected, actor_name, reply) ->
      apply_change(state, reply, edit.import_prepared(
        _,
        prepared,
        mode,
        expected,
        actor_name,
      ))
    PreviewImport(prepared, mode, reply) -> {
      process.send(reply, edit.preview(state, prepared, mode))
      actor.continue(state)
    }
    Bulk(ids, action, expected, actor_name, reply) ->
      apply_change(state, reply, edit.bulk(_, ids, action, expected, actor_name))
    FlushHits(reply) -> {
      let state = periodic.flush_hits(state)
      process.send(reply, Nil)
      actor.continue(state)
    }
    SaveHits(self) -> {
      process.send_after(self, 1000, SaveHits(self))
      actor.continue(periodic.save_hits_if_due(state))
    }
    Schedule(self) -> {
      process.send_after(self, schedule_interval, Schedule(self))
      actor.continue(periodic.schedule(state))
    }
    Watch(self) -> {
      schedule_watch(state.config, self)
      actor.continue(watch.tick(state))
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

/// Applies a change (`mutate.run`) and replies with its outcome.
fn apply_change(
  state: State,
  reply: Subject(Result(a, ChangeError)),
  change: fn(State) -> Result(#(a, List(Rule), String), ChangeError),
) -> actor.Next(State, Message) {
  mutate.run(state, reply, mutate.Errors(busy: Busy, storage: Storage), change)
  |> actor.continue
}

/// Reads the file again (`SIGHUP`, the admin, the API): the new state, and
/// the number of rules or why the file was refused.
fn reload_file(
  state: State,
  actor_name: String,
) -> #(State, Result(Int, ReloadError)) {
  let #(state, outcome) = reload.reload(state, actor_name, report_busy: True)
  #(
    state,
    result.map_error(outcome, fn(failure) {
      case failure {
        store_file.LockHeld(reason) -> ReloadBusy(reason)
        store_file.LockNotCreated(_)
        | store_file.Content(store_file.IdsNotWritten(..)) ->
          ReloadStorage(store_file.reason(failure))
        store_file.Content(store_file.Invalid(..)) ->
          ReloadRejected(store_file.reason(failure))
      }
    }),
  )
}

fn schedule_watch(config: Config, self: Subject(Message)) -> Nil {
  case config.watch_interval > 0 {
    True -> {
      process.send_after(self, config.watch_interval, Watch(self))
      Nil
    }
    False -> Nil
  }
}
