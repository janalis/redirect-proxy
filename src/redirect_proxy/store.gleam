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
import redirect_proxy/snapshot
import redirect_proxy/store/file as store_file
import redirect_proxy/store/hits
import redirect_proxy/store/rules.{
  check_conflicts, check_lint, check_loop, merge, prepare_import, warn_loops,
  warn_problems,
} as store_rules
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
/// matcher: a caller timing out would crash while its change still commits.
const timeout = 30_000

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
    reply: Subject(Result(#(store_rules.Diff, String), List(String))),
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
pub fn start(
  settings: Settings,
  name: Name(Message),
) -> Result(actor.Started(Store), actor.StartError) {
  ffi.ets_new(last_good_table)
  ffi.ets_new(checkers_table)
  actor.new_with_initialiser(30_000, fn(subject) {
    start_checker(subject, settings)
    let started = ffi.monotonic_micros()
    use state <- result.try(
      case
        store_file.load_locked(
          files(settings),
          store_file.FirstStart,
          start_lock_timeout,
        )
      {
        Ok(#(rules, fingerprint)) -> {
          publish(matcher.build(rules), settings, rules)
          request_check(settings, Problems)
          metrics.reloaded(ffi.monotonic_micros() - started)
          log.info(
            "loaded "
            <> int.to_string(list.length(rules))
            <> " redirection rule(s) from "
            <> settings.rules_path,
          )
          Ok(
            State(
              settings:,
              rules:,
              fingerprint:,
              stamp: ffi.file_stamp(settings.rules_path),
              hits_saved_at: ffi.now_seconds(),
              hits_saved_draining: False,
              hits_written: hits.nothing_written,
              checked_at: ffi.now_seconds(),
              next_boundary: #(
                rules,
                rule.next_boundary(rules, ffi.now_seconds()),
              ),
            ),
          )
        }
        Error(reason) ->
          // A restart after a crash: the last good rules are still being
          // served. Keep them rather than failing again until the supervisor
          // gives up and stops the whole node. The empty fingerprint makes
          // the next change re-read the file first (and refuse while it is
          // invalid).
          case ffi.ets_get(last_good_table, settings.rules_path) {
            Ok(rules) -> {
              metrics.incr(metrics.ReloadFailures)
              log.error(
                "store restarted with an invalid redirections file, keeping the "
                <> int.to_string(list.length(rules))
                <> " rule(s) loaded before: "
                <> reason,
              )
              Ok(
                State(
                  settings:,
                  rules:,
                  fingerprint: "",
                  stamp: ffi.file_stamp(settings.rules_path),
                  hits_saved_at: ffi.now_seconds(),
                  hits_saved_draining: False,
                  hits_written: hits.nothing_written,
                  checked_at: ffi.now_seconds(),
                  next_boundary: #(
                    rules,
                    rule.next_boundary(rules, ffi.now_seconds()),
                  ),
                ),
              )
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
  actor.call(store, timeout, All)
}

/// Every rule and the version of the rule set (the fingerprint of the file
/// last read or written), for `import_rules_versioned` and `bulk_versioned`.
pub fn versioned(store: Store) -> #(List(Rule), String) {
  actor.call(store, timeout, Versioned)
}

pub fn get(store: Store, id: String) -> Result(Rule, Nil) {
  actor.call(store, timeout, Get(id, _))
}

pub fn create(
  store: Store,
  rule: Rule,
  by actor_name: String,
) -> Result(Rule, List(String)) {
  actor.call(store, timeout, Create(rule, actor_name, _))
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
  actor.call(store, timeout, Update(rule, expected, actor_name, _))
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
  actor.call(store, timeout, Delete(id, expected, actor_name, _))
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
  actor.call(store, 60_000, Import(prepared, mode, expected, actor_name, _))
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
  actor.call(store, 60_000, PreviewImport(prepared, mode, _))
}

/// Enables, disables or deletes several rules in one write, recorded as one
/// audit entry. Every id must exist. Returns the number of rules changed.
pub fn bulk(
  store: Store,
  ids: List(String),
  action: BulkAction,
  by actor_name: String,
) -> Result(Int, List(String)) {
  bulk_versioned(store, ids, action, None, actor_name)
  |> result.map_error(describe_set_change_error)
}

/// `bulk`, only if the rule set is still at version `expected` (when given).
pub fn bulk_versioned(
  store: Store,
  ids: List(String),
  action: BulkAction,
  expected: Option(String),
  by actor_name: String,
) -> Result(Int, SetChangeError) {
  actor.call(store, timeout, Bulk(
    list.unique(ids),
    action,
    expected,
    actor_name,
    _,
  ))
}

pub fn reload(store: Store, by actor_name: String) -> Result(Int, String) {
  actor.call(store, 60_000, Reload(actor_name, _))
}

/// Saves the hit counts and waits for the write, so that the hits counted
/// while draining before a stop are kept.
pub fn flush_hits(store: Store) -> Nil {
  actor.call(store, 10_000, FlushHits)
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
        use fingerprint <- result.try(commit_rule(
          state.settings,
          valid,
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
          commit_rule(state.settings, valid, rules, uncovers: True)
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
          commit_rules(state.settings, rules, check_conflicts: False)
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
        use Nil <- result.try(check_collection_version(state, expected))
        let rules = case mode {
          Replace -> prepared
          Merge -> merge(state.rules, prepared)
        }
        let action = case mode {
          Replace -> "rules.import.replace"
          Merge -> "rules.import.merge"
        }
        let outcome = commit_rules(state.settings, rules, check_conflicts: True)
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
      let rules = case mode {
        Replace -> prepared
        Merge -> merge(state.rules, prepared)
      }
      process.send(
        reply,
        check_conflicts(rules)
          |> result.map(fn(_) {
            #(store_rules.diff(state.rules, rules), state.fingerprint)
          }),
      )
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
        // enabling may bring two exact rules for one path back together
        use fingerprint <- result.try(commit_rules(
          state.settings,
          rules,
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
          publish(matcher.build(state.rules), state.settings, state.rules)
          request_check(state.settings, Loops)
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
      case stamp == state.stamp {
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
          let state = State(..state, stamp:)
          // the store's own writes leave the fingerprint unchanged
          case content {
            Ok(content) if content != <<>> ->
              case store_file.fingerprint(content) == state.fingerprint {
                True -> actor.continue(state)
                False -> handle(state, ReloadInBackground("watch"))
              }
            _ -> actor.continue(state)
          }
        }
      }
    }

    ReloadInBackground(actor_name) -> {
      let reply = process.new_subject()
      let next = handle(state, Reload(actor_name, reply))
      // drain our own reply
      let _ = process.receive(reply, 0)
      next
    }

    Reload(actor_name, reply) -> {
      let started = ffi.monotonic_micros()
      case
        store_file.load_locked(
          files(state.settings),
          store_file.Reloading,
          lock_timeout,
        )
      {
        Ok(#(rules, fingerprint)) -> {
          publish(matcher.build(rules), state.settings, rules)
          request_check(state.settings, Problems)
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
          log.info(
            "reloaded " <> int.to_string(list.length(rules)) <> " rule(s)",
          )
          process.send(reply, Ok(list.length(rules)))
          actor.continue(State(..state, rules:, fingerprint:))
        }
        Error(reason) -> {
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
          process.send(reply, Error(reason))
          actor.continue(state)
        }
      }
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
fn mutate(
  state: State,
  reply: Subject(Result(a, e)),
  to_error: fn(String) -> e,
  change: fn(State) -> Result(#(a, List(Rule), String), e),
) -> actor.Next(State, Message) {
  let outcome =
    ffi.with_file_lock(state.settings.rules_path, lock_timeout, fn() {
      case refresh(state) {
        Error(reason) -> #(state, Error(to_error(reason)))
        Ok(state) ->
          case change(state) {
            Ok(#(value, rules, fingerprint)) -> #(
              State(..state, rules:, fingerprint:),
              Ok(value),
            )
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

/// Reloads the rules when the file was changed by another process since it
/// was last read or written. A missing file keeps the current rules (they
/// are written back by the mutation).
fn refresh(state: State) -> Result(State, String) {
  case simplifile.read_bits(state.settings.rules_path) {
    Error(_) -> Ok(state)
    Ok(content) ->
      case store_file.fingerprint(content) == state.fingerprint {
        True -> Ok(state)
        False ->
          case store_file.load(files(state.settings), store_file.Reloading) {
            Error(reason) ->
              Error(
                "storage: the redirections file was changed outside the server and is invalid, so it was not overwritten. Fix it, then retry. "
                <> reason,
              )
            Ok(#(rules, fingerprint)) -> {
              let started = ffi.monotonic_micros()
              publish(matcher.build(rules), state.settings, rules)
              request_check(state.settings, Problems)
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
              Ok(State(..state, rules:, fingerprint:))
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

/// The last rules published, by file path: what a restarted store resumes
/// from when the file has become invalid. Created by the process calling
/// `start` (the supervisor), so that it outlives the store process.
const last_good_table = "redirect_proxy_store_last_good"

// --- background checks ---------------------------------------------------------

/// The checker of each store, by rules path.
const checkers_table = "redirect_proxy_store_checkers"

/// What to log about the rules now published: only redirect loops (a change
/// that may uncover one elsewhere), or also the rules that can never apply
/// (a whole new rule set).
type Check {
  Loops
  Problems
}

/// Logging the loops and the rules that can never apply goes over every
/// rule: at 50 000 rules it takes about half a second. It only logs, so it
/// runs in a process of its own, after the change is answered, rather than
/// in the store's, before. A burst of changes is checked once, on the rules
/// as they are when the checker gets to it. Linked to the store: they stop
/// together.
fn start_checker(store: Store, settings: Settings) -> Nil {
  let ready = process.new_subject()
  process.spawn(fn() {
    let checks = process.new_subject()
    process.send(ready, checks)
    checker_loop(checks, store, settings.ignore_trailing_slash)
  })
  let assert Ok(checks) = process.receive(ready, 5000)
  ffi.ets_put(checkers_table, settings.rules_path, checks)
}

fn request_check(settings: Settings, check: Check) -> Nil {
  case ffi.ets_get(checkers_table, settings.rules_path) {
    Ok(checks) -> process.send(checks, check)
    Error(Nil) -> Nil
  }
}

fn checker_loop(
  checks: Subject(Check),
  store: Store,
  ignore_trailing_slash: Bool,
) -> Nil {
  let check = pending_checks(checks, process.receive_forever(checks))
  let outcome =
    ffi.rescue(fn() {
      // the rules as published: the snapshot is their matcher
      let rules = all(store)
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
  checker_loop(checks, store, ignore_trailing_slash)
}

/// The checks requested meanwhile, as one: `Problems` covers `Loops`.
fn pending_checks(checks: Subject(Check), check: Check) -> Check {
  case process.receive(checks, 0) {
    Ok(next) ->
      pending_checks(checks, case check, next {
        Problems, _ | _, Problems -> Problems
        Loops, Loops -> Loops
      })
    Error(Nil) -> check
  }
}

fn publish(
  built: matcher.Matcher,
  settings: Settings,
  rules: List(Rule),
) -> Nil {
  ffi.ets_put(last_good_table, settings.rules_path, rules)
  built
  |> matcher.carry_hits(from: snapshot.current())
  |> snapshot.publish
  // Building and parsing leave a lot of garbage in this long lived process.
  ffi.garbage_collect()
}

/// Checks then commits a change of one rule (`changed`, in `rules`): it
/// must be able to apply, conflict with no other rule and not loop. With
/// `uncovers`, loops the change uncovers elsewhere are logged (an updated
/// rule may no longer shadow one that loops).
fn commit_rule(
  settings: Settings,
  changed: Rule,
  rules: List(Rule),
  uncovers uncovers: Bool,
) -> Result(String, List(String)) {
  use Nil <- result.try(check_lint(changed))
  use Nil <- result.try(check_conflicts(rules))
  let built = matcher.build(rules)
  use Nil <- result.try(check_loop(
    built,
    changed,
    settings.ignore_trailing_slash,
  ))
  use fingerprint <- result.try(commit(settings, rules, built))
  case uncovers {
    True -> request_check(settings, Loops)
    False -> Nil
  }
  Ok(fingerprint)
}

/// Commits a change of a set of rules (bulk, import, delete), checking
/// conflicts when the change can add some, and logging the loops and rules
/// that can never apply.
fn commit_rules(
  settings: Settings,
  rules: List(Rule),
  check_conflicts check: Bool,
) -> Result(String, List(String)) {
  use Nil <- result.try(case check {
    True -> check_conflicts(rules)
    False -> Ok(Nil)
  })
  use fingerprint <- result.try(commit(settings, rules, matcher.build(rules)))
  request_check(settings, Problems)
  Ok(fingerprint)
}

/// Writes then publishes the rules (`built` is their matcher). Returns the
/// fingerprint of the file.
fn commit(
  settings: Settings,
  rules: List(Rule),
  built: matcher.Matcher,
) -> Result(String, List(String)) {
  case store_file.persist(files(settings), rules) {
    Ok(fingerprint) -> {
      publish(built, settings, rules)
      Ok(fingerprint)
    }
    Error(reason) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("failed to persist redirections: " <> reason)
      Error(["storage: " <> reason])
    }
  }
}
