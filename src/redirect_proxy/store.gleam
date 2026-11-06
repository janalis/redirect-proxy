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

import gleam/bit_array
import gleam/bool
import gleam/crypto
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
import redirect_proxy/store/rules.{
  check_conflicts, check_loop, merge, prepare_import, validate_all, warn_loops,
} as store_rules
import simplifile

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

pub opaque type Message {
  All(reply: Subject(List(Rule)))
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
    actor: String,
    reply: Subject(Result(Int, List(String))),
  )
  /// `rules` are prepared and validated, as for `Import`.
  PreviewImport(
    rules: List(Rule),
    mode: ImportMode,
    reply: Subject(Result(store_rules.Diff, List(String))),
  )
  Bulk(
    ids: List(String),
    action: BulkAction,
    actor: String,
    reply: Subject(Result(Int, List(String))),
  )
  Reload(actor: String, reply: Subject(Result(Int, String)))
  ReloadInBackground(actor: String)
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
  actor.new_with_initialiser(30_000, fn(subject) {
    let started = ffi.monotonic_micros()
    use #(rules, fingerprint) <- result.try(load_locked(
      settings,
      FirstStart,
      start_lock_timeout,
    ))
    let state = State(settings:, rules:, fingerprint:)
    publish(warn_loops(matcher.build(rules), rules))
    metrics.reloaded(ffi.monotonic_micros() - started)
    log.info(
      "loaded "
      <> int.to_string(list.length(rules))
      <> " redirection rule(s) from "
      <> settings.rules_path,
    )
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
  // Validation is done here, in the caller's process, so that the store
  // does not hold the file lock (nor block other callers) while it runs.
  use prepared <- result.try(prepare_import(rules, actor_name))
  actor.call(store, 60_000, Import(prepared, mode, actor_name, _))
}

/// What an import would change, without writing anything: rules added,
/// removed and changed (by id). Fails like `import_rules` would.
pub fn preview_import(
  store: Store,
  rules: List(Rule),
  mode: ImportMode,
  by actor_name: String,
) -> Result(store_rules.Diff, List(String)) {
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
  actor.call(store, timeout, Bulk(list.unique(ids), action, actor_name, _))
}

pub fn reload(store: Store, by actor_name: String) -> Result(Int, String) {
  actor.call(store, 60_000, Reload(actor_name, _))
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
        use Nil <- result.try(check_conflicts(rules))
        let built = matcher.build(rules)
        use Nil <- result.try(check_loop(built, valid))
        use fingerprint <- result.try(commit(state.settings, rules, built))
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
        use Nil <- result.try(
          check_conflicts(rules) |> result.map_error(Invalid),
        )
        let built = matcher.build(rules)
        use Nil <- result.try(
          check_loop(built, valid) |> result.map_error(Invalid),
        )
        use fingerprint <- result.try(
          commit(state.settings, rules, built) |> result.map_error(Invalid),
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
        // removing a rule may uncover a loop it was shadowing
        let built = warn_loops(matcher.build(rules), rules)
        use fingerprint <- result.try(
          commit(state.settings, rules, built) |> result.map_error(Invalid),
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

    Import(prepared, mode, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { [e] })
      {
        let rules = case mode {
          Replace -> prepared
          Merge -> merge(state.rules, prepared)
        }
        let action = case mode {
          Replace -> "rules.import.replace"
          Merge -> "rules.import.merge"
        }
        let outcome = {
          use Nil <- result.try(check_conflicts(rules))
          let built = warn_loops(matcher.build(rules), rules)
          commit(state.settings, rules, built)
        }
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
            Error(errors)
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
          |> result.map(fn(_) { store_rules.diff(state.rules, rules) }),
      )
      actor.continue(state)
    }

    Bulk(ids, action, actor_name, reply) -> {
      use state <- mutate(state, reply, fn(e) { [e] })
      {
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
        use Nil <- result.try(check_conflicts(rules))
        let built = warn_loops(matcher.build(rules), rules)
        use fingerprint <- result.try(commit(state.settings, rules, built))
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
      case load_locked(state.settings, Reloading, lock_timeout) {
        Ok(#(rules, fingerprint)) -> {
          publish(warn_loops(matcher.build(rules), rules))
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
      case fingerprint(content) == state.fingerprint {
        True -> Ok(state)
        False ->
          case load(state.settings, Reloading) {
            Error(reason) ->
              Error(
                "storage: the redirections file was changed outside the server and is invalid, so it was not overwritten. Fix it, then retry. "
                <> reason,
              )
            Ok(#(rules, fingerprint)) -> {
              let started = ffi.monotonic_micros()
              publish(warn_loops(matcher.build(rules), rules))
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

fn fingerprint(content: BitArray) -> String {
  crypto.hash(crypto.Sha256, content) |> bit_array.base16_encode
}

fn publish(built: matcher.Matcher) -> Nil {
  built
  |> matcher.carry_hits(from: snapshot.current())
  |> snapshot.publish
  // Building and parsing leave a lot of garbage in this long lived process.
  ffi.garbage_collect()
}

/// Writes then publishes the rules (`built` is their matcher). Returns the
/// fingerprint of the file.
fn commit(
  settings: Settings,
  rules: List(Rule),
  built: matcher.Matcher,
) -> Result(String, List(String)) {
  case persist(settings, rules) {
    Ok(fingerprint) -> {
      publish(built)
      Ok(fingerprint)
    }
    Error(reason) -> {
      log.error("failed to persist redirections: " <> reason)
      Error(["storage: " <> reason])
    }
  }
}

type LoadMode {
  /// Server start: a missing file is created empty.
  FirstStart
  /// Reload: a missing file is an error, so that the current rules stay live
  /// while the file is being replaced or was moved away.
  Reloading
}

/// `load` holding the cross-process file lock, for callers that do not hold
/// it already: loading may write the file back.
fn load_locked(
  settings: Settings,
  mode: LoadMode,
  wait: Int,
) -> Result(#(List(Rule), String), String) {
  ffi.with_file_lock(settings.rules_path, wait, fn() { load(settings, mode) })
  |> result.flatten
}

/// Reads, validates and returns the rules with the file fingerprint. Writes
/// the file when it is created or when ids were assigned, so the caller must
/// hold the file lock.
fn load(
  settings: Settings,
  mode: LoadMode,
) -> Result(#(List(Rule), String), String) {
  case simplifile.is_file(settings.rules_path), mode {
    Ok(True), _ -> {
      use bits <- result.try(
        simplifile.read_bits(settings.rules_path)
        |> result.map_error(fn(e) {
          "cannot read "
          <> settings.rules_path
          <> ": "
          <> simplifile.describe_error(e)
        }),
      )
      use content <- result.try(
        bit_array.to_string(bits)
        |> result.replace_error(settings.rules_path <> ": not valid UTF-8"),
      )
      use rules <- result.try(
        rule.file_from_string(content)
        |> result.map_error(fn(e) { settings.rules_path <> ": " <> e }),
      )
      // Hand written files may omit ids: assign them on load and write them
      // back so that they stay stable across reloads.
      let missing_ids = list.any(rules, fn(r) { r.id == "" })
      let rules =
        list.map(rules, fn(r) {
          case r.id {
            "" -> rule.Rule(..r, id: id.uuid())
            _ -> r
          }
        })
      use rules <- result.try(
        validate_all(rules)
        |> result.map_error(fn(errors) {
          settings.rules_path <> ": " <> string.join(errors, "; ")
        }),
      )
      case missing_ids {
        True ->
          persist(settings, rules)
          |> result.map(fn(fingerprint) { #(rules, fingerprint) })
        False -> Ok(#(rules, fingerprint(bits)))
      }
    }
    Ok(False), FirstStart -> {
      // First start: create an empty file so operators know where it lives.
      use fingerprint <- result.try(persist(settings, []))
      Ok(#([], fingerprint))
    }
    Ok(False), Reloading -> Error(settings.rules_path <> ": file not found")
    Error(e), _ ->
      Error(
        "cannot read "
        <> settings.rules_path
        <> ": "
        <> simplifile.describe_error(e),
      )
  }
}

/// Backs up then atomically rewrites the file. Returns its fingerprint.
fn persist(settings: Settings, rules: List(Rule)) -> Result(String, String) {
  let describe = fn(e) { simplifile.describe_error(e) }
  use Nil <- result.try(
    simplifile.create_directory_all(settings.backups_dir)
    |> result.map_error(describe),
  )
  use Nil <- result.try(backup(settings))
  let content = rule.file_to_string(rules) <> "\n"
  use Nil <- result.try(ffi.atomic_write(settings.rules_path, content))
  Ok(fingerprint(bit_array.from_string(content)))
}

fn backup(settings: Settings) -> Result(Nil, String) {
  case settings.backups, simplifile.is_file(settings.rules_path) {
    0, _ -> Ok(Nil)
    _, Ok(True) -> {
      let name = backup_name(settings.backups_dir, ffi.now_millis())
      use Nil <- result.try(
        simplifile.copy_file(settings.rules_path, name)
        |> result.map_error(simplifile.describe_error),
      )
      prune_backups(settings)
      Ok(Nil)
    }
    _, _ -> Ok(Nil)
  }
}

/// `redirects-<ms>.json`, bumping the timestamp while the name is taken (two
/// writes in the same millisecond) so names stay unique and sortable.
fn backup_name(dir: String, millis: Int) -> String {
  let name = dir <> "/redirects-" <> int.to_string(millis) <> ".json"
  case simplifile.is_file(name) {
    Ok(True) -> backup_name(dir, millis + 1)
    _ -> name
  }
}

fn prune_backups(settings: Settings) -> Nil {
  case simplifile.read_directory(settings.backups_dir) {
    Ok(files) -> {
      files
      |> list.filter(fn(f) {
        string.starts_with(f, "redirects-") && string.ends_with(f, ".json")
      })
      // names embed a millisecond timestamp of constant width: sort newest first
      |> list.sort(fn(a, b) { string.compare(b, a) })
      |> list.drop(settings.backups)
      |> list.each(fn(f) {
        let _ = simplifile.delete(settings.backups_dir <> "/" <> f)
        Nil
      })
    }
    Error(_) -> Nil
  }
}
