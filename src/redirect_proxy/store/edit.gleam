//// What each change asked of the store makes of the rules: the new rule
//// set and the file it is written to, with its audit entry, or why the
//// change was refused. Run by the store's actor (`mutate.run`), holding
//// the file lock.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set
import gleam/string
import redirect_proxy/audit
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/id
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/audit_entries
import redirect_proxy/store/commit
import redirect_proxy/store/rule_change.{
  type BulkAction, type ChangeError, type ImportMode, AlreadyExists, Conflict,
  Disable, Enable, Invalid, Merge, NotFound, Remove, Replace, Stale, Storage,
}
import redirect_proxy/store/rules/diff
import redirect_proxy/store/rules/imports
import redirect_proxy/store/rules/validate
import redirect_proxy/store/state.{type State}

/// What an import would make of the rule set, before the checks of the
/// rules it changes (done by the caller, not to block the store).
pub type Preview {
  Preview(
    diff: diff.Diff,
    fingerprint: String,
    rules: List(Rule),
    ignore_trailing_slash: Bool,
  )
}

pub fn create(
  state: State,
  input: Rule,
  actor_name: String,
) -> Result(#(Rule, List(Rule), String), ChangeError) {
  let now = system_ffi.now_rfc3339()
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
  use <- bool.guard(
    list.any(state.rules, fn(r) { r.id == new_id }),
    Error(AlreadyExists),
  )
  use valid <- result.try(rule.validate(candidate) |> result.map_error(Invalid))
  let rules = list.append(state.rules, [valid])
  // a new rule only adds matches: a loop it makes goes through it
  use fingerprint <- result.try(
    commit.one(state.config.target, valid, None, rules, uncovers: False)
    |> result.map_error(refused),
  )
  audit.record(
    state.config.audit_path,
    actor_name,
    "rule.create",
    valid.id,
    None,
    Some(rule.to_json(valid)),
  )
  Ok(#(valid, rules, fingerprint))
}

pub fn update(
  state: State,
  input: Rule,
  expected: Option(String),
  actor_name: String,
) -> Result(#(Rule, List(Rule), String), ChangeError) {
  use existing <- result.try(
    list.find(state.rules, fn(r) { r.id == input.id })
    |> result.replace_error(NotFound),
  )
  use Nil <- result.try(check_version(existing, expected))
  let candidate =
    rule.Rule(
      ..input,
      created_at: existing.created_at,
      updated_at: system_ffi.now_rfc3339(),
      updated_by: actor_name,
    )
  use valid <- result.try(rule.validate(candidate) |> result.map_error(Invalid))
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
      state.config.target,
      valid,
      Some(existing),
      rules,
      uncovers: True,
    )
    |> result.map_error(refused),
  )
  audit.record(
    state.config.audit_path,
    actor_name,
    "rule.update",
    valid.id,
    Some(rule.to_json(existing)),
    Some(rule.to_json(valid)),
  )
  Ok(#(valid, rules, fingerprint))
}

pub fn delete(
  state: State,
  rule_id: String,
  expected: Option(String),
  actor_name: String,
) -> Result(#(Rule, List(Rule), String), ChangeError) {
  use existing <- result.try(
    list.find(state.rules, fn(r) { r.id == rule_id })
    |> result.replace_error(NotFound),
  )
  use Nil <- result.try(check_version(existing, expected))
  let rules = list.filter(state.rules, fn(r) { r.id != rule_id })
  // removing a rule adds no conflict (and a file with conflicts can
  // still lose rules); it may uncover a loop it was shadowing
  use fingerprint <- result.try(
    commit.many(state.config.target, rules, changed: [], check_conflicts: False)
    |> result.map_error(refused),
  )
  audit.record(
    state.config.audit_path,
    actor_name,
    "rule.delete",
    rule_id,
    Some(rule.to_json(existing)),
    None,
  )
  Ok(#(existing, rules, fingerprint))
}

pub fn import_prepared(
  state: State,
  prepared: List(Rule),
  mode: ImportMode,
  expected: Option(String),
  actor_name: String,
) -> Result(#(Int, List(Rule), String), ChangeError) {
  use Nil <- result.try(check_collection_version(state, expected))
  use #(prepared, rules) <- result.try(
    imported(state.rules, prepared, mode) |> result.map_error(Invalid),
  )
  let action = import_action(mode)
  let summary = int.to_string(list.length(prepared)) <> " rule(s)"
  let outcome =
    commit.many(
      state.config.target,
      rules,
      changed: diff.changed_rules(state.rules, rules),
      check_conflicts: True,
    )
  case outcome {
    Ok(fingerprint) -> {
      audit_entries.rules_change(
        state,
        actor_name,
        action,
        summary,
        rules,
        fingerprint,
      )
      Ok(#(list.length(prepared), rules, fingerprint))
    }
    Error(refusal) -> {
      audit_entries.refused(
        state.config.audit_path,
        actor_name,
        action,
        summary,
        refusal,
      )
      Error(refused(refusal))
    }
  }
}

pub fn preview(
  state: State,
  prepared: List(Rule),
  mode: ImportMode,
) -> Result(Preview, List(FieldError)) {
  use #(_, rules) <- result.try(imported(state.rules, prepared, mode))
  use Nil <- result.try(validate.check_conflicts(rules))
  Ok(Preview(
    diff: diff.diff(state.rules, rules),
    fingerprint: state.fingerprint,
    rules:,
    ignore_trailing_slash: state.config.target.ignore_trailing_slash,
  ))
}

pub fn bulk(
  state: State,
  ids: List(String),
  action: BulkAction,
  expected: Option(String),
  actor_name: String,
) -> Result(#(Int, List(Rule), String), ChangeError) {
  use Nil <- result.try(check_collection_version(state, expected))
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
  let now = system_ffi.now_rfc3339()
  let change = fn(r: Rule, enabled: Bool) {
    case set.contains(wanted, r.id) && r.enabled != enabled {
      True -> rule.Rule(..r, enabled:, updated_at: now, updated_by: actor_name)
      False -> r
    }
  }
  let rules = case action {
    Remove -> list.filter(state.rules, fn(r) { !set.contains(wanted, r.id) })
    Enable -> list.map(state.rules, change(_, True))
    Disable -> list.map(state.rules, change(_, False))
  }
  // enabling may bring two exact rules for one path back together, or
  // rules that loop or can never apply
  use fingerprint <- result.try(
    commit.many(
      state.config.target,
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
  audit_entries.rules_change(
    state,
    actor_name,
    "rules.bulk." <> rule_change.bulk_action_to_string(action),
    int.to_string(count) <> " rule(s)",
    rules,
    fingerprint,
  )
  Ok(#(count, rules, fingerprint))
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

/// The rules an import of `prepared` leaves, and `prepared` with its ids
/// resolved (`imports.apply`).
pub fn imported(
  existing: List(Rule),
  prepared: List(Rule),
  mode: ImportMode,
) -> Result(#(List(Rule), List(Rule)), List(FieldError)) {
  imports.apply(existing, prepared, replace: mode == Replace)
}

pub fn import_action(mode: ImportMode) -> String {
  case mode {
    Replace -> "rules.import.replace"
    Merge -> "rules.import.merge"
  }
}

/// A change `commit` refused.
pub fn refused(refusal: commit.Refusal) -> ChangeError {
  case refusal {
    commit.Refused(errors) -> Invalid(errors)
    commit.NotWritten(reason) -> Storage(reason)
  }
}
