//// The audit entries the store records for changes of the rule set and for
//// changes and reloads that failed.

import gleam/json
import gleam/option.{None, Some}
import redirect_proxy/audit
import redirect_proxy/field_error
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/commit
import redirect_proxy/store/rules/diff
import redirect_proxy/store/state.{type State}

/// Audits a new rule set: the file fingerprints before and after, and the
/// rules added, removed and changed.
pub fn rules_change(
  state: State,
  actor_name: String,
  action: String,
  target: String,
  rules: List(Rule),
  fingerprint: String,
) -> Nil {
  rule_set(
    state.config.audit_path,
    #(state.rules, state.fingerprint),
    actor_name,
    action,
    target,
    rules,
    fingerprint,
  )
}

/// `rules_change`, from the rules and fingerprint `before`.
pub fn rule_set(
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

/// Audits a change of the rule set `commit` refused, as `<action>_failed`.
pub fn refused(
  audit_path: String,
  actor_name: String,
  action: String,
  target: String,
  refusal: commit.Refusal,
) -> Nil {
  audit.record(
    audit_path,
    actor_name,
    action <> "_failed",
    target,
    None,
    Some(refusal_json(refusal)),
  )
}

/// The errors of a change `commit` refused, for its audit entry.
fn refusal_json(refusal: commit.Refusal) -> json.Json {
  let errors = case refusal {
    commit.Refused(errors) -> field_error.to_strings(errors)
    commit.NotWritten(reason) -> ["storage: " <> reason]
  }
  json.object([#("errors", json.array(errors, json.string))])
}

/// Audits a reload of the file that was refused, and why.
pub fn reload_failed(state: State, actor_name: String, reason: String) -> Nil {
  audit.record(
    state.config.audit_path,
    actor_name,
    "rules.reload_failed",
    state.config.rules_path,
    None,
    Some(json.object([#("error", json.string(reason))])),
  )
}
