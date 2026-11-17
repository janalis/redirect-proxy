//// Store calls for tests: unversioned, with the errors as the
//// `field: message` text the tests compare.

import gleam/list
import gleam/option.{None}
import gleam/result
import redirect_proxy/field_error.{type FieldError}
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules

pub fn create(
  s: store.Store,
  r: Rule,
  by actor: String,
) -> Result(Rule, List(String)) {
  store.create(s, r, actor) |> result.map_error(describe)
}

pub fn update(
  s: store.Store,
  r: Rule,
  by actor: String,
) -> Result(Rule, List(String)) {
  store.update_versioned(s, r, None, actor) |> result.map_error(describe)
}

pub fn delete(
  s: store.Store,
  id: String,
  by actor: String,
) -> Result(Rule, List(String)) {
  store.delete_versioned(s, id, None, actor) |> result.map_error(describe)
}

pub fn import_rules(
  s: store.Store,
  rules: List(Rule),
  mode: store.ImportMode,
  by actor: String,
) -> Result(Int, List(String)) {
  store.import_rules(s, rules, mode, actor) |> result.map_error(describe)
}

pub fn preview_import(
  s: store.Store,
  rules: List(Rule),
  mode: store.ImportMode,
  by actor: String,
) -> Result(#(store_rules.Diff, String), List(String)) {
  store.preview_import(s, rules, mode, actor) |> messages
}

/// A refused change, as text.
pub fn describe(error: store.ChangeError) -> List(String) {
  case error {
    store.NotFound -> ["id: rule not found"]
    store.AlreadyExists -> ["id: already exists"]
    store.Conflict(_) -> ["version: the rule was modified concurrently"]
    store.Stale(_) -> ["version: the rules were changed since they were read"]
    store.Invalid(errors) -> field_error.to_strings(errors)
  }
}

/// The errors of `result` as text.
pub fn messages(
  result: Result(a, List(FieldError)),
) -> Result(a, List(String)) {
  result.map_error(result, list.map(_, field_error.to_string))
}
