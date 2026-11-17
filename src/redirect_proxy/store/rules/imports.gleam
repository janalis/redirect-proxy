//// Imports of rules: preparing and validating the incoming rules, resolving
//// their ids and dates against the current ones, and merging them in.

import gleam/dict
import gleam/list
import gleam/result
import gleam/set
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/id
import redirect_proxy/matcher
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/rules/check
import redirect_proxy/store/rules/diff
import redirect_proxy/store/rules/validate

pub fn prepare_import(
  incoming: List(Rule),
  actor_name: String,
) -> Result(List(Rule), List(FieldError)) {
  let now = ffi.now_rfc3339()
  incoming
  |> list.map(fn(r) {
    rule.Rule(
      ..r,
      // trimmed against the current rules: `resolve_ids`
      id: case string.trim(r.id) {
        "" -> id.uuid()
        _ -> r.id
      },
      // a blank creation date is resolved against the current rules
      // (`keep_created_at`): an export without it must not reset it
      updated_at: now,
      updated_by: actor_name,
    )
  })
  // ids are checked against the current rules: `check_new_ids`
  |> validate.validate_all
}

/// The checks of an import of `incoming` that replaces `current`: the
/// prepared rules, or every problem found.
pub fn check_import(
  incoming: List(Rule),
  current: List(Rule),
  ignore_trailing_slash: Bool,
) -> Result(List(Rule), List(FieldError)) {
  use rules <- result.try(prepare_import(incoming, "cli"))
  let rules = resolve_ids(current, rules)
  // `prepare_import` checked the conflicts already (`validate_all`)
  use Nil <- result.try(check_new_ids(current, rules))
  // as an import, the rules it leaves as they are are not checked again
  use Nil <- result.try(check.check_changed(
    matcher.build(rules),
    rules,
    diff.changed_rules(current, rules),
    ignore_trailing_slash,
  ))
  Ok(rules)
}

/// The rules an import of `prepared` leaves, and `prepared` with its ids
/// resolved against the `existing` rules: the same for an import and its
/// preview. With `replace`, the imported rules replace every rule, else
/// they are merged in (rules with an existing id are updated). Rules
/// imported again unchanged are kept as they were.
pub fn apply(
  existing: List(Rule),
  prepared: List(Rule),
  replace replace: Bool,
) -> Result(#(List(Rule), List(Rule)), List(FieldError)) {
  let prepared = resolve_ids(existing, prepared)
  use Nil <- result.try(check_new_ids(existing, prepared))
  let rules =
    case replace {
      True -> prepared
      False -> merge(existing, prepared)
    }
    |> keep_created_at(existing, _)
    |> keep_unchanged(existing, _)
  Ok(#(prepared, rules))
}

/// The ids of imported rules: kept as given when a current rule has it
/// (spaces and all: a file may have loaded with them), else trimmed.
fn resolve_ids(existing: List(Rule), incoming: List(Rule)) -> List(Rule) {
  let known = list.map(existing, fn(r) { r.id }) |> set.from_list
  list.map(incoming, fn(r) {
    case set.contains(known, r.id) {
      True -> r
      False -> rule.Rule(..r, id: string.trim(r.id))
    }
  })
}

/// Refuses imported rules that would add an id that is not URL-safe or is
/// reserved (`rule.is_valid_id`), and duplicate ids. The ids of current rules are kept: a file
/// that loaded with them can be imported again.
fn check_new_ids(
  existing: List(Rule),
  rules: List(Rule),
) -> Result(Nil, List(FieldError)) {
  let known = list.map(existing, fn(r) { r.id }) |> set.from_list
  let invalid =
    list.filter(rules, fn(r) {
      !set.contains(known, r.id) && !rule.is_valid_id(r.id)
    })
    |> list.map(fn(r) {
      case rule.is_reserved_id(r.id) {
        True ->
          FieldError(
            "id",
            r.id <> " is reserved (it names a page or an operation)",
          )
        False -> FieldError("id", r.id <> ": " <> rule.valid_id_hint())
      }
    })
  // ids trimmed by `resolve_ids` may now be the same
  case list.append(invalid, validate.duplicate_ids(rules)) {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

/// Gives the imported rules without a creation date (a CSV file has none)
/// the one of the current rule with the same id, else their import date.
pub fn keep_created_at(existing: List(Rule), rules: List(Rule)) -> List(Rule) {
  let created =
    list.fold(existing, dict.new(), fn(acc, r: Rule) {
      case r.created_at {
        "" -> acc
        c -> dict.insert(acc, r.id, c)
      }
    })
  list.map(rules, fn(r) {
    case r.created_at {
      "" ->
        rule.Rule(
          ..r,
          created_at: dict.get(created, r.id) |> result.unwrap(r.updated_at),
        )
      _ -> r
    }
  })
}

/// Gives the imported rules that are the same as current ones but for
/// their dates and author (as `diff` compares them) back as they were:
/// importing rules again unchanged leaves their version (ETag) alone.
fn keep_unchanged(existing: List(Rule), rules: List(Rule)) -> List(Rule) {
  let current =
    list.fold(existing, dict.new(), fn(acc, r: Rule) {
      dict.insert(acc, r.id, r)
    })
  list.map(rules, fn(r) {
    case dict.get(current, r.id) {
      Ok(before) ->
        case diff.same_content(before, r) {
          True -> before
          False -> r
        }
      Error(Nil) -> r
    }
  })
}

fn merge(existing: List(Rule), incoming: List(Rule)) -> List(Rule) {
  let incoming_by_id =
    list.fold(incoming, dict.new(), fn(acc, r) { dict.insert(acc, r.id, r) })
  let updated =
    list.map(existing, fn(r) {
      dict.get(incoming_by_id, r.id) |> result.unwrap(r)
    })
  let existing_ids = list.map(existing, fn(r) { r.id }) |> set.from_list
  let added = list.filter(incoming, fn(r) { !set.contains(existing_ids, r.id) })
  list.append(updated, added)
}
