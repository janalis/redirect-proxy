//// Validation of a whole rule set: every rule, and the conflicts between
//// them (duplicate ids, two exact rules for one path, exact rules
//// redirecting to themselves).

import gleam/dict
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/ffi
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/matcher
import redirect_proxy/rule.{type Rule}

/// Validates every rule of a file and checks for conflicts.
pub fn validate_all(rules: List(Rule)) -> Result(List(Rule), List(FieldError)) {
  let #(valid, errors) =
    rules
    |> list.index_map(fn(r, index) {
      rule.validate(r)
      |> result.map_error(fn(errors) {
        list.map(errors, field_error.about(
          _,
          "rule #"
            <> int.to_string(index + 1)
            <> " ("
            <> r.host
            <> r.source
            <> ")",
        ))
      })
    })
    |> result.partition
  case errors {
    [] -> {
      let valid = list.reverse(valid)
      use Nil <- result.try(check_conflicts(valid))
      Ok(valid)
    }
    _ -> Error(errors |> list.reverse |> list.flatten)
  }
}

/// Rejects duplicate ids and duplicate exact sources on the same host, and
/// exact rules redirecting to themselves.
pub fn check_conflicts(rules: List(Rule)) -> Result(Nil, List(FieldError)) {
  let duplicate_ids = duplicate_ids(rules)

  // in the form the matcher compares hosts and paths: example.com:8080 and
  // example.com are one host, /café and /caf%C3%A9 one path
  let exact_key = fn(r: Rule) {
    let host = matcher.normalise_request_host(r.host)
    let source = ffi.normalise_path(r.source)
    let path = case r.case_insensitive {
      True -> host <> " " <> string.lowercase(source)
      False -> host <> " " <> source
    }
    // the same query conditions in any order are one key
    case rule.query_conditions(r) {
      [] -> path
      conditions -> path <> "?" <> uri.query_to_string(conditions)
    }
  }
  let duplicate_sources =
    rules
    |> list.filter(fn(r) { r.kind == rule.Exact && r.enabled })
    |> list.group(exact_key)
    // rules for one path may take turns (starts_at/expires_at)
    |> dict.filter(fn(_, group) {
      list.combination_pairs(group)
      |> list.any(fn(pair) { rule.windows_overlap(pair.0, pair.1) })
    })
    |> dict.keys
    |> list.map(fn(key) {
      FieldError(
        "source",
        "another enabled exact rule already matches "
          <> key
          <> " (at the same time)",
      )
    })

  let loops =
    rules
    |> list.filter(fn(r) { r.kind == rule.Exact && r.enabled && is_loop(r) })
    |> list.map(fn(r) {
      FieldError(
        "target",
        "rule " <> r.host <> r.source <> " redirects to itself",
      )
    })

  case list.flatten([duplicate_ids, duplicate_sources, loops]) {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

fn is_loop(r: Rule) -> Bool {
  // a rule with query conditions only loops when its target asks again for
  // its path with those conditions: left to the redirect loop check
  r.query == ""
  && {
    r.target == r.source
    || {
      r.host != "*"
      && {
        r.target == "http://" <> r.host <> r.source
        || r.target == "https://" <> r.host <> r.source
        || r.target == "//" <> r.host <> r.source
      }
    }
  }
}

/// The ids that more than one rule has, as errors, in order.
pub fn duplicate_ids(rules: List(Rule)) -> List(FieldError) {
  rules
  |> list.group(fn(r) { r.id })
  |> dict.filter(fn(id, group) { id != "" && list.length(group) > 1 })
  |> dict.keys
  |> list.sort(string.compare)
  |> list.map(fn(id) { FieldError("id", "duplicate id " <> id) })
}
