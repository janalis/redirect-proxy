//// Checks and transformations of rule sets, independent of the store
//// actor: validation, conflicts, redirect loops, imports and export.

import gleam/dict
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/set
import gleam/string
import gleam/uri
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/matcher/loop as matcher_loop
import redirect_proxy/rule.{type Rule}

/// Refuses a change when a request to the changed rule would be redirected
/// back to it: now (`built`, the matcher of `rules`), or once a rule that
/// starts later does (see `Later`).
pub fn check_loop(
  built: matcher.Matcher,
  rules: List(Rule),
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> Result(Nil, List(String)) {
  let #(result, _) =
    follow_loop(built, Unbuilt(rules), changed, ignore_trailing_slash)
  result
}

/// The matcher of the rules not expired yet, starting later or not, built
/// when a check needs it (once per check of a set of rules): `None` when
/// no rule starts later (the matcher of now then says it all).
type Later {
  Unbuilt(rules: List(Rule))
  /// with the rules by id, their schedules kept
  Built(Option(#(matcher.Matcher, dict.Dict(String, Rule))))
}

fn later_matcher(
  later: Later,
) -> #(Option(#(matcher.Matcher, dict.Dict(String, Rule))), Later) {
  case later {
    Built(built) -> #(built, later)
    Unbuilt(rules) -> {
      let now = ffi.now_seconds()
      let pending =
        list.filter(rules, fn(r) { r.enabled && rule.window(r).1 > now })
      let built = case
        list.any(pending, fn(r) { r.starts_at != "" && rule.window(r).0 > now })
      {
        False -> None
        True ->
          Some(#(
            pending
              |> list.map(fn(r) {
                rule.Rule(..r, starts_at: "", expires_at: "")
              })
              |> matcher.build,
            list.map(pending, fn(r) { #(r.id, r) }) |> dict.from_list,
          ))
      }
      #(built, Built(built))
    }
  }
}

fn follow_loop(
  built: matcher.Matcher,
  later: Later,
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> #(Result(Nil, List(String)), Later) {
  let refused = fn(cycle) {
    Error(["target: redirect loop: " <> describe_cycle(cycle)])
  }
  case changed.enabled {
    False -> #(Ok(Nil), later)
    True ->
      case matcher_loop.redirect_loop(built, changed, ignore_trailing_slash) {
        Ok(cycle) -> #(refused(cycle), later)
        Error(Nil) -> {
          let #(found, later) = later_matcher(later)
          let found = {
            use #(matcher, by_id) <- result.try(option.to_result(found, Nil))
            use cycle <- result.map(matcher_loop.redirect_loop(
              matcher,
              changed,
              ignore_trailing_slash,
            ))
            #(cycle, list.filter_map(cycle, fn(r) { dict.get(by_id, r.id) }))
          }
          case found {
            // its rules all apply at some time to come
            Ok(#(cycle, scheduled)) ->
              case at_once(scheduled) {
                True -> #(refused(cycle), later)
                False -> #(Ok(Nil), later)
              }
            Error(Nil) -> #(Ok(Nil), later)
          }
        }
      }
  }
}

/// Whether the rules (of a cycle) all apply together at some time from now.
fn at_once(rules: List(Rule)) -> Bool {
  let #(from, until) =
    list.fold(rules, #(ffi.now_seconds(), max_window_end), fn(acc, r) {
      let #(from, until) = rule.window(r)
      #(int.max(acc.0, from), int.min(acc.1, until))
    })
  from < until
}

const max_window_end = 1_000_000_000_000

/// Refuses a change to a rule that could never apply as written.
pub fn check_lint(changed: Rule) -> Result(Nil, List(String)) {
  case rule.lint(changed) {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

/// The rules of `after` that are new, or changed other than in their dates
/// and author, compared to `before`.
pub fn changed_rules(before: List(Rule), after: List(Rule)) -> List(Rule) {
  let d = diff(before, after)
  let ids = set.from_list(list.append(d.added, d.changed))
  list.filter(after, fn(r) { set.contains(ids, r.id) })
}

/// Refuses a change of several rules (`changed`, in the matcher `built`)
/// when one of them could never apply as written or loops, as a change of
/// one rule is. Rules the change leaves alone are not checked: a file that
/// loaded before can still be imported again.
pub fn check_changed(
  built: matcher.Matcher,
  rules: List(Rule),
  changed: List(Rule),
  ignore_trailing_slash: Bool,
) -> Result(Nil, List(String)) {
  let #(errors, _) =
    list.fold(changed, #([], Unbuilt(rules)), fn(acc, r) {
      let #(errors, later) = acc
      let #(loop, later) = follow_loop(built, later, r, ignore_trailing_slash)
      let loop = case loop {
        Ok(Nil) -> []
        Error(errors) -> errors
      }
      let found =
        list.append(rule.lint(r), loop)
        |> list.map(fn(e) {
          "rule " <> r.id <> " (" <> r.host <> r.source <> "): " <> e
        })
      #([found, ..errors], later)
    })
  let errors = list.reverse(errors) |> list.flatten
  case errors {
    [] -> Ok(Nil)
    _ -> Error(errors)
  }
}

/// Logs the redirect loops of a rule set, each cycle once, and the rules that
/// can never apply (loading never fails on them, so that a file that loaded
/// before keeps loading).
pub fn warn_problems(
  built: matcher.Matcher,
  rules: List(Rule),
  ignore_trailing_slash: Bool,
) -> matcher.Matcher {
  list.each(rules, fn(r) {
    list.each(rule.lint(r), fn(problem) {
      log.warning(
        "rule " <> r.id <> " (" <> r.host <> r.source <> "): " <> problem,
      )
    })
  })
  warn_loops(built, rules, ignore_trailing_slash)
}

/// Logs the redirect loops of a rule set, each cycle once: for changes that
/// may uncover a loop without being part of it (a rule that no longer
/// shadows another, a scheduled rule starting or expiring).
pub fn warn_loops(
  built: matcher.Matcher,
  rules: List(Rule),
  ignore_trailing_slash: Bool,
) -> matcher.Matcher {
  let _ =
    rules
    |> list.filter(fn(r) { r.enabled })
    |> list.fold(set.new(), fn(reported, r) {
      case matcher_loop.redirect_loop(built, r, ignore_trailing_slash) {
        Error(Nil) -> reported
        Ok(cycle) -> {
          let key =
            cycle
            |> list.map(fn(r) { r.id })
            |> list.unique
            |> list.sort(string.compare)
          case set.contains(reported, key) {
            True -> reported
            False -> {
              log.warning("redirect loop: " <> describe_cycle(cycle))
              set.insert(reported, key)
            }
          }
        }
      }
    })
  built
}

fn describe_cycle(cycle: List(Rule)) -> String {
  cycle
  |> list.map(fn(r) { r.host <> r.source })
  |> string.join(" -> ")
}

/// Validates every rule of a file and checks for conflicts.
pub fn validate_all(rules: List(Rule)) -> Result(List(Rule), List(String)) {
  let #(valid, errors) =
    rules
    |> list.index_map(fn(r, index) {
      rule.validate(r)
      |> result.map_error(fn(errors) {
        list.map(errors, fn(e) {
          "rule #"
          <> int.to_string(index + 1)
          <> " ("
          <> r.host
          <> r.source
          <> "): "
          <> e
        })
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
pub fn check_conflicts(rules: List(Rule)) -> Result(Nil, List(String)) {
  let duplicate_ids =
    rules
    |> list.group(fn(r) { r.id })
    |> dict.filter(fn(key, group) { key != "" && list.length(group) > 1 })
    |> dict.keys
    |> list.map(fn(key) { "id: duplicate id " <> key })

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
      "source: another enabled exact rule already matches "
      <> key
      <> " (at the same time)"
    })

  let loops =
    rules
    |> list.filter(fn(r) { r.kind == rule.Exact && r.enabled && is_loop(r) })
    |> list.map(fn(r) {
      "target: rule " <> r.host <> r.source <> " redirects to itself"
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

pub fn prepare_import(
  incoming: List(Rule),
  actor_name: String,
) -> Result(List(Rule), List(String)) {
  let now = ffi.now_rfc3339()
  incoming
  |> list.map(fn(r) {
    rule.Rule(
      ..r,
      id: case string.trim(r.id) {
        "" -> id.uuid()
        given -> given
      },
      // a blank creation date is resolved against the current rules
      // (`keep_created_at`): an export without it must not reset it
      updated_at: now,
      updated_by: actor_name,
    )
  })
  // ids are checked against the current rules: `check_new_ids`
  |> validate_all
}

/// The checks of an import of `incoming` that replaces `current`: the
/// prepared rules, or every problem found.
pub fn check_import(
  incoming: List(Rule),
  current: List(Rule),
  ignore_trailing_slash: Bool,
) -> Result(List(Rule), List(String)) {
  use rules <- result.try(prepare_import(incoming, "cli"))
  use Nil <- result.try(check_new_ids(current, rules))
  use Nil <- result.try(check_conflicts(rules))
  // as an import, the rules it leaves as they are are not checked again
  use Nil <- result.try(check_changed(
    matcher.build(rules),
    rules,
    changed_rules(current, rules),
    ignore_trailing_slash,
  ))
  Ok(rules)
}

/// Refuses imported rules that would add an id that is not URL-safe or is
/// reserved (`rule.is_valid_id`). The ids of current rules are kept: a file
/// that loaded with them can be imported again.
pub fn check_new_ids(
  existing: List(Rule),
  rules: List(Rule),
) -> Result(Nil, List(String)) {
  let known = list.map(existing, fn(r) { r.id }) |> set.from_list
  case
    list.filter(rules, fn(r) {
      !set.contains(known, r.id) && !rule.is_valid_id(r.id)
    })
  {
    [] -> Ok(Nil)
    invalid ->
      Error(
        list.map(invalid, fn(r) {
          case rule.is_reserved_id(r.id) {
            True ->
              "id: " <> r.id <> " is reserved (it names a page or an operation)"
            False -> "id: " <> r.id <> ": " <> rule.valid_id_hint()
          }
        }),
      )
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

pub fn merge(existing: List(Rule), incoming: List(Rule)) -> List(Rule) {
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

/// Encodes rules for download/export.
pub fn export(rules: List(Rule)) -> String {
  json.object([
    #("version", json.int(rule.file_format_version)),
    #("rules", json.array(rules, rule.to_json)),
  ])
  |> json.to_string
}

/// What changed between two rule sets, by rule id.
pub type Diff {
  Diff(added: List(String), removed: List(String), changed: List(String))
}

/// Compares two rule sets. Timestamps and authors are ignored: an import
/// sets them on every rule even when nothing else changed.
pub fn diff(before: List(Rule), after: List(Rule)) -> Diff {
  let content = fn(r: Rule) {
    rule.Rule(..r, created_at: "", updated_at: "", updated_by: "")
  }
  let index = fn(rules: List(Rule)) {
    list.fold(rules, dict.new(), fn(acc, r) {
      dict.insert(acc, r.id, content(r))
    })
  }
  let old = index(before)
  let new = index(after)
  Diff(
    added: dict.keys(new) |> list.filter(fn(id) { !dict.has_key(old, id) }),
    removed: dict.keys(old) |> list.filter(fn(id) { !dict.has_key(new, id) }),
    changed: dict.to_list(new)
      |> list.filter_map(fn(entry) {
        case dict.get(old, entry.0) {
          Ok(previous) if previous != entry.1 -> Ok(entry.0)
          _ -> Error(Nil)
        }
      }),
  )
}

/// A diff for the audit trail: counts and up to 100 ids of each kind.
pub fn diff_to_json(d: Diff) -> List(#(String, json.Json)) {
  let ids = fn(name, list) {
    [
      #(name, json.int(list.length(list))),
      #(
        name <> "_ids",
        json.array(
          list |> list.sort(string.compare) |> list.take(100),
          json.string,
        ),
      ),
    ]
  }
  list.flatten([
    ids("added", d.added),
    ids("removed", d.removed),
    ids("changed", d.changed),
  ])
}

/// The fields rules can be sorted by; `-field` sorts in descending order.
/// The filters of the rules list, in the admin and the API.
pub type Filter {
  Filter(
    /// Case-insensitive text searched in the host, source, target, note,
    /// tags and id ("" for any).
    text: String,
    /// A host as written in rules, or "" for any.
    host: String,
    /// `exact`, `prefix` or `regex`, or "" for any.
    kind: String,
    enabled: Option(Bool),
    /// Rules with this tag (case-insensitive), or "" for any.
    tag: String,
  )
}

pub fn filter(rules: List(Rule), f: Filter) -> List(Rule) {
  let needle = string.lowercase(string.trim(f.text))
  let host = case string.trim(f.host) {
    "" -> ""
    h -> rule.normalise_host(h)
  }
  let tag = string.lowercase(string.trim(f.tag))
  list.filter(rules, fn(r) {
    {
      needle == ""
      || list.any(
        [r.host, r.source, r.target, r.note, r.id, ..r.tags],
        fn(field) { string.contains(string.lowercase(field), needle) },
      )
    }
    && { tag == "" || list.contains(r.tags, tag) }
    && { host == "" || r.host == host }
    && { f.kind == "" || rule.kind_to_string(r.kind) == f.kind }
    && case f.enabled {
      Some(enabled) -> r.enabled == enabled
      None -> True
    }
  })
}

pub const sort_fields = ["source", "host", "hits", "last_hit", "updated"]

/// Sorts rules by `by` (one of `sort_fields`, optionally prefixed with `-`;
/// "" keeps the file order). Hit counts come from `hits`, last hit times
/// from `last_hit`.
pub fn sort(
  rules: List(Rule),
  by: String,
  hits: fn(String) -> Int,
  last_hit: fn(String) -> Int,
) -> Result(List(Rule), Nil) {
  let #(field, descending) = case by {
    "-" <> field -> #(field, True)
    field -> #(field, False)
  }
  let compare = case field {
    "" -> Ok(fn(_, _) { order.Eq })
    "source" -> Ok(fn(a: Rule, b: Rule) { string.compare(a.source, b.source) })
    "host" -> Ok(fn(a: Rule, b: Rule) { string.compare(a.host, b.host) })
    "updated" ->
      Ok(fn(a: Rule, b: Rule) { string.compare(a.updated_at, b.updated_at) })
    "hits" -> Ok(fn(a: Rule, b: Rule) { int.compare(hits(a.id), hits(b.id)) })
    "last_hit" ->
      Ok(fn(a: Rule, b: Rule) { int.compare(last_hit(a.id), last_hit(b.id)) })
    _ -> Error(Nil)
  }
  use compare <- result.map(compare)
  case field {
    "" -> rules
    _ ->
      list.sort(rules, case descending {
        True -> fn(a, b) { order.negate(compare(a, b)) }
        False -> compare
      })
  }
}
