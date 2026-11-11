//// Checks and transformations of rule sets, independent of the store
//// actor: validation, conflicts, redirect loops, imports and export.

import gleam/bool
import gleam/dict.{type Dict}
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
/// back to it: now (`built`, the matcher of `rules`), or at a later time
/// within its window when the rules in effect change (a rule starts or
/// expires).
pub fn check_loop(
  built: matcher.Matcher,
  rules: List(Rule),
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> Result(Nil, List(String)) {
  follow_loop(built, rules, later(rules), changed, ignore_trailing_slash).0
}

/// What a check knows of the times to come: when the rules in effect
/// change (a rule starts or expires), worked out once, and the matchers
/// of the times it built, kept for the other rules of the change.
type Later {
  Later(changes: List(Change), matchers: Dict(Int, matcher.Matcher))
}

/// A rule (`id`) starts, or expires, `at` a time to come.
type Change {
  Change(at: Int, id: String, expires: Bool)
}

fn later(rules: List(Rule)) -> Later {
  let now = ffi.now_seconds()
  let changes =
    list.fold(rules, [], fn(acc, r) {
      case r.enabled && { r.starts_at != "" || r.expires_at != "" } {
        False -> acc
        True -> {
          let #(starts, expires) = rule.window(r)
          let acc = case starts > now {
            True -> [Change(starts, r.id, False), ..acc]
            False -> acc
          }
          case expires > now && expires < max_window_end {
            True -> [Change(expires, r.id, True), ..acc]
            False -> acc
          }
        }
      }
    })
    |> list.sort(fn(a, b) { int.compare(a.at, b.at) })
  Later(changes:, matchers: dict.new())
}

const max_window_end = 1_000_000_000_000

/// The most times to come a rule is followed at, the nearest (see
/// `follow_loop`), and the most matchers a check keeps for them, all rules
/// of a change together (each is a matcher of every rule).
const max_times_ahead = 8

const max_matchers_ahead = 32

fn follow_loop(
  built: matcher.Matcher,
  rules: List(Rule),
  later: Later,
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> #(Result(Nil, List(String)), Later) {
  use <- bool.guard(!changed.enabled, #(Ok(Nil), later))
  let found = fn(matcher) {
    matcher_loop.redirect_loop(matcher, changed, ignore_trailing_slash)
  }
  let refused = fn(cycle) {
    Error(["target: redirect loop: " <> describe_cycle(cycle)])
  }
  let #(starts, _) = rule.window(changed)
  case found(built) {
    Ok(cycle) -> #(refused(cycle), later)
    Error(Nil) ->
      list.fold_until(
        changes_ahead(later.changes, changed),
        #(Ok(Nil), later),
        fn(acc, at) {
          let #(_, later) = acc
          let follow = fn(matcher, later) {
            case found(matcher) {
              Ok(cycle) -> list.Stop(#(refused(cycle), later))
              Error(Nil) -> list.Continue(#(Ok(Nil), later))
            }
          }
          case dict.get(later.matchers, at) {
            Ok(matcher) -> follow(matcher, later)
            Error(Nil) ->
              case dict.size(later.matchers) < max_matchers_ahead {
                True -> {
                  let matcher = matcher.build_at(rules, at)
                  follow(
                    matcher,
                    Later(
                      ..later,
                      matchers: dict.insert(later.matchers, at, matcher),
                    ),
                  )
                }
                // past them, the start of a rule that starts later is
                // still followed (it can only loop from then), with a
                // matcher not kept; a loop that comes about at another
                // time is logged then (the store republishes the rules,
                // and checks them)
                False if at == starts ->
                  follow(matcher.build_at(rules, at), later)
                False -> list.Continue(acc)
              }
          }
        },
      )
  }
}

/// The times to come, within the window of `changed`, at which the rules
/// in effect change: its start, and the starts and expiries of the other
/// rules; the nearest. None, the usual case, when no rule has a schedule.
fn changes_ahead(changes: List(Change), changed: Rule) -> List(Int) {
  let #(from, until) = rule.window(changed)
  changes
  |> list.filter(fn(c) {
    c.at >= from && c.at < until && !{ c.expires && c.id == changed.id }
  })
  |> list.map(fn(c) { c.at })
  |> list.unique
  |> list.take(max_times_ahead)
}

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
    list.fold(changed, #([], later(rules)), fn(acc, r) {
      let #(errors, later) = acc
      let #(loop, later) =
        follow_loop(built, rules, later, r, ignore_trailing_slash)
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
  let rules = resolve_ids(current, rules)
  // `prepare_import` checked the conflicts already (`validate_all`)
  use Nil <- result.try(check_new_ids(current, rules))
  // as an import, the rules it leaves as they are are not checked again
  use Nil <- result.try(check_changed(
    matcher.build(rules),
    rules,
    changed_rules(current, rules),
    ignore_trailing_slash,
  ))
  Ok(rules)
}

/// The ids of imported rules: kept as given when a current rule has it
/// (spaces and all: a file may have loaded with them), else trimmed.
pub fn resolve_ids(existing: List(Rule), incoming: List(Rule)) -> List(Rule) {
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
pub fn check_new_ids(
  existing: List(Rule),
  rules: List(Rule),
) -> Result(Nil, List(String)) {
  let known = list.map(existing, fn(r) { r.id }) |> set.from_list
  let invalid =
    list.filter(rules, fn(r) {
      !set.contains(known, r.id) && !rule.is_valid_id(r.id)
    })
    |> list.map(fn(r) {
      case rule.is_reserved_id(r.id) {
        True ->
          "id: " <> r.id <> " is reserved (it names a page or an operation)"
        False -> "id: " <> r.id <> ": " <> rule.valid_id_hint()
      }
    })
  // ids trimmed by `resolve_ids` may now be the same
  case list.append(invalid, duplicate_ids(rules)) {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

/// The ids that more than one rule has, as errors, in order.
fn duplicate_ids(rules: List(Rule)) -> List(String) {
  rules
  |> list.group(fn(r) { r.id })
  |> dict.filter(fn(id, group) { id != "" && list.length(group) > 1 })
  |> dict.keys
  |> list.sort(string.compare)
  |> list.map(fn(id) { "id: duplicate id " <> id })
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
pub fn keep_unchanged(existing: List(Rule), rules: List(Rule)) -> List(Rule) {
  let current =
    list.fold(existing, dict.new(), fn(acc, r: Rule) {
      dict.insert(acc, r.id, r)
    })
  list.map(rules, fn(r) {
    case dict.get(current, r.id) {
      Ok(before) ->
        case content(before) == content(r) {
          True -> before
          False -> r
        }
      Error(Nil) -> r
    }
  })
}

/// A rule without its dates and author: two rules the same but for them
/// are the same change (`diff`, `keep_unchanged`).
fn content(r: Rule) -> Rule {
  rule.Rule(..r, created_at: "", updated_at: "", updated_by: "")
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
