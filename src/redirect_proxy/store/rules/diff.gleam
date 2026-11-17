//// What changed between two rule sets, by rule id, ignoring dates and
//// authors; and its JSON for the audit trail.

import gleam/dict
import gleam/json
import gleam/list
import gleam/set
import gleam/string
import redirect_proxy/rule.{type Rule}

/// The rules of `after` that are new, or changed other than in their dates
/// and author, compared to `before`.
pub fn changed_rules(before: List(Rule), after: List(Rule)) -> List(Rule) {
  let d = diff(before, after)
  let ids = set.from_list(list.append(d.added, d.changed))
  list.filter(after, fn(r) { set.contains(ids, r.id) })
}

/// Whether two rules are the same but for their dates and author, as
/// `diff` compares them.
pub fn same_content(a: Rule, b: Rule) -> Bool {
  content(a) == content(b)
}

/// A rule without its dates and author: two rules the same but for them
/// are the same change (`diff`, `same_content`).
fn content(r: Rule) -> Rule {
  rule.Rule(..r, created_at: "", updated_at: "", updated_by: "")
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
pub fn to_json(d: Diff) -> List(#(String, json.Json)) {
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
