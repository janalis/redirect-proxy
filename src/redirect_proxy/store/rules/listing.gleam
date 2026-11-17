//// The rules list of the admin and the API: its filters and sort orders,
//// and the export of rules for download.

import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/string
import redirect_proxy/rule.{type Rule}

/// Encodes rules for download/export.
pub fn export(rules: List(Rule)) -> String {
  json.object([
    #("version", json.int(rule.file_format_version)),
    #("rules", json.array(rules, rule.to_json)),
  ])
  |> json.to_string
}

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

/// The fields rules can be sorted by, named as in the JSON of a rule;
/// `-field` sorts in descending order.
pub const sort_fields = ["source", "host", "hits", "last_hit_at", "updated_at"]

/// Earlier names of sort fields, still accepted: `#(old, current)`.
pub const sort_aliases = [
  #("last_hit", "last_hit_at"),
  #("updated", "updated_at"),
]

/// `by` with an earlier field name replaced by the current one
/// (`-updated` is `-updated_at`).
pub fn current_sort(by: String) -> String {
  let #(sign, field) = case by {
    "-" <> field -> #("-", field)
    field -> #("", field)
  }
  case list.key_find(sort_aliases, field) {
    Ok(current) -> sign <> current
    Error(Nil) -> by
  }
}

/// Sorts rules by `by` (one of `sort_fields` or `sort_aliases`, optionally
/// prefixed with `-`; "" keeps the file order). Hit counts come from
/// `hits`, last hit times from `last_hit`.
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
  let field = list.key_find(sort_aliases, field) |> result.unwrap(field)
  let compare = case field {
    "" -> Ok(fn(_, _) { order.Eq })
    "source" -> Ok(fn(a: Rule, b: Rule) { string.compare(a.source, b.source) })
    "host" -> Ok(fn(a: Rule, b: Rule) { string.compare(a.host, b.host) })
    "updated_at" ->
      Ok(fn(a: Rule, b: Rule) { string.compare(a.updated_at, b.updated_at) })
    "hits" -> Ok(fn(a: Rule, b: Rule) { int.compare(hits(a.id), hits(b.id)) })
    "last_hit_at" ->
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
