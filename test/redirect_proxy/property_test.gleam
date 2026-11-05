//// Property based tests (qcheck).

import gleam/dict
import gleam/list
import gleam/result
import gleam/string
import qcheck
import redirect_proxy/matcher
import redirect_proxy/rule.{Rule}

fn segment() -> qcheck.Generator(String) {
  qcheck.non_empty_string_from(
    qcheck.codepoint_from_strings("a", ["b", "c", "x", "-", "_", "1", "2"]),
  )
}

fn path() -> qcheck.Generator(String) {
  qcheck.list_from(segment())
  |> qcheck.map(fn(segments) { "/" <> string.join(segments, "/") })
}

fn host() -> qcheck.Generator(String) {
  qcheck.from_generators(qcheck.return("*"), [
    qcheck.return("a.test"),
    qcheck.return("b.test"),
  ])
}

fn rules() -> qcheck.Generator(List(rule.Rule)) {
  qcheck.generic_list(
    elements_from: exact_rule(),
    length_from: qcheck.bounded_int(0, 12),
  )
}

/// Runs a property with a bounded number of cases to keep the suite fast.
fn check(generator: qcheck.Generator(a), property: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(200)
  |> qcheck.run(generator, property)
}

fn exact_rule() -> qcheck.Generator(rule.Rule) {
  qcheck.map3(host(), path(), path(), fn(host, source, target) {
    Rule(..rule.blank(), id: host <> source, host:, source:, target:)
  })
}

/// Expanding a template without `$` is the identity.
pub fn expand_without_placeholders_is_identity_test() {
  use template <- qcheck.given(
    qcheck.string_from(
      qcheck.codepoint_from_strings("a", ["/", "?", "=", "&", "{", "}", "1"]),
    ),
  )
  assert rule.expand(template, ["x", "y"]) == template
}

/// `$$` always becomes a single `$`.
pub fn expand_dollar_escape_test() {
  use n <- qcheck.given(qcheck.bounded_int(0, 20))
  let template = string.repeat("$$", n)
  assert rule.expand(template, []) == string.repeat("$", n)
}

/// Serialising then parsing a rule file gives back the same rules.
pub fn file_round_trip_test() {
  use rules <- check(rules())
  let rules =
    list.map(rules, fn(r) {
      Rule(
        ..r,
        note: r.source,
        status: 302,
        preserve_query: string.length(r.source) % 2 == 0,
      )
    })
  assert rule.file_from_string(rule.file_to_string(rules)) == Ok(rules)
}

/// The matcher agrees with a naive reference implementation for exact rules:
/// the first enabled rule of the request host wins, then the wildcard host.
pub fn matcher_agrees_with_reference_test() {
  use #(rules, probe_host, probe_path) <- check(qcheck.tuple3(
    rules(),
    host(),
    path(),
  ))
  let probe_host = case probe_host {
    "*" -> "c.test"
    h -> h
  }
  let reference = fn(h, p) {
    list.find(rules, fn(r) { r.host == h && r.source == p })
  }
  let expected =
    reference(probe_host, probe_path)
    |> result.lazy_or(fn() { reference("*", probe_path) })
    |> result.map(fn(r) { r.target })
  let actual =
    matcher.lookup(matcher.build(rules), probe_host, probe_path)
    |> result.map(fn(m) { m.location })
  assert actual == expected
}

/// Every rule in a matcher built from unique exact rules can be found.
pub fn every_exact_rule_is_reachable_test() {
  use rules <- check(rules())
  let unique =
    rules
    |> list.fold(dict.new(), fn(acc, r) {
      case dict.has_key(acc, #(r.host, r.source)) {
        True -> acc
        False -> dict.insert(acc, #(r.host, r.source), r)
      }
    })
    |> dict.values
  let m = matcher.build(unique)
  list.each(unique, fn(r) {
    let host = case r.host {
      "*" -> "zzz.test"
      h -> h
    }
    let assert Ok(found) = matcher.lookup(m, host, r.source)
    // a host-specific rule may shadow a wildcard one for the same path
    assert found.rule.source == r.source
  })
}
