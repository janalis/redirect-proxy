//// Property based tests (qcheck).

import gleam/dict
import gleam/int
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import qcheck
import redirect_proxy/ffi
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

// --- indexed prefix and regex matching -----------------------------------------

fn mixed_segment() -> qcheck.Generator(String) {
  qcheck.non_empty_string_from(
    qcheck.codepoint_from_strings("a", ["b", "A", "B", "é", "É", "-", "1"]),
  )
}

fn mixed_path() -> qcheck.Generator(String) {
  qcheck.generic_list(
    elements_from: mixed_segment(),
    length_from: qcheck.bounded_int(0, 3),
  )
  |> qcheck.map(fn(segments) { "/" <> string.join(segments, "/") })
}

/// Prefix and regex rules of the wildcard host, with mixed priorities,
/// letter case and regex shapes (indexable or not).
fn pattern_rule() -> qcheck.Generator(rule.Rule) {
  qcheck.map4(
    mixed_path(),
    qcheck.bounded_int(0, 6),
    qcheck.bounded_int(1, 3),
    qcheck.bool(),
    fn(source, shape, priority, case_insensitive) {
      let #(kind, source) = case shape {
        0 | 1 -> #(rule.Prefix, source)
        2 -> #(rule.Prefix, source <> "/")
        3 -> #(rule.Regex, "^" <> source <> "(.*)$")
        4 -> #(rule.Regex, "^" <> source <> "?(.*)")
        5 -> #(rule.Regex, "(.*)" <> source <> "$")
        _ -> #(rule.Regex, "^" <> source <> "|^/b(.*)")
      }
      Rule(
        ..rule.blank(),
        id: source,
        kind:,
        source:,
        target: "/t/$1",
        priority:,
        case_insensitive:,
      )
    },
  )
}

/// The resolution order of the matcher, trying every rule in turn.
fn reference_lookup(
  rules: List(rule.Rule),
  path: String,
) -> Result(String, Nil) {
  let prefix =
    rules
    |> list.filter(fn(r) { r.kind == rule.Prefix })
    |> list.sort(fn(a, b) {
      case int.compare(string.length(b.source), string.length(a.source)) {
        order.Eq -> int.compare(a.priority, b.priority)
        other -> other
      }
    })
    |> list.find(fn(r) {
      case r.case_insensitive {
        False -> string.starts_with(path, r.source)
        True ->
          string.starts_with(string.lowercase(path), string.lowercase(r.source))
      }
    })
    |> result.map(fn(r) {
      rule.expand(r.target, [
        path,
        string.drop_start(path, string.length(r.source)),
      ])
    })
  use <- result.lazy_or(prefix)
  rules
  |> list.filter(fn(r) { r.kind == rule.Regex })
  |> list.sort(fn(a, b) { int.compare(a.priority, b.priority) })
  |> list.find_map(fn(r) {
    use re <- result.try(
      ffi.regex_compile(r.source, r.case_insensitive)
      |> result.replace_error(Nil),
    )
    ffi.regex_run(re, path)
    |> result.replace_error(Nil)
    |> result.map(fn(captures) { rule.expand(r.target, captures) })
  })
}

/// The indexed prefix and regex matching gives the same result as trying
/// every rule in resolution order.
pub fn indexed_matching_agrees_with_reference_test() {
  use #(rules, probe) <- check(qcheck.tuple2(
    qcheck.generic_list(
      elements_from: pattern_rule(),
      length_from: qcheck.bounded_int(0, 10),
    ),
    mixed_path(),
  ))
  let m = matcher.build(rules)
  // probe both a random path and paths extending each rule's source
  let probes = [
    probe,
    ..list.map(rules, fn(r) {
      string.replace(r.source, "^", "")
      |> string.replace("(.*)$", "")
      |> string.replace("(.*)", "")
      <> probe
    })
  ]
  list.each(probes, fn(path) {
    let actual =
      matcher.lookup(m, "test.local", path)
      |> result.map(fn(found) { found.location })
    assert actual == reference_lookup(rules, path)
  })
}
