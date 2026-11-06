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

fn check_many(
  count: Int,
  generator: qcheck.Generator(a),
  property: fn(a) -> Nil,
) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(count)
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

// --- wildcard hosts and path normalisation --------------------------------------

fn wildcard_host() -> qcheck.Generator(String) {
  qcheck.from_generators(qcheck.return("*"), [
    qcheck.return("*.x.test"),
    qcheck.return("*.b.x.test"),
    qcheck.return("b.x.test"),
    qcheck.return("a.b.x.test"),
  ])
}

/// The hosts a request host is looked up under, in order.
fn reference_hosts(host: String) -> List(String) {
  list.flatten([[host], wildcard_parents(host), ["*"]])
}

fn wildcard_parents(name: String) -> List(String) {
  case string.split_once(name, ".") {
    Ok(#(_, parent)) -> ["*." <> parent, ..wildcard_parents(parent)]
    Error(Nil) -> []
  }
}

pub fn wildcard_lookup_agrees_with_reference_test() {
  use #(rules, probe_host, probe_path) <- check(qcheck.tuple3(
    qcheck.generic_list(
      elements_from: qcheck.map2(wildcard_host(), path(), fn(host, source) {
        Rule(..rule.blank(), id: host <> source, host:, source:, target: host)
      }),
      length_from: qcheck.bounded_int(0, 10),
    ),
    qcheck.from_generators(qcheck.return("a.b.x.test"), [
      qcheck.return("b.x.test"),
      qcheck.return("c.b.x.test"),
      qcheck.return("x.test"),
      qcheck.return("other.test"),
    ]),
    path(),
  ))
  let expected =
    reference_hosts(probe_host)
    |> list.find_map(fn(h) {
      list.find(rules, fn(r) { r.host == h && r.source == probe_path })
    })
    |> result.map(fn(r) { r.target })
  let actual =
    matcher.lookup(matcher.build(rules), probe_host, probe_path)
    |> result.map(fn(m) { m.location })
  assert actual == expected
}

pub fn path_normalisation_is_idempotent_test() {
  use path <- qcheck.given(
    qcheck.string_from(
      qcheck.codepoint_from_strings("/", [
        "a", "%", "2", "F", "f", "C", "3", "A", "9", "7", "E", "é", "-",
      ]),
    ),
  )
  let once = ffi.normalise_path(path)
  assert ffi.normalise_path(once) == once
  // an escaped slash or percent sign is never decoded
  assert !string.contains(ffi.normalise_path("/x%2Fy%25"), "/x/")
  assert string.contains(ffi.normalise_path("/x%2fy"), "%2F")
}

// --- open redirects -----------------------------------------------------------

/// Request path tails built from characters that browsers treat as URL
/// structure: slashes, backslashes, `@`, `:`, dots, encoded slashes, tabs
/// and line breaks (which browsers drop), query and fragment markers. Half
/// of them start with a known attack.
fn hostile_tail() -> qcheck.Generator(String) {
  let noise =
    qcheck.string_from(
      qcheck.codepoint_from_strings("/", [
        "\\", "@", ":", ".", "e", "v", "%", "2", "F", "\t", "\n", "?", "#", " ",
        "é",
      ]),
    )
  let attack =
    qcheck.from_generators(qcheck.return("//evil.test"), [
      qcheck.return("/\\evil.test"),
      qcheck.return("\\\\evil.test"),
      qcheck.return("@evil.test"),
      qcheck.return(".evil.test"),
      qcheck.return(":1@evil.test"),
      qcheck.return("https://evil.test"),
      qcheck.return("/\t/evil.test"),
      qcheck.return("%2F%2Fevil.test"),
    ])
  qcheck.from_generators(noise, [
    qcheck.map2(attack, noise, fn(a, n) { a <> n }),
  ])
}

/// Targets whose host is fixed, with the request path substituted in places
/// where it could try to change the host.
const absolute_targets = [
  "https://t.test$1", "https://t.test/$1", "https://t.test:8443$1",
  "https://t.test/a$1", "https://t.test$1?x=1", "//t.test$1",
]

/// Same-host targets: the result must stay a path on the request host.
const relative_targets = ["/$1", "/a$1", "/$1/b"]

/// Whatever the request path, a matched rule never redirects to a host other
/// than the one written in its target: the `Location` sent by the redirect
/// listener keeps the target's host, or stays a path on the same host.
pub fn location_never_leaves_the_target_host_test() {
  use #(kind, target_index, tail, query) <- check_many(
    1000,
    qcheck.tuple4(
      qcheck.bounded_int(0, 1),
      qcheck.bounded_int(0, 8),
      hostile_tail(),
      qcheck.from_generators(qcheck.return(""), [qcheck.return("q=@evil")]),
    ),
  )
  let targets = list.append(absolute_targets, relative_targets)
  let assert Ok(target) = list.drop(targets, target_index) |> list.first
  let r = case kind {
    0 ->
      Rule(..rule.blank(), id: "p", kind: rule.Prefix, source: "/go", target:)
    _ ->
      Rule(
        ..rule.blank(),
        id: "r",
        kind: rule.Regex,
        source: "^/go(.*)$",
        target:,
      )
  }
  let query = case query {
    "" -> Error(Nil)
    q -> Ok(q)
  }
  case
    matcher.lookup(
      matcher.build([Rule(..r, preserve_query: True)]),
      "x.test",
      "/go" <> tail,
    )
  {
    // the guard refused a substitution leaving the host
    Error(Nil) -> Nil
    Ok(m) -> {
      let location = matcher.location(m, query)
      case list.contains(absolute_targets, target) {
        True -> {
          assert browser_host(location) == Ok("t.test")
        }
        False -> {
          assert browser_host(location) == Error(Nil)
        }
      }
    }
  }
}

/// The host a browser would navigate to for a `Location` value, following
/// the WHATWG URL parser on the points that matter: tabs and line breaks are
/// removed, `\` is a `/`, a leading `//` starts an authority, the host is what
/// follows the last `@` and precedes the port. `Error(Nil)` for a path on the
/// current host.
fn browser_host(location: String) -> Result(String, Nil) {
  let url =
    location
    |> string.replace("\t", "")
    |> string.replace("\n", "")
    |> string.replace("\r", "")
    |> string.replace("\\", "/")
  let authority = case url {
    "//" <> rest -> Ok(rest)
    _ ->
      case string.split_once(url, "://") {
        Ok(#(scheme, rest)) ->
          case is_scheme(scheme) {
            True -> Ok(rest)
            False -> Error(Nil)
          }
        Error(Nil) -> Error(Nil)
      }
  }
  use rest <- result.map(authority)
  let authority =
    list.fold(["/", "?", "#"], rest, fn(acc, stop) {
      case string.split_once(acc, stop) {
        Ok(#(before, _)) -> before
        Error(Nil) -> acc
      }
    })
  let host = case string.split(authority, "@") |> list.last {
    Ok(h) -> h
    Error(Nil) -> authority
  }
  case string.split_once(host, ":") {
    Ok(#(h, _)) -> h
    Error(Nil) -> host
  }
}

/// A URL scheme: a letter, then letters, digits, `+`, `-` or `.`.
fn is_scheme(text: String) -> Bool {
  case string.to_graphemes(string.lowercase(text)) {
    [first, ..rest] ->
      string.contains("abcdefghijklmnopqrstuvwxyz", first)
      && list.all(rest, string.contains(
        "abcdefghijklmnopqrstuvwxyz0123456789+-.",
        _,
      ))
    [] -> False
  }
}
