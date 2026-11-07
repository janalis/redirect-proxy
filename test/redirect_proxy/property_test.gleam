//// Property based tests (qcheck).

import gleam/dict
import gleam/int
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import qcheck
import redirect_proxy/access_log_format as fmt
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

/// Any text, control characters, quotes and backslashes included.
fn wild_text() -> qcheck.Generator(String) {
  qcheck.string_from(
    qcheck.from_generators(qcheck.bounded_codepoint(0, 127), [
      qcheck.codepoint_from_strings("\"", [
        "\\",
        "\n",
        "\r",
        "é",
        "€",
        "\u{85}",
        "\u{9F}",
        "\u{2028}",
        "\u{2029}",
      ]),
      qcheck.bounded_codepoint(0, 0x10FFFF),
    ]),
  )
}

fn any_rule() -> qcheck.Generator(rule.Rule) {
  qcheck.map5(
    qcheck.tuple3(host(), wild_text(), wild_text()),
    qcheck.from_generators(qcheck.return(rule.Exact), [
      qcheck.return(rule.Prefix),
      qcheck.return(rule.Regex),
    ]),
    qcheck.tuple3(qcheck.bool(), qcheck.bool(), qcheck.bool()),
    qcheck.from_generators(qcheck.return(301), [
      qcheck.return(302),
      qcheck.return(303),
      qcheck.return(307),
      qcheck.return(308),
    ]),
    qcheck.tuple2(qcheck.bounded_int(-1000, 1000), wild_text()),
    fn(text, kind, flags, status, rest) {
      let #(host, source, target) = text
      let #(preserve_query, case_insensitive, enabled) = flags
      let #(priority, note) = rest
      Rule(
        ..rule.blank(),
        id: note <> "-id",
        host:,
        source:,
        kind:,
        target:,
        status:,
        preserve_query:,
        case_insensitive:,
        enabled:,
        priority:,
        note:,
      )
    },
  )
}

/// Every field of every kind of rule survives a write and a read of the
/// rules file, whatever its text.
pub fn any_rule_file_round_trip_test() {
  use rules <- check(qcheck.generic_list(
    elements_from: any_rule(),
    length_from: qcheck.bounded_int(0, 6),
  ))
  assert rule.file_from_string(rule.file_to_string(rules)) == Ok(rules)
}

/// Whatever a client sends (headers, path, query) or a rule redirects to, an
/// access log line never contains a raw control character: it could forge
/// log lines (log injection) or break the log parser.
pub fn access_log_lines_have_no_control_characters_test() {
  let formats =
    [
      #(fmt.combined, "default"),
      #(fmt.common, "default"),
      #(fmt.json, "default"),
      #("$host $uri?$args $http_x_custom $location", "default"),
      #("{\"ua\":\"$http_user_agent\",\"uri\":\"$request_uri\"}", "json"),
    ]
    |> list.map(fn(f) {
      let assert Ok(format) = fmt.parse(f.0, f.1)
      format
    })
  use #(request, client, location) <- check_many(
    300,
    qcheck.tuple3(
      qcheck.tuple3(wild_text(), wild_text(), wild_text()),
      qcheck.tuple3(wild_text(), wild_text(), wild_text()),
      wild_text(),
    ),
  )
  let #(host, path, query) = request
  let #(user_agent, referer, custom) = client
  let entry =
    fmt.Entry(
      listener: "redirect",
      client_ip: "203.0.113.0",
      method: "GET",
      host:,
      path:,
      query:,
      protocol: "HTTP/1.1",
      status: 301,
      bytes: 0,
      headers: [
        #("user-agent", user_agent),
        #("referer", referer),
        #("x-custom", custom),
      ],
      location:,
      rule_id: "r",
      time_us: 0,
      duration_us: 1,
    )
  list.each(formats, fn(format) {
    list.each([True, False], fn(log_query) {
      let line = fmt.render(format, log_query, entry)
      let controls =
        string.to_utf_codepoints(line)
        |> list.map(string.utf_codepoint_to_int)
        |> list.filter(fn(c) {
          c < 0x20 || { c >= 0x7F && c <= 0x9F } || c == 0x2028 || c == 0x2029
        })
      assert controls == []
    })
  })
}

/// A target template compiled once expands like `expand_with` reads it,
/// placeholders, `$$`, `${...}` and stray `$` or `{` included.
pub fn compiled_template_expands_like_expand_with_test() {
  let template =
    qcheck.string_from(
      qcheck.codepoint_from_strings("$", [
        "$", "{", "}", "0", "1", "2", "9", "h", "o", "s", "t", "u", "b", "/",
        "x", "-",
      ]),
    )
  let vars = rule.RequestVars(host: "req.test", sub: "a.b")
  check_many(1000, template, fn(template) {
    let captures = ["whole", "one", "two"]
    assert rule.expand_template(rule.compile_template(template), captures, vars)
      == rule.expand_with(template, captures, vars)
  })
  // the shapes that matter, written out
  list.each(
    [
      "", "/plain", "$1", "/a/$1/b", "$$1", "${1}", "${12}", "${host}",
      "https://${host}/$1", "${sub}.new.test", "${nope}", "${", "$", "$x", "a$",
      "$0-$2-$9",
    ],
    fn(template) {
      let captures = ["whole", "one", "two"]
      assert rule.expand_template(
          rule.compile_template(template),
          captures,
          vars,
        )
        == rule.expand_with(template, captures, vars)
    },
  )
}

/// Exact rules with query conditions, against a reference: the rules for
/// the path (or its case, for case-insensitive ones) whose conditions the
/// request has, most conditions first, then priority, then case-sensitive
/// ones, then file order.
pub fn query_rules_match_like_the_reference_test() {
  let subset =
    qcheck.generic_list(
      qcheck.from_generators(qcheck.return("a=1"), [
        qcheck.return("a=2"),
        qcheck.return("b=1"),
        qcheck.return("c=3"),
      ]),
      qcheck.bounded_int(0, 3),
    )
    |> qcheck.map(fn(chosen) { list.unique(chosen) |> string.join("&") })
  let source =
    qcheck.from_generators(qcheck.return("/q"), [
      qcheck.return("/Q"),
      qcheck.return("/r"),
    ])
  let query_rule =
    qcheck.map4(
      source,
      subset,
      qcheck.bool(),
      qcheck.bounded_int(1, 3),
      fn(source, query, case_insensitive, priority) {
        Rule(
          ..rule.blank(),
          source:,
          target: "/to",
          query: case query {
            "" -> "a=1"
            q -> q
          },
          case_insensitive:,
          priority:,
        )
      },
    )
  let input =
    qcheck.map3(
      qcheck.generic_list(query_rule, qcheck.bounded_int(0, 8)),
      source,
      subset,
      fn(rules, path, query) {
        let rules =
          list.index_map(rules, fn(r, i) { Rule(..r, id: int.to_string(i)) })
        #(rules, path, query)
      },
    )
  check_many(1000, input, fn(input) {
    let #(rules, path, query) = input
    let request = rule.request_query(query)
    let expected =
      rules
      |> list.index_map(fn(r, i) { #(i, r) })
      |> list.filter(fn(entry) {
        let r = entry.1
        query != ""
        && {
          r.source == path
          && !r.case_insensitive
          || r.case_insensitive
          && string.lowercase(r.source) == string.lowercase(path)
        }
        && rule.query_matches(rule.query_conditions(r), request)
      })
      |> list.sort(fn(a, b) {
        let #(ai, a) = a
        let #(bi, b) = b
        int.compare(
          list.length(rule.query_conditions(b)),
          list.length(rule.query_conditions(a)),
        )
        |> order.break_tie(int.compare(a.priority, b.priority))
        |> order.break_tie(bool_order(a.case_insensitive, b.case_insensitive))
        |> order.break_tie(int.compare(ai, bi))
      })
      |> list.first
      |> result.map(fn(entry) { { entry.1 }.id })
    let found =
      matcher.lookup_query(matcher.build(rules), "x.test", path, query)
      |> result.map(fn(m) { m.rule.id })
    assert found == expected
  })
}

fn bool_order(a: Bool, b: Bool) -> order.Order {
  case a, b {
    False, True -> order.Lt
    True, False -> order.Gt
    _, _ -> order.Eq
  }
}

/// The next boundary tells the same as `crosses_boundary`: a rule starts or
/// expires in `(after, now]` exactly when the next one after `after` is not
/// later than `now`.
pub fn next_boundary_agrees_with_crosses_boundary_test() {
  let at = fn(seconds) {
    case seconds {
      0 -> ""
      s -> ffi.rfc3339(1_800_000_000 + s * 60)
    }
  }
  let scheduled =
    qcheck.map3(
      qcheck.bounded_int(0, 20),
      qcheck.bounded_int(0, 20),
      qcheck.bool(),
      fn(from, until, enabled) {
        Rule(
          ..rule.blank(),
          enabled:,
          starts_at: at(from),
          expires_at: at(until),
        )
      },
    )
  let input =
    qcheck.map3(
      qcheck.generic_list(scheduled, qcheck.bounded_int(0, 6)),
      qcheck.bounded_int(-1, 21),
      qcheck.bounded_int(0, 22),
      fn(rules, after, span) {
        #(
          rules,
          1_800_000_000 + after * 60,
          1_800_000_000 + { after + span } * 60,
        )
      },
    )
  check_many(1000, input, fn(input) {
    let #(rules, after, now) = input
    assert rule.crosses_boundary(rules, after, now)
      == { rule.next_boundary(rules, after) <= now }
  })
}
