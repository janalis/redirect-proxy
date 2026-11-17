//// The URL tester's explanations, on their own: parsing, the order and
//// verdicts of candidates, the redirect chain, and (property) agreement
//// with the matcher on generated rule sets.

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import qcheck
import redirect_proxy/matcher
import redirect_proxy/matcher/explain.{
  Applied, Disabled, OutOfSchedule, Refused, Shadowed,
}
import redirect_proxy/rule.{type Rule, Exact, Prefix, Regex, Rule}

const past = "2000-01-01T00:00:00Z"

fn r(id: String, host: String, kind: rule.MatchKind, source: String) -> Rule {
  Rule(..rule.blank(), id:, host:, kind:, source:, target: "/to/" <> id)
}

fn verdicts(rules: List(Rule), url: String, tolerant: Bool) {
  let assert Ok(e) = explain.explain(matcher.build(rules), rules, url, tolerant)
  list.map(e.candidates, fn(c) { #(c.rule.id, c.verdict) })
}

// --- parsing ------------------------------------------------------------------

pub fn urls_without_a_host_are_refused_test() {
  let m = matcher.empty()
  assert explain.explain(m, [], "", False) == Error(Nil)
  assert explain.explain(m, [], "/path/only", False) == Error(Nil)
  assert explain.explain(m, [], "not a url", False) == Error(Nil)
}

pub fn host_and_path_are_normalised_test() {
  let assert Ok(e) =
    explain.explain(
      matcher.empty(),
      [],
      "  http://Sub.Example.TEST.:8080  ",
      False,
    )
  assert e.host == "sub.example.test"
  assert e.path == "/"
  assert e.candidates == []
  assert e.chain == []
  assert !e.loops
}

// --- candidates -----------------------------------------------------------------

/// The request host's rules, then `*.parent` ones from the closest parent,
/// then `*`: the first applies, the others are shadowed.
pub fn candidates_follow_host_precedence_test() {
  let rules = [
    r("any", "*", Prefix, "/"),
    r("test", "*.test", Prefix, "/"),
    r("parent", "*.a.test", Prefix, "/"),
    r("own", "B.A.test", Prefix, "/"),
    r("other", "c.test", Prefix, "/"),
  ]
  assert verdicts(rules, "http://b.a.test/x", False)
    == [
      #("own", Applied),
      #("parent", Shadowed),
      #("test", Shadowed),
      #("any", Shadowed),
    ]
}

/// Exact rules, then prefix rules (the longest first), then regex rules (by
/// priority), whatever their order in the file.
pub fn candidates_follow_kind_order_test() {
  let rules = [
    Rule(..r("re2", "*", Regex, "^/a"), priority: 2),
    Rule(..r("re1", "*", Regex, "^/a/b"), priority: 1),
    r("short", "*", Prefix, "/a"),
    r("long", "*", Prefix, "/a/b"),
    r("exact", "*", Exact, "/a/b"),
    r("miss", "*", Exact, "/a/c"),
  ]
  assert verdicts(rules, "http://h.test/a/b", False)
    == [
      #("exact", Applied),
      #("long", Shadowed),
      #("short", Shadowed),
      #("re1", Shadowed),
      #("re2", Shadowed),
    ]
}

pub fn disabled_and_scheduled_rules_test() {
  let rules = [
    Rule(..r("off", "*", Exact, "/a"), enabled: False),
    Rule(..r("over", "*", Exact, "/a"), expires_at: past),
    r("on", "*", Prefix, "/"),
  ]
  assert verdicts(rules, "http://h.test/a", False)
    == [#("off", Disabled), #("over", OutOfSchedule), #("on", Applied)]
  // nothing applies: the chain is empty
  let only = list.take(rules, 2)
  let assert Ok(e) =
    explain.explain(matcher.build(only), only, "http://h.test/a", False)
  assert list.map(e.candidates, fn(c) { c.verdict })
    == [Disabled, OutOfSchedule]
  assert e.chain == []
  assert !e.loops
}

/// A rule only reached by adding or removing the trailing slash is listed
/// as the one that applies, with the tolerant lookup only.
pub fn trailing_slash_retry_is_listed_test() {
  let rules = [r("docs", "*", Exact, "/docs")]
  assert verdicts(rules, "http://h.test/docs/", True) == [#("docs", Applied)]
  assert verdicts(rules, "http://h.test/docs/", False) == []
}

/// Query conditions decide which exact rules are candidates.
pub fn query_conditions_select_candidates_test() {
  let rules = [
    r("plain", "*", Exact, "/p"),
    Rule(..r("lang", "*", Exact, "/p"), query: "lang=fr"),
  ]
  assert verdicts(rules, "http://h.test/p?lang=fr&x=1", False)
    == [#("lang", Applied), #("plain", Shadowed)]
  assert verdicts(rules, "http://h.test/p?lang=en", False)
    == [#("plain", Applied)]
}

// --- chain ----------------------------------------------------------------------

pub fn chain_records_each_hop_test() {
  let rules = [
    Rule(..r("one", "*", Exact, "/a"), target: "https://b.test/b", status: 308),
    Rule(..r("two", "b.test", Exact, "/b"), target: "/c", status: 302),
  ]
  let assert Ok(e) =
    explain.explain(matcher.build(rules), rules, "http://a.test/a", False)
  assert e.chain
    == [
      explain.Hop("https://b.test/b", 308, "one"),
      explain.Hop("/c", 302, "two"),
    ]
  assert !e.loops
}

pub fn a_rule_redirecting_to_itself_loops_test() {
  let rules = [Rule(..r("self", "*", Exact, "/a"), target: "/a")]
  let assert Ok(e) =
    explain.explain(matcher.build(rules), rules, "http://h.test/a", False)
  assert list.map(e.chain, fn(h) { h.rule_id }) == ["self"]
  assert e.loops
}

// --- agreement with the matcher (property) --------------------------------------

/// Few segments, so that generated rules and probes often share paths.
fn segment() -> qcheck.Generator(String) {
  pick(["a", "A", "b"])
}

fn gen_path() -> qcheck.Generator(String) {
  qcheck.generic_list(
    elements_from: segment(),
    length_from: qcheck.bounded_int(0, 2),
  )
  |> qcheck.map2(qcheck.bool(), fn(segments, slash) {
    "/"
    <> string.join(segments, "/")
    <> case slash && segments != [] {
      True -> "/"
      False -> ""
    }
  })
}

fn pick(values: List(a)) -> qcheck.Generator(a) {
  let assert [first, ..rest] = list.map(values, qcheck.return)
  qcheck.from_generators(first, rest)
}

const rule_hosts = ["*", "*", "a.test", "*.test", "*.a.test", "b.a.test"]

const targets = [
  "/t/$1", "/static", "https://example.com$1", "https://$1.example.com/",
  "https://${host}/$1", "/a",
]

const queries = ["", "", "x=1", "x=1&y=2"]

/// Exact, prefix and regex rules over a few hosts, enabled or not, some out
/// of their schedule, with query conditions, letter case options and
/// targets that the substitution guard may refuse.
fn gen_rule() -> qcheck.Generator(Rule) {
  let shape =
    qcheck.tuple4(
      qcheck.bounded_int(0, 5),
      gen_path(),
      pick(rule_hosts),
      pick(targets),
    )
  let options =
    qcheck.tuple4(
      qcheck.bounded_int(0, 9),
      qcheck.bool(),
      qcheck.bounded_int(1, 3),
      pick(queries),
    )
  use #(kind, source, host, target), #(state, flag, priority, query) <- qcheck.map2(
    shape,
    options,
  )
  let #(kind, source) = case kind {
    0 | 1 -> #(Exact, source)
    2 | 3 -> #(Prefix, source)
    4 -> #(Regex, "^" <> source <> "(.*)$")
    _ -> #(Regex, "^/(?:" <> string.drop_start(source, 1) <> ")?(.*)")
  }
  Rule(
    ..rule.blank(),
    host:,
    kind:,
    source:,
    target:,
    priority:,
    case_insensitive: flag,
    whole_segments: kind == Prefix && priority == 2,
    query: case kind {
      Exact -> query
      _ -> ""
    },
    enabled: state != 0,
    expires_at: case state {
      1 -> past
      _ -> ""
    },
  )
}

fn gen_rules() -> qcheck.Generator(List(Rule)) {
  qcheck.generic_list(
    elements_from: gen_rule(),
    length_from: qcheck.bounded_int(0, 10),
  )
  |> qcheck.map(fn(rules) {
    list.index_map(rules, fn(r, i) { Rule(..r, id: "r" <> int.to_string(i)) })
  })
}

/// Whatever the rules, the explanation agrees with the matcher: the rule it
/// marks as applied is the one the lookup finds, every enabled and allowed
/// rule listed before it is disabled, out of schedule or refused, and the
/// chain starts with the redirect the lookup gives.
pub fn explanation_agrees_with_lookup_test() {
  let probe =
    qcheck.tuple4(
      pick(["a.test", "b.a.test", "x.b.a.test", "c.test", "B.A.Test:8080"]),
      qcheck.tuple2(gen_path(), qcheck.bounded_int(0, 12)),
      pick(["", "x=1", "x=1&y=2", "x=2"]),
      qcheck.bool(),
    )
  use #(rules, #(host, #(path, pick_source), query, tolerant)) <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(1000),
    qcheck.tuple2(gen_rules(), probe),
  )
  // most often, the path of one of the rules (so that several may match)
  let path = case list.drop(rules, pick_source) {
    [Rule(kind: Exact, source:, ..), ..]
    | [Rule(kind: Prefix, source:, ..), ..] -> source
    _ -> path
  }
  let m = matcher.build(rules)
  let url =
    "http://"
    <> host
    <> path
    <> case query {
      "" -> ""
      q -> "?" <> q
    }
  let assert Ok(e) = explain.explain(m, rules, url, tolerant)
  let found = case tolerant {
    True -> matcher.lookup_tolerant_query(m, host, path, query)
    False -> matcher.lookup_query(m, host, path, query)
  }
  let ids = list.map(e.candidates, fn(c) { c.rule.id })
  assert list.unique(ids) == ids
  let applied = list.filter(e.candidates, fn(c) { c.verdict == Applied })
  let #(before, _) =
    list.split_while(e.candidates, fn(c) { c.verdict != Applied })
  // nothing usable comes before the rule that applies (or at all, if none)
  list.each(before, fn(c) {
    assert c.verdict != Shadowed
  })
  list.each(e.candidates, fn(c) {
    case c.verdict {
      Applied | Shadowed -> {
        assert c.rule.enabled && c.rule.expires_at == ""
      }
      Disabled -> {
        assert !c.rule.enabled
      }
      OutOfSchedule -> {
        assert c.rule.enabled && c.rule.expires_at == past
      }
      Refused -> Nil
    }
  })
  case found {
    Ok(m) -> {
      assert list.map(applied, fn(c) { c.rule.id }) == [m.redirect.id]
      let request_query = case query {
        "" -> Error(Nil)
        q -> Ok(q)
      }
      let assert [first, ..] = e.chain
      assert first
        == explain.Hop(
          matcher.location(m, request_query),
          m.redirect.status,
          m.redirect.id,
        )
    }
    Error(Nil) -> {
      assert applied == []
      assert e.chain == []
      assert !e.loops
    }
  }
  assert result.is_ok(found) == { e.chain != [] }
}
