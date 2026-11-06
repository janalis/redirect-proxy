import gleam/list
import redirect_proxy/matcher
import redirect_proxy/rule.{Rule}

fn r(
  id: String,
  host: String,
  kind: rule.MatchKind,
  source: String,
  target: String,
) {
  Rule(..rule.blank(), id:, host:, kind:, source:, target:)
}

fn location(
  m: matcher.Matcher,
  host: String,
  path: String,
) -> Result(String, Nil) {
  case matcher.lookup(m, host, path) {
    Ok(found) -> Ok(found.location)
    Error(Nil) -> Error(Nil)
  }
}

fn matched_id(m: matcher.Matcher, host: String, path: String) -> String {
  let assert Ok(found) = matcher.lookup(m, host, path)
  found.rule.id
}

pub fn exact_match_test() {
  let m = matcher.build([r("1", "*", rule.Exact, "/a", "/b")])
  assert location(m, "x.test", "/a") == Ok("/b")
  assert location(m, "x.test", "/a/") == Error(Nil)
  assert location(m, "x.test", "/A") == Error(Nil)
}

pub fn case_insensitive_exact_test() {
  let m =
    matcher.build([
      Rule(..r("1", "*", rule.Exact, "/About", "/b"), case_insensitive: True),
    ])
  assert location(m, "x", "/about") == Ok("/b")
  assert location(m, "x", "/ABOUT") == Ok("/b")
}

pub fn host_specific_rules_win_over_wildcard_test() {
  let m =
    matcher.build([
      r("wild", "*", rule.Exact, "/a", "/wild"),
      r("host", "example.com", rule.Regex, "^/a$", "/host"),
    ])
  // a regex on the specific host beats an exact rule on the wildcard
  assert matched_id(m, "example.com", "/a") == "host"
  assert matched_id(m, "other.com", "/a") == "wild"
}

pub fn host_is_normalised_test() {
  let m = matcher.build([r("1", "example.com", rule.Exact, "/a", "/b")])
  assert location(m, "EXAMPLE.com:8080", "/a") == Ok("/b")
  assert matcher.normalise_request_host("[::1]:8080") == "[::1]"
  assert matcher.normalise_request_host("Example.com") == "example.com"
}

pub fn precedence_exact_prefix_regex_test() {
  let m =
    matcher.build([
      r("regex", "*", rule.Regex, "^/docs/.*$", "/regex"),
      r("prefix", "*", rule.Prefix, "/docs/", "/prefix/$1"),
      r("exact", "*", rule.Exact, "/docs/index", "/exact"),
    ])
  assert matched_id(m, "h", "/docs/index") == "exact"
  assert matched_id(m, "h", "/docs/other") == "prefix"
}

pub fn longest_prefix_wins_test() {
  let m =
    matcher.build([
      r("short", "*", rule.Prefix, "/a/", "/short/$1"),
      r("long", "*", rule.Prefix, "/a/b/", "/long/$1"),
    ])
  assert location(m, "h", "/a/b/c") == Ok("/long/c")
  assert location(m, "h", "/a/x") == Ok("/short/x")
}

pub fn prefix_priority_breaks_ties_test() {
  let m =
    matcher.build([
      Rule(..r("low", "*", rule.Prefix, "/a", "/low"), priority: 50),
      Rule(..r("high", "*", rule.Prefix, "/b", "/high"), priority: 10),
      Rule(..r("first", "*", rule.Prefix, "/a", "/first"), priority: 1),
    ])
  assert matched_id(m, "h", "/a/x") == "first"
}

pub fn regex_priority_then_order_test() {
  let m =
    matcher.build([
      Rule(..r("late", "*", rule.Regex, "^/x", "/late"), priority: 200),
      Rule(..r("a", "*", rule.Regex, "^/x", "/a"), priority: 100),
      Rule(..r("b", "*", rule.Regex, "^/x", "/b"), priority: 100),
    ])
  assert matched_id(m, "h", "/x") == "a"
}

pub fn regex_captures_test() {
  let m =
    matcher.build([
      r(
        "1",
        "*",
        rule.Regex,
        "^/blog/(\\d+)/([a-z-]+)$",
        "https://n.test/p/$1?slug=$2",
      ),
    ])
  assert location(m, "h", "/blog/42/hello-world")
    == Ok("https://n.test/p/42?slug=hello-world")
  assert location(m, "h", "/blog/x/y") == Error(Nil)
}

pub fn case_insensitive_regex_test() {
  let m =
    matcher.build([
      Rule(..r("1", "*", rule.Regex, "^/old$", "/new"), case_insensitive: True),
    ])
  assert location(m, "h", "/OLD") == Ok("/new")
}

pub fn disabled_rules_are_ignored_test() {
  let m =
    matcher.build([Rule(..r("1", "*", rule.Exact, "/a", "/b"), enabled: False)])
  assert location(m, "h", "/a") == Error(Nil)
  assert matcher.size(m) == 0
}

pub fn query_string_handling_test() {
  let keep =
    matcher.build([
      Rule(..r("1", "*", rule.Exact, "/a", "/b"), preserve_query: True),
      Rule(..r("2", "*", rule.Exact, "/c", "/d?x=1"), preserve_query: True),
      r("3", "*", rule.Exact, "/e", "/f"),
    ])
  let loc = fn(path, query) {
    let assert Ok(found) = matcher.lookup(keep, "h", path)
    matcher.location(found, query)
  }
  assert loc("/a", Ok("q=1")) == "/b?q=1"
  assert loc("/a", Error(Nil)) == "/b"
  assert loc("/a", Ok("")) == "/b"
  assert loc("/c", Ok("q=1")) == "/d?x=1&q=1"
  assert loc("/e", Ok("q=1")) == "/f"
}

pub fn location_strips_crlf_test() {
  let m = matcher.build([r("1", "*", rule.Prefix, "/p/", "/x/$1")])
  let assert Ok(found) = matcher.lookup(m, "h", "/p/a\r\nb")
  assert matcher.location(found, Error(Nil)) == "/x/ab"
}

pub fn empty_matcher_test() {
  assert location(matcher.empty(), "h", "/") == Error(Nil)
  assert matcher.size(matcher.empty()) == 0
}

pub fn large_rule_set_test() {
  let rules =
    list.repeat(Nil, 5000)
    |> list.index_map(fn(_, i) {
      let n = int_to_string(i)
      r(n, "*", rule.Exact, "/page/" <> n, "/new/" <> n)
    })
  let m = matcher.build(rules)
  assert matcher.size(m) == 5000
  assert location(m, "h", "/page/4999") == Ok("/new/4999")
}

import gleam/int

fn int_to_string(i: Int) -> String {
  int.to_string(i)
}

pub fn substitutions_cannot_leave_the_host_test() {
  let m =
    matcher.build([
      r("1", "*", rule.Prefix, "/old/", "/$1"),
      r("2", "*", rule.Prefix, "/go", "https://example.com$1"),
      Rule(
        ..r("3", "*", rule.Regex, "^/r/(.*)$", "https://example.com/$1"),
        priority: 1,
      ),
      Rule(
        ..r("4", "*", rule.Regex, "^/u/(.*)$", "https://$1.example.com/"),
        priority: 1,
      ),
      Rule(..r("5", "*", rule.Regex, "^/u/(.*)$", "/users/$1"), priority: 2),
    ])
  // collapsed to a path on the same host
  assert location(m, "h", "/old//evil.com") == Ok("/evil.com")
  assert location(m, "h", "/old/\\evil.com") == Ok("/evil.com")
  assert location(m, "h", "/old/page") == Ok("/page")
  // the host cannot be extended or replaced
  assert location(m, "h", "/go/page") == Ok("https://example.com/page")
  assert location(m, "h", "/go.evil.com") == Error(Nil)
  assert location(m, "h", "/go@evil.com") == Error(Nil)
  // a path after a fixed host is fine, even with slashes
  assert location(m, "h", "/r//evil.com") == Ok("https://example.com//evil.com")
  // a subdomain capture must stay a subdomain; otherwise the next rule applies
  assert location(m, "h", "/u/blog") == Ok("https://blog.example.com/")
  assert location(m, "h", "/u/evil.com%23") == Ok("/users/evil.com%23")
  assert location(m, "h", "/u/evil.com/x") == Ok("/users/evil.com/x")
}

pub fn hit_counts_are_carried_to_the_next_matcher_test() {
  let a = r("a", "*", rule.Exact, "/a", "/b")
  let b = r("b", "*", rule.Exact, "/c", "/d")
  let first = matcher.build([a, b])
  matcher.record_hit(first, "a")
  matcher.record_hit(first, "a")
  matcher.record_hit(first, "b")
  matcher.record_hit(first, "unknown")
  assert matcher.hit_count(first, "a") == 2
  // b deleted, a disabled: a keeps its count, b is dropped
  let next =
    matcher.build([Rule(..a, enabled: False)])
    |> matcher.carry_hits(from: first)
  assert matcher.hit_count(next, "a") == 2
  assert matcher.hit_count(next, "b") == 0
}

pub fn prefix_index_prefers_longest_then_priority_test() {
  let m =
    matcher.build([
      Rule(..r("1", "*", rule.Prefix, "/a/", "/short/$1"), priority: 1),
      Rule(..r("2", "*", rule.Prefix, "/a/b/", "/low/$1"), priority: 9),
      Rule(..r("3", "*", rule.Prefix, "/A/B/", "/ci/$1"), priority: 5)
        |> fn(x) { Rule(..x, case_insensitive: True) },
      r("4", "*", rule.Prefix, "/é/", "/accent/$1"),
    ])
  let loc = fn(path) {
    let assert Ok(found) = matcher.lookup(m, "x.test", path)
    found.location
  }
  assert loc("/a/b/c") == "/ci/c"
  assert loc("/a/x") == "/short/x"
  assert loc("/é/ü") == "/accent/ü"
  assert matcher.lookup(m, "x.test", "/") == Error(Nil)
}

pub fn regex_index_keeps_priority_order_test() {
  let m =
    matcher.build([
      Rule(..r("1", "*", rule.Regex, "^/r/(.*)$", "/indexed/$1"), priority: 5),
      Rule(..r("2", "*", rule.Regex, "(.*)/z$", "/any/$1"), priority: 1),
      Rule(..r("3", "*", rule.Regex, "^/r/a?(.*)$", "/opt/$1"), priority: 9),
    ])
  let loc = fn(path) {
    let assert Ok(found) = matcher.lookup(m, "x.test", path)
    found.location
  }
  assert loc("/r/q/z") == "/any//r/q"
  assert loc("/r/q") == "/indexed/q"
  assert matcher.lookup(m, "x.test", "/s/q") == Error(Nil)
}

pub fn preserved_query_goes_before_the_fragment_test() {
  let m =
    matcher.build([
      Rule(..r("1", "*", rule.Exact, "/a", "/b#top"), preserve_query: True),
      Rule(..r("2", "*", rule.Exact, "/c", "/d?x=1#top"), preserve_query: True),
    ])
  let loc = fn(path) {
    let assert Ok(found) = matcher.lookup(m, "h", path)
    matcher.location(found, Ok("q=1"))
  }
  assert loc("/a") == "/b?q=1#top"
  assert loc("/c") == "/d?x=1&q=1#top"
}

pub fn rule_hosts_ignore_port_and_trailing_dot_test() {
  let m =
    matcher.build([
      r("1", "example.com:8080", rule.Exact, "/a", "/b"),
      r("2", "other.test.", rule.Exact, "/c", "/d"),
    ])
  assert location(m, "example.com:8080", "/a") == Ok("/b")
  assert location(m, "example.com", "/a") == Ok("/b")
  assert location(m, "other.test", "/c") == Ok("/d")
  assert location(m, "other.test.:443", "/c") == Ok("/d")
  assert location(m, "[::1]:8080", "/c") == Error(Nil)
}
