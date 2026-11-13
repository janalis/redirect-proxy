import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
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
  // every trailing dot: the listener accepts `example.com..`
  assert location(m, "example.com.", "/a") == Ok("/b")
  assert location(m, "example.com..:80", "/a") == Ok("/b")
  assert matcher.normalise_request_host("..") == ""
  // in one pass: a long run of dots costs bytes, not graphemes squared
  let dots = "example.com" <> string.repeat(".", 100_000)
  assert matcher.normalise_request_host(dots) == "example.com"
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

/// A target ending in `?` or `&` gets the preserved query without an extra
/// separator.
pub fn preserved_query_after_an_open_target_query_test() {
  let keep = fn(source, target) {
    Rule(..r(source, "*", rule.Exact, source, target), preserve_query: True)
  }
  let m = matcher.build([keep("/open", "/d?"), keep("/amp", "/d?x=1&#top")])
  let loc = fn(path, query) {
    let assert Ok(found) = matcher.lookup(m, "h", path)
    matcher.location(found, Ok(query))
  }
  assert loc("/open", "q=1") == "/d?q=1"
  assert loc("/amp", "q=1") == "/d?x=1&q=1#top"
}

/// The target's own query parameters win over the request's of the same
/// name; the others are appended.
pub fn target_query_parameters_win_test() {
  let keep = fn(source, target) {
    Rule(..r(source, "*", rule.Exact, source, target), preserve_query: True)
  }
  let m =
    matcher.build([
      keep("/set", "/d?lang=fr#top"),
      keep("/encoded", "/d?l%61ng=fr"),
      keep("/open", "/d?lang=fr&"),
    ])
  let loc = fn(path, query) {
    let assert Ok(found) = matcher.lookup(m, "h", path)
    matcher.location(found, Ok(query))
  }
  assert loc("/set", "lang=en&utm=x") == "/d?lang=fr&utm=x#top"
  assert loc("/set", "lang=en") == "/d?lang=fr#top"
  assert loc("/set", "lang=en&lang=de&q=1") == "/d?lang=fr&q=1#top"
  // names are compared decoded
  assert loc("/encoded", "lang=en&q=1") == "/d?l%61ng=fr&q=1"
  assert loc("/set", "l%61ng=en") == "/d?lang=fr#top"
  assert loc("/open", "lang=en&q=1") == "/d?lang=fr&q=1"
  // a malformed parameter is passed on as sent
  assert loc("/set", "x=%zz") == "/d?lang=fr&x=%zz#top"
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
import redirect_proxy/matcher/loop as matcher_loop

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
  // a prefix rule refused leaves the request to a shorter prefix
  let m =
    matcher.build([
      r("go", "*", rule.Prefix, "/go", "https://example.com$1"),
      r("all", "*", rule.Prefix, "/", "/home"),
    ])
  assert location(m, "h", "/go/page") == Ok("https://example.com/page")
  assert location(m, "h", "/go.evil.com") == Ok("/home")
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
  // a header value: non-ASCII percent-encoded
  assert loc("/é/ü") == "/accent/%C3%BC"
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

pub fn redirect_loop_test() {
  let prefix = r("p", "*", rule.Prefix, "/a/", "/a/b/$1")
  let to_c = r("1", "example.com", rule.Exact, "/x", "https://other.test/y")
  let back = r("2", "other.test", rule.Exact, "/y", "https://example.com/x")
  let plain = r("3", "*", rule.Prefix, "/old/", "/new/$1")
  let m = matcher.build([prefix, to_c, back, plain])
  let ids = fn(result) {
    case result {
      Ok(cycle) -> Ok(list.map(cycle, fn(x: rule.Rule) { x.id }))
      Error(Nil) -> Error(Nil)
    }
  }
  // /a/x -> /a/b/x -> /a/b/b/x ...
  let assert Ok(growing) = matcher_loop.redirect_loop(m, prefix, False)
  assert list.length(growing) == 21
  assert list.all(growing, fn(r) { r.id == "p" })
  // across hosts
  assert ids(matcher_loop.redirect_loop(m, to_c, False)) == Ok(["1", "2", "1"])
  assert matcher_loop.redirect_loop(m, plain, False) == Error(Nil)
}

pub fn shadowed_rule_is_not_a_loop_test() {
  // /a/b is caught by a more specific exact rule: no loop
  let prefix = r("p", "*", rule.Prefix, "/a/", "/a/b")
  let exact = r("e", "*", rule.Exact, "/a/b", "/done")
  let m = matcher.build([prefix, exact])
  assert matcher_loop.redirect_loop(m, prefix, False) == Error(Nil)
}

pub fn wildcard_hosts_test() {
  let m =
    matcher.build([
      r("1", "*.example.com", rule.Exact, "/a", "/wild"),
      r("2", "*.b.example.com", rule.Exact, "/a", "/closer"),
      r("3", "c.example.com", rule.Exact, "/a", "/exact"),
      r("4", "*", rule.Exact, "/a", "/any"),
    ])
  assert location(m, "x.example.com", "/a") == Ok("/wild")
  assert location(m, "x.y.example.com", "/a") == Ok("/wild")
  // the closest wildcard wins, an exact host wins over wildcards
  assert location(m, "x.b.example.com", "/a") == Ok("/closer")
  assert location(m, "c.example.com", "/a") == Ok("/exact")
  // subdomains only: the apex falls through to *
  assert location(m, "example.com", "/a") == Ok("/any")
  assert location(m, "X.Example.com:8080", "/a") == Ok("/wild")
  // longest DNS name: parents are looked up
  let long = string.repeat("a.", 120) <> "example.com"
  assert location(m, long, "/a") == Ok("/wild")
  // longer: no parent lookups, one per label would be quadratic (this
  // host has 100 000 labels)
  let huge = string.repeat("a.", 100_000) <> "example.com"
  assert location(m, huge, "/a") == Ok("/any")
}

pub fn equivalent_paths_match_test() {
  let m =
    matcher.build([
      r("1", "*", rule.Exact, "/café", "/coffee"),
      r("2", "*", rule.Exact, "/a%2fb", "/slash"),
      r("3", "*", rule.Prefix, "/docs/", "/manual/$1"),
      r("4", "*", rule.Exact, "/~user", "/home"),
    ])
  assert location(m, "h", "/caf%C3%A9") == Ok("/coffee")
  assert location(m, "h", "/caf%c3%a9") == Ok("/coffee")
  assert location(m, "h", "/café") == Ok("/coffee")
  // an encoded slash stays different from a path separator
  assert location(m, "h", "/a%2Fb") == Ok("/slash")
  assert location(m, "h", "/a/b") == Error(Nil)
  assert location(m, "h", "/%7Euser") == Ok("/home")
  // captures may hold decoded characters: Location stays ASCII
  let assert Ok(found) = matcher.lookup(m, "h", "/docs/%C3%A9t%C3%A9")
  assert matcher.location(found, Error(Nil)) == "/manual/%C3%A9t%C3%A9"
}

pub fn dot_segments_are_removed_test() {
  let m =
    matcher.build([
      r("1", "*", rule.Exact, "/b", "/bee"),
      r("2", "*", rule.Regex, "^/docs/(.*)$", "https://cdn.test/a/$1"),
      r("3", "*", rule.Exact, "/", "/root"),
      r("4", "*", rule.Exact, "/a/", "/a-slash"),
    ])
  assert location(m, "h", "/a/../b") == Ok("/bee")
  assert location(m, "h", "/./b") == Ok("/bee")
  assert location(m, "h", "/a/%2E%2E/b") == Ok("/bee")
  assert location(m, "h", "/a/.%2e/b") == Ok("/bee")
  // a dot segment at the end leaves the trailing slash
  assert location(m, "h", "/a/b/..") == Ok("/a-slash")
  assert location(m, "h", "/a/.") == Ok("/a-slash")
  // `..` above the root stays at the root
  assert location(m, "h", "/../..") == Ok("/root")
  // a capture cannot climb out of the target path
  assert location(m, "h", "/docs/../../b2/x") == Error(Nil)
  assert location(m, "h", "/docs/%2e%2e/%2e%2e/b2/x") == Error(Nil)
  assert location(m, "h", "/docs/x/../y") == Ok("https://cdn.test/a/y")
  // not dot segments: dotted names, encoded slashes
  assert location(m, "h", "/docs/.well-known/..x")
    == Ok("https://cdn.test/a/.well-known/..x")
  assert location(m, "h", "/docs/..%2F..%2Fb2")
    == Ok("https://cdn.test/a/..%2F..%2Fb2")
}

pub fn dot_segments_in_rule_sources_test() {
  // sources are normalised the same way as request paths
  let m = matcher.build([r("1", "*", rule.Prefix, "/x/../docs/", "/m/$1")])
  assert location(m, "h", "/docs/a") == Ok("/m/a")
}

pub fn trailing_slash_tolerance_test() {
  let m =
    matcher.build([
      r("1", "*", rule.Exact, "/a", "/no-slash"),
      r("2", "*", rule.Exact, "/b/", "/slash"),
      r("3", "*", rule.Exact, "/c", "/c-exact"),
      r("4", "*", rule.Exact, "/c/", "/c-slash"),
    ])
  let tolerant = fn(path) {
    case matcher.lookup_tolerant(m, "h", path) {
      Ok(found) -> Ok(found.location)
      Error(Nil) -> Error(Nil)
    }
  }
  assert location(m, "h", "/a/") == Error(Nil)
  assert tolerant("/a/") == Ok("/no-slash")
  assert tolerant("/b") == Ok("/slash")
  // an exact match is never replaced by the other form
  assert tolerant("/c") == Ok("/c-exact")
  assert tolerant("/c/") == Ok("/c-slash")
  assert tolerant("/") == Error(Nil)
}

/// The trailing slash retry is made host by host: the request host's rule
/// for the other form wins over a `*` or `*.parent` rule for the form sent.
pub fn trailing_slash_retry_is_per_host_test() {
  let m =
    matcher.build([
      r("docs", "a.example.test", rule.Exact, "/docs", "/host"),
      r("wild", "*.example.test", rule.Exact, "/docs/", "/wildcard"),
      r("all", "*", rule.Prefix, "/", "/catch-all"),
    ])
  let tolerant = fn(host, path) {
    matcher.lookup_tolerant(m, host, path) |> result.map(fn(m) { m.location })
  }
  assert tolerant("a.example.test", "/docs/") == Ok("/host")
  assert tolerant("a.example.test", "/docs") == Ok("/host")
  // another subdomain: its parent's rule, for either form, before `*`
  assert tolerant("b.example.test", "/docs") == Ok("/wildcard")
  assert tolerant("other.test", "/docs/") == Ok("/catch-all")
  // without the retry, the catch-all takes what the host has no rule for
  assert location(m, "a.example.test", "/docs/") == Ok("/wildcard")
}

pub fn redirect_loop_through_trailing_slash_retry_test() {
  // /docs misses, is retried as /docs/ and redirected to /docs again
  let slash = r("s", "*", rule.Exact, "/docs/", "/docs")
  let m = matcher.build([slash])
  assert matcher_loop.redirect_loop(m, slash, False) == Error(Nil)
  let assert Ok(chain) = matcher_loop.redirect_loop(m, slash, True)
  // /docs/ -> /docs -> /docs: the URL repeats only after the second hop.
  assert list.map(chain, fn(r) { r.id }) == ["s", "s", "s"]
}

/// Each regex run is capped; after a few capped runs the request stops
/// trying further regex rules, so one crafted path cannot cost the cap once
/// per rule.
pub fn regex_budget_is_per_request_test() {
  let path = "/" <> string.repeat("a", 30) <> "!"
  let expensive = fn(id) { r(id, "*", rule.Regex, "^/(a+)+$", "/x") }
  let cheap = r("cheap", "*", rule.Regex, "^/a+!$", "/found")
  let two = matcher.build([expensive("1"), expensive("2"), cheap])
  assert location(two, "x.test", path) == Ok("/found")
  let three =
    matcher.build([expensive("1"), expensive("2"), expensive("3"), cheap])
  assert location(three, "x.test", path) == Error(Nil)
}

/// A request that exhausts a host's regex budget is a miss: it does not go
/// on to the rules of `*.parent` hosts or `*`, which a crafted path could
/// otherwise reach past the host's own regex rules.
pub fn regex_budget_stops_the_lookup_test() {
  let path = "/" <> string.repeat("a", 30) <> "!"
  let expensive = fn(id) { r(id, "x.test", rule.Regex, "^/(a+)+$", "/x") }
  let catch_all = fn(host) { r("all", host, rule.Prefix, "/", "/caught") }
  let rules = [expensive("1"), expensive("2"), expensive("3")]
  assert location(matcher.build([catch_all("*"), ..rules]), "x.test", path)
    == Error(Nil)
  assert location(matcher.build([catch_all("*.test"), ..rules]), "x.test", path)
    == Error(Nil)
  assert matcher.lookup_tolerant(
      matcher.build([catch_all("*"), ..rules]),
      "x.test",
      path,
    )
    == Error(Nil)
  // a path the regexes refuse cheaply still reaches the broader rules
  assert location(matcher.build([catch_all("*"), ..rules]), "x.test", "/b")
    == Ok("/caught")
}

/// Substitutions apply to prefix and regex rules only: an exact rule's
/// target is used as written.
pub fn exact_targets_are_literal_test() {
  let m = matcher.build([r("1", "*", rule.Exact, "/a", "/price$5?x=$$")])
  assert location(m, "x.test", "/a") == Ok("/price$5?x=$$")
}

/// The rest of the path after a case-insensitive prefix keeps its case and
/// is cut where the prefix ends in bytes, like a case-sensitive prefix: here
/// before a combining accent (e + U+0301), which counting characters dropped.
pub fn case_insensitive_prefix_remainder_test() {
  let rules = fn(ci) {
    matcher.build([
      rule.Rule(
        ..r("1", "*", rule.Prefix, "/E", "/t/[$1]"),
        source: case ci {
          True -> "/E"
          False -> "/e"
        },
        case_insensitive: ci,
      ),
    ])
  }
  let path = "/e\u{301}Rest"
  assert location(rules(True), "x.test", path)
    == location(rules(False), "x.test", path)
  assert location(rules(True), "x.test", "/eRest") == Ok("/t/[Rest]")
}

/// A whole-segments prefix matches the path itself and what is below it,
/// not longer names that start the same way.
pub fn whole_segments_prefix_test() {
  let blog =
    rule.Rule(
      ..r("1", "*", rule.Prefix, "/blog", "https://new.test/news$1"),
      whole_segments: True,
    )
  let m = matcher.build([blog])
  assert location(m, "x.test", "/blog") == Ok("https://new.test/news")
  assert location(m, "x.test", "/blog/") == Ok("https://new.test/news/")
  assert location(m, "x.test", "/blog/2024/x")
    == Ok("https://new.test/news/2024/x")
  assert location(m, "x.test", "/blogger") == Error(Nil)
  // a shorter plain prefix still gets what the longer one leaves
  let m = matcher.build([blog, r("2", "*", rule.Prefix, "/b", "/other$1")])
  assert location(m, "x.test", "/blogger") == Ok("/otherlogger")
  // case-insensitive
  let m = matcher.build([rule.Rule(..blog, case_insensitive: True)])
  assert location(m, "x.test", "/BLOG/a") == Ok("https://new.test/news/a")
  assert location(m, "x.test", "/BLOGS") == Error(Nil)
}

/// A source that ends with `/` already ends on a segment boundary: whole
/// segments then match everything below it, as a plain prefix does.
pub fn whole_segments_prefix_with_trailing_slash_test() {
  let trail =
    rule.Rule(
      ..r("1", "*", rule.Prefix, "/trail/", "/new/$1"),
      whole_segments: True,
    )
  let m = matcher.build([trail])
  assert location(m, "x.test", "/trail/") == Ok("/new/")
  assert location(m, "x.test", "/trail/x") == Ok("/new/x")
  assert location(m, "x.test", "/trail/x/y") == Ok("/new/x/y")
  assert location(m, "x.test", "/trailx") == Error(Nil)
  // the URL tester agrees with the listener
  let assert Ok(explained) =
    explain.explain(m, [trail], "http://x.test/trail/x", False)
  assert list.map(explained.candidates, fn(c) { c.rule.id }) == ["1"]
}

/// The URL tester follows redirects as a browser does: a preserved query
/// goes on to the next hop, and asking the same path with another query is
/// not a loop.
pub fn explain_follows_queries_test() {
  let rules = [
    rule.Rule(..r("s", "*", rule.Exact, "/s", "/p"), preserve_query: True),
    rule.Rule(
      ..r("p", "*", rule.Exact, "/p", "/q"),
      query: "x=1",
      preserve_query: True,
    ),
    r("a", "*", rule.Exact, "/a", "/a?x=1"),
    rule.Rule(..r("ax", "*", rule.Exact, "/a", "/b"), query: "x=1"),
  ]
  let m = matcher.build(rules)
  let assert Ok(explained) =
    explain.explain(m, rules, "http://h.test/s?x=1", False)
  assert list.map(explained.chain, fn(h) { h.location }) == ["/p?x=1", "/q?x=1"]
  assert !explained.loops
  let assert Ok(explained) = explain.explain(m, rules, "http://h.test/a", False)
  assert list.map(explained.chain, fn(h) { h.rule_id }) == ["a", "ax"]
  assert !explained.loops
}

/// The tester reports a rule whose substitution would leave its target's
/// host as refused, not as shadowing the rule that applies instead.
pub fn explain_reports_refused_targets_test() {
  let rules = [
    r("go", "*", rule.Prefix, "/go", "https://example.com$1"),
    Rule(
      ..r("u", "*.test", rule.Regex, "^/u/(.*)$", "https://$1.example.com/"),
      enabled: False,
    ),
    r("sub", "*.test", rule.Prefix, "/s", "https://${sub}.example.com/p$1"),
    r("all", "*", rule.Prefix, "/", "/home"),
  ]
  let m = matcher.build(rules)
  let verdicts = fn(url) {
    let assert Ok(explained) = explain.explain(m, rules, url, False)
    list.map(explained.candidates, fn(c) { #(c.rule.id, c.verdict) })
  }
  assert verdicts("http://h.test/go.evil.com")
    == [#("go", explain.Refused), #("all", explain.Applied)]
  assert verdicts("http://h.test/go/page")
    == [#("go", explain.Applied), #("all", explain.Shadowed)]
  // refused whether enabled or not: enabling it would not help
  assert verdicts("http://h.test/u/evil.com/x")
    == [#("u", explain.Refused), #("all", explain.Applied)]
  assert verdicts("http://h.test/u/blog")
    == [#("u", explain.Disabled), #("all", explain.Applied)]
  // `${sub}` is what the `*` of the rule's host stands for, as when serving
  assert verdicts("http://a.test/s/x")
    == [#("sub", explain.Applied), #("all", explain.Shadowed)]
  assert location(m, "a.test", "/s/x") == Ok("https://a.example.com/p/x")
  assert verdicts("http://a.h.test/s/x")
    == [#("sub", explain.Applied), #("all", explain.Shadowed)]
  assert location(m, "a.h.test", "/s/x") == Ok("https://a.h.example.com/p/x")
}

pub fn hit_records_test() {
  let m = matcher.build([r("a", "*", rule.Exact, "/a", "/x")])
  assert matcher.last_hit(m, "a") == 0
  matcher.record_hit(m, "a")
  matcher.record_hit(m, "a")
  let assert [record] = matcher.hit_records(m)
  assert record.rule_id == "a" && record.count == 2 && record.last > 0
  // carried to the next matcher, and seeded from saved records
  let next =
    matcher.build([r("a", "*", rule.Exact, "/a", "/y")])
    |> matcher.carry_hits(from: m)
  assert matcher.hit_count(next, "a") == 2
  assert matcher.last_hit(next, "a") == record.last
  matcher.seed_hits(next, [
    matcher.HitRecord("a", 5, record.last - 100),
    matcher.HitRecord("gone", 9, 1),
  ])
  assert matcher.hit_count(next, "a") == 7
  // the most recent last hit wins
  assert matcher.last_hit(next, "a") == record.last
}

pub fn rules_outside_their_window_are_not_matched_test() {
  let past =
    rule.Rule(
      ..r("1", "*", rule.Exact, "/p", "/past"),
      expires_at: "2000-01-01T00:00:00Z",
    )
  let future =
    rule.Rule(
      ..r("2", "*", rule.Exact, "/f", "/future"),
      starts_at: "2999-01-01T00:00:00Z",
    )
  let now =
    rule.Rule(
      ..r("3", "*", rule.Exact, "/n", "/now"),
      starts_at: "2000-01-01T00:00:00Z",
      expires_at: "2999-01-01T00:00:00Z",
    )
  let m = matcher.build([past, future, now])
  assert location(m, "x.test", "/p") == Error(Nil)
  assert location(m, "x.test", "/f") == Error(Nil)
  assert location(m, "x.test", "/n") == Ok("/now")
  assert matcher.size(m) == 1
}

/// `${host}` is the request host and `${sub}` what a wildcard host's `*`
/// stands for; a capture can never move the redirect to another host.
pub fn host_placeholders_test() {
  let https = r("1", "*", rule.Prefix, "/", "https://${host}/$1")
  let m = matcher.build([https])
  assert location(m, "Shop.Test:80", "/a/b") == Ok("https://shop.test/a/b")
  // a request host that is not a host name never fills ${host}
  assert location(m, "x@evil.test", "/a") == Error(Nil)
  // the path cannot change the authority
  let m =
    matcher.build([r("1", "*", rule.Regex, "^(.*)$", "https://${host}$1")])
  assert location(m, "shop.test", "/x") == Ok("https://shop.test/x")
  assert location(m, "shop.test", "@evil.test/x") == Error(Nil)
  // keep the subdomain
  let m =
    matcher.build([
      r("2", "*.old.test", rule.Prefix, "/", "https://${sub}.new.test/$1"),
    ])
  assert location(m, "a.b.old.test", "/p") == Ok("https://a.b.new.test/p")
  assert location(m, "old.test", "/p") == Error(Nil)
  // `_` is allowed in rule hosts, so in ${host} and ${sub} too
  assert location(m, "my_app.old.test", "/p") == Ok("https://my_app.new.test/p")
  let m = matcher.build([https])
  assert location(m, "my_app.test", "/p") == Ok("https://my_app.test/p")
}

/// Exact rules with query conditions: every parameter must be present with
/// its value (others are allowed); they win over the plain rule for the
/// path, and more conditions win.
pub fn query_conditions_test() {
  let q = fn(id, query, target) {
    rule.Rule(..r(id, "*", rule.Exact, "/page.php", target), query:)
  }
  let m =
    matcher.build([
      r("plain", "*", rule.Exact, "/page.php", "/pages"),
      q("one", "id=42", "/article-42"),
      q("two", "lang=fr&id=42", "/fr/article-42"),
    ])
  let at = fn(query) {
    case matcher.lookup_query(m, "x.test", "/page.php", query) {
      Ok(found) -> found.location
      Error(Nil) -> ""
    }
  }
  assert at("id=42") == "/article-42"
  assert at("utm=x&id=42") == "/article-42"
  assert at("id=42&lang=fr") == "/fr/article-42"
  assert at("id=43") == "/pages"
  assert at("") == "/pages"
  // percent-encoding does not matter
  assert at("id=%34%32") == "/article-42"
  // a malformed parameter does not hide the others
  assert at("id=42&x=%zz") == "/article-42"
  assert at("x=%zz&lang=fr&id=42") == "/fr/article-42"
  // the URL tester resolves the query too
  let assert matcher.Redirected(_, location) =
    matcher.resolve_url(m, "https://x.test/page.php?id=42", False)
  assert location == "/article-42"
}

/// Many prefix lengths make a tree of indexes: the longest prefix still
/// wins, whatever branch it is in, and keys of an inner node are found.
pub fn prefix_index_with_many_lengths_test() {
  let prefix = fn(source, target) {
    Rule(..rule.blank(), id: source, kind: rule.Prefix, source:, target:)
  }
  let rules =
    int.range(1, 31, [], list.prepend)
    |> list.flat_map(fn(n) {
      [
        prefix("/" <> string.repeat("a", n), "/a" <> int.to_string(n)),
        prefix("/" <> string.repeat("b", n) <> "/", "/b" <> int.to_string(n)),
      ]
    })
    |> list.append([prefix("/c", "/c")])
  let m = matcher.build(rules)
  let target = fn(path) {
    case matcher.lookup(m, "x.test", path) {
      Ok(found) -> found.rule.target
      Error(Nil) -> ""
    }
  }
  assert target("/" <> string.repeat("a", 30) <> "/x") == "/a30"
  assert target("/" <> string.repeat("a", 12) <> "z") == "/a12"
  assert target("/a") == "/a1"
  assert target("/" <> string.repeat("b", 7) <> "/x") == "/b7"
  assert target("/" <> string.repeat("b", 6) <> "/x") == "/b6"
  assert target("/" <> string.repeat("b", 7)) == ""
  assert target("/cc") == "/c"
  assert target("/d") == ""
}

/// A path crafted to cost every regex just under the PCRE limit (no run is
/// stopped, so `max_exhausted_runs` does not apply) cannot cost a request
/// more than the regex budget: past it the request is a miss, counted in
/// the regex limit metric.
pub fn regex_cost_per_request_is_bounded_test() {
  let costly = fn(count) {
    int.range(from: count, to: 0, with: [], run: list.prepend)
    |> list.map(fn(i) {
      let id = int.to_string(i)
      r(id, "*", rule.Regex, "^/(?:q" <> id <> ")?(\\w+\\s?)*$", "/costly")
    })
  }
  let last =
    Rule(..r("last", "*", rule.Regex, "^/.*!$", "/caught"), priority: 1000)
  let crafted = "/word word word word !"
  // a few costly rules fit in the budget: the last rule is reached
  let m = matcher.build(list.append(costly(20), [last]))
  assert location(m, "h", crafted) == Ok("/caught")
  // a hundred do not: the request stops, and it is counted
  let m = matcher.build(list.append(costly(100), [last]))
  let before = ffi.regex_limit_count()
  assert location(m, "h", crafted) == Error(Nil)
  assert ffi.regex_limit_count() == before + 1
  // usual paths cost nothing near the budget
  assert location(m, "h", "/plain!") == Ok("/caught")
}

/// A rule of a `*.domain` host is sampled under a host of that domain, so
/// that `${host}` and `${sub}` apply and its loops are seen.
pub fn wildcard_host_loops_are_detected_test() {
  let looping =
    r("w", "*.example.com", rule.Prefix, "/old", "https://${host}/old$1")
  let m = matcher.build([looping])
  let assert Ok([first, again]) = matcher_loop.redirect_loop(m, looping, False)
  assert first.id == "w" && again.id == "w"
  let sub =
    r(
      "s",
      "*.example.com",
      rule.Prefix,
      "/go",
      "https://${sub}.example.com/go$1",
    )
  let m = matcher.build([sub])
  assert matcher_loop.redirect_loop(m, sub, False) |> result.is_ok
  // one that leaves the domain does not loop
  let away = r("a", "*.example.com", rule.Prefix, "/x", "https://new.test/x$1")
  assert matcher_loop.redirect_loop(matcher.build([away]), away, False)
    == Error(Nil)
}

/// A chain still redirecting after the 20 redirects browsers follow is
/// reported as a loop, even when every URL is new; a longer chain that
/// ends is not.
pub fn explain_reports_endless_chains_test() {
  let growing = r("g", "*", rule.Prefix, "/a", "/a/a$1")
  let rules = [growing]
  let assert Ok(explained) =
    explain.explain(matcher.build(rules), rules, "http://h.test/a/x", False)
  assert explained.loops
  assert list.length(explained.chain) == 21
  let assert Ok(checked) =
    matcher_loop.redirect_loop(matcher.build(rules), growing, False)
  assert list.length(checked) == list.length(explained.chain)
  // a chain of 15 redirects that ends is not one
  let ends =
    int.range(from: 1, to: 16, with: [], run: list.prepend)
    |> list.map(fn(i) {
      let n = int.to_string(i)
      r(n, "*", rule.Exact, "/" <> n, "/" <> int.to_string(i + 1))
    })
  let assert Ok(explained) =
    explain.explain(matcher.build(ends), ends, "http://h.test/1", False)
  assert !explained.loops
  assert list.length(explained.chain) == 15
  let assert Ok(first) = list.find(ends, fn(r) { r.source == "/1" })
  assert matcher_loop.redirect_loop(matcher.build(ends), first, False)
    == Error(Nil)
}

/// Query conditions, as documented: a parameter sent several times matches
/// if one of its values does; names and values keep their case, even on a
/// case-insensitive rule; other parameters are allowed.
pub fn query_conditions_as_documented_test() {
  let m =
    matcher.build([
      Rule(
        ..r("q", "*", rule.Exact, "/p", "/q"),
        query: "a=2",
        case_insensitive: True,
      ),
    ])
  let found = fn(query) {
    matcher.lookup_query(m, "h", "/p", query) |> result.is_ok
  }
  assert found("a=1&a=2")
  assert found("x=9&a=2")
  assert found("a=%32")
  assert !found("A=2")
  assert !found("a=1")
  // the path keeps ignoring case
  assert matcher.lookup_query(m, "h", "/P", "a=2") |> result.is_ok
}

pub fn mixed_case_query_rules_keep_file_order_test() {
  let sensitive =
    Rule(
      ..r("sensitive", "*", rule.Exact, "/Page", "/sensitive"),
      query: "id=42",
    )
  let folded =
    Rule(
      ..r("folded", "*", rule.Exact, "/page", "/folded"),
      query: "id=42",
      case_insensitive: True,
    )
  let target = fn(rules) {
    let assert Ok(found) =
      matcher.lookup_query(
        matcher.build(rules),
        "x.test",
        "/Page",
        "id=42&lang=fr",
      )
    found.location
  }
  // The rules come from different index groups for this mixed-case path.
  assert target([folded, sensitive]) == "/folded"
  assert target([sensitive, folded]) == "/sensitive"
  // Equal index keys must preserve the same order.
  let sensitive = Rule(..sensitive, source: "/page")
  let target = fn(rules) {
    let assert Ok(found) =
      matcher.lookup_query(
        matcher.build(rules),
        "x.test",
        "/page",
        "id=42&lang=fr",
      )
    found.location
  }
  assert target([folded, sensitive]) == "/folded"
  assert target([sensitive, folded]) == "/sensitive"
  // Priority wins over file order in either matching mode.
  assert target([folded, Rule(..sensitive, priority: 1)]) == "/sensitive"
  assert target([sensitive, Rule(..folded, priority: 1)]) == "/folded"
  // Specificity wins over both priority and file order.
  assert target([
      Rule(..folded, priority: 1),
      Rule(..sensitive, query: "id=42&lang=fr", priority: 999),
    ])
    == "/sensitive"
  assert target([
      Rule(..sensitive, priority: 1),
      Rule(..folded, query: "id=42&lang=fr", priority: 999),
    ])
    == "/folded"
}

pub fn unicode_prefix_precedence_uses_consumed_path_test() {
  let prefix = fn(id, source, case_insensitive, priority) {
    Rule(
      ..r(id, "*", rule.Prefix, source, "/" <> id <> "/$1"),
      case_insensitive:,
      priority:,
    )
  }
  let check_orders = fn(rules, path, expected) {
    list.each([rules, list.reverse(rules)], fn(ordered) {
      assert location(matcher.build(ordered), "h", path) == Ok(expected)
    })
  }
  // Kelvin sign lower-cases from three UTF-8 bytes to one ASCII byte.
  // Both insensitive: longer consumed prefix wins despite source lengths.
  check_orders(
    [
      prefix("short", "/K", True, 1),
      prefix("long", "/kk", True, 999),
    ],
    "/kkXYZ",
    "/long/XYZ",
  )
  // A sensitive Unicode source must not outrank a longer insensitive one.
  check_orders(
    [
      prefix("short", "/K", False, 1),
      prefix("long", "/kk", True, 999),
    ],
    "/KkXYZ",
    "/long/XYZ",
  )
  // The insensitive Unicode source must not outrank a longer sensitive one.
  check_orders(
    [
      prefix("short", "/K", True, 1),
      prefix("long", "/kk", False, 999),
    ],
    "/kkXYZ",
    "/long/XYZ",
  )
  // Encoded requests and sources are normalized before precedence is decided.
  check_orders(
    [
      prefix("short", "/%E2%84%AA", False, 1),
      prefix("long", "/kk", True, 999),
    ],
    "/%E2%84%AAkXYZ",
    "/long/XYZ",
  )
  // Equal consumed prefixes use priority, then original file order.
  let unicode = prefix("unicode", "/K", True, 100)
  let ascii = prefix("ascii", "/k", False, 100)
  assert location(matcher.build([unicode, ascii]), "h", "/kXYZ")
    == Ok("/unicode/XYZ")
  assert location(matcher.build([ascii, unicode]), "h", "/kXYZ")
    == Ok("/ascii/XYZ")
  check_orders([Rule(..unicode, priority: 1), ascii], "/kXYZ", "/unicode/XYZ")
  check_orders([unicode, Rule(..ascii, priority: 1)], "/kXYZ", "/ascii/XYZ")
}

pub fn redirect_destinations_use_browser_backslashes_test() {
  list.each(
    [
      "/x\\..\\a",
      "http://h/x\\..\\a",
      "//h/x\\..\\a",
      "/\\h/x\\..\\a",
    ],
    fn(target) {
      let r = r("loop", "h", rule.Exact, "/a", target)
      let assert Ok(r) = rule.validate(r)
      let m = matcher.build([r])
      let assert Ok(chain) = matcher_loop.redirect_loop(m, r, False)
      assert list.map(chain, fn(r) { r.id }) == ["loop", "loop"]
      let assert Ok(explained) = explain.explain(m, [r], "http://h/a", False)
      assert explained.loops
    },
  )
}

pub fn redirect_destination_slashes_preserve_query_data_test() {
  assert matcher_loop.next_request("h", "/x\\a?q=one\\two#frag\\data")
    == Ok(#("h", "/x/a", "q=one\\two"))
  assert matcher_loop.next_request("h", "/x%5Ca?q=%5C")
    == Ok(#("h", "/x%5Ca", "q=%5C"))
  assert matcher_loop.next_request("h", "https://other/x\\a?q=one\\two")
    == Ok(#("other", "/x/a", "q=one\\two"))
  assert matcher_loop.next_request("h", "/\\other/x\\a")
    == Ok(#("other", "/x/a", ""))
  assert matcher_loop.next_request("h", "/x\\a#frag?query\\data")
    == Ok(#("h", "/x/a", ""))
}

pub fn explanation_prefix_order_matches_consumed_path_test() {
  let short =
    Rule(..r("short", "*", rule.Prefix, "/K", "/short"), case_insensitive: True)
  let long =
    Rule(..r("long", "*", rule.Prefix, "/kk", "/long"), case_insensitive: True)
  let order = fn(rules, url) {
    let m = matcher.build(rules)
    let assert Ok(e) = explain.explain(m, rules, url, False)
    list.map(e.candidates, fn(c) { #(c.rule.id, c.verdict) })
  }
  list.each([[short, long], [long, short]], fn(rules) {
    assert order(rules, "http://h/kkXYZ")
      == [#("long", explain.Applied), #("short", explain.Shadowed)]
  })
  assert order(
      [Rule(..short, case_insensitive: False), long],
      "http://h/%E2%84%AAkXYZ",
    )
    == [#("long", explain.Applied), #("short", explain.Shadowed)]
  let same = Rule(..r("same", "*", rule.Prefix, "/k", "/same"), priority: 1)
  assert order([short, same], "http://h/kXYZ")
    == [#("same", explain.Applied), #("short", explain.Shadowed)]
  let same = Rule(..same, priority: 100)
  assert order([short, same], "http://h/kXYZ")
    == [#("short", explain.Applied), #("same", explain.Shadowed)]
  assert order([same, short], "http://h/kXYZ")
    == [#("same", explain.Applied), #("short", explain.Shadowed)]
}

pub fn explanation_exact_order_matches_runtime_test() {
  let plain = r("plain", "*", rule.Exact, "/Page", "/plain")
  let one = Rule(..r("one", "*", rule.Exact, "/Page", "/one"), query: "id=42")
  let two =
    Rule(
      ..r("two", "*", rule.Exact, "/Page", "/two"),
      query: "id=42&lang=fr",
      priority: 999,
    )
  let folded =
    Rule(
      ..r("folded", "*", rule.Exact, "/page", "/folded"),
      query: "id=42",
      case_insensitive: True,
    )
  let ordered = fn(rules) {
    let m = matcher.build(rules)
    let assert Ok(found) =
      matcher.lookup_query(m, "h.test", "/Page", "id=42&lang=fr")
    let assert Ok(e) =
      explain.explain(m, rules, "http://h.test/Page?id=42&lang=fr", False)
    let assert [first, ..] = e.candidates
    assert first.rule.id == found.rule.id
    assert first.verdict == explain.Applied
    list.map(e.candidates, fn(c) { c.rule.id })
  }
  assert ordered([plain, one, two]) == ["two", "one", "plain"]
  assert ordered([plain, folded, one]) == ["folded", "one", "plain"]
  assert ordered([plain, one, folded]) == ["one", "folded", "plain"]
  assert ordered([plain, folded, Rule(..one, priority: 1)])
    == ["one", "folded", "plain"]
  assert ordered([plain, one, Rule(..folded, priority: 1)])
    == ["folded", "one", "plain"]
  let plain_folded = Rule(..folded, query: "", priority: 1)
  // Plain exact matching gives sensitive rules precedence, ignoring priority.
  assert ordered([plain_folded, plain]) == ["plain", "folded"]
  // Host precedence wins even when the wildcard query is more specific.
  assert ordered([two, Rule(..plain, host: "h.test")]) == ["plain", "two"]
}

pub fn repeated_rules_with_new_urls_can_terminate_test() {
  let grow = r("grow", "*", rule.Prefix, "/a", "/ab$1")
  let exit = r("exit", "*", rule.Prefix, "/abb", "/done")
  let rules = [grow, exit]
  let m = matcher.build(rules)
  assert matcher_loop.redirect_loop(m, grow, False) == Error(Nil)
  let assert Ok(e) = explain.explain(m, rules, "http://h/aloop-check", False)
  assert !e.loops
  assert list.map(e.chain, fn(hop) { hop.rule_id }) == ["grow", "grow", "exit"]
  let assert Ok(grow) = rule.validate(grow)
  let assert Ok(exit) = rule.validate(exit)
  assert matcher_loop.redirect_loop(matcher.build([grow, exit]), grow, False)
    == Error(Nil)
}

pub fn redirect_loop_states_include_host_and_query_test() {
  let cross = r("cross", "*", rule.Exact, "/a", "http://b.test/a")
  let exit = r("exit", "b.test", rule.Exact, "/a", "/done")
  let m = matcher.build([cross, exit])
  assert matcher_loop.redirect_loop(m, cross, False) == Error(Nil)
  let assert Ok(e) = explain.explain(m, [cross, exit], "http://a.test/a", False)
  assert !e.loops
  let first = r("query", "*", rule.Exact, "/a", "/a?x=1")
  let second = Rule(..r("exit", "*", rule.Exact, "/a", "/done"), query: "x=1")
  let rules = [first, second]
  let m = matcher.build(rules)
  assert matcher_loop.redirect_loop(m, first, False) == Error(Nil)
  let assert Ok(e) = explain.explain(m, rules, "http://h/a", False)
  assert !e.loops
}
