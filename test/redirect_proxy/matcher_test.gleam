import gleam/list
import gleam/string
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
  assert ids(matcher_loop.redirect_loop(m, prefix, False)) == Ok(["p", "p"])
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

pub fn redirect_loop_through_trailing_slash_retry_test() {
  // /docs misses, is retried as /docs/ and redirected to /docs again
  let slash = r("s", "*", rule.Exact, "/docs/", "/docs")
  let m = matcher.build([slash])
  assert matcher_loop.redirect_loop(m, slash, False) == Error(Nil)
  let assert Ok([first, second]) = matcher_loop.redirect_loop(m, slash, True)
  assert first.id == "s"
  assert second.id == "s"
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
  // the URL tester resolves the query too
  let assert matcher.Redirected(_, location) =
    matcher.resolve_url(m, "https://x.test/page.php?id=42", False)
  assert location == "/article-42"
}
