import gleam/list
import gleam/string
import redirect_proxy/rule.{Rule}

fn base() -> rule.Rule {
  Rule(..rule.blank(), source: "/old", target: "/new")
}

pub fn valid_rule_is_normalised_test() {
  let assert Ok(r) =
    rule.validate(
      Rule(..base(), host: "  Example.COM ", source: " /a ", target: " /b "),
    )
  assert r.host == "example.com"
  assert r.source == "/a"
  assert r.target == "/b"
}

pub fn empty_host_becomes_wildcard_test() {
  let assert Ok(r) = rule.validate(Rule(..base(), host: ""))
  assert r.host == "*"
}

pub fn host_with_port_is_accepted_test() {
  let assert Ok(_) = rule.validate(Rule(..base(), host: "example.com:8080"))
}

pub fn invalid_hosts_are_rejected_test() {
  ["exa mple.com", "-bad.com", "bad-.com", "a..b", "example.com:99999", "é.com"]
  |> list.each(fn(host) {
    let assert Error(errors) = rule.validate(Rule(..base(), host:))
    assert list.any(errors, string.starts_with(_, "host:"))
  })
}

pub fn exact_source_must_start_with_slash_test() {
  let assert Error(errors) = rule.validate(Rule(..base(), source: "old"))
  assert errors == ["source: must start with /"]
}

pub fn invalid_regex_is_rejected_test() {
  let assert Error([error]) =
    rule.validate(Rule(..base(), kind: rule.Regex, source: "^/(unclosed"))
  assert string.starts_with(error, "source: invalid regular expression")
}

pub fn targets_test() {
  let ok = [
    "/path",
    "https://example.com",
    "http://example.com/x?y=1",
    "//cdn.example.com/x",
    "HTTPS://EXAMPLE.COM",
  ]
  let bad = ["javascript:alert(1)", "example.com", "ftp://example.com", ""]
  list.each(ok, fn(target) {
    let assert Ok(_) = rule.validate(Rule(..base(), target:))
  })
  list.each(bad, fn(target) {
    let assert Error(errors) = rule.validate(Rule(..base(), target:))
    assert list.any(errors, string.starts_with(_, "target:"))
  })
}

pub fn header_injection_is_rejected_test() {
  let assert Error(errors) =
    rule.validate(Rule(..base(), target: "/x\r\nset-cookie: a=b"))
  assert list.contains(errors, "target: contains control characters")
}

pub fn status_must_be_a_redirect_test() {
  [301, 302, 303, 307, 308]
  |> list.each(fn(status) {
    let assert Ok(_) = rule.validate(Rule(..base(), status:))
  })
  [200, 300, 304, 305, 404]
  |> list.each(fn(status) {
    let assert Error(_) = rule.validate(Rule(..base(), status:))
  })
}

pub fn json_round_trip_test() {
  let r =
    Rule(
      ..base(),
      id: "abc",
      host: "example.com",
      kind: rule.Prefix,
      status: 308,
      preserve_query: True,
      case_insensitive: True,
      priority: 5,
      enabled: False,
      note: "hello \"world\"",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-02T00:00:00Z",
      updated_by: "admin",
    )
  let assert Ok([decoded]) = rule.file_from_string(rule.file_to_string([r]))
  assert decoded == r
}

pub fn bare_array_with_defaults_test() {
  let assert Ok([r]) =
    rule.file_from_string("[{\"source\": \"/a\", \"target\": \"/b\"}]")
  assert r.host == "*"
  assert r.kind == rule.Exact
  assert r.status == 301
  assert r.enabled
  assert r.priority == rule.default_priority
}

pub fn unsupported_version_test() {
  let assert Error(message) =
    rule.file_from_string("{\"version\": 2, \"rules\": []}")
  assert string.contains(message, "version 2")
}

pub fn invalid_json_test() {
  let assert Error(_) = rule.file_from_string("{nope")
  let assert Error(_) = rule.file_from_string("[{\"source\": 1}]")
}

pub fn expand_test() {
  let captures = ["/blog/42/hello", "42", "hello"]
  assert rule.expand("/a/$1/$2", captures) == "/a/42/hello"
  assert rule.expand("/a/${1}0", captures) == "/a/420"
  assert rule.expand("/all$0", captures) == "/all/blog/42/hello"
  assert rule.expand("/cost$$5", captures) == "/cost$5"
  assert rule.expand("/missing$9", captures) == "/missing"
  assert rule.expand("/literal$x", captures) == "/literal$x"
  assert rule.expand("/trailing$", captures) == "/trailing$"
  assert rule.expand("/brace${x}", captures) == "/brace${x}"
}

pub fn kind_from_string_test() {
  assert rule.kind_from_string("EXACT") == Ok(rule.Exact)
  assert rule.kind_from_string("prefix") == Ok(rule.Prefix)
  assert rule.kind_from_string("regex") == Ok(rule.Regex)
  assert rule.kind_from_string("glob") == Error(Nil)
}

pub fn catastrophic_regexes_are_rejected_test() {
  let regex = fn(source) { Rule(..base(), kind: rule.Regex, source:) }
  let assert Error(_) = rule.compile(regex("^/(a+)+$"))
  let assert Error(_) = rule.compile(regex("^/(\\w+\\s?)*$"))
  let assert Error(_) = rule.compile(regex("^(.*a){20}$"))
  let assert Error(_) = rule.compile(regex("^/(a|aa)+$"))
}

pub fn common_regexes_are_accepted_test() {
  let regex = fn(source) { Rule(..base(), kind: rule.Regex, source:) }
  let assert Ok(_) = rule.compile(regex("^/(.*)$"))
  let assert Ok(_) = rule.compile(regex("^/blog/(.*)/(.*)$"))
  let assert Ok(_) = rule.compile(regex("^/blog/(\\d+)(?:/[a-z0-9-]+)?/?$"))
  let assert Ok(_) =
    rule.compile(regex("^/(fr|en|de)/products/([^/]+)\\.html$"))
  let assert Ok(_) = rule.compile(regex("\\.php$"))
}

pub fn target_guard_shapes_test() {
  assert rule.target_guard("/static") == rule.Static
  assert rule.target_guard("/new/$1") == rule.SameHostPath
  assert rule.target_guard("https://Example.com$1")
    == rule.FixedHost("example.com")
  assert rule.target_guard("https://example.com:8443/$1")
    == rule.FixedHost("example.com:8443")
  assert rule.target_guard("//example.com${1}") == rule.FixedHost("example.com")
  assert rule.target_guard("https://$1.example.com/")
    == rule.SubdomainOf(".example.com")
  assert rule.target_guard("https://example$1.com/") == rule.Unsafe
  assert rule.target_guard("https://$1.com/") == rule.Unsafe
  assert rule.target_guard("https://x$1.example.com/") == rule.Unsafe
  assert rule.target_guard("https://$1-$2.example.com/")
    == rule.SubdomainOf(".example.com")
  // the host is entirely a capture: nothing can match it
  assert rule.target_guard("https://$1/") == rule.FixedHost("")
}

pub fn guard_blocks_open_redirects_test() {
  let path = rule.target_guard("/$1")
  assert rule.guard_location(path, "//evil.com", rule.no_vars)
    == Ok("/evil.com")
  assert rule.guard_location(path, "/\\evil.com", rule.no_vars)
    == Ok("/evil.com")
  assert rule.guard_location(path, "/\t/evil.com", rule.no_vars)
    == Ok("/evil.com")
  assert rule.guard_location(path, "/blog/post", rule.no_vars)
    == Ok("/blog/post")

  let fixed = rule.target_guard("https://example.com$1")
  assert rule.guard_location(fixed, "https://example.com/blog", rule.no_vars)
    == Ok("https://example.com/blog")
  assert rule.guard_location(fixed, "https://example.com?q", rule.no_vars)
    == Ok("https://example.com?q")
  assert rule.guard_location(fixed, "https://example.com", rule.no_vars)
    == Ok("https://example.com")
  assert rule.guard_location(
      fixed,
      "https://example.com.evil.com/",
      rule.no_vars,
    )
    == Error(Nil)
  assert rule.guard_location(
      fixed,
      "https://example.com@evil.com/",
      rule.no_vars,
    )
    == Error(Nil)
  assert rule.guard_location(
      fixed,
      "https://example.com:1@evil.com",
      rule.no_vars,
    )
    == Error(Nil)

  let sub = rule.target_guard("https://$1.example.com/")
  assert rule.guard_location(sub, "https://blog.example.com/", rule.no_vars)
    == Ok("https://blog.example.com/")
  assert rule.guard_location(
      sub,
      "https://evil.com#.example.com/",
      rule.no_vars,
    )
    == Error(Nil)
  assert rule.guard_location(
      sub,
      "https://evil.com/.example.com/",
      rule.no_vars,
    )
    == Error(Nil)
  assert rule.guard_location(sub, "https://.example.com/", rule.no_vars)
    == Error(Nil)
  assert rule.guard_location(rule.Unsafe, "/x", rule.no_vars) == Error(Nil)
}

pub fn wildcard_and_international_hosts_test() {
  let with_host = fn(host) {
    rule.validate(Rule(..rule.blank(), host:, source: "/a", target: "/b"))
  }
  let assert Ok(r) = with_host("*.Example.com")
  assert r.host == "*.example.com"
  let assert Ok(_) = with_host("*.a.example.com")
  // a whole top-level domain, or a wildcard elsewhere, is refused
  let assert Error(_) = with_host("*.com")
  let assert Error(_) = with_host("a.*.example.com")
  let assert Error(_) = with_host("*.*.example.com")
  // international names must be given in punycode
  let assert Error([reason]) = with_host("café.example")
  assert string.contains(reason, "punycode")
  let assert Ok(_) = with_host("xn--caf-dma.example")
}

pub fn lint_flags_parts_that_never_match_test() {
  assert rule.lint(base()) == []
  let assert [query] = rule.lint(Rule(..base(), source: "/page.php?id=5"))
  assert string.starts_with(query, "source: cannot contain a query string")
  let assert [fragment] =
    rule.lint(Rule(..base(), kind: rule.Prefix, source: "/a#b"))
  assert string.starts_with(fragment, "source: cannot contain a fragment")
  let assert [port] = rule.lint(Rule(..base(), host: "example.com:8080"))
  assert string.starts_with(port, "host: remove the port")
  let assert [slashes] =
    rule.lint(Rule(..base(), kind: rule.Prefix, source: "//legacy/"))
  assert string.starts_with(slashes, "source: cannot start with //")
  // `?` is a quantifier in a regex
  assert rule.lint(Rule(..base(), kind: rule.Regex, source: "^/a?$")) == []
}

pub fn whole_segments_test() {
  let prefix = Rule(..base(), kind: rule.Prefix, whole_segments: True)
  let assert Ok(_) = rule.validate(prefix)
  let assert Error([reason]) =
    rule.validate(Rule(..base(), whole_segments: True))
  assert string.starts_with(reason, "whole_segments:")
  // only written when set: existing files and rule versions do not change
  assert !string.contains(rule.file_to_string([base()]), "whole_segments")
  assert rule.file_from_string(rule.file_to_string([prefix])) == Ok([prefix])
  assert rule.version(prefix)
    != rule.version(Rule(..prefix, whole_segments: False))
}

pub fn schedule_test() {
  let timed =
    Rule(
      ..base(),
      starts_at: "2026-12-01T00:00:00Z",
      expires_at: "2026-12-02T00:00:00+01:00",
    )
  let assert Ok(_) = rule.validate(timed)
  let #(from, until) = rule.window(timed)
  assert until - from == 23 * 3600
  assert rule.is_active(timed, from)
  assert !rule.is_active(timed, from - 1)
  assert !rule.is_active(timed, until)
  assert !rule.is_active(Rule(..timed, enabled: False), from)
  assert rule.is_active(base(), 0)
  // the time zone is required, and the window must not be empty
  let assert Error([no_zone]) =
    rule.validate(Rule(..base(), starts_at: "2026-12-01T00:00:00"))
  assert string.starts_with(no_zone, "starts_at:")
  let assert Error([order]) =
    rule.validate(Rule(..timed, expires_at: "2026-11-30T00:00:00Z"))
  assert order == "expires_at: must be after starts_at"
  // written only when set
  assert !string.contains(rule.file_to_string([base()]), "starts_at")
  assert rule.file_from_string(rule.file_to_string([timed])) == Ok([timed])
  // crossing a boundary
  assert rule.crosses_boundary([timed], from - 1, from)
  assert !rule.crosses_boundary([timed], from, until - 1)
  assert rule.crosses_boundary([timed], until - 1, until)
}

pub fn host_placeholder_lint_test() {
  let prefix = Rule(..base(), kind: rule.Prefix, source: "/")
  assert rule.lint(Rule(..prefix, target: "https://${host}/$1")) == []
  assert rule.lint(Rule(..prefix, target: "https://${sub}.new.test/$1")) == []
  let assert [exact] = rule.lint(Rule(..base(), target: "https://${host}/x"))
  assert string.starts_with(exact, "target: ${host} and ${sub} only apply")
  let assert [unsafe] = rule.lint(Rule(..prefix, target: "https://a$1b.test/"))
  assert string.starts_with(unsafe, "target: placeholders in the host")
  assert rule.expand_with(
      "${host}|${sub}|$${host}|${9}",
      ["p"],
      rule.RequestVars("h.test", "s"),
    )
    == "h.test|s|${host}|"
}

pub fn query_validation_test() {
  let assert Ok(r) = rule.validate(Rule(..base(), query: "?id=42"))
  assert r.query == "id=42"
  assert rule.query_conditions(Rule(..r, query: "b=2&a=1"))
    == [#("a", "1"), #("b", "2")]
  let assert Error([kind]) =
    rule.validate(Rule(..base(), kind: rule.Prefix, query: "id=1"))
  assert kind == "query: only applies to exact rules"
  let assert Error([shape]) = rule.validate(Rule(..base(), query: "=x"))
  assert string.starts_with(shape, "query: must be name=value pairs")
  assert !string.contains(rule.file_to_string([base()]), "\"query\"")
  assert rule.file_from_string(rule.file_to_string([r])) == Ok([r])
}

pub fn request_query_skips_malformed_parameters_test() {
  assert rule.request_query("a=1&b=2") == [#("a", "1"), #("b", "2")]
  assert rule.request_query("a=1&b=%zz&c=%33") == [#("a", "1"), #("c", "3")]
  assert rule.request_query("") == []
}

/// The host a location really goes to, as browsers parse it: case does not
/// matter, user info is skipped, `\` counts as `/`.
pub fn guard_location_reads_the_host_like_a_browser_test() {
  let fixed = rule.FixedHost("example.com")
  let ok = fn(location) {
    rule.guard_location(fixed, location, rule.no_vars) == Ok(location)
  }
  assert ok("https://example.com/a")
  assert ok("HTTPS://Example.COM/a?b#c")
  assert ok("https:\\\\example.com\\a")
  assert ok("//example.com")
  assert ok("https://user@example.com/a")
  assert !ok("https://example.com@evil.test/a")
  assert !ok("https://a@example.com@evil.test")
  assert !ok("https://evil.test/@example.com")
  assert !ok("https://evil.test\\@example.com")
  assert !ok("https://evil.test?@example.com")
  assert !ok("https://evil.test#@example.com")
  assert !ok("https://example.com.evil.test/")
  // a host that is not ASCII is compared in lower case too
  let accented = rule.FixedHost("café.example")
  assert rule.guard_location(accented, "https://CAFÉ.example/x", rule.no_vars)
    == Ok("https://CAFÉ.example/x")
}
