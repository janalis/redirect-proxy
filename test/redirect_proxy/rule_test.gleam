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
  assert rule.guard_location(path, "//evil.com") == Ok("/evil.com")
  assert rule.guard_location(path, "/\\evil.com") == Ok("/evil.com")
  assert rule.guard_location(path, "/\t/evil.com") == Ok("/evil.com")
  assert rule.guard_location(path, "/blog/post") == Ok("/blog/post")

  let fixed = rule.target_guard("https://example.com$1")
  assert rule.guard_location(fixed, "https://example.com/blog")
    == Ok("https://example.com/blog")
  assert rule.guard_location(fixed, "https://example.com?q")
    == Ok("https://example.com?q")
  assert rule.guard_location(fixed, "https://example.com")
    == Ok("https://example.com")
  assert rule.guard_location(fixed, "https://example.com.evil.com/")
    == Error(Nil)
  assert rule.guard_location(fixed, "https://example.com@evil.com/")
    == Error(Nil)
  assert rule.guard_location(fixed, "https://example.com:1@evil.com")
    == Error(Nil)

  let sub = rule.target_guard("https://$1.example.com/")
  assert rule.guard_location(sub, "https://blog.example.com/")
    == Ok("https://blog.example.com/")
  assert rule.guard_location(sub, "https://evil.com#.example.com/")
    == Error(Nil)
  assert rule.guard_location(sub, "https://evil.com/.example.com/")
    == Error(Nil)
  assert rule.guard_location(sub, "https://.example.com/") == Error(Nil)
  assert rule.guard_location(rule.Unsafe, "/x") == Error(Nil)
}
