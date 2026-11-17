//// Target templates and their substitution guard, tested on their own
//// (rule_test covers the common shapes, property_test the guard end to end).

import gleam/list

import redirect_proxy/rule/template.{RequestVars}

const captures = ["/blog/42", "42", "hello"]

const vars = RequestVars(host: "req.test", sub: "a.b")

// --- expand -------------------------------------------------------------------

pub fn expand_empty_and_dollar_only_templates_test() {
  assert template.expand("", ["x"]) == ""
  assert template.expand("$", []) == "$"
  assert template.expand("$$$", []) == "$$"
  // an escaped `$` is not the start of a placeholder
  assert template.expand("$$1", captures) == "$1"
  assert template.expand("$$${1}", captures) == "$42"
}

/// `$n` takes one digit; `${n}` any number of them.
pub fn expand_reads_one_digit_without_braces_test() {
  assert template.expand("$10", captures) == "420"
  let eleven = [
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11",
  ]
  assert template.expand("${10}", eleven) == "c10"
  assert template.expand("${11}", eleven) == "c11"
  assert template.expand("${12}", eleven) == ""
}

/// Placeholders that do not close or name nothing are kept as written.
pub fn expand_keeps_malformed_placeholders_test() {
  assert template.expand("/a${1", captures) == "/a${1"
  assert template.expand("/a${}", captures) == "/a${}"
  assert template.expand("/a${ 1}", captures) == "/a${ 1}"
  assert template.expand("/a${x}/$1", captures) == "/a${x}/42"
  assert template.expand("/a${1/$2", captures) == "/a${1/hello"
  // `expand` knows no request variables
  assert template.expand("/${host}/${sub}", captures) == "/${host}/${sub}"
}

/// A capture holding `$` is inserted as it is, not expanded again.
pub fn expand_does_not_expand_captures_test() {
  assert template.expand("/$1", ["", "$2", "x"]) == "/$2"
  assert template.expand("/${1}", ["", "${0}"]) == "/${0}"
  assert template.expand_with("/$1", ["", "${host}"], vars) == "/${host}"
}

pub fn expand_unicode_test() {
  assert template.expand("/café/$1/ü", ["", "日本"]) == "/café/日本/ü"
  assert template.expand("/$é", []) == "/$é"
  // a digit carrying a combining mark is one grapheme, not a placeholder
  assert template.expand("/$1\u{0301}", captures) == "/$1\u{0301}"
}

pub fn expand_with_request_variables_test() {
  assert template.expand_with("https://${host}/${sub}/$1", captures, vars)
    == "https://req.test/a.b/42"
  // names are case-sensitive; unknown names stay as written
  assert template.expand_with("${HOST}${Sub}${nope}", captures, vars)
    == "${HOST}${Sub}${nope}"
  // a number in braces is always a capture
  assert template.expand_with("${0}", captures, vars) == "/blog/42"
  assert template.expand_with("${host}${sub}", [], template.no_vars) == ""
}

/// The compiled form gives what `expand_with` gives, on the edge cases above.
pub fn compiled_template_agrees_on_edge_cases_test() {
  let templates = [
    "", "$", "$$$", "$$1", "$10", "${10}", "/a${1", "/a${}", "/a${ 1}",
    "/a${1/$2", "/café/$1/ü", "/$é", "/$1\u{0301}", "${HOST}${host}${sub}",
    "https://${host}/${sub}/$1", "plain",
  ]
  list.each(templates, fn(t) {
    list.each([[], captures, ["", "$2", "${host}"]], fn(captures) {
      list.each([vars, template.no_vars], fn(vars) {
        assert template.expand_template(
            template.compile_template(t),
            captures,
            vars,
          )
          == template.expand_with(t, captures, vars)
      })
    })
  })
}

// --- target_guard ---------------------------------------------------------------

pub fn target_guard_static_and_path_test() {
  assert template.target_guard("") == template.Static
  assert template.target_guard("https://example.com/a") == template.Static
  // any `$`, escaped or stray, makes the target a template
  assert template.target_guard("/cost$$") == template.SameHostPath
  assert template.target_guard("/a$") == template.SameHostPath
}

pub fn target_guard_request_host_test() {
  assert template.target_guard("https://${host}") == template.RequestHost
  assert template.target_guard("https://${host}/$1") == template.RequestHost
  assert template.target_guard("https://${host}$1") == template.RequestHost
  assert template.target_guard("//${host}/$1") == template.RequestHost
  // anything that extends the request host is refused
  assert template.target_guard("https://${host}.evil.test/$1")
    == template.Unsafe
  assert template.target_guard("https://${host}:8443/$1") == template.Unsafe
  assert template.target_guard("https://${host}${sub}/") == template.Unsafe
}

pub fn target_guard_subdomain_test() {
  assert template.target_guard("https://${sub}.example.com/$1")
    == template.SubdomainOf(".example.com")
  assert template.target_guard("https://${1}.example.com/")
    == template.SubdomainOf(".example.com")
  assert template.target_guard("//$1.example.com/")
    == template.SubdomainOf(".example.com")
  assert template.target_guard("https://$1.example.com:8443/")
    == template.SubdomainOf(".example.com:8443")
  // an empty label, or a placeholder after the suffix, is not a suffix
  assert template.target_guard("https://$1..example.com/") == template.Unsafe
  assert template.target_guard("https://$1.example.com.$2/") == template.Unsafe
  assert template.target_guard("https://$1.example.com.${2}/")
    == template.Unsafe
}

pub fn target_guard_literal_host_test() {
  // the scheme and host are compared in lower case
  assert template.target_guard("HTTP://Example.COM/$1")
    == template.LiteralHost("example.com")
  // `\` ends the host as `/` does, as browsers read http(s) URLs
  assert template.target_guard("http:\\\\example.com\\$1")
    == template.LiteralHost("example.com")
  assert template.target_guard("https:///example.com/$1")
    == template.LiteralHost("example.com")
  assert template.target_guard("https://例え.jp/$1")
    == template.LiteralHost("例え.jp")
  assert template.target_guard("https://example.com:8443$1")
    == template.FixedHost("example.com:8443")
}

// --- guard_location -----------------------------------------------------------

pub fn static_location_is_sent_as_it_is_test() {
  assert template.guard_location(template.Static, "/a b", vars) == Ok("/a b")
}

pub fn same_host_path_edges_test() {
  let path = fn(location) {
    template.guard_location(template.SameHostPath, location, template.no_vars)
  }
  assert path("") == Ok("")
  assert path("/") == Ok("/")
  assert path("//") == Ok("/")
  assert path("\\\\\\evil.test") == Ok("/evil.test")
  assert path("/\\/\\evil.test/x") == Ok("/evil.test/x")
  assert path("/\r\n/evil.test") == Ok("/evil.test")
  // only the leading run is collapsed
  assert path("/a//b") == Ok("/a//b")
  assert path("/x\ty") == Ok("/xy")
  assert path("rel/../x") == Ok("rel/../x")
}

pub fn request_host_location_test() {
  let guard = fn(location, vars) {
    template.guard_location(template.RequestHost, location, vars)
  }
  assert guard("https://req.test/x", vars) == Ok("https://req.test/x")
  assert guard("https://REQ.test/x", vars) == Ok("https://REQ.test/x")
  assert guard("https://req.test/\tx", vars) == Ok("https://req.test/x")
  assert guard("https://req.test.evil.test/", vars) == Error(Nil)
  assert guard("https://req.test@evil.test/", vars) == Error(Nil)
  assert guard("https://req.test:8443/", vars) == Error(Nil)
  assert guard("https://evil.test/req.test", vars) == Error(Nil)
  assert guard("/x", vars) == Error(Nil)
  // a request without a valid host name never redirects
  assert guard("https:///x", template.no_vars) == Error(Nil)
}

pub fn fixed_host_with_port_test() {
  let guard = template.FixedHost("example.com:8443")
  let at = fn(location) {
    template.guard_location(guard, location, template.no_vars)
  }
  assert at("https://example.com:8443/x") == Ok("https://example.com:8443/x")
  assert at("https://example.com/x") == Error(Nil)
  assert at("https://example.com:8443.evil.test/") == Error(Nil)
  // tabs are dropped before the host is read, as browsers do
  assert at("https://example.com:84\t43/x") == Ok("https://example.com:8443/x")
  assert at("https://example.com:8443\t.evil.test/") == Error(Nil)
}

pub fn subdomain_location_edges_test() {
  let guard = template.SubdomainOf(".example.com")
  let at = fn(location) {
    template.guard_location(guard, location, template.no_vars)
  }
  assert at("https://a_b.example.com/") == Ok("https://a_b.example.com/")
  assert at("https://x.y.example.com/") == Ok("https://x.y.example.com/")
  assert at("https://BLOG.Example.com/") == Ok("https://BLOG.Example.com/")
  assert at("https://a\t.example.com/") == Ok("https://a.example.com/")
  assert at("https://a.example.com:444/") == Error(Nil)
  assert at("https://a%2eevil.example.com/") == Error(Nil)
  assert at("https://example.com/") == Error(Nil)
  assert at("/a.example.com") == Error(Nil)
}

pub fn literal_host_only_drops_whitespace_test() {
  assert template.guard_location(
      template.LiteralHost("example.com"),
      "https://example.com/a\r\n/b",
      template.no_vars,
    )
    == Ok("https://example.com/a/b")
}
