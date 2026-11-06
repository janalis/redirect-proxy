//// Compiled, immutable rule set optimised for the request hot path.
////
//// Resolution order for a request `(host, path)`:
////
//// 1. rules attached to the request host, then
//// 2. rules attached to the wildcard host `*`.
////
//// Within a host: exact rules (O(1) dictionary lookup) win over prefix rules
//// (longest prefix first, then priority) which win over regex rules
//// (priority order, then insertion order). The first match wins.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option
import gleam/order
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/ffi
import redirect_proxy/rule.{type Rule, Exact, Prefix, Regex}

pub opaque type Matcher {
  Matcher(hosts: Dict(String, HostRules), size: Int)
}

type HostRules {
  HostRules(
    exact: Dict(String, Rule),
    exact_ci: Dict(String, Rule),
    prefix: List(Rule),
    regex: List(#(Rule, ffi.CompiledRegex)),
  )
}

pub type Match {
  Match(rule: Rule, location: String)
}

pub fn empty() -> Matcher {
  Matcher(hosts: dict.new(), size: 0)
}

/// Number of enabled rules in the matcher.
pub fn size(matcher: Matcher) -> Int {
  matcher.size
}

/// Builds a matcher. Disabled rules are skipped. Rules are expected to have
/// gone through `rule.validate`; a regex that fails to compile is skipped.
pub fn build(rules: List(Rule)) -> Matcher {
  let enabled = list.filter(rules, fn(r) { r.enabled })
  let grouped = list.group(enabled, fn(r) { r.host })
  let hosts =
    dict.map_values(grouped, fn(_host, rules) {
      // list.group prepends, restore the original order for stable sorting
      build_host(list.reverse(rules))
    })
  Matcher(hosts:, size: list.length(enabled))
}

fn build_host(rules: List(Rule)) -> HostRules {
  let exact =
    rules
    |> list.filter(fn(r) { r.kind == Exact && !r.case_insensitive })
    |> list.fold(dict.new(), fn(acc, r) {
      // first rule wins on duplicates
      case dict.has_key(acc, r.source) {
        True -> acc
        False -> dict.insert(acc, r.source, r)
      }
    })
  let exact_ci =
    rules
    |> list.filter(fn(r) { r.kind == Exact && r.case_insensitive })
    |> list.fold(dict.new(), fn(acc, r) {
      let key = string.lowercase(r.source)
      case dict.has_key(acc, key) {
        True -> acc
        False -> dict.insert(acc, key, r)
      }
    })
  let prefix =
    rules
    |> list.filter(fn(r) { r.kind == Prefix })
    |> list.sort(fn(a, b) {
      int.compare(string.length(b.source), string.length(a.source))
      |> order.break_tie(int.compare(a.priority, b.priority))
    })
  let regex =
    rules
    |> list.filter(fn(r) { r.kind == Regex })
    |> list.sort(fn(a, b) { int.compare(a.priority, b.priority) })
    |> list.filter_map(fn(r) {
      ffi.regex_compile(r.source, r.case_insensitive)
      |> result.map(fn(compiled) { #(r, compiled) })
    })
  HostRules(exact:, exact_ci:, prefix:, regex:)
}

/// Strips the port from a Host header value and lower-cases it.
pub fn normalise_request_host(host: String) -> String {
  let host = string.lowercase(host)
  case string.starts_with(host, "[") {
    // IPv6 literal: [::1]:8080
    True ->
      case string.split_once(host, "]") {
        Ok(#(addr, _)) -> addr <> "]"
        Error(_) -> host
      }
    False ->
      case string.split_once(host, ":") {
        Ok(#(name, _port)) -> name
        Error(_) -> host
      }
  }
}

/// Finds the rule that applies to a request and computes the redirect
/// location (without the query string).
pub fn lookup(
  matcher: Matcher,
  host: String,
  path: String,
) -> Result(Match, Nil) {
  let host = normalise_request_host(host)
  lookup_host(matcher, host, path)
  |> result.lazy_or(fn() { lookup_host(matcher, "*", path) })
}

fn lookup_host(
  matcher: Matcher,
  host: String,
  path: String,
) -> Result(Match, Nil) {
  use rules <- result.try(dict.get(matcher.hosts, host))
  match_exact(rules, path)
  |> result.lazy_or(fn() { match_prefix(rules.prefix, path) })
  |> result.lazy_or(fn() { match_regex(rules.regex, path) })
}

fn match_exact(rules: HostRules, path: String) -> Result(Match, Nil) {
  case dict.get(rules.exact, path) {
    Ok(r) -> Ok(Match(r, r.target))
    Error(Nil) ->
      case dict.size(rules.exact_ci) {
        0 -> Error(Nil)
        _ ->
          dict.get(rules.exact_ci, string.lowercase(path))
          |> result.map(fn(r) { Match(r, r.target) })
      }
  }
}

fn match_prefix(rules: List(Rule), path: String) -> Result(Match, Nil) {
  case rules {
    [] -> Error(Nil)
    [r, ..rest] -> {
      let matched = case r.case_insensitive {
        False -> string.starts_with(path, r.source)
        True ->
          string.starts_with(string.lowercase(path), string.lowercase(r.source))
      }
      case matched {
        True -> {
          let remainder = string.drop_start(path, string.length(r.source))
          // a substitution leaving the target's host: the rule does not apply
          rule.expand(r.target, [path, remainder])
          |> rule.guard_location(rule.target_guard(r.target), _)
          |> result.map(Match(r, _))
        }
        False -> match_prefix(rest, path)
      }
    }
  }
}

fn match_regex(
  rules: List(#(Rule, ffi.CompiledRegex)),
  path: String,
) -> Result(Match, Nil) {
  case rules {
    [] -> Error(Nil)
    [#(r, regex), ..rest] ->
      case ffi.regex_run(regex, path) {
        Ok(captures) ->
          case
            rule.guard_location(
              rule.target_guard(r.target),
              rule.expand(r.target, captures),
            )
          {
            Ok(location) -> Ok(Match(r, location))
            // the substitution would leave the target's host: try the next
            Error(Nil) -> match_regex(rest, path)
          }
        Error(_) -> match_regex(rest, path)
      }
  }
}

/// Builds the final `Location` header value: appends the request query
/// string when the rule asks for it and strips any CR/LF characters.
pub fn location(m: Match, query: Result(String, Nil)) -> String {
  let base = case m.rule.preserve_query, query {
    True, Ok(q) if q != "" ->
      case string.contains(m.location, "?") {
        True -> m.location <> "&" <> q
        False -> m.location <> "?" <> q
      }
    _, _ -> m.location
  }
  ffi.strip_control(base)
}

pub type UrlResolution {
  Redirected(match: Match, location: String)
  NotMatched
  BadUrl
}

/// Resolves an absolute URL the way the redirect listener would (used by the
/// admin and API URL testers).
pub fn resolve_url(matcher: Matcher, url: String) -> UrlResolution {
  case uri.parse(string.trim(url)) {
    Ok(uri.Uri(host: option.Some(host), path:, query:, ..)) -> {
      let path = case path {
        "" -> "/"
        p -> p
      }
      case lookup(matcher, host, path) {
        Ok(m) -> Redirected(m, location(m, option.to_result(query, Nil)))
        Error(Nil) -> NotMatched
      }
    }
    _ -> BadUrl
  }
}
