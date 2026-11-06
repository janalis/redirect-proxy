//// Redirect loop detection: follows the redirects of a sample request
//// through a compiled matcher, as a browser would.

import gleam/bool
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/matcher.{
  type Match, type Matcher, location, lookup, lookup_tolerant,
  normalise_request_host,
} as _
import redirect_proxy/rule.{type Rule, Exact, Prefix, Regex}

/// Host used to sample requests to wildcard rules: no host-specific rule
/// applies to it.
const loop_check_host = "loop-check.invalid"

/// Whether a sample request to `r` is redirected back to `r`: follows the
/// redirects, as a browser would, through this matcher for up to 10 hops.
/// Returns the rules of the cycle, starting and ending with `r`. Regex rules
/// cannot be sampled (they may still be part of a cycle started elsewhere);
/// a rule shadowed by another one for its sample request is not checked.
/// With `ignore_trailing_slash`, a request that misses is retried with or
/// without its trailing slash, as the redirect listener does.
pub fn redirect_loop(
  matcher: Matcher,
  r: Rule,
  ignore_trailing_slash: Bool,
) -> Result(List(Rule), Nil) {
  let lookup = case ignore_trailing_slash {
    True -> lookup_tolerant
    False -> lookup
  }
  use path <- result.try(case r.kind {
    Exact -> Ok(r.source)
    // a path the rule matches: past a segment boundary for whole segments
    Prefix ->
      case r.whole_segments && !string.ends_with(r.source, "/") {
        True -> Ok(r.source <> "/loop-check")
        False -> Ok(r.source <> "loop-check")
      }
    Regex -> Error(Nil)
  })
  let host = case normalise_request_host(r.host) {
    "*" -> loop_check_host
    h -> h
  }
  case lookup(matcher, host, path) {
    Ok(first) if first.rule.id == r.id ->
      follow(lookup, matcher, host, first, [r], 10)
    _ -> Error(Nil)
  }
}

fn follow(
  lookup: fn(Matcher, String, String) -> Result(Match, Nil),
  matcher: Matcher,
  host: String,
  current: Match,
  chain: List(Rule),
  hops: Int,
) -> Result(List(Rule), Nil) {
  use <- bool.guard(hops == 0, Error(Nil))
  use #(host, path) <- result.try(next_request(
    host,
    location(current, Error(Nil)),
  ))
  use next <- result.try(lookup(matcher, host, path))
  let chain = [next.rule, ..chain]
  case list.last(chain) {
    Ok(start) if start.id == next.rule.id -> Ok(list.reverse(chain))
    _ -> follow(lookup, matcher, host, next, chain, hops - 1)
  }
}

/// The host and path a browser requests when redirected to `location`.
pub fn next_request(
  host: String,
  location: String,
) -> Result(#(String, String), Nil) {
  let lower = string.lowercase(location)
  case
    string.starts_with(lower, "http://")
    || string.starts_with(lower, "https://")
    || string.starts_with(location, "//")
  {
    True ->
      case uri.parse(location) {
        Ok(uri.Uri(host: option.Some(next_host), path:, ..)) ->
          Ok(
            #(next_host, case path {
              "" -> "/"
              p -> p
            }),
          )
        _ -> Error(Nil)
      }
    False ->
      case string.starts_with(location, "/") {
        True -> {
          let path = case string.split_once(location, "?") {
            Ok(#(path, _)) -> path
            Error(Nil) -> location
          }
          let path = case string.split_once(path, "#") {
            Ok(#(path, _)) -> path
            Error(Nil) -> path
          }
          Ok(#(host, path))
        }
        False -> Error(Nil)
      }
  }
}
