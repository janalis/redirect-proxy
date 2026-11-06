//// Explains how a URL is resolved, for the URL testers: every rule of the
//// candidate hosts that matches the path, in resolution order, which one
//// applies, which are shadowed or disabled, and the redirect chain a browser
//// would follow.

import gleam/list
import gleam/option
import gleam/order
import gleam/result
import gleam/set
import gleam/string
import gleam/uri
import redirect_proxy/ffi
import redirect_proxy/matcher.{type Matcher}
import redirect_proxy/matcher/loop
import redirect_proxy/rule.{type Rule, Exact, Prefix, Regex}

pub type Verdict {
  /// The rule the redirect listener uses.
  Applied
  /// Enabled and matching, but another rule wins (more specific host,
  /// earlier kind, longer prefix, lower priority).
  Shadowed
  /// Would match if it were enabled.
  Disabled
  /// Enabled and matching, but outside its `starts_at`/`expires_at` window.
  OutOfSchedule
}

pub type Candidate {
  Candidate(rule: Rule, verdict: Verdict)
}

/// One redirect of the chain: the location sent, by which rule.
pub type Hop {
  Hop(location: String, status: Int, rule_id: String)
}

pub type Explanation {
  Explanation(
    host: String,
    /// The path as compared (normalised).
    path: String,
    candidates: List(Candidate),
    chain: List(Hop),
    /// The chain comes back to a URL it already visited.
    loops: Bool,
  )
}

const max_hops = 10

/// `rules` are all the rules (disabled ones too); `matcher` is the published
/// one, which decides the rule that applies.
pub fn explain(
  matcher: Matcher,
  rules: List(Rule),
  url: String,
  ignore_trailing_slash: Bool,
) -> Result(Explanation, Nil) {
  use #(host, path, query) <- result.try(parse(url))
  let host = matcher.normalise_request_host(host)
  let path = ffi.normalise_path(path)
  let find = fn(host, path, query) {
    case ignore_trailing_slash {
      True -> matcher.lookup_tolerant_query(matcher, host, path, query)
      False -> matcher.lookup_query(matcher, host, path, query)
    }
  }
  let request_query = result.unwrap(query, "")
  let applied = find(host, path, request_query)
  let now = ffi.now_seconds()
  let applied_id = case applied {
    Ok(m) -> m.rule.id
    Error(Nil) -> ""
  }
  let candidates =
    hosts(host)
    |> list.flat_map(fn(h) {
      rules
      |> list.filter(fn(r) { matcher.normalise_request_host(r.host) == h })
      |> resolution_order
      |> list.filter(matches(_, path, request_query))
    })
    |> list.map(fn(r) {
      Candidate(r, case r.id == applied_id, r.enabled {
        True, _ -> Applied
        False, False -> Disabled
        False, True ->
          case rule.is_active(r, now) {
            True -> Shadowed
            False -> OutOfSchedule
          }
      })
    })
  // a trailing slash retry matches another path: still list its rule
  let candidates = case applied {
    Ok(m) ->
      case list.any(candidates, fn(c) { c.verdict == Applied }) {
        True -> candidates
        False -> [Candidate(m.rule, Applied), ..candidates]
      }
    Error(Nil) -> candidates
  }
  let #(chain, loops) = case applied {
    Error(Nil) -> #([], False)
    Ok(m) -> {
      let first = matcher.location(m, query)
      follow(find, host, first, m, set.from_list([host <> path]), [], max_hops)
    }
  }
  Ok(Explanation(host:, path:, candidates:, chain:, loops:))
}

fn parse(url: String) -> Result(#(String, String, Result(String, Nil)), Nil) {
  case uri.parse(string.trim(url)) {
    Ok(uri.Uri(host: option.Some(host), path:, query:, ..)) ->
      Ok(#(
        host,
        case path {
          "" -> "/"
          p -> p
        },
        option.to_result(query, Nil),
      ))
    _ -> Error(Nil)
  }
}

/// The hosts a request host is looked up under, in order.
fn hosts(host: String) -> List(String) {
  list.flatten([[host], parents(host), ["*"]])
}

fn parents(name: String) -> List(String) {
  case string.split_once(name, ".") {
    Ok(#(_, parent)) -> ["*." <> parent, ..parents(parent)]
    Error(Nil) -> []
  }
}

/// Exact rules, then prefix rules (longest first, then priority), then regex
/// rules (by priority); file order breaks ties, as in the matcher.
fn resolution_order(rules: List(Rule)) -> List(Rule) {
  let of = fn(kind) { list.filter(rules, fn(r) { r.kind == kind }) }
  list.flatten([
    of(Exact),
    of(Prefix)
      |> list.sort(fn(a, b) {
        string.length(b.source)
        |> int_compare(string.length(a.source))
        |> order.break_tie(int_compare(a.priority, b.priority))
      }),
    of(Regex) |> list.sort(fn(a, b) { int_compare(a.priority, b.priority) }),
  ])
}

fn int_compare(a: Int, b: Int) -> order.Order {
  case a < b, a > b {
    True, _ -> order.Lt
    _, True -> order.Gt
    _, _ -> order.Eq
  }
}

fn matches(r: Rule, path: String, query: String) -> Bool {
  rule.query_matches(rule.query_conditions(r), rule.request_query(query))
  && matches_path(r, path)
}

fn matches_path(r: Rule, path: String) -> Bool {
  let fold = fn(s) {
    case r.case_insensitive {
      True -> string.lowercase(s)
      False -> s
    }
  }
  case r.kind {
    Exact -> fold(ffi.normalise_path(r.source)) == fold(path)
    Prefix -> {
      let source = fold(ffi.normalise_path(r.source))
      let path = fold(path)
      string.starts_with(path, source)
      && case r.whole_segments {
        False -> True
        True -> {
          let rest = string.drop_start(path, string.length(source))
          rest == "" || string.starts_with(rest, "/")
        }
      }
    }
    Regex ->
      case ffi.regex_compile(r.source, r.case_insensitive) {
        Ok(regex) -> result.is_ok(ffi.regex_run(regex, path))
        Error(_) -> False
      }
  }
}

fn follow(
  find: fn(String, String, String) -> Result(matcher.Match, Nil),
  host: String,
  location: String,
  current: matcher.Match,
  seen: set.Set(String),
  chain: List(Hop),
  hops: Int,
) -> #(List(Hop), Bool) {
  let chain = [Hop(location, current.rule.status, current.rule.id), ..chain]
  let next = case hops {
    0 -> Error(Nil)
    _ -> loop.next_request(host, location)
  }
  case next {
    Error(Nil) -> #(list.reverse(chain), False)
    Ok(#(next_host, next_path, next_query)) -> {
      let next_host = matcher.normalise_request_host(next_host)
      let key = next_host <> ffi.normalise_path(next_path)
      case set.contains(seen, key), find(next_host, next_path, next_query) {
        True, Ok(_) -> #(list.reverse(chain), True)
        _, Error(Nil) -> #(list.reverse(chain), False)
        False, Ok(m) ->
          follow(
            find,
            next_host,
            matcher.location(m, Error(Nil)),
            m,
            set.insert(seen, key),
            chain,
            hops - 1,
          )
      }
    }
  }
}
