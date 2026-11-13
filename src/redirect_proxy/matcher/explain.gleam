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
  /// Matches the path, but its substitution would leave its target's host
  /// (open redirect guard): the request goes to the next rule, whether this
  /// one is enabled or not.
  Refused
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
    /// The chain comes back to a URL it already visited, or still
    /// redirects after `max_hops`, where browsers stop with too many
    /// redirects.
    loops: Bool,
  )
}

/// The redirects browsers follow (Chrome and Firefox: 20).
const max_hops = 20

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
      |> list.filter(matches(_, path, request_query))
      |> resolution_order(path)
    })
    |> list.map(fn(r) {
      Candidate(r, case r.id == applied_id, r.enabled {
        True, _ -> Applied
        False, enabled ->
          case matcher.target_allowed(r, host, path), enabled {
            False, _ -> Refused
            True, False -> Disabled
            True, True ->
              case rule.is_active(r, now) {
                True -> Shadowed
                False -> OutOfSchedule
              }
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
      let seen = set.from_list([request_key(host, path, request_query)])
      follow(find, host, first, m, seen, [], max_hops)
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

/// Exact rules, then prefix rules (longest consumed path first, then priority),
/// then regex rules (by priority); file order breaks ties, as in the
/// matcher.
fn resolution_order(rules: List(Rule), path: String) -> List(Rule) {
  let of = fn(kind) { list.filter(rules, fn(r) { r.kind == kind }) }
  list.flatten([
    exact_order(of(Exact)),
    of(Prefix)
      |> list.map(fn(r) { #(r, string.byte_size(prefix_remainder(r, path))) })
      |> list.sort(fn(a, b) {
        int_compare(a.1, b.1)
        |> order.break_tie(int_compare({ a.0 }.priority, { b.0 }.priority))
      })
      |> list.map(fn(entry) { entry.0 }),
    of(Regex) |> list.sort(fn(a, b) { int_compare(a.priority, b.priority) }),
  ])
}

/// Query-conditioned exact rules precede plain exact rules. Stable sorting
/// retains file order on specificity/priority ties, across matching modes.
fn exact_order(rules: List(Rule)) -> List(Rule) {
  let #(conditional, plain) = list.partition(rules, fn(r) { r.query != "" })
  let #(sensitive, folded) =
    list.partition(plain, fn(r) { !r.case_insensitive })
  list.flatten([
    conditional
      |> list.map(fn(r) { #(r, list.length(rule.query_conditions(r))) })
      |> list.sort(fn(a, b) {
        int_compare(b.1, a.1)
        |> order.break_tie(int_compare({ a.0 }.priority, { b.0 }.priority))
      })
      |> list.map(fn(entry) { entry.0 }),
    sensitive,
    folded,
  ])
}

fn int_compare(a: Int, b: Int) -> order.Order {
  case a < b, a > b {
    True, _ -> order.Lt
    _, True -> order.Gt
    _, _ -> order.Eq
  }
}

fn prefix_remainder(r: Rule, path: String) -> String {
  matcher.prefix_remainder(
    rule.Rule(..r, source: ffi.normalise_path(r.source)),
    path,
  )
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
      string.starts_with(fold(path), source)
      && case r.whole_segments {
        False -> True
        True -> rule.on_segment_boundary(source, prefix_remainder(r, path))
      }
    }
    Regex ->
      case ffi.regex_compile(r.source, r.case_insensitive) {
        Ok(regex) -> result.is_ok(ffi.regex_run(regex, path))
        Error(_) -> False
      }
  }
}

/// A request, for loop detection: the query decides some rules.
fn request_key(host: String, path: String, query: String) -> String {
  host <> ffi.normalise_path(path) <> "?" <> query
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
  case loop.next_request(host, location) {
    Error(Nil) -> #(list.reverse(chain), False)
    Ok(#(next_host, next_path, next_query)) -> {
      let next_host = matcher.normalise_request_host(next_host)
      let key = request_key(next_host, next_path, next_query)
      case set.contains(seen, key), find(next_host, next_path, next_query) {
        True, Ok(_) -> #(list.reverse(chain), True)
        _, Error(Nil) -> #(list.reverse(chain), False)
        // still redirecting after `max_hops`
        False, Ok(_) if hops == 0 -> #(list.reverse(chain), True)
        False, Ok(m) ->
          follow(
            find,
            next_host,
            // a rule preserving the query keeps the one it was asked
            matcher.location(m, Ok(next_query)),
            m,
            set.insert(seen, key),
            chain,
            hops - 1,
          )
      }
    }
  }
}
