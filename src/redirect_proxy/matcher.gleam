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
////
//// Prefix rules, and regex rules starting with a literal (`^/old/(.*)`), are
//// indexed by that literal: for each distinct byte length of the literals,
//// the request path is cut to that length and looked up in a dictionary.
//// A lookup costs one dictionary access per distinct length instead of one
//// comparison (or one regex run) per rule. The candidates found carry their
//// rank in the resolution order above, so the result is the same as trying
//// every rule in that order.
////
//// The matcher also holds the hit counter of every rule (`record_hit`): a
//// lock-free `counters` array, carried over to the next matcher by rule id
//// (`carry_hits`).

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
  Matcher(
    hosts: Dict(String, HostRules),
    size: Int,
    /// Rule id to its slot in `hits`, for every rule (disabled ones too, so
    /// that their count survives being disabled then enabled again).
    slots: Dict(String, Int),
    hits: ffi.Counters,
  )
}

type HostRules {
  HostRules(
    exact: Dict(String, Rule),
    exact_ci: Dict(String, Rule),
    /// Case-sensitive prefix rules, keyed by their source.
    prefix: Index(PrefixRule),
    /// Case-insensitive prefix rules, keyed by their lower-cased source and
    /// looked up with the lower-cased path.
    prefix_ci: Index(PrefixRule),
    /// Regex rules anchored on a literal prefix, keyed by that literal.
    regex: Index(RegexRule),
    /// The other regex rules, in rank order.
    regex_unindexed: List(RegexRule),
  )
}

/// Entries keyed by a literal prefix of the path. `lengths` lists the
/// distinct key lengths in bytes; entries sharing a key are in rank order.
type Index(a) {
  Index(lengths: List(Int), entries: Dict(String, List(a)))
}

type PrefixRule {
  PrefixRule(rank: Int, rule: Rule, guard: rule.TargetGuard)
}

type RegexRule {
  RegexRule(
    rank: Int,
    rule: Rule,
    regex: ffi.CompiledRegex,
    guard: rule.TargetGuard,
  )
}

pub type Match {
  Match(rule: Rule, location: String)
}

pub fn empty() -> Matcher {
  Matcher(hosts: dict.new(), size: 0, slots: dict.new(), hits: new_hits(0))
}

fn new_hits(rules: Int) -> ffi.Counters {
  ffi.counter_new(int.max(rules, 1))
}

/// Number of enabled rules in the matcher.
pub fn size(matcher: Matcher) -> Int {
  matcher.size
}

/// Builds a matcher. Disabled rules are skipped. Rules are expected to have
/// gone through `rule.validate`; a regex that fails to compile is skipped.
pub fn build(rules: List(Rule)) -> Matcher {
  let enabled = list.filter(rules, fn(r) { r.enabled })
  // like request hosts, rule hosts are matched without port or trailing dot
  let grouped = list.group(enabled, fn(r) { normalise_request_host(r.host) })
  let hosts =
    dict.map_values(grouped, fn(_host, rules) {
      // list.group prepends, restore the original order for stable sorting
      build_host(list.reverse(rules))
    })
  let #(slots, count) =
    list.fold(rules, #(dict.new(), 0), fn(acc, r) {
      let #(slots, count) = acc
      case dict.has_key(slots, r.id) {
        True -> acc
        False -> #(dict.insert(slots, r.id, count + 1), count + 1)
      }
    })
  Matcher(hosts:, size: list.length(enabled), slots:, hits: new_hits(count))
}

/// Counts a hit of a rule. Lock-free: concurrent request processes do not
/// contend even on the same rule.
pub fn record_hit(matcher: Matcher, rule_id: String) -> Nil {
  case dict.get(matcher.slots, rule_id) {
    Ok(slot) -> ffi.counter_add(matcher.hits, slot, 1)
    Error(Nil) -> Nil
  }
}

/// Hits of a rule since the server started.
pub fn hit_count(matcher: Matcher, rule_id: String) -> Int {
  case dict.get(matcher.slots, rule_id) {
    Ok(slot) -> ffi.counter_get(matcher.hits, slot)
    Error(Nil) -> 0
  }
}

/// Adds the hits counted by `previous` to the rules of `next` with the same
/// id. Rules that no longer exist are dropped. Hits recorded on `previous`
/// while this runs may be lost.
pub fn carry_hits(next: Matcher, from previous: Matcher) -> Matcher {
  dict.each(next.slots, fn(rule_id, slot) {
    case hit_count(previous, rule_id) {
      0 -> Nil
      count -> ffi.counter_add(next.hits, slot, count)
    }
  })
  next
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
    |> list.index_map(fn(r, rank) {
      PrefixRule(rank:, rule: r, guard: rule.target_guard(r.target))
    })
  let #(prefix_ci, prefix) =
    list.partition(prefix, fn(p) { p.rule.case_insensitive })
  let regex =
    rules
    |> list.filter(fn(r) { r.kind == Regex })
    |> list.sort(fn(a, b) { int.compare(a.priority, b.priority) })
    |> list.filter_map(fn(r) {
      ffi.regex_compile(r.source, r.case_insensitive)
      |> result.map(fn(compiled) { #(r, compiled) })
    })
    |> list.index_map(fn(entry, rank) {
      let #(r, regex) = entry
      RegexRule(rank:, rule: r, regex:, guard: rule.target_guard(r.target))
    })
  let #(regex_unindexed, regex) =
    list.partition(regex, fn(r) { regex_literal(r.rule) == "" })
  HostRules(
    exact:,
    exact_ci:,
    prefix: index(prefix, fn(p) { p.rule.source }),
    prefix_ci: index(prefix_ci, fn(p) { string.lowercase(p.rule.source) }),
    regex: index(regex, fn(r) { regex_literal(r.rule) }),
    regex_unindexed:,
  )
}

/// Indexes entries (given in rank order) by `key`.
fn index(entries: List(a), key: fn(a) -> String) -> Index(a) {
  let grouped =
    entries
    |> list.reverse
    |> list.fold(dict.new(), fn(acc, entry) {
      // folding the reversed list keeps each group in rank order
      dict.upsert(acc, key(entry), fn(group) {
        [entry, ..option.unwrap(group, [])]
      })
    })
  let lengths =
    grouped
    |> dict.keys
    |> list.map(string.byte_size)
    |> list.unique
    |> list.sort(fn(a, b) { int.compare(b, a) })
  Index(lengths:, entries: grouped)
}

/// The entries whose key is a prefix of `subject`, in no particular order.
fn candidates(index: Index(a), subject: String) -> List(a) {
  let size = string.byte_size(subject)
  list.fold(index.lengths, [], fn(found, length) {
    case length <= size {
      False -> found
      True ->
        case dict.get(index.entries, ffi.byte_take(subject, length)) {
          Ok(entries) -> list.append(entries, found)
          Error(Nil) -> found
        }
    }
  })
}

/// The literal a regex rule's pattern starts with: a path can only match if
/// it starts with it. "" when the pattern does not start with `^` and a
/// literal, may match elsewhere than at the start (`|`), or ignores case.
fn regex_literal(r: Rule) -> String {
  case r.case_insensitive, string.contains(r.source, "|"), r.source {
    False, False, "^" <> rest ->
      take_literal(string.to_utf_codepoints(rest), [])
    _, _, _ -> ""
  }
}

fn take_literal(rest: List(UtfCodepoint), taken: List(UtfCodepoint)) -> String {
  let done = fn(taken) { taken |> list.reverse |> string.from_utf_codepoints }
  case rest {
    [] -> done(taken)
    [c, ..more] ->
      case string.utf_codepoint_to_int(c) {
        // `?`, `*`, `{`: the previous character is optional
        0x3F | 0x2A | 0x7B ->
          case taken {
            [_, ..kept] -> done(kept)
            [] -> ""
          }
        // `\ . [ ] ( ) } + ^ $`: not a literal character (`+` keeps the
        // previous one, which still occurs at least once)
        0x5C | 0x2E | 0x5B | 0x5D | 0x28 | 0x29 | 0x7D | 0x2B | 0x5E | 0x24 ->
          done(taken)
        _ -> take_literal(more, [c, ..taken])
      }
  }
}

/// Strips the port and a trailing dot (`example.com.`) from a Host header
/// value and lower-cases it.
pub fn normalise_request_host(host: String) -> String {
  let host = strip_port(string.lowercase(host))
  case string.ends_with(host, ".") {
    True -> string.drop_end(host, 1)
    False -> host
  }
}

fn strip_port(host: String) -> String {
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
  |> result.lazy_or(fn() { match_prefix(rules, path) })
  |> result.lazy_or(fn() { match_regex(rules, path) })
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

fn match_prefix(rules: HostRules, path: String) -> Result(Match, Nil) {
  let found = candidates(rules.prefix, path)
  let found = case rules.prefix_ci.lengths {
    [] -> found
    _ -> list.append(candidates(rules.prefix_ci, string.lowercase(path)), found)
  }
  case found {
    [] -> Error(Nil)
    [first, ..others] -> {
      let best =
        list.fold(others, first, fn(best, p) {
          case p.rank < best.rank {
            True -> p
            False -> best
          }
        })
      let r = best.rule
      let remainder = case r.case_insensitive {
        False -> ffi.byte_drop(path, string.byte_size(r.source))
        // lower-casing may change byte lengths outside ASCII
        True -> string.drop_start(path, string.length(r.source))
      }
      // a substitution leaving the target's host: the rule does not apply
      rule.expand(r.target, [path, remainder])
      |> rule.guard_location(best.guard, _)
      |> result.map(Match(r, _))
    }
  }
}

fn match_regex(rules: HostRules, path: String) -> Result(Match, Nil) {
  let indexed =
    candidates(rules.regex, path)
    |> list.sort(fn(a, b) { int.compare(a.rank, b.rank) })
  run_regexes(indexed, rules.regex_unindexed, path)
}

/// Runs the regex rules of two lists sorted by rank, merged in rank order,
/// until one matches.
fn run_regexes(
  a: List(RegexRule),
  b: List(RegexRule),
  path: String,
) -> Result(Match, Nil) {
  let next = case a, b {
    [], [] -> Error(Nil)
    [x, ..rest], [] -> Ok(#(x, rest, []))
    [], [y, ..rest] -> Ok(#(y, [], rest))
    [x, ..rest_a], [y, ..] if x.rank < y.rank -> Ok(#(x, rest_a, b))
    _, [y, ..rest_b] -> Ok(#(y, a, rest_b))
  }
  case next {
    Error(Nil) -> Error(Nil)
    Ok(#(entry, a, b)) ->
      case ffi.regex_run(entry.regex, path) {
        Ok(captures) ->
          case
            rule.guard_location(
              entry.guard,
              rule.expand(entry.rule.target, captures),
            )
          {
            Ok(location) -> Ok(Match(entry.rule, location))
            // the substitution would leave the target's host: try the next
            Error(Nil) -> run_regexes(a, b, path)
          }
        // a run exhausting its budget is counted by `regex_run`
        Error(_) -> run_regexes(a, b, path)
      }
  }
}

/// Builds the final `Location` header value: appends the request query
/// string when the rule asks for it (before a `#fragment` of the target)
/// and strips any CR/LF characters.
pub fn location(m: Match, query: Result(String, Nil)) -> String {
  let base = case m.rule.preserve_query, query {
    True, Ok(q) if q != "" -> {
      let #(url, fragment) = case string.split_once(m.location, "#") {
        Ok(#(url, fragment)) -> #(url, "#" <> fragment)
        Error(Nil) -> #(m.location, "")
      }
      case string.contains(url, "?") {
        True -> url <> "&" <> q <> fragment
        False -> url <> "?" <> q <> fragment
      }
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
