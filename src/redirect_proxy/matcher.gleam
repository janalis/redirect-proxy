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
//// indexed by that literal: the request path is cut to the byte length of
//// the literals and looked up in a dictionary, along a tree of such lengths
//// (`Index`), so that a lookup costs a few dictionary accesses instead of
//// one comparison (or one regex run) per rule. The candidates found carry
//// their rank in the resolution order above, so the result is the same as
//// trying every rule in that order. Targets are parsed once, when the
//// matcher is built (`template.compile_template`).
////
//// The matcher also holds the hit count and the time of the last hit of
//// every rule (`record_hit`): a lock-free `counters` array, carried over to
//// the next matcher by rule id (`carry_hits`) and kept across restarts by
//// the store (`hit_records`, `seed_hits`).

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
import redirect_proxy/rule/template

pub opaque type Matcher {
  Matcher(
    hosts: Dict(String, HostRules),
    size: Int,
    /// Whether some rule has a `*.domain` host: lookups then also try the
    /// parent domains of the request host.
    wildcards: Bool,
    /// Enabled rules by kind: exact, prefix, regex.
    kinds: #(Int, Int, Int),
    /// Rule id to its slot, for every rule (disabled ones too, so that their
    /// count survives being disabled then enabled again). Slot `n` uses
    /// `hits` indexes `2n - 1` (count) and `2n` (last hit, in seconds).
    slots: Dict(String, Int),
    hits: ffi.Counters,
  )
}

type HostRules {
  HostRules(
    /// Exact rules with query conditions, keyed by their source (lower-cased
    /// when case-insensitive).
    exact_query: Dict(String, QueryGroup),
    /// Whether some exact rule with query conditions is case-insensitive:
    /// otherwise the path is not lower-cased to look them up.
    exact_query_ci: Bool,
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

/// Entries keyed by a literal prefix of the path; entries sharing a key are
/// in rank order. A lookup cuts the path to each key length and looks the
/// cut up, so a `Leaf` costs one lookup per distinct length. With more
/// lengths than `leaf_lengths`, a `Node` keeps the keys of its shortest
/// length, and the longer keys in one child index per first `length`
/// bytes: a lookup only follows the child of the path's own first bytes,
/// so it costs a few lookups however many lengths there are.
type Index(a) {
  Leaf(lengths: List(Int), entries: Dict(String, List(a)))
  Node(
    length: Int,
    entries: Dict(String, List(a)),
    children: Dict(String, Index(a)),
  )
}

const leaf_lengths = 4

type QueryRule {
  QueryRule(rule: Rule, conditions: List(#(String, String)))
}

/// The query rules of one path, most conditions first, then priority, then
/// file order. A rule can only match a request that has its first
/// condition, so they are indexed by it: a request only tries the rules of
/// its own parameters. `always` holds the rules without a condition that
/// parses (they match any query).
type QueryGroup {
  QueryGroup(
    always: List(#(Int, QueryRule)),
    by_first: Dict(#(String, String), List(#(Int, QueryRule))),
  )
}

type PrefixRule {
  PrefixRule(
    rank: Int,
    rule: Rule,
    template: template.Template,
    guard: template.TargetGuard,
  )
}

type RegexRule {
  RegexRule(
    rank: Int,
    rule: Rule,
    regex: ffi.CompiledRegex,
    template: template.Template,
    guard: template.TargetGuard,
  )
}

pub type Match {
  Match(rule: Rule, location: String)
}

pub fn empty() -> Matcher {
  Matcher(
    hosts: dict.new(),
    size: 0,
    wildcards: False,
    kinds: #(0, 0, 0),
    slots: dict.new(),
    hits: new_hits(0),
  )
}

fn new_hits(rules: Int) -> ffi.Counters {
  ffi.counter_new(int.max(2 * rules, 2))
}

fn count_index(slot: Int) -> Int {
  2 * slot - 1
}

fn last_index(slot: Int) -> Int {
  2 * slot
}

/// Enabled rules by kind: exact, prefix, regex.
pub fn kinds(matcher: Matcher) -> #(Int, Int, Int) {
  matcher.kinds
}

/// Number of enabled rules in the matcher.
pub fn size(matcher: Matcher) -> Int {
  matcher.size
}

/// Builds a matcher. Disabled rules, and rules outside their
/// `starts_at`/`expires_at` window now, are skipped. Rules are expected to
/// have gone through `rule.validate`; a regex that fails to compile is
/// skipped.
pub fn build(rules: List(Rule)) -> Matcher {
  let now = ffi.now_seconds()
  let enabled =
    rules
    |> list.filter(rule.is_active(_, now))
    // paths are compared in one form: see `ffi.normalise_path`
    |> list.map(fn(r) {
      case r.kind {
        Regex -> r
        Exact | Prefix -> rule.Rule(..r, source: ffi.normalise_path(r.source))
      }
    })
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
  Matcher(
    hosts:,
    size: list.length(enabled),
    wildcards: dict.keys(hosts) |> list.any(string.starts_with(_, "*.")),
    kinds: list.fold(enabled, #(0, 0, 0), fn(acc, r) {
      case r.kind {
        Exact -> #(acc.0 + 1, acc.1, acc.2)
        Prefix -> #(acc.0, acc.1 + 1, acc.2)
        Regex -> #(acc.0, acc.1, acc.2 + 1)
      }
    }),
    slots:,
    hits: new_hits(count),
  )
}

/// Counts a hit of a rule. Lock-free: concurrent request processes do not
/// contend even on the same rule.
pub fn record_hit(matcher: Matcher, rule_id: String) -> Nil {
  case dict.get(matcher.slots, rule_id) {
    Ok(slot) -> {
      ffi.counter_add(matcher.hits, count_index(slot), 1)
      ffi.counter_put(matcher.hits, last_index(slot), ffi.now_seconds())
    }
    Error(Nil) -> Nil
  }
}

/// Hits of a rule (kept across restarts by the store).
pub fn hit_count(matcher: Matcher, rule_id: String) -> Int {
  case dict.get(matcher.slots, rule_id) {
    Ok(slot) -> ffi.counter_get(matcher.hits, count_index(slot))
    Error(Nil) -> 0
  }
}

/// When a rule was last hit, in seconds since the epoch (0: never).
pub fn last_hit(matcher: Matcher, rule_id: String) -> Int {
  case dict.get(matcher.slots, rule_id) {
    Ok(slot) -> ffi.counter_get(matcher.hits, last_index(slot))
    Error(Nil) -> 0
  }
}

/// A rule's hits, as saved and restored by the store.
pub type HitRecord {
  HitRecord(rule_id: String, count: Int, last: Int)
}

/// The hits of every rule hit at least once.
pub fn hit_records(matcher: Matcher) -> List(HitRecord) {
  dict.to_list(matcher.slots)
  |> list.filter_map(fn(entry) {
    let #(rule_id, slot) = entry
    case ffi.counter_get(matcher.hits, count_index(slot)) {
      0 -> Error(Nil)
      count ->
        Ok(HitRecord(
          rule_id:,
          count:,
          last: ffi.counter_get(matcher.hits, last_index(slot)),
        ))
    }
  })
}

/// Adds saved hits to the rules of `matcher` with the same id.
pub fn seed_hits(matcher: Matcher, records: List(HitRecord)) -> Nil {
  list.each(records, fn(record) {
    case dict.get(matcher.slots, record.rule_id) {
      Ok(slot) -> add_hits(matcher, slot, record.count, record.last)
      Error(Nil) -> Nil
    }
  })
}

fn add_hits(matcher: Matcher, slot: Int, count: Int, last: Int) -> Nil {
  ffi.counter_add(matcher.hits, count_index(slot), count)
  case last > ffi.counter_get(matcher.hits, last_index(slot)) {
    True -> ffi.counter_put(matcher.hits, last_index(slot), last)
    False -> Nil
  }
}

/// Adds the hits counted by `previous` to the rules of `next` with the same
/// id. Rules that no longer exist are dropped. Hits recorded on `previous`
/// while this runs may be lost.
pub fn carry_hits(next: Matcher, from previous: Matcher) -> Matcher {
  dict.each(next.slots, fn(rule_id, slot) {
    case hit_count(previous, rule_id) {
      0 -> Nil
      count -> add_hits(next, slot, count, last_hit(previous, rule_id))
    }
  })
  next
}

fn build_host(rules: List(Rule)) -> HostRules {
  let #(with_query, rules) =
    list.partition(rules, fn(r) { r.kind == Exact && r.query != "" })
  let exact_query =
    with_query
    |> list.map(fn(r) { QueryRule(r, rule.query_conditions(r)) })
    // more conditions are more specific, then priority, then file order
    |> list.sort(fn(a, b) {
      int.compare(list.length(b.conditions), list.length(a.conditions))
      |> order.break_tie(int.compare(a.rule.priority, b.rule.priority))
    })
    |> list.reverse
    |> list.fold(dict.new(), fn(acc, q) {
      let key = case q.rule.case_insensitive {
        True -> string.lowercase(q.rule.source)
        False -> q.rule.source
      }
      dict.upsert(acc, key, fn(group) { [q, ..option.unwrap(group, [])] })
    })
    |> dict.map_values(fn(_, rules) { query_group(rules) })
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
      // in bytes, like the index: longest first
      int.compare(string.byte_size(b.source), string.byte_size(a.source))
      |> order.break_tie(int.compare(a.priority, b.priority))
    })
    |> list.index_map(fn(r, rank) {
      PrefixRule(
        rank:,
        rule: r,
        template: template.compile_template(r.target),
        guard: template.target_guard(r.target),
      )
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
      RegexRule(
        rank:,
        rule: r,
        regex:,
        template: template.compile_template(r.target),
        guard: template.target_guard(r.target),
      )
    })
  let #(regex_unindexed, regex) =
    list.partition(regex, fn(r) { regex_literal(r.rule) == "" })
  HostRules(
    exact_query:,
    exact_query_ci: list.any(with_query, fn(r) { r.case_insensitive }),
    exact:,
    exact_ci:,
    prefix: index(prefix, fn(p) { p.rule.source }),
    prefix_ci: index(prefix_ci, fn(p) { string.lowercase(p.rule.source) }),
    regex: index(regex, fn(r) { regex_literal(r.rule) }),
    regex_unindexed:,
  )
}

/// `path` without its start whose lower-cased form is `lowered_bytes` long
/// (a case-insensitive prefix, indexed lower-cased): lower-casing may change
/// byte lengths outside ASCII, so the path is walked code point by code
/// point, keeping the case of what remains.
fn drop_lowered(path: String, lowered_bytes: Int) -> String {
  drop_codepoints(string.to_utf_codepoints(path), lowered_bytes)
  |> string.from_utf_codepoints
}

fn drop_codepoints(rest: List(UtfCodepoint), bytes: Int) -> List(UtfCodepoint) {
  case rest, bytes > 0 {
    [c, ..tail], True ->
      drop_codepoints(
        tail,
        bytes
          - string.byte_size(string.lowercase(string.from_utf_codepoints([c]))),
      )
    _, _ -> rest
  }
}

/// Indexes entries (given in rank order) by `key`.
fn index(entries: List(a), key: fn(a) -> String) -> Index(a) {
  entries
  |> list.reverse
  |> list.fold(dict.new(), fn(acc, entry) {
    // folding the reversed list keeps each group in rank order
    dict.upsert(acc, key(entry), fn(group) {
      [entry, ..option.unwrap(group, [])]
    })
  })
  |> dict.to_list
  |> index_tree
}

fn index_tree(groups: List(#(String, List(a)))) -> Index(a) {
  let lengths =
    groups
    |> list.map(fn(group) { string.byte_size(group.0) })
    |> list.unique
    |> list.sort(fn(a, b) { int.compare(b, a) })
  case list.length(lengths) <= leaf_lengths, list.last(lengths) {
    True, _ | _, Error(Nil) -> Leaf(lengths:, entries: dict.from_list(groups))
    False, Ok(shortest) -> {
      let #(here, longer) =
        list.partition(groups, fn(group) {
          string.byte_size(group.0) == shortest
        })
      // every child has fewer lengths: the tree ends
      let children =
        longer
        |> list.group(fn(group) { ffi.byte_take(group.0, shortest) })
        |> dict.map_values(fn(_, groups) { index_tree(groups) })
      Node(length: shortest, entries: dict.from_list(here), children:)
    }
  }
}

fn is_empty(index: Index(a)) -> Bool {
  case index {
    Leaf(lengths: [], ..) -> True
    _ -> False
  }
}

/// The entries whose key is a prefix of `subject`, in no particular order.
fn candidates(index: Index(a), subject: String) -> List(a) {
  case index {
    Leaf(lengths:, entries:) -> {
      let size = string.byte_size(subject)
      list.fold(lengths, [], fn(found, length) {
        case length <= size {
          False -> found
          True ->
            case dict.get(entries, ffi.byte_take(subject, length)) {
              Ok(entries) -> list.append(entries, found)
              Error(Nil) -> found
            }
        }
      })
    }
    Node(length:, entries:, children:) ->
      case string.byte_size(subject) < length {
        // every key is at least `length` bytes long
        True -> []
        False -> {
          let head = ffi.byte_take(subject, length)
          let deeper = case dict.get(children, head) {
            Ok(child) -> candidates(child, subject)
            Error(Nil) -> []
          }
          case dict.get(entries, head) {
            Ok(found) -> list.append(found, deeper)
            Error(Nil) -> deeper
          }
        }
      }
  }
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
  let host = strip_port(ffi.lowercase_host(host))
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
/// location (without the query string). Rules of the request host win, then
/// those of `*.parent` domains from the closest one (`a.b.example.com`:
/// `*.b.example.com`, then `*.example.com`), then those of `*`. The path is
/// compared in normalised form (`ffi.normalise_path`).
pub fn lookup(
  matcher: Matcher,
  host: String,
  path: String,
) -> Result(Match, Nil) {
  lookup_query(matcher, host, path, "")
}

/// `lookup`, for a request with a query string (raw, without `?`): exact
/// rules with query conditions can then match.
pub fn lookup_query(
  matcher: Matcher,
  host: String,
  path: String,
  query: String,
) -> Result(Match, Nil) {
  let #(host, vars) = request_host(host)
  lookup_normalised(matcher, host, ffi.normalise_path(path), query, vars)
}

/// The normalised request host and the variables it gives.
fn request_host(host: String) -> #(String, template.RequestVars) {
  let host = normalise_request_host(host)
  // `${host}` only ever holds a host name
  let vars =
    template.RequestVars(
      host: case rule.is_host_name(host) {
        True -> host
        False -> ""
      },
      sub: "",
    )
  #(host, vars)
}

/// `lookup_query` for a normalised host and path.
fn lookup_normalised(
  matcher: Matcher,
  host: String,
  path: String,
  query: String,
  vars: template.RequestVars,
) -> Result(Match, Nil) {
  lookup_host(matcher, host, path, query, vars)
  |> result.lazy_or(fn() {
    case matcher.wildcards {
      True -> lookup_wildcards(matcher, host, path, query, vars)
      False -> Error(Nil)
    }
  })
  |> result.lazy_or(fn() { lookup_host(matcher, "*", path, query, vars) })
}

/// `lookup`, retrying a miss with the trailing slash added or removed
/// (`/docs/` finds the `/docs` rule and the other way round).
pub fn lookup_tolerant(
  matcher: Matcher,
  host: String,
  path: String,
) -> Result(Match, Nil) {
  lookup_tolerant_query(matcher, host, path, "")
}

/// `lookup_tolerant` with the request query string.
pub fn lookup_tolerant_query(
  matcher: Matcher,
  host: String,
  path: String,
  query: String,
) -> Result(Match, Nil) {
  // the host and path are normalised once for both lookups (a trailing
  // `/` is kept by the normalisation, so the retry can add or drop it on
  // the normalised path)
  let #(host, vars) = request_host(host)
  let normalised = ffi.normalise_path(path)
  use <- result.lazy_or(lookup_normalised(
    matcher,
    host,
    normalised,
    query,
    vars,
  ))
  case normalised {
    "/" | "" -> Error(Nil)
    _ ->
      case string.ends_with(normalised, "/") {
        True ->
          lookup_normalised(
            matcher,
            host,
            string.drop_end(normalised, 1),
            query,
            vars,
          )
        False ->
          lookup_normalised(matcher, host, normalised <> "/", query, vars)
      }
  }
}

/// `*.parent` rules, from the closest parent of `host` (the label being
/// removed). `${sub}` is what the `*` stands for in the request host.
fn lookup_wildcards(
  matcher: Matcher,
  host: String,
  path: String,
  query: String,
  vars: template.RequestVars,
) -> Result(Match, Nil) {
  case string.split_once(host, ".") {
    Ok(#(_, parent)) -> {
      let sub = case vars.host {
        "" -> ""
        full -> string.drop_end(full, string.byte_size(parent) + 1)
      }
      lookup_host(
        matcher,
        "*." <> parent,
        path,
        query,
        template.RequestVars(..vars, sub:),
      )
      |> result.lazy_or(fn() {
        lookup_wildcards(matcher, parent, path, query, vars)
      })
    }
    Error(Nil) -> Error(Nil)
  }
}

fn lookup_host(
  matcher: Matcher,
  host: String,
  path: String,
  query: String,
  vars: template.RequestVars,
) -> Result(Match, Nil) {
  use rules <- result.try(dict.get(matcher.hosts, host))
  match_query(rules, path, query)
  |> result.lazy_or(fn() { match_exact(rules, path) })
  |> result.lazy_or(fn() { match_prefix(rules, path, vars) })
  |> result.lazy_or(fn() { match_regex(rules, path, vars) })
}

fn query_group(rules: List(QueryRule)) -> QueryGroup {
  let numbered = list.index_map(rules, fn(q, position) { #(position, q) })
  let #(always, conditional) =
    list.partition(numbered, fn(entry) { { entry.1 }.conditions == [] })
  let by_first =
    conditional
    |> list.reverse
    |> list.fold(dict.new(), fn(acc, entry) {
      case { entry.1 }.conditions {
        [first, ..] ->
          dict.upsert(acc, first, fn(group) {
            [entry, ..option.unwrap(group, [])]
          })
        // in `always`
        [] -> acc
      }
    })
  QueryGroup(always:, by_first:)
}

/// The rules of a group the request may match, in the group's order.
fn query_candidates(
  group: QueryGroup,
  request: List(#(String, String)),
) -> List(QueryRule) {
  request
  |> list.unique
  |> list.flat_map(fn(param) {
    dict.get(group.by_first, param) |> result.unwrap([])
  })
  |> list.append(group.always)
  |> list.sort(fn(a, b) { int.compare(a.0, b.0) })
  |> list.map(fn(entry) { entry.1 })
}

/// Exact rules with query conditions: the first whose conditions the
/// request query has (most conditions first). The query is only parsed
/// when the path has such rules.
fn match_query(
  rules: HostRules,
  path: String,
  query: String,
) -> Result(Match, Nil) {
  case dict.size(rules.exact_query), query {
    0, _ | _, "" -> Error(Nil)
    _, _ -> {
      let exact_group = dict.get(rules.exact_query, path)
      let folded_group = case rules.exact_query_ci {
        True -> dict.get(rules.exact_query, string.lowercase(path))
        False -> Error(Nil)
      }
      case exact_group, folded_group {
        Error(Nil), Error(Nil) -> Error(Nil)
        _, _ -> {
          let request = rule.request_query(query)
          let candidates = fn(group) {
            group
            |> result.map(query_candidates(_, request))
            |> result.unwrap([])
          }
          let exact =
            candidates(exact_group)
            |> list.filter(fn(q) { !q.rule.case_insensitive })
          let folded =
            candidates(folded_group)
            |> list.filter(fn(q) { q.rule.case_insensitive })
          // each list is in match order already (sorted when built): only
          // rules from both need sorting again
          let found = case exact, folded {
            [], found | found, [] -> found
            _, _ ->
              list.append(exact, folded)
              |> list.sort(fn(a, b) {
                int.compare(
                  list.length(b.conditions),
                  list.length(a.conditions),
                )
                |> order.break_tie(int.compare(a.rule.priority, b.rule.priority))
              })
          }
          found
          |> list.find(fn(q) { rule.query_matches(q.conditions, request) })
          |> result.map(fn(q) { Match(q.rule, q.rule.target) })
        }
      }
    }
  }
}

/// The target is used as written: substitutions are for prefix and regex
/// rules.
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

fn match_prefix(
  rules: HostRules,
  path: String,
  vars: template.RequestVars,
) -> Result(Match, Nil) {
  let found = candidates(rules.prefix, path)
  let found = case is_empty(rules.prefix_ci) {
    True -> found
    False ->
      list.append(candidates(rules.prefix_ci, string.lowercase(path)), found)
  }
  let found =
    list.filter_map(found, fn(p) {
      let remainder = prefix_remainder(p.rule, path)
      // whole segments: `/blog` matches `/blog` and `/blog/…`, not `/blogger`
      case
        !p.rule.whole_segments
        || remainder == ""
        || string.starts_with(remainder, "/")
      {
        True -> Ok(#(p, remainder))
        False -> Error(Nil)
      }
    })
  case found {
    [] -> Error(Nil)
    [first, ..others] -> {
      let #(best, remainder) =
        list.fold(others, first, fn(best, p) {
          case { p.0 }.rank < { best.0 }.rank {
            True -> p
            False -> best
          }
        })
      let r = best.rule
      // a substitution leaving the target's host: the rule does not apply
      template.expand_template(best.template, [path, remainder], vars)
      |> template.guard_location(best.guard, _, vars)
      |> result.map(Match(r, _))
    }
  }
}

/// The rest of `path` after the source of prefix rule `r`.
fn prefix_remainder(r: Rule, path: String) -> String {
  case r.case_insensitive {
    False -> ffi.byte_drop(path, string.byte_size(r.source))
    // cut where the lower-cased prefix ends, in bytes, like the index
    True -> drop_lowered(path, string.byte_size(string.lowercase(r.source)))
  }
}

fn match_regex(
  rules: HostRules,
  path: String,
  vars: template.RequestVars,
) -> Result(Match, Nil) {
  let indexed =
    candidates(rules.regex, path)
    |> list.sort(fn(a, b) { int.compare(a.rank, b.rank) })
  run_regexes(indexed, rules.regex_unindexed, path, vars, 0, 0, 0)
}

/// Reductions the regex rules of one host may cost a request in all. A run
/// that exhausts the PCRE limit costs about 13 000, a usual one under 300:
/// this is some 15 exhausted runs, far above what real rules spend, but it
/// bounds a crafted path that costs every unindexed regex just under the
/// limit (which `max_exhausted_runs` does not see).
const regex_reductions_budget = 200_000

/// Reading the reduction count costs about a hundred reductions: it is read
/// every `budget_check_every` runs only, so that the usual handful of regex
/// rules costs nothing more. The cost of the runs before the first reading
/// is not counted (at most `budget_check_every` runs, each capped).
const budget_check_every = 32

/// Regex runs of one request that may exhaust their budget before the
/// request stops trying the next regex rules: each run is capped, but a
/// crafted path could otherwise cost the cap once per regex rule.
const max_exhausted_runs = 3

/// Runs the regex rules of two lists sorted by rank, merged in rank order,
/// until one matches, or the request spent its regex budget: `runs` so far,
/// and the reduction count past which it stops (`until`, 0 until measured).
fn run_regexes(
  a: List(RegexRule),
  b: List(RegexRule),
  path: String,
  vars: template.RequestVars,
  exhausted: Int,
  runs: Int,
  until: Int,
) -> Result(Match, Nil) {
  let next = case a, b {
    [], [] -> Error(Nil)
    [x, ..rest], [] -> Ok(#(x, rest, []))
    [], [y, ..rest] -> Ok(#(y, [], rest))
    [x, ..rest_a], [y, ..] if x.rank < y.rank -> Ok(#(x, rest_a, b))
    _, [y, ..rest_b] -> Ok(#(y, a, rest_b))
  }
  let runs = runs + 1
  let until = case runs % budget_check_every {
    0 ->
      case until, ffi.reductions() {
        0, now -> now + regex_reductions_budget
        until, now if now > until -> -1
        until, _ -> until
      }
    _ -> until
  }
  case next {
    Error(Nil) -> Error(Nil)
    // over budget: a miss, counted like an exhausted run
    Ok(_) if until < 0 -> {
      ffi.count_regex_limit()
      Error(Nil)
    }
    Ok(#(entry, a, b)) ->
      case ffi.regex_run(entry.regex, path) {
        Ok(captures) ->
          case
            template.guard_location(
              entry.guard,
              template.expand_template(entry.template, captures, vars),
              vars,
            )
          {
            Ok(location) -> Ok(Match(entry.rule, location))
            // the substitution would leave the target's host: try the next
            Error(Nil) -> run_regexes(a, b, path, vars, exhausted, runs, until)
          }
        Error(ffi.NoMatch) ->
          run_regexes(a, b, path, vars, exhausted, runs, until)
        // a run exhausting its budget is counted by `regex_run`
        Error(ffi.LimitExceeded) ->
          case exhausted + 1 >= max_exhausted_runs {
            True -> Error(Nil)
            False -> run_regexes(a, b, path, vars, exhausted + 1, runs, until)
          }
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
      merge_query(url, q) <> fragment
    }
    _, _ -> m.location
  }
  // a header value must be ASCII: captures may hold decoded characters
  base |> ffi.strip_control |> ffi.encode_non_ascii
}

/// Appends the request query to the target URL, after the target's own
/// parameters, which win: a request parameter the target sets (by its
/// decoded name) is dropped. A target ending in `?` or `&` gets no extra
/// separator.
fn merge_query(url: String, query: String) -> String {
  case string.split_once(url, "?") {
    Error(Nil) -> url <> "?" <> query
    Ok(#(_, target_query)) -> {
      let kept = case rule.request_query(target_query) {
        [] -> query
        target ->
          query
          |> string.split("&")
          |> list.filter(fn(pair) {
            case rule.request_query(pair) {
              [#(name, _)] -> !result.is_ok(list.key_find(target, name))
              // empty or malformed: kept as the request sent it
              _ -> pair != ""
            }
          })
          |> string.join("&")
      }
      case kept, string.ends_with(url, "?") || string.ends_with(url, "&") {
        "", _ -> url
        _, True -> url <> kept
        _, False -> url <> "&" <> kept
      }
    }
  }
}

pub type UrlResolution {
  Redirected(match: Match, location: String)
  NotMatched
  BadUrl
}

/// Resolves an absolute URL the way the redirect listener would (used by the
/// admin and API URL testers), with the same trailing slash handling.
pub fn resolve_url(
  matcher: Matcher,
  url: String,
  ignore_trailing_slash: Bool,
) -> UrlResolution {
  case uri.parse(string.trim(url)) {
    Ok(uri.Uri(host: option.Some(host), path:, query:, ..)) -> {
      let path = case path {
        "" -> "/"
        p -> p
      }
      let request_query = option.unwrap(query, "")
      let found = case ignore_trailing_slash {
        True -> lookup_tolerant_query(matcher, host, path, request_query)
        False -> lookup_query(matcher, host, path, request_query)
      }
      case found {
        Ok(m) -> Redirected(m, location(m, option.to_result(query, Nil)))
        Error(Nil) -> NotMatched
      }
    }
    _ -> BadUrl
  }
}
