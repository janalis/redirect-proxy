//// Redirection rules: data model, JSON codec and validation.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/ffi

pub type MatchKind {
  /// The request path must be equal to `source`.
  Exact
  /// The request path must start with `source`. The remainder of the path is
  /// available as `$1` in the target.
  Prefix
  /// `source` is a PCRE regular expression applied to the request path.
  /// Capture groups are available as `$1`..`$n` in the target.
  Regex
}

pub type Rule {
  Rule(
    id: String,
    /// Lower-cased host name the rule applies to, or `*` for every host.
    host: String,
    source: String,
    kind: MatchKind,
    target: String,
    status: Int,
    preserve_query: Bool,
    case_insensitive: Bool,
    /// Prefix rules: match whole path segments only, so that `/blog` matches
    /// `/blog` and `/blog/…` but not `/blogger`.
    whole_segments: Bool,
    /// Exact rules: query parameters the request must have, with these
    /// values (`id=42&lang=fr`; other parameters are allowed). "": none.
    query: String,
    /// Lower values are evaluated first (prefix ties and regex ordering).
    priority: Int,
    enabled: Bool,
    /// RFC 3339 date-time from which the rule applies ("" for always).
    starts_at: String,
    /// RFC 3339 date-time from which the rule no longer applies ("" for
    /// never).
    expires_at: String,
    note: String,
    /// Free labels for grouping and filtering (a campaign, a site, a
    /// migration), lower case, sorted and without duplicates once validated.
    tags: List(String),
    created_at: String,
    updated_at: String,
    updated_by: String,
  )
}

pub const file_format_version = 1

pub const allowed_statuses = [301, 302, 303, 307, 308]

pub const default_priority = 100

pub const max_source_length = 2048

pub const max_target_length = 4096

pub const max_tags = 20

pub const max_tag_length = 40

/// Tags as validated rules hold them: trimmed, lower case, without empty
/// ones or duplicates, sorted.
pub fn normalise_tags(tags: List(String)) -> List(String) {
  tags
  |> list.map(fn(t) { string.lowercase(string.trim(t)) })
  |> list.filter(fn(t) { t != "" })
  |> list.unique
  |> list.sort(string.compare)
}

/// Tags written as text, separated by commas (`campaign, legacy`).
pub fn tags_from_string(text: String) -> List(String) {
  string.split(text, ",") |> normalise_tags
}

pub fn tags_to_string(tags: List(String)) -> String {
  string.join(tags, ", ")
}

/// A blank rule with sensible defaults, used by the admin "new" form.
pub fn blank() -> Rule {
  Rule(
    id: "",
    host: "*",
    source: "/",
    kind: Exact,
    target: "",
    status: 301,
    preserve_query: False,
    case_insensitive: False,
    whole_segments: False,
    query: "",
    priority: default_priority,
    enabled: True,
    starts_at: "",
    expires_at: "",
    note: "",
    tags: [],
    created_at: "",
    updated_at: "",
    updated_by: "",
  )
}

// --- kinds ------------------------------------------------------------------

/// Every match kind, in the order they are documented.
pub const kinds = [Exact, Prefix, Regex]

/// The names of the match kinds (`exact`, `prefix`, `regex`).
pub fn kind_names() -> List(String) {
  list.map(kinds, kind_to_string)
}

pub fn kind_to_string(kind: MatchKind) -> String {
  case kind {
    Exact -> "exact"
    Prefix -> "prefix"
    Regex -> "regex"
  }
}

pub fn kind_from_string(value: String) -> Result(MatchKind, Nil) {
  case string.lowercase(value) {
    "exact" -> Ok(Exact)
    "prefix" -> Ok(Prefix)
    "regex" -> Ok(Regex)
    _ -> Error(Nil)
  }
}

// --- versions ---------------------------------------------------------------

/// A version tag derived from the full content of the rule (used as HTTP
/// ETag and for optimistic concurrency). Any change to any field changes it.
pub fn version(rule: Rule) -> String {
  crypto.hash(crypto.Sha256, <<json.to_string(to_json(rule)):utf8>>)
  |> bit_array.slice(0, 12)
  |> result.unwrap(<<>>)
  |> bit_array.base64_url_encode(False)
}

// --- JSON -------------------------------------------------------------------

pub fn to_json(rule: Rule) -> Json {
  json.object(json_fields(rule))
}

/// The fields of `to_json`, for representations that add their own.
pub fn json_fields(rule: Rule) -> List(#(String, Json)) {
  [
    #("id", json.string(rule.id)),
    #("host", json.string(rule.host)),
    #("source", json.string(rule.source)),
    #("match", json.string(kind_to_string(rule.kind))),
    #("target", json.string(rule.target)),
    #("status", json.int(rule.status)),
    #("preserve_query", json.bool(rule.preserve_query)),
    #("case_insensitive", json.bool(rule.case_insensitive)),
    #("priority", json.int(rule.priority)),
    #("enabled", json.bool(rule.enabled)),
    #("note", json.string(rule.note)),
    #("created_at", json.string(rule.created_at)),
    #("updated_at", json.string(rule.updated_at)),
    #("updated_by", json.string(rule.updated_by)),
    // only when set: existing files and rule versions stay as they were
    ..list.flatten([
      case rule.whole_segments {
        True -> [#("whole_segments", json.bool(True))]
        False -> []
      },
      case rule.query {
        "" -> []
        q -> [#("query", json.string(q))]
      },
      case rule.starts_at {
        "" -> []
        at -> [#("starts_at", json.string(at))]
      },
      case rule.expires_at {
        "" -> []
        at -> [#("expires_at", json.string(at))]
      },
      case rule.tags {
        [] -> []
        tags -> [#("tags", json.array(tags, json.string))]
      },
    ])
  ]
}

fn kind_decoder() -> decode.Decoder(MatchKind) {
  use value <- decode.then(decode.string)
  case kind_from_string(value) {
    Ok(kind) -> decode.success(kind)
    Error(Nil) -> decode.failure(Exact, "exact | prefix | regex")
  }
}

/// Decodes a rule. Only `source` and `target` are mandatory so that
/// hand-written files and imports stay terse.
pub fn decoder() -> decode.Decoder(Rule) {
  use id <- decode.optional_field("id", "", decode.string)
  use host <- decode.optional_field("host", "*", decode.string)
  use source <- decode.field("source", decode.string)
  use kind <- decode.optional_field("match", Exact, kind_decoder())
  use target <- decode.field("target", decode.string)
  use status <- decode.optional_field("status", 301, decode.int)
  use preserve_query <- decode.optional_field(
    "preserve_query",
    False,
    decode.bool,
  )
  use case_insensitive <- decode.optional_field(
    "case_insensitive",
    False,
    decode.bool,
  )
  use whole_segments <- decode.optional_field(
    "whole_segments",
    False,
    decode.bool,
  )
  use query <- decode.optional_field("query", "", decode.string)
  use priority <- decode.optional_field(
    "priority",
    default_priority,
    decode.int,
  )
  use enabled <- decode.optional_field("enabled", True, decode.bool)
  use starts_at <- decode.optional_field("starts_at", "", decode.string)
  use expires_at <- decode.optional_field("expires_at", "", decode.string)
  use note <- decode.optional_field("note", "", decode.string)
  use tags <- decode.optional_field("tags", [], decode.list(decode.string))
  use created_at <- decode.optional_field("created_at", "", decode.string)
  use updated_at <- decode.optional_field("updated_at", "", decode.string)
  use updated_by <- decode.optional_field("updated_by", "", decode.string)
  decode.success(Rule(
    id:,
    host:,
    source:,
    kind:,
    target:,
    status:,
    preserve_query:,
    case_insensitive:,
    whole_segments:,
    query:,
    priority:,
    enabled:,
    starts_at:,
    expires_at:,
    note:,
    tags:,
    created_at:,
    updated_at:,
    updated_by:,
  ))
}

/// Serialises a full redirections file.
pub fn file_to_string(rules: List(Rule)) -> String {
  json.object([
    #("version", json.int(file_format_version)),
    #("rules", json.array(rules, to_json)),
  ])
  |> json.to_string
}

/// Parses a redirections file. Both the versioned object form
/// (`{"version": 1, "rules": [...]}`) and a bare array of rules are accepted.
pub fn file_from_string(content: String) -> Result(List(Rule), String) {
  // a UTF-8 byte order mark, as some editors write
  let content = case content {
    "\u{FEFF}" <> rest -> rest
    _ -> content
  }
  let versioned = {
    use version <- decode.optional_field(
      "version",
      file_format_version,
      decode.int,
    )
    use rules <- decode.field("rules", decode.list(decoder()))
    decode.success(#(version, rules))
  }
  let bare = decode.list(decoder()) |> decode.map(fn(r) { #(1, r) })
  case json.parse(content, decode.one_of(versioned, [bare])) {
    Ok(#(version, rules)) if version == file_format_version -> Ok(rules)
    Ok(#(version, _)) ->
      Error("unsupported file format version " <> int.to_string(version))
    Error(error) -> Error(describe_json_error(error))
  }
}

pub fn describe_json_error(error: json.DecodeError) -> String {
  case error {
    json.UnexpectedEndOfInput -> "unexpected end of JSON input"
    json.UnexpectedByte(byte) -> "unexpected byte " <> byte <> " in JSON input"
    json.UnexpectedSequence(seq) ->
      "unexpected sequence " <> seq <> " in JSON input"
    json.UnableToDecode(errors) ->
      errors
      |> list.map(fn(e) {
        "expected "
        <> e.expected
        <> " but found "
        <> e.found
        <> " at "
        <> string.join(e.path, ".")
      })
      |> string.join("; ")
  }
}

// --- validation -------------------------------------------------------------

/// Normalises and validates a rule. Returns the normalised rule or a list of
/// human readable errors (each prefixed with the field name and a colon).
pub fn validate(rule: Rule) -> Result(Rule, List(String)) {
  let host = normalise_host(rule.host)
  let source = string.trim(rule.source)
  let target = string.trim(rule.target)
  let note = string.trim(rule.note)
  let query = case string.trim(rule.query) {
    "?" <> q -> q
    q -> q
  }
  let starts_at = string.trim(rule.starts_at)
  let expires_at = string.trim(rule.expires_at)
  let tags = normalise_tags(rule.tags)
  let rule =
    Rule(
      ..rule,
      tags:,
      host:,
      source:,
      target:,
      note:,
      query:,
      starts_at:,
      expires_at:,
    )
  let time = fn(value) {
    case value {
      "" -> Ok(Nil)
      v -> ffi.parse_rfc3339(v) |> result.replace(Nil)
    }
  }

  let errors =
    []
    |> check(
      is_ascii(host),
      "host: write international names in punycode (xn--...), e.g. xn--caf-dma.example for café.example",
    )
    |> check(
      !is_ascii(host) || valid_host(host),
      "host: must be `*`, a host name or `*.` followed by a domain (*.example.com)",
    )
    |> check(source != "", "source: is required")
    |> check(string.length(source) <= max_source_length, "source: is too long")
    |> check(no_control_chars(source), "source: contains control characters")
    |> check_source(rule)
    |> check(target != "", "target: is required")
    |> check(string.length(target) <= max_target_length, "target: is too long")
    |> check(no_control_chars(target), "target: contains control characters")
    |> check(
      valid_target(target),
      "target: must be an absolute http(s) URL, a protocol-relative URL (//host/...) or a path starting with /",
    )
    |> check(
      list.contains(allowed_statuses, rule.status),
      "status: must be one of 301, 302, 303, 307, 308",
    )
    |> check(
      rule.priority >= 0 && rule.priority <= 1_000_000,
      "priority: must be between 0 and 1000000",
    )
    |> check(string.length(note) <= 1000, "note: is too long")
    |> check(
      list.length(tags) <= max_tags,
      "tags: at most " <> int.to_string(max_tags) <> " tags",
    )
    |> check(
      list.all(tags, fn(t) {
        string.length(t) <= max_tag_length
        && no_control_chars(t)
        && !string.contains(t, ",")
      }),
      "tags: each tag is at most "
        <> int.to_string(max_tag_length)
        <> " characters, without commas",
    )
    |> check(
      !rule.whole_segments || rule.kind == Prefix,
      "whole_segments: only applies to prefix rules",
    )
    |> check(
      query == "" || rule.kind == Exact,
      "query: only applies to exact rules",
    )
    |> check(
      query == ""
        || case uri.parse_query(query) {
        Ok([_, ..] as pairs) -> list.all(pairs, fn(pair) { pair.0 != "" })
        _ -> False
      },
      "query: must be name=value pairs separated by &, e.g. id=42&lang=fr",
    )
    |> check(
      time(starts_at) == Ok(Nil),
      "starts_at: must be an RFC 3339 date-time with a time zone, e.g. 2026-12-01T00:00:00Z",
    )
    |> check(
      time(expires_at) == Ok(Nil),
      "expires_at: must be an RFC 3339 date-time with a time zone, e.g. 2026-12-31T23:59:59Z",
    )
    |> check(
      {
        let #(from, until) = window(rule)
        from < until
      },
      "expires_at: must be after starts_at",
    )

  case errors {
    [] -> Ok(rule)
    _ -> Error(list.reverse(errors))
  }
}

// --- query conditions -------------------------------------------------------

/// The parameters of `rule.query`, decoded and sorted (for comparisons).
pub fn query_conditions(rule: Rule) -> List(#(String, String)) {
  case rule.query {
    "" -> []
    q ->
      uri.parse_query(q)
      |> result.unwrap([])
      |> list.sort(fn(a, b) {
        string.compare(a.0, b.0) |> order.break_tie(string.compare(a.1, b.1))
      })
  }
}

/// The parameters of a request query string. A malformed parameter (a bad
/// percent escape such as `%zz`) is skipped instead of discarding the whole
/// query, so that it cannot hide the parameters a rule matches on.
pub fn request_query(query: String) -> List(#(String, String)) {
  case uri.parse_query(query) {
    Ok(params) -> params
    Error(Nil) ->
      string.split(query, "&")
      |> list.flat_map(fn(pair) { uri.parse_query(pair) |> result.unwrap([]) })
  }
}

/// Whether a request query string has every condition.
pub fn query_matches(
  conditions: List(#(String, String)),
  request: List(#(String, String)),
) -> Bool {
  list.all(conditions, list.contains(request, _))
}

// --- schedule ---------------------------------------------------------------

/// Bounds of the time window of a rule, in seconds since the epoch: from
/// `starts_at` (included) to `expires_at` (excluded). Unset or invalid
/// bounds are open.
pub fn window(rule: Rule) -> #(Int, Int) {
  let bound = fn(value, open) {
    case value {
      "" -> open
      v -> ffi.parse_rfc3339(v) |> result.unwrap(open)
    }
  }
  #(bound(rule.starts_at, min_time), bound(rule.expires_at, max_time))
}

const min_time = -1_000_000_000_000

const max_time = 1_000_000_000_000

/// Enabled, and `now` is within its window.
pub fn is_active(rule: Rule, now: Int) -> Bool {
  rule.enabled
  && case rule.starts_at, rule.expires_at {
    // the common case: no parsing
    "", "" -> True
    _, _ -> {
      let #(from, until) = window(rule)
      from <= now && now < until
    }
  }
}

/// Whether a rule starts or expires after `after` and no later than `now`:
/// the published rules are then out of date.
pub fn crosses_boundary(rules: List(Rule), after: Int, now: Int) -> Bool {
  list.any(rules, fn(r) {
    r.enabled
    && { r.starts_at != "" || r.expires_at != "" }
    && {
      let #(from, until) = window(r)
      { from > after && from <= now } || { until > after && until <= now }
    }
  })
}

/// The first `starts_at` or `expires_at` of an enabled rule later than
/// `after` (a time far in the future when there is none): the rules change
/// what applies at that time. `crosses_boundary(rules, after, now)` is
/// `next_boundary(rules, after) <= now`.
pub fn next_boundary(rules: List(Rule), after: Int) -> Int {
  list.fold(rules, max_time, fn(next, r) {
    case r.enabled && { r.starts_at != "" || r.expires_at != "" } {
      False -> next
      True -> {
        let #(from, until) = window(r)
        let next = case from > after && from < next {
          True -> from
          False -> next
        }
        case until > after && until < next {
          True -> until
          False -> next
        }
      }
    }
  })
}

/// Whether the windows of two rules overlap (two exact rules for one path
/// may take turns).
pub fn windows_overlap(a: Rule, b: Rule) -> Bool {
  let #(a_from, a_until) = window(a)
  let #(b_from, b_until) = window(b)
  a_from < b_until && b_from < a_until
}

/// Parts of a valid rule that can never apply as written. A file with them
/// still loads (so that a file that loaded before keeps loading), but changes
/// made in the admin or the API are refused.
pub fn lint(rule: Rule) -> List(String) {
  let path_rule = rule.kind == Exact || rule.kind == Prefix
  []
  |> check(
    !path_rule || !string.contains(rule.source, "?"),
    "source: cannot contain a query string (?): put the parameters in `query` (exact rules)",
  )
  |> check(
    !path_rule || !string.contains(rule.source, "#"),
    "source: cannot contain a fragment (#): browsers never send it",
  )
  // the HTTP server reads `//a/b` as an authority (`a`) and a path (`/b`)
  |> check(
    !path_rule || !string.starts_with(rule.source, "//"),
    "source: cannot start with //: such a request path is read as /<rest after the next />",
  )
  |> check(
    !string.contains(rule.host, ":"),
    "host: remove the port: requests are matched on the host name only",
  )
  |> check(
    rule.kind != Exact
      || !{
      string.contains(rule.target, "${host}")
      || string.contains(rule.target, "${sub}")
    },
    "target: ${host} and ${sub} only apply to prefix and regex rules: an exact rule's target is used as written",
  )
  |> check(
    rule.kind == Exact || target_guard(rule.target) != Unsafe,
    "target: placeholders in the host never redirect: use ${host}, or placeholders before a fixed domain ($1.example.com, ${sub}.example.com)",
  )
  |> list.reverse
}

fn check(errors: List(String), ok: Bool, message: String) -> List(String) {
  case ok {
    True -> errors
    False -> [message, ..errors]
  }
}

fn check_source(errors: List(String), rule: Rule) -> List(String) {
  case rule.kind {
    Exact | Prefix ->
      check(
        errors,
        string.starts_with(rule.source, "/"),
        "source: must start with /",
      )
    Regex ->
      case compile(rule) {
        Ok(_) -> errors
        Error(message) -> ["source: " <> message, ..errors]
      }
  }
}

/// Compiles the regex of a `Regex` rule and makes sure it cannot be abused to
/// burn CPU with catastrophic backtracking (ReDoS).
pub fn compile(rule: Rule) -> Result(ffi.CompiledRegex, String) {
  use regex <- result.try(
    ffi.regex_compile(rule.source, rule.case_insensitive)
    |> result.map_error(fn(e) { "invalid regular expression: " <> e }),
  )
  // Adversarial subjects: runs of a single character followed by a character
  // that forces a failure, with and without a leading slash. They expose
  // exponential backtracking; polynomial cases are bounded at request time by
  // the PCRE match limit (an exhausted match counts as "no match").
  let probes =
    ["a", "A", "0", "-", "_", ".", "/", "~", "%", "a/", "ab", " "]
    |> list.flat_map(fn(unit) {
      [
        "/" <> string.repeat(unit, 40) <> "!",
        "/" <> string.repeat(unit, 40) <> "\u{1}",
        string.repeat(unit, 40) <> "!",
      ]
    })
  let exhausts =
    list.any(probes, fn(probe) {
      ffi.regex_run(regex, probe) == Error(ffi.LimitExceeded)
    })
  case exhausts {
    True ->
      Error(
        "regular expression is too expensive to evaluate (catastrophic backtracking)",
      )
    False -> Ok(regex)
  }
}

/// Only letters, digits, `-`, `_` and `.` (what a rule host may hold): what
/// `${host}` and `${sub}` may hold.
pub fn is_host_name(host: String) -> Bool {
  ffi.is_host_name(host)
}

pub fn normalise_host(host: String) -> String {
  case string.trim(host) |> string.lowercase {
    "" -> "*"
    h -> h
  }
}

fn is_ascii(value: String) -> Bool {
  string.byte_size(value) == string.length(value)
  && list.all(string.to_utf_codepoints(value), fn(c) {
    string.utf_codepoint_to_int(c) < 128
  })
}

fn valid_host(host: String) -> Bool {
  case host {
    "*" -> True
    // every subdomain of a domain of at least two labels (not `*.com`)
    "*." <> domain ->
      string.contains(domain, ".")
      && !string.contains(domain, "*")
      && valid_host(domain)
    _ -> {
      let #(name, port) = case string.split_once(host, ":") {
        Ok(#(name, port)) -> #(name, Ok(port))
        Error(_) -> #(host, Error(Nil))
      }
      let port_ok = case port {
        Error(_) -> True
        Ok(port) ->
          case int.parse(port) {
            Ok(p) -> p > 0 && p < 65_536
            Error(_) -> False
          }
      }
      let labels = string.split(name, ".")
      port_ok && string.length(name) <= 253 && list.all(labels, valid_label)
    }
  }
}

fn valid_label(label: String) -> Bool {
  let length = string.length(label)
  length > 0
  && length <= 63
  && !string.starts_with(label, "-")
  && !string.ends_with(label, "-")
  && string.to_graphemes(label)
  |> list.all(fn(c) {
    string.contains("abcdefghijklmnopqrstuvwxyz0123456789-_", c)
  })
}

fn no_control_chars(value: String) -> Bool {
  value
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    let code = string.utf_codepoint_to_int(cp)
    code >= 32 && code != 127
  })
}

fn valid_target(target: String) -> Bool {
  let lower = string.lowercase(target)
  string.starts_with(lower, "http://")
  || string.starts_with(lower, "https://")
  || string.starts_with(target, "//")
  || string.starts_with(target, "/")
}

// --- target templating ------------------------------------------------------

/// What a request gives to `${host}` and `${sub}` in targets.
pub type RequestVars {
  RequestVars(
    /// The request host: lower case, without port ("" when not a valid
    /// host name, so that a target using it never redirects).
    host: String,
    /// The part of the request host matched by the `*` of a wildcard rule
    /// host (`a.b` for `a.b.example.com` and `*.example.com`), else "".
    sub: String,
  )
}

pub const no_vars = RequestVars(host: "", sub: "")

/// Expands `$0`..`$9`, `${n}` and `$$` in a target template using captures.
pub fn expand(template: String, captures: List(String)) -> String {
  do_expand(template, captures, [], "")
}

/// `expand`, with `${host}` and `${sub}` from the request too.
pub fn expand_with(
  template: String,
  captures: List(String),
  vars: RequestVars,
) -> String {
  do_expand(template, captures, [#("host", vars.host), #("sub", vars.sub)], "")
}

fn do_expand(
  rest: String,
  captures: List(String),
  named: List(#(String, String)),
  acc: String,
) -> String {
  let do_expand = fn(rest, acc) { do_expand(rest, captures, named, acc) }
  case string.split_once(rest, "$") {
    Error(Nil) -> acc <> rest
    Ok(#(before, after)) -> {
      let acc = acc <> before
      case string.pop_grapheme(after) {
        Ok(#("$", tail)) -> do_expand(tail, acc <> "$")
        Ok(#("{", tail)) ->
          case string.split_once(tail, "}") {
            Ok(#(name, tail2)) ->
              case int.parse(name), list.key_find(named, name) {
                Ok(n), _ -> do_expand(tail2, acc <> capture(captures, n))
                _, Ok(value) -> do_expand(tail2, acc <> value)
                _, _ -> do_expand(tail, acc <> "${")
              }
            Error(_) -> do_expand(tail, acc <> "${")
          }
        Ok(#(c, tail)) ->
          case int.parse(c) {
            Ok(n) -> do_expand(tail, acc <> capture(captures, n))
            Error(_) -> do_expand(after, acc <> "$")
          }
        Error(Nil) -> acc <> "$"
      }
    }
  }
}

/// A target template parsed once (when the matcher is built), so that a
/// redirect does not parse it again: the same result as `expand_with`.
pub opaque type Template {
  Template(parts: List(Part))
}

type Part {
  Literal(String)
  Capture(Int)
  RequestHostPart
  SubPart
}

/// Parses a target template, the way `expand_with` reads it.
pub fn compile_template(template: String) -> Template {
  Template(compile_parts(template, []) |> merge_literals([]))
}

fn compile_parts(rest: String, parts: List(Part)) -> List(Part) {
  case string.split_once(rest, "$") {
    Error(Nil) -> list.reverse([Literal(rest), ..parts])
    Ok(#(before, after)) -> {
      let parts = [Literal(before), ..parts]
      case string.pop_grapheme(after) {
        Ok(#("$", tail)) -> compile_parts(tail, [Literal("$"), ..parts])
        Ok(#("{", tail)) ->
          case string.split_once(tail, "}") {
            Ok(#(name, tail2)) ->
              case int.parse(name), name {
                Ok(n), _ -> compile_parts(tail2, [Capture(n), ..parts])
                _, "host" -> compile_parts(tail2, [RequestHostPart, ..parts])
                _, "sub" -> compile_parts(tail2, [SubPart, ..parts])
                _, _ -> compile_parts(tail, [Literal("${"), ..parts])
              }
            Error(_) -> compile_parts(tail, [Literal("${"), ..parts])
          }
        Ok(#(c, tail)) ->
          case int.parse(c) {
            Ok(n) -> compile_parts(tail, [Capture(n), ..parts])
            Error(_) -> compile_parts(after, [Literal("$"), ..parts])
          }
        Error(Nil) -> list.reverse([Literal("$"), ..parts])
      }
    }
  }
}

/// Joins neighbouring literals and drops empty ones.
fn merge_literals(parts: List(Part), merged: List(Part)) -> List(Part) {
  case parts, merged {
    [], _ -> list.reverse(merged)
    [Literal(""), ..rest], _ -> merge_literals(rest, merged)
    [Literal(a), ..rest], [Literal(b), ..done] ->
      merge_literals(rest, [Literal(b <> a), ..done])
    [part, ..rest], _ -> merge_literals(rest, [part, ..merged])
  }
}

/// `expand_with` for a compiled template.
pub fn expand_template(
  template: Template,
  captures: List(String),
  vars: RequestVars,
) -> String {
  case template.parts {
    // no placeholder: nothing to build
    [] -> ""
    [Literal(text)] -> text
    parts ->
      list.fold(parts, "", fn(acc, part) {
        case part {
          Literal(text) -> acc <> text
          Capture(n) -> acc <> capture(captures, n)
          RequestHostPart -> acc <> vars.host
          SubPart -> acc <> vars.sub
        }
      })
  }
}

fn capture(captures: List(String), index: Int) -> String {
  captures
  |> list.drop(index)
  |> list.first
  |> result.unwrap("")
}

// --- substitution guard ---------------------------------------------------------

/// What a target template allows its substitutions to produce. Captures come
/// from the request path, so without a guard `/old/(.*)` -> `/$1` would send
/// `/old//evil.com` to `//evil.com`, and `https://example.com$1` would send
/// `/go.evil.com` or `/go@evil.com` to another host (open redirects).
pub type TargetGuard {
  /// No placeholder: the target is used as is.
  Static
  /// A path on the same host: leading `/` and `\` runs are collapsed to one
  /// `/`, so the result never becomes protocol-relative.
  SameHostPath
  /// The result must keep this host (`example.com`, with its port if any).
  FixedHost(String)
  /// `https://${host}/...`: the result must keep the request's host.
  RequestHost
  /// The result must stay a host ending with this suffix (`.example.com`),
  /// for templates such as `https://$1.example.com/`.
  SubdomainOf(String)
  /// Placeholders inside the host in another shape: never redirect.
  Unsafe
}

pub fn target_guard(template: String) -> TargetGuard {
  case string.contains(template, "$") {
    False -> Static
    True ->
      case authority(template) {
        Error(Nil) -> SameHostPath
        // `${host}`, then only placeholders (`https://${host}$1`): the
        // result is checked to keep the request's host
        Ok("${host}" <> rest) if rest == "" -> RequestHost
        Ok("${host}" <> rest) ->
          case expand(rest, []) {
            "" -> RequestHost
            _ -> Unsafe
          }
        Ok(host) ->
          case string.split_once(host, "$") {
            Error(Nil) -> FixedHost(host)
            Ok(#(literal, from_placeholder)) ->
              case expand("$" <> from_placeholder, []) {
                // only placeholders after the literal (`example.com$1`): they
                // must not extend the host
                "" -> FixedHost(literal)
                // `$1.example.com`: the host starts with the placeholders
                _ if literal == "" -> subdomain_guard(host)
                _ -> Unsafe
              }
          }
      }
  }
}

/// `$1.example.com`: placeholders, then a literal domain starting with `.`
/// of at least two labels (`$1.com` would allow any `.com` domain).
fn subdomain_guard(host: String) -> TargetGuard {
  let suffix = case list.last(string.split(host, "$")) {
    // drop the digits or `{n}` of the last placeholder
    Ok(last) ->
      case string.pop_grapheme(last) {
        Ok(#("{", rest)) ->
          string.split_once(rest, "}") |> result.map(fn(p) { p.1 })
        _ -> Ok(drop_digits(last))
      }
    Error(Nil) -> Error(Nil)
  }
  case suffix {
    Ok(suffix) -> {
      let labels = string.split(suffix, ".") |> list.drop(1)
      case
        string.starts_with(suffix, ".")
        && list.length(labels) >= 2
        && !list.contains(labels, "")
      {
        True -> SubdomainOf(suffix)
        False -> Unsafe
      }
    }
    Error(Nil) -> Unsafe
  }
}

fn drop_digits(text: String) -> String {
  case string.pop_grapheme(text) {
    Ok(#(c, rest)) ->
      case int.parse(c) {
        Ok(_) -> drop_digits(rest)
        Error(_) -> text
      }
    Error(Nil) -> text
  }
}

/// Checks an expanded location against the guard of its template. Returns
/// the location to send, or `Error(Nil)` when it would leave the allowed
/// host. Tabs and line breaks, which browsers ignore in URLs, are removed.
pub fn guard_location(
  guard: TargetGuard,
  location: String,
  vars: RequestVars,
) -> Result(String, Nil) {
  case guard {
    Static -> Ok(location)
    Unsafe -> Error(Nil)
    RequestHost -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) if host == vars.host && host != "" -> Ok(location)
        _ -> Error(Nil)
      }
    }
    SameHostPath -> {
      let location = strip_url_whitespace(location)
      case string.pop_grapheme(location) {
        Ok(#(c, rest)) if c == "/" || c == "\\" -> Ok("/" <> drop_slashes(rest))
        _ -> Ok(location)
      }
    }
    FixedHost(expected) -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) if host == expected -> Ok(location)
        _ -> Error(Nil)
      }
    }
    SubdomainOf(suffix) -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) ->
          case string.ends_with(host, suffix) {
            True -> {
              let sub = string.drop_end(host, string.length(suffix))
              case ffi.is_host_name(sub) {
                True -> Ok(location)
                False -> Error(Nil)
              }
            }
            False -> Error(Nil)
          }
        Error(Nil) -> Error(Nil)
      }
    }
  }
}

fn drop_slashes(text: String) -> String {
  case string.pop_grapheme(text) {
    Ok(#(c, rest)) if c == "/" || c == "\\" -> drop_slashes(rest)
    _ -> text
  }
}

fn strip_url_whitespace(url: String) -> String {
  ffi.strip_url_whitespace(url)
}

/// The host (with port, without user info), lower-cased, of an absolute or
/// protocol-relative URL, parsed the way browsers do for http(s): `\` counts
/// as `/` and extra slashes after the scheme are ignored. `Error(Nil)` for a
/// path.
fn authority(url: String) -> Result(String, Nil) {
  // only the scheme is lowered here (ASCII): the host is lowered below,
  // with Unicode case mapping if it is not ASCII (`ffi.lowercase_host`)
  let scheme = ffi.lowercase_ascii(ffi.byte_take(url, 8))
  let after = case scheme {
    "http://" <> _ | "http:\\\\" <> _ -> Ok(7)
    "https://" <> _ | "https:\\\\" <> _ -> Ok(8)
    "//" <> _ | "/\\" <> _ | "\\/" <> _ | "\\\\" <> _ -> Ok(2)
    _ -> Error(Nil)
  }
  use after <- result.map(after)
  let rest = ffi.byte_drop(url, after)
  rest |> drop_slashes |> ffi.url_host |> ffi.lowercase_host
}
