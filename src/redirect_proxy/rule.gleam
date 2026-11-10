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
import redirect_proxy/rule/template

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

/// `file_to_string`, encoding again only the rules that changed since the
/// calling process last wrote a file this way (the store: it rewrites the
/// whole file after each change). The same text as `file_to_string`.
pub fn file_to_string_cached(rules: List(Rule)) -> String {
  "{\"version\":"
  <> int.to_string(file_format_version)
  <> ",\"rules\":["
  <> string.join(
    ffi.encode_cached(rules, fn(r) { json.to_string(to_json(r)) }),
    ",",
  )
  <> "]}"
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

/// Whether a prefix `source` that a path starts with, leaving `remainder`,
/// ends on a segment boundary of that path (for `whole_segments`): `/blog`
/// matches `/blog` and `/blog/…` but not `/blogger`, and a source ending
/// with `/`, such as `/blog/`, matches everything below it.
pub fn on_segment_boundary(source: String, remainder: String) -> Bool {
  remainder == ""
  || string.starts_with(remainder, "/")
  || string.ends_with(source, "/")
}

// --- validation -------------------------------------------------------------

/// Normalises and validates a rule. Returns the normalised rule or a list of
/// human readable errors (each prefixed with the field name and a colon).
pub fn validate(rule: Rule) -> Result(Rule, List(String)) {
  let host = normalise_host(rule.host)
  let source = trim(rule.source)
  let target = trim(rule.target)
  let note = trim(rule.note)
  let query = case trim(rule.query) {
    "?" <> q -> q
    q -> q
  }
  let starts_at = trim(rule.starts_at)
  let expires_at = trim(rule.expires_at)
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

// --- ids -------------------------------------------------------------------

/// Ids a new rule cannot take: they name pages of the admin or operations of
/// the API at the place of a rule id (`/rules/bulk`, `/api/redirects/export`),
/// or path segments that are removed (`.`, `..`).
pub const reserved_ids = ["new", "bulk", "export", "import", ".", ".."]

pub fn is_reserved_id(id: String) -> Bool {
  list.contains(reserved_ids, id)
}

/// What `is_valid_id` accepts.
pub fn valid_id_hint() -> String {
  "up to 128 letters, digits, '.', '_', '~' or '-', and not "
  <> string.join(reserved_ids, ", ")
}

/// Whether a rule may take `id` when created or imported: it goes in URLs,
/// so only unreserved URL characters (RFC 3986), and no reserved id.
pub fn is_valid_id(id: String) -> Bool {
  id != ""
  && !is_reserved_id(id)
  && string.byte_size(id) <= 128
  && string.to_utf_codepoints(id)
  |> list.all(fn(c) {
    let c = string.utf_codepoint_to_int(c)
    { c >= 0x30 && c <= 0x39 }
    || { c >= 0x41 && c <= 0x5A }
    || { c >= 0x61 && c <= 0x7A }
    || c == 0x2E
    || c == 0x5F
    || c == 0x7E
    || c == 0x2D
  })
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
    rule.kind == Exact || template.target_guard(rule.target) != template.Unsafe,
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
  case trim(host) |> string.lowercase {
    "" -> "*"
    h -> h
  }
}

fn is_ascii(value: String) -> Bool {
  ffi.is_ascii(value)
}

/// `string.trim`, without its cost for the usual value that has nothing to
/// trim (it runs for every field of every rule when a file loads).
fn trim(value: String) -> String {
  case ffi.needs_trim(value) {
    True -> string.trim(value)
    False -> value
  }
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
  ffi.no_control_chars(value)
}

fn valid_target(target: String) -> Bool {
  let lower = string.lowercase(target)
  string.starts_with(lower, "http://")
  || string.starts_with(lower, "https://")
  || string.starts_with(target, "//")
  || string.starts_with(target, "/")
}
