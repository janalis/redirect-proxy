//// Redirection rules: data model, JSON codec and validation.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/result
import gleam/string
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
    /// Lower values are evaluated first (prefix ties and regex ordering).
    priority: Int,
    enabled: Bool,
    note: String,
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
    priority: default_priority,
    enabled: True,
    note: "",
    created_at: "",
    updated_at: "",
    updated_by: "",
  )
}

// --- kinds ------------------------------------------------------------------

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
  json.object([
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
  ])
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
  use priority <- decode.optional_field(
    "priority",
    default_priority,
    decode.int,
  )
  use enabled <- decode.optional_field("enabled", True, decode.bool)
  use note <- decode.optional_field("note", "", decode.string)
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
    priority:,
    enabled:,
    note:,
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
  let rule = Rule(..rule, host:, source:, target:, note:)

  let errors =
    []
    |> check(valid_host(host), "host: must be `*` or a valid host name")
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

  case errors {
    [] -> Ok(rule)
    _ -> Error(list.reverse(errors))
  }
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

pub fn normalise_host(host: String) -> String {
  case string.trim(host) |> string.lowercase {
    "" -> "*"
    h -> h
  }
}

fn valid_host(host: String) -> Bool {
  case host {
    "*" -> True
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

/// Expands `$0`..`$9`, `${n}` and `$$` in a target template using captures.
pub fn expand(template: String, captures: List(String)) -> String {
  do_expand(template, captures, "")
}

fn do_expand(rest: String, captures: List(String), acc: String) -> String {
  case string.split_once(rest, "$") {
    Error(Nil) -> acc <> rest
    Ok(#(before, after)) -> {
      let acc = acc <> before
      case string.pop_grapheme(after) {
        Ok(#("$", tail)) -> do_expand(tail, captures, acc <> "$")
        Ok(#("{", tail)) ->
          case string.split_once(tail, "}") {
            Ok(#(digits, tail2)) ->
              case int.parse(digits) {
                Ok(n) -> do_expand(tail2, captures, acc <> capture(captures, n))
                Error(_) -> do_expand(tail, captures, acc <> "${")
              }
            Error(_) -> do_expand(tail, captures, acc <> "${")
          }
        Ok(#(c, tail)) ->
          case int.parse(c) {
            Ok(n) -> do_expand(tail, captures, acc <> capture(captures, n))
            Error(_) -> do_expand(after, captures, acc <> "$")
          }
        Error(Nil) -> acc <> "$"
      }
    }
  }
}

fn capture(captures: List(String), index: Int) -> String {
  captures
  |> list.drop(index)
  |> list.first
  |> result.unwrap("")
}
