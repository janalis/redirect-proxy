//// Rules as CSV (RFC 4180), for spreadsheets: import with a header row
//// naming the columns (only `source` and `target` are required, as in
//// JSON), and export with every column.
////
//// A cell starting with `=`, `+`, `-`, `@`, a tab or a carriage return
//// would run as a formula in a spreadsheet: the export prefixes it with
//// `'` (and a cell starting with `'` too, so that it survives), and the
//// import removes that one prefix again.

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/rule.{type Rule, Rule}

/// The columns of an export, in order. An import takes any of them.
pub const columns = [
  "id", "host", "match", "source", "target", "status", "preserve_query",
  "case_insensitive", "whole_segments", "query", "priority", "enabled",
  "starts_at", "expires_at", "tags", "note",
]

/// Whether an import body is CSV rather than JSON (which starts with `{` or
/// `[`).
pub fn looks_like_csv(content: String) -> Bool {
  case string.trim_start(strip_bom(content)) {
    "{" <> _ | "[" <> _ -> False
    "" -> False
    _ -> True
  }
}

// --- import -----------------------------------------------------------------

/// The rules of an import in either format: JSON (a rules file or an array
/// of rules) or CSV.
pub fn parse_import(content: String) -> Result(List(Rule), List(String)) {
  case looks_like_csv(content) {
    True -> parse(content)
    False -> rule.file_from_string(content) |> result.map_error(fn(e) { [e] })
  }
}

/// The rules of a CSV document. Errors name the line (`line 3: status: must
/// be a number`); rules are validated later, as JSON imports are.
pub fn parse(content: String) -> Result(List(Rule), List(String)) {
  use records <- result.try(
    records(strip_bom(content)) |> result.map_error(fn(e) { [e] }),
  )
  case records {
    [] -> Error(["the CSV has no header row"])
    [#(_, header), ..rows] -> {
      let header = list.map(header, fn(h) { string.lowercase(string.trim(h)) })
      use Nil <- result.try(check_header(header))
      let #(rules, errors) =
        rows
        |> list.map(fn(row) { row_to_rule(header, row) })
        |> result.partition
      case errors {
        [] -> Ok(list.reverse(rules))
        _ -> Error(list.reverse(errors))
      }
    }
  }
}

fn check_header(header: List(String)) -> Result(Nil, List(String)) {
  let unknown = list.filter(header, fn(h) { !list.contains(columns, h) })
  let missing =
    ["source", "target"] |> list.filter(fn(c) { !list.contains(header, c) })
  let duplicated =
    list.filter(columns, fn(c) { list.count(header, fn(h) { h == c }) > 1 })
  case unknown, missing, duplicated {
    [], [], [] -> Ok(Nil)
    _, _, _ ->
      Error(
        list.flatten([
          list.map(unknown, fn(c) {
            "line 1: unknown column "
            <> c
            <> " (columns: "
            <> string.join(columns, ", ")
            <> ")"
          }),
          list.map(missing, fn(c) {
            "line 1: the " <> c <> " column is required"
          }),
          list.map(duplicated, fn(c) {
            "line 1: column " <> c <> " appears twice"
          }),
        ]),
      )
  }
}

fn row_to_rule(
  header: List(String),
  row: #(Int, List(String)),
) -> Result(Rule, String) {
  let #(line, cells) = row
  let at = fn(message) { "line " <> int.to_string(line) <> ": " <> message }
  use <- guard(
    list.length(cells) > list.length(header),
    at("more cells than columns"),
  )
  let values = list.zip(header, list.map(cells, unescape_formula))
  let get = fn(name) { list.key_find(values, name) |> result.unwrap("") }
  let int_of = fn(name, default) {
    case string.trim(get(name)) {
      "" -> Ok(default)
      v ->
        int.parse(v) |> result.replace_error(at(name <> ": must be a number"))
    }
  }
  let bool_of = fn(name, default) {
    case string.lowercase(string.trim(get(name))) {
      "" -> Ok(default)
      "true" | "yes" | "1" | "on" -> Ok(True)
      "false" | "no" | "0" | "off" -> Ok(False)
      _ -> Error(at(name <> ": must be true or false"))
    }
  }
  let defaults = rule.blank()
  use kind <- result.try(case string.trim(get("match")) {
    "" -> Ok(rule.Exact)
    k ->
      rule.kind_from_string(string.lowercase(k))
      |> result.replace_error(at("match: must be exact, prefix or regex"))
  })
  use status <- result.try(int_of("status", defaults.status))
  use priority <- result.try(int_of("priority", defaults.priority))
  use preserve_query <- result.try(bool_of(
    "preserve_query",
    defaults.preserve_query,
  ))
  use case_insensitive <- result.try(bool_of(
    "case_insensitive",
    defaults.case_insensitive,
  ))
  use whole_segments <- result.try(bool_of(
    "whole_segments",
    defaults.whole_segments,
  ))
  use enabled <- result.try(bool_of("enabled", defaults.enabled))
  Ok(
    Rule(
      ..defaults,
      id: string.trim(get("id")),
      host: case string.trim(get("host")) {
        "" -> defaults.host
        h -> h
      },
      kind:,
      source: get("source"),
      target: get("target"),
      status:,
      preserve_query:,
      case_insensitive:,
      whole_segments:,
      query: get("query"),
      priority:,
      enabled:,
      starts_at: get("starts_at"),
      expires_at: get("expires_at"),
      tags: rule.tags_from_string(get("tags")),
      note: get("note"),
    ),
  )
}

fn guard(condition: Bool, error: String, next: fn() -> Result(a, String)) {
  case condition {
    True -> Error(error)
    False -> next()
  }
}

/// The records of a CSV document with the line each starts on; blank lines
/// are skipped.
fn records(content: String) -> Result(List(#(Int, List(String))), String) {
  parse_loop(string.to_graphemes(content), 1, 1, False, [], [], [])
  |> result.map(fn(records) { list.filter(records, fn(r) { r.1 != [""] }) })
}

fn parse_loop(
  chars: List(String),
  line: Int,
  record_line: Int,
  quoted: Bool,
  field: List(String),
  record: List(String),
  done: List(#(Int, List(String))),
) -> Result(List(#(Int, List(String))), String) {
  let field_text = fn() { string.concat(list.reverse(field)) }
  let end_record = fn() {
    [#(record_line, list.reverse([field_text(), ..record])), ..done]
  }
  case quoted, chars {
    // end of input
    True, [] ->
      Error(
        "line " <> int.to_string(record_line) <> ": unterminated quoted cell",
      )
    False, [] ->
      case field, record {
        [], [] -> Ok(list.reverse(done))
        _, _ -> Ok(list.reverse(end_record()))
      }
    // inside quotes: a doubled quote is a quote, a single one ends them
    True, ["\"", "\"", ..rest] ->
      parse_loop(rest, line, record_line, True, ["\"", ..field], record, done)
    True, ["\"", ..rest] ->
      case rest {
        [] | [",", ..] | ["\n", ..] | ["\r\n", ..] | ["\r", ..] ->
          parse_loop(rest, line, record_line, False, field, record, done)
        _ ->
          Error(
            "line "
            <> int.to_string(line)
            <> ": a quoted cell must end at a comma or the end of the line",
          )
      }
    True, [c, ..rest] if c == "\n" || c == "\r\n" || c == "\r" ->
      parse_loop(rest, line + 1, record_line, True, [c, ..field], record, done)
    True, [c, ..rest] ->
      parse_loop(rest, line, record_line, True, [c, ..field], record, done)
    // outside quotes
    False, ["\"", ..rest] if field == [] ->
      parse_loop(rest, line, record_line, True, field, record, done)
    False, [",", ..rest] ->
      parse_loop(
        rest,
        line,
        record_line,
        False,
        [],
        [field_text(), ..record],
        done,
      )
    False, [c, ..rest] if c == "\n" || c == "\r\n" || c == "\r" ->
      parse_loop(rest, line + 1, line + 1, False, [], [], end_record())
    False, [c, ..rest] ->
      parse_loop(rest, line, record_line, False, [c, ..field], record, done)
  }
}

fn strip_bom(content: String) -> String {
  case content {
    "\u{FEFF}" <> rest -> rest
    _ -> content
  }
}

fn unescape_formula(cell: String) -> String {
  case cell {
    "'" <> rest ->
      case needs_escape(rest) {
        True -> rest
        False -> cell
      }
    _ -> cell
  }
}

/// Whether an exported cell gets a `'` prefix: it would start a formula, or
/// starts with `'` itself. Bytes are compared, not graphemes: `=` followed
/// by a combining mark is one grapheme, but a spreadsheet still reads `=`.
fn needs_escape(cell: String) -> Bool {
  list.any(["=", "+", "-", "@", "\t", "\r", "'"], string.starts_with(cell, _))
}

// --- export -----------------------------------------------------------------

/// Every rule, one line each, under a header of `columns`.
pub fn to_string(rules: List(Rule)) -> String {
  let lines =
    list.map(rules, fn(r) {
      [
        r.id,
        r.host,
        rule.kind_to_string(r.kind),
        r.source,
        r.target,
        int.to_string(r.status),
        bool(r.preserve_query),
        bool(r.case_insensitive),
        bool(r.whole_segments),
        r.query,
        int.to_string(r.priority),
        bool(r.enabled),
        r.starts_at,
        r.expires_at,
        rule.tags_to_string(r.tags),
        r.note,
      ]
    })
  [columns, ..lines]
  |> list.map(fn(cells) { list.map(cells, cell) |> string.join(",") })
  |> list.map(fn(line) { line <> "\r\n" })
  |> string.concat
}

fn bool(value: Bool) -> String {
  case value {
    True -> "true"
    False -> "false"
  }
}

fn cell(value: String) -> String {
  let value = case needs_escape(value) {
    True -> "'" <> value
    False -> value
  }
  case
    string.contains(value, ",")
    || string.contains(value, "\"")
    || string.contains(value, "\n")
    || string.contains(value, "\r")
    || string.trim(value) != value
  {
    True -> "\"" <> string.replace(value, "\"", "\"\"") <> "\""
    False -> value
  }
}
