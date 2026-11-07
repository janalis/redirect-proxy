//// Rules as CSV (RFC 4180), for spreadsheets: import with a header row
//// naming the columns (only `source` and `target` are required, as in
//// JSON), and export with every column.
////
//// A cell starting with `=`, `+`, `-`, `@`, a tab or a carriage return
//// would run as a formula in a spreadsheet: the export prefixes it with
//// `'` (and a cell starting with `'` too, so that it survives), and the
//// import removes that one prefix again.

import gleam/bit_array
import gleam/bool
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
      // a column typed in then cleared in a spreadsheet leaves empty cells
      // at the end of every line
      let header =
        list.map(header, fn(h) { string.lowercase(string.trim(h)) })
        |> drop_trailing_empty
      use Nil <- result.try(check_header(header))
      let #(rules, errors) =
        rows
        |> list.map(fn(row) { row_to_rule(header, row) })
        |> result.partition
      case errors {
        [] -> Ok(list.reverse(rules))
        _ -> Error(first_errors(list.reverse(errors)))
      }
    }
  }
}

/// Errors reported for one document: a broken file of 100 000 rows does
/// not give a response of 100 000 lines.
const max_errors = 100

fn first_errors(errors: List(String)) -> List(String) {
  case list.length(errors) - max_errors {
    more if more > 0 ->
      list.append(list.take(errors, max_errors), [
        "… and " <> int.to_string(more) <> " more errors",
      ])
    _ -> errors
  }
}

fn drop_trailing_empty(cells: List(String)) -> List(String) {
  cells
  |> list.reverse
  |> list.drop_while(fn(c) { string.trim(c) == "" })
  |> list.reverse
}

fn check_header(header: List(String)) -> Result(Nil, List(String)) {
  use <- bool.guard(
    case header {
      [only] -> string.contains(only, ";")
      _ -> False
    },
    Error([
      "line 1: the columns are separated by semicolons; separate them by commas (in a spreadsheet, save as \"CSV UTF-8 (comma delimited)\")",
    ]),
  )
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
    list.length(drop_trailing_empty(cells)) > list.length(header),
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
/// are skipped. Works on the bytes (the separators are ASCII, so cells stay
/// valid UTF-8): a list of graphemes would take many times the size of an
/// import of several megabytes.
fn records(content: String) -> Result(List(#(Int, List(String))), String) {
  parse_loop(bit_array.from_string(content), 1, 1, False, <<>>, [], [])
  // lines of empty cells only (`,,,`), as spreadsheets write below the data
  |> result.map(fn(records) {
    list.filter(records, fn(r) {
      !list.all(r.1, fn(c) { string.trim(c) == "" })
    })
  })
}

fn parse_loop(
  bytes: BitArray,
  line: Int,
  record_line: Int,
  quoted: Bool,
  field: BitArray,
  record: List(String),
  done: List(#(Int, List(String))),
) -> Result(List(#(Int, List(String))), String) {
  let field_text = fn() { bit_array.to_string(field) |> result.unwrap("") }
  let end_record = fn() {
    [#(record_line, list.reverse([field_text(), ..record])), ..done]
  }
  case quoted, bytes {
    // end of input
    True, <<>> ->
      Error(
        "line " <> int.to_string(record_line) <> ": unterminated quoted cell",
      )
    False, <<>> ->
      case field, record {
        <<>>, [] -> Ok(list.reverse(done))
        _, _ -> Ok(list.reverse(end_record()))
      }
    // inside quotes: a doubled quote is a quote, a single one ends them
    True, <<"\"\"":utf8, rest:bits>> ->
      parse_loop(
        rest,
        line,
        record_line,
        True,
        <<field:bits, "\"":utf8>>,
        record,
        done,
      )
    True, <<"\"":utf8, rest:bits>> ->
      case rest {
        <<>>
        | <<",":utf8, _:bits>>
        | <<"\n":utf8, _:bits>>
        | <<"\r":utf8, _:bits>> ->
          parse_loop(rest, line, record_line, False, field, record, done)
        _ ->
          Error(
            "line "
            <> int.to_string(line)
            <> ": a quoted cell must end at a comma or the end of the line",
          )
      }
    True, <<"\r\n":utf8, rest:bits>> ->
      parse_loop(
        rest,
        line + 1,
        record_line,
        True,
        <<field:bits, "\r\n":utf8>>,
        record,
        done,
      )
    True, <<c, rest:bits>> if c == 10 || c == 13 ->
      parse_loop(
        rest,
        line + 1,
        record_line,
        True,
        <<field:bits, c>>,
        record,
        done,
      )
    True, <<c, rest:bits>> ->
      parse_loop(rest, line, record_line, True, <<field:bits, c>>, record, done)
    // outside quotes
    False, <<"\"":utf8, rest:bits>> if field == <<>> ->
      parse_loop(rest, line, record_line, True, field, record, done)
    False, <<",":utf8, rest:bits>> ->
      parse_loop(
        rest,
        line,
        record_line,
        False,
        <<>>,
        [field_text(), ..record],
        done,
      )
    False, <<"\r\n":utf8, rest:bits>> ->
      parse_loop(rest, line + 1, line + 1, False, <<>>, [], end_record())
    False, <<c, rest:bits>> if c == 10 || c == 13 ->
      parse_loop(rest, line + 1, line + 1, False, <<>>, [], end_record())
    False, <<c, rest:bits>> ->
      parse_loop(
        rest,
        line,
        record_line,
        False,
        <<field:bits, c>>,
        record,
        done,
      )
    // not reached: a String is whole bytes
    _, _ -> Error("line " <> int.to_string(line) <> ": invalid input")
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

/// `to_string` with a UTF-8 byte order mark, for spreadsheets: without it,
/// Excel reads the file as ANSI and corrupts every non-ASCII character
/// (`café` shows as `cafÃ©`). Imports skip the mark.
pub fn to_spreadsheet_string(rules: List(Rule)) -> String {
  "\u{FEFF}" <> to_string(rules)
}

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
