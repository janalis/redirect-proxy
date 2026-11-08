import gleam/list
import gleam/string
import redirect_proxy/rule.{Rule}
import redirect_proxy/rule_csv

pub fn minimal_csv_test() {
  let assert Ok([r]) = rule_csv.parse("source,target\n/old,/new\n")
  assert r.source == "/old"
  assert r.target == "/new"
  // the defaults of a JSON import
  assert r.host == "*"
  assert r.kind == rule.Exact
  assert r.status == 301
  assert r.enabled
}

pub fn quoting_test() {
  let csv =
    "\u{FEFF}Source,TARGET,note,tags\r\n"
    <> "/a,/b,\"says \"\"hi\"\", twice\",\"Campaign, legacy\"\r\n"
    <> "\r\n"
    <> "/c,/d,\"two\nlines\",\r\n"
  let assert Ok([a, c]) = rule_csv.parse(csv)
  assert a.note == "says \"hi\", twice"
  assert a.tags == ["campaign", "legacy"]
  assert c.note == "two\nlines"
  assert c.tags == []
}

/// A quote, comma or line break followed by a combining mark (U+1E000) is one
/// grapheme with it: the cell must still be quoted, its quote doubled.
pub fn quoting_before_combining_marks_test() {
  [
    "a\"\u{1E000}\n",
    "\"\u{1E000}",
    "a,\u{1E000}",
    "a\r\u{1E000}b",
    "\u{1E000}\"x",
  ]
  |> list.each(fn(target) {
    let r = Rule(..rule.blank(), id: "x", source: "/s", target:)
    let assert Ok([back]) = rule_csv.parse_import(rule_csv.to_string([r]))
    assert back.target == target
  })
}

pub fn every_column_test() {
  let csv =
    "match,source,target,status,preserve_query,case_insensitive,whole_segments,priority,enabled,host,starts_at,expires_at,query,id\n"
    <> "prefix,/blog,/news,302,yes,1,true,5,false,example.com,2026-01-01T00:00:00Z,,,r1\n"
  let assert Ok([r]) = rule_csv.parse(csv)
  assert r.kind == rule.Prefix
  assert r.status == 302
  assert r.preserve_query && r.case_insensitive && r.whole_segments
  assert r.priority == 5
  assert !r.enabled
  assert r.host == "example.com"
  assert r.starts_at == "2026-01-01T00:00:00Z"
  assert r.id == "r1"
}

pub fn errors_name_the_line_test() {
  let assert Error([unknown]) =
    rule_csv.parse("source,target,colour\n/a,/b,red\n")
  assert string.starts_with(unknown, "line 1: unknown column colour")
  let assert Error([missing]) = rule_csv.parse("source\n/a\n")
  assert missing == "line 1: the target column is required"
  let assert Error([_]) = rule_csv.parse("source,target,source\n/a,/b,/c\n")
  let assert Error(errors) =
    rule_csv.parse(
      "source,target,status,enabled\n/a,/b,301,true\n/c,/d,moved,true\n/e,/f,301,maybe\n/g,/h,301,true,extra\n",
    )
  assert errors
    == [
      "line 3: status: must be a number",
      "line 4: enabled: must be true or false",
      "line 5: more cells than columns",
    ]
  // a quoted cell spanning lines counts its lines
  let assert Error([multi]) =
    rule_csv.parse("source,target,note,status\n/a,/b,\"x\ny\",bad\n")
  assert multi == "line 2: status: must be a number"
  let assert Error([unterminated]) = rule_csv.parse("source,target\n/a,\"/b\n")
  assert string.contains(unterminated, "unterminated")
  let assert Error([_]) = rule_csv.parse("")
}

pub fn round_trip_test() {
  let rules = [
    Rule(
      ..rule.blank(),
      id: "a",
      source: "/old",
      target: "https://example.com/new?a=1,2",
      tags: ["campaign", "legacy"],
      note: "line one\nline \"two\"",
    ),
    Rule(
      ..rule.blank(),
      id: "b",
      kind: rule.Regex,
      source: "^/p/(\\d+)$",
      target: "/q/$1",
      status: 308,
      enabled: False,
      note: " padded ",
    ),
  ]
  let assert Ok(back) = rule_csv.parse(rule_csv.to_string(rules))
  assert back == rules
}

/// Cells a spreadsheet would run as a formula are prefixed with `'` on
/// export, and the prefix is removed on import.
pub fn formula_cells_test() {
  let r =
    Rule(
      ..rule.blank(),
      id: "f",
      source: "/f",
      target: "/x",
      note: "=HYPERLINK(\"x\")",
    )
  let csv = rule_csv.to_string([r])
  assert string.contains(csv, "\"'=HYPERLINK(\"\"x\"\")\"")
  let assert Ok([back]) = rule_csv.parse(csv)
  assert back.note == "=HYPERLINK(\"x\")"
  // a quote that does not protect a formula is kept
  let assert Ok([kept]) = rule_csv.parse("source,target,note\n/a,/b,'quoted\n")
  assert kept.note == "'quoted"
  // cells that start with a quote, or with a formula character followed by
  // a combining mark, survive a round trip and are escaped
  let tricky = ["'=keep", "'plain", "=\u{0301}HYPERLINK(1)", "-tag"]
  list.each(tricky, fn(note) {
    let csv = rule_csv.to_string([Rule(..r, note:)])
    assert string.contains(csv, ",'" <> note)
      || string.contains(csv, "\"'" <> note)
    let assert Ok([back]) = rule_csv.parse(csv)
    assert back.note == note
  })
}

pub fn format_detection_test() {
  assert rule_csv.looks_like_csv("source,target\n/a,/b")
  assert !rule_csv.looks_like_csv("  [{\"source\": \"/a\"}]")
  assert !rule_csv.looks_like_csv("{\"version\": 1}")
  let assert Ok([_]) =
    rule_csv.parse_import("[{\"source\":\"/a\",\"target\":\"/b\"}]")
  let assert Ok([_]) = rule_csv.parse_import("source,target\n/a,/b")
  assert list.length(rule_csv.columns) == 16
}

pub fn json_with_a_byte_order_mark_test() {
  let assert Ok([_]) =
    rule_csv.parse_import("\u{FEFF}[{\"source\":\"/a\",\"target\":\"/b\"}]")
}

/// Cells are split on ASCII bytes: multi-byte characters stay whole, and
/// line numbers count line breaks inside quoted cells.
pub fn multibyte_cells_and_line_numbers_test() {
  let assert Ok([a, b]) =
    rule_csv.parse("source,target,note\n/café,/naïve,\"日本語,\r\n🎉\"\r/x,/y,ok\n")
  assert #(a.source, a.target, a.note) == #("/café", "/naïve", "日本語,\r\n🎉")
  assert #(b.source, b.target, b.note) == #("/x", "/y", "ok")
  let assert Error([error]) =
    rule_csv.parse("source,target,note\n/a,/b,\"x\ny\"\n/c,/d,\"z\"q\n")
  assert string.starts_with(error, "line 4:")
}

pub fn errors_are_capped_test() {
  let rows = string.repeat("/a,/b,x\n", 250)
  let assert Error(errors) = rule_csv.parse("source,target,status\n" <> rows)
  assert list.length(errors) == 101
  assert list.last(errors) == Ok("… and 150 more errors")
}

/// What spreadsheets leave behind: a cleared column (a trailing empty cell
/// on every line) and formatted rows below the data (lines of commas).
pub fn spreadsheet_leftovers_are_ignored_test() {
  let csv = "source,target,\r\n/a,/b,\r\n,,\r\n/c,/d,\r\n , ,\r\n"
  let assert Ok([a, c]) = rule_csv.parse(csv)
  assert a.source == "/a" && c.target == "/d"
  // a cell in a column without a header is still an error
  let assert Error([extra]) = rule_csv.parse("source,target\n/a,/b,x\n")
  assert string.contains(extra, "more cells than columns")
}

/// French-locale spreadsheets separate cells with `;`: say so.
pub fn semicolon_separators_get_a_hint_test() {
  let assert Error([hint]) = rule_csv.parse("source;target\n/a;/b\n")
  assert string.contains(hint, "semicolons")
}

/// The spreadsheet export starts with a UTF-8 byte order mark, so that
/// Excel reads non-ASCII text right; imports skip it.
pub fn spreadsheet_export_has_a_bom_test() {
  let r = Rule(..rule.blank(), id: "1", source: "/café", target: "/menü")
  let csv = rule_csv.to_spreadsheet_string([r])
  assert string.starts_with(csv, "\u{FEFF}id,")
  let assert Ok([back]) = rule_csv.parse_import(csv)
  assert back.source == "/café" && back.target == "/menü"
}
