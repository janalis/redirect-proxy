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
