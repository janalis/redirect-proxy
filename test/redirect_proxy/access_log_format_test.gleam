import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/string
import mist
import qcheck
import redirect_proxy/access_log_format.{
  type Entry, Entry, Header, Literal, Status, Var,
} as fmt
import redirect_proxy/ffi

// 2026-11-06T09:30:05.123456Z
const time_us = 1_793_957_405_123_456

fn entry() -> Entry {
  Entry(
    listener: "redirect",
    client_ip: "203.0.113.0",
    method: "GET",
    host: "old.example.com",
    path: "/blog/42",
    query: "utm_source=mail&email=a%40b.c",
    protocol: "HTTP/1.1",
    status: 301,
    bytes: 0,
    headers: [
      #("referer", "https://ref.example/search?q=me"),
      #("user-agent", "Mozilla/5.0 \"quoted\""),
      #("x-request-id", "abc-123"),
    ],
    location: "https://new.example.com/articles/42?utm_source=mail",
    rule_id: "r1",
    time_us:,
    duration_us: 1534,
  )
}

fn render(format: String, log_query: Bool) -> String {
  let assert Ok(f) = fmt.parse(format, "default")
  fmt.render(f, log_query, entry())
}

pub fn combined_test() {
  let line = render("combined", False)
  let assert Ok(#(_, rest)) = string.split_once(line, "] ")
  assert string.starts_with(line, "203.0.113.0 - - [06/Nov/2026:")
  assert rest
    == "\"GET /blog/42 HTTP/1.1\" 301 0 \"https://ref.example/search\" \"Mozilla/5.0 \\x22quoted\\x22\""
}

pub fn combined_with_query_test() {
  let line = render("combined", True)
  assert string.contains(
    line,
    "\"GET /blog/42?utm_source=mail&email=a%40b.c HTTP/1.1\"",
  )
  assert string.contains(line, "\"https://ref.example/search?q=me\"")
}

pub fn common_test() {
  let line = render("common", False)
  assert string.ends_with(line, "] \"GET /blog/42 HTTP/1.1\" 301 0")
}

pub fn json_test() {
  let line = render("json", False)
  let decoder = {
    use status <- decode.field("status", decode.int)
    use time <- decode.field("request_time", decode.float)
    use args <- decode.field("args", decode.string)
    use ua <- decode.field("http_user_agent", decode.string)
    use location <- decode.field("location", decode.string)
    decode.success(#(status, time, args, ua, location))
  }
  let assert Ok(#(301, 0.001, "", "Mozilla/5.0 \"quoted\"", location)) =
    json.parse(line, decoder)
  assert location == "https://new.example.com/articles/42"
}

pub fn json_escapes_invalid_utf8_test() {
  let assert Ok(f) = fmt.parse("{\"ua\":\"$http_user_agent\"}", "json")
  let bad = Entry(..entry(), headers: [#("user-agent", "a\nb\u{1}c")])
  assert fmt.render(f, False, bad) == "{\"ua\":\"a\\nb\\u0001c\"}"
}

pub fn custom_template_test() {
  let line =
    render(
      "$remote_addr ${request_method}:$uri $status ${request_time}s $http_x_request_id $msec $rule_id $$ $1",
      False,
    )
  assert line
    == "203.0.113.0 GET:/blog/42 301 0.001s abc-123 1793957405.123 r1 $$ $1"
}

pub fn empty_values_are_dashes_test() {
  let line = render("[$args] [$http_x_missing]", False)
  assert line == "[-] [-]"
  let assert Ok(f) = fmt.parse("[$args]", "none")
  assert fmt.render(f, False, entry()) == "[]"
}

pub fn listener_variable_test() {
  assert render("$listener $status", False) == "redirect 301"
  assert string.contains(render("json", False), "\"listener\":\"redirect\"")
}

pub fn credentials_are_refused_test() {
  let assert Error(e) = fmt.parse("$http_authorization", "default")
  assert string.contains(e, "credentials")
  let assert Error(_) = fmt.parse("$http_cookie", "default")
  let assert Error(_) = fmt.parse("${http_proxy_authorization}", "default")
}

pub fn parse_test() {
  let assert Ok(f) = fmt.parse("a $status ${http_x_id}b", "default")
  assert f.segments
    == [
      Literal("a "),
      Var(Status),
      Literal(" "),
      Var(Header("x-id")),
      Literal("b"),
    ]
  let assert Error(e) = fmt.parse("$nope", "default")
  assert string.contains(e, "$nope")
  let assert Error(_) = fmt.parse("${status", "default")
  let assert Error(_) = fmt.parse("", "default")
  let assert Error(_) = fmt.parse("$status", "xml")
}

pub fn anonymize_test() {
  assert fmt.anonymize("192.168.17.42") == "192.168.17.0"
  assert fmt.anonymize("2001:db8:85a3:1234:8a2e:370:7334:1")
    == "2001:db8:85a3::"
  assert fmt.anonymize("::ffff:10.1.2.3") == "10.1.2.0"
  assert fmt.anonymize("not an ip") == ""
}

pub fn client_ip_test() {
  let trusted = ["10.0.0.0/8"]
  let xff = [#("x-forwarded-for", "198.51.100.7, 203.0.113.9, 10.0.0.2")]
  // untrusted peer: headers are ignored
  assert fmt.client_ip("192.0.2.1", xff, trusted) == "192.0.2.1"
  assert fmt.client_ip("192.0.2.1", xff, []) == "192.0.2.1"
  // trusted peer: rightmost untrusted hop
  assert fmt.client_ip("10.0.0.1", xff, trusted) == "203.0.113.9"
  assert fmt.client_ip(
      "10.0.0.1",
      [#("x-forwarded-for", "10.0.0.3, 10.0.0.2")],
      trusted,
    )
    == "10.0.0.3"
  assert fmt.client_ip("10.0.0.1", [#("x-real-ip", " 198.51.100.8 ")], trusted)
    == "198.51.100.8"
  assert fmt.client_ip("10.0.0.1", [], trusted) == "10.0.0.1"
}

pub fn text_lines_never_break_test() {
  use value <- qcheck.given(qcheck.string())
  let assert Ok(f) = fmt.parse("combined", "default")
  let e =
    Entry(..entry(), path: value, headers: [
      #("user-agent", value),
      #("referer", value),
    ])
  let line = fmt.render(f, True, e)
  assert !string.contains(line, "\n")
  assert !string.contains(line, "\r")
}

pub fn anonymize_peer_matches_anonymize_test() {
  [
    mist.IpV4(192, 168, 17, 42),
    mist.IpV4(10, 0, 0, 1),
    mist.IpV6(0x2001, 0xdb8, 0x85a3, 0x1234, 0x8a2e, 0x370, 0x7334, 1),
    mist.IpV6(0, 0, 0, 0, 0, 0, 0, 1),
    mist.IpV6(0, 0, 0, 0, 0, 0xffff, 0x0a01, 0x0203),
  ]
  |> list.each(fn(ip) {
    assert ffi.anonymize_peer(ip)
      == fmt.anonymize(mist.ip_address_to_string(ip))
  })
}

pub fn cached_time_follows_the_second_test() {
  // creates the shared cache (no handler is installed)
  let assert Ok(Nil) = ffi.access_log_start([], 0, 0, False)
  let seconds_of = fn(t) {
    let local = ffi.time_local(t)
    let iso = ffi.time_iso8601(t)
    // the seconds do not depend on the time zone: 09:30:05 UTC is xx:x0:05
    let assert [_, after_minutes] = string.split(local, " ")
    assert string.length(after_minutes) == 5
    #(string.slice(local, 18, 2), string.slice(iso, 17, 2))
  }
  assert seconds_of(time_us) == #("05", "05")
  assert seconds_of(time_us + 876_543) == #("05", "05")
  assert seconds_of(time_us + 1_000_000) == #("06", "06")
  // an older second (requests logged out of order) is rendered again
  assert seconds_of(time_us) == #("05", "05")
  assert ffi.time_local(time_us) != ffi.time_local(time_us + 1_000_000)
  ffi.access_log_stop()
}
