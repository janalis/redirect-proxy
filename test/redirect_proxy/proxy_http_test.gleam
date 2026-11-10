//// The HTTP/1.1 server of the redirect listener, at the protocol level.

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{Response}
import gleam/int
import gleam/list
import gleam/option
import gleam/string
import redirect_proxy/proxy/http as proxy_http
import support

@external(erlang, "test_net_ffi", "session")
fn session(port: Int, chunks: List(BitArray), wait_ms: Int) -> #(BitArray, Bool)

@external(erlang, "test_net_ffi", "paced_session")
fn paced_session(
  port: Int,
  chunks: List(BitArray),
  gap_ms: Int,
  wait_ms: Int,
) -> #(BitArray, Bool)

/// Answers 200 with what it received in headers; `/crash` crashes.
fn echo_handler(req: Request(proxy_http.Peer)) {
  case req.path {
    "/crash" -> panic as "handler crash (expected by the test)"
    _ -> Nil
  }
  proxy_http.Answer(Response(
    200,
    [
      #("x-method", http.method_to_string(req.method)),
      #("x-path", req.path),
      #("x-query", option.unwrap(req.query, "-")),
      #("x-host", req.host),
      #("x-port", int.to_string(option.unwrap(req.port, 0))),
      #(
        "x-headers",
        list.map(req.headers, fn(h) { h.0 <> "=" <> h.1 }) |> string.join(";"),
      ),
      #("x-peer", case req.body {
        Ok(_) -> "yes"
        Error(Nil) -> "no"
      }),
    ],
    bytes_tree.from_string("hello"),
  ))
}

fn start() -> Int {
  start_with_idle_timeout(300)
}

fn start_with_idle_timeout(idle_timeout_ms: Int) -> Int {
  let assert Ok(started) =
    proxy_http.start(
      "127.0.0.1",
      0,
      echo_handler,
      proxy_http.Options(
        idle_timeout_ms:,
        max_head_bytes: 1024,
        peer: True,
        upstream: option.None,
      ),
    )
  started.data
}

fn exchange(chunks: List(String)) -> #(String, Bool) {
  exchange_on(start(), chunks)
}

fn exchange_on(port: Int, chunks: List(String)) -> #(String, Bool) {
  let #(received, closed) =
    session(port, list.map(chunks, bit_array.from_string), 1000)
  let assert Ok(text) = bit_array.to_string(received)
  #(text, closed)
}

fn responses(text: String) -> Int {
  list.length(string.split(text, "HTTP/1.1 ")) - 1
}

pub fn request_is_parsed_test() {
  let #(text, _) =
    exchange([
      "GET /a/b?x=1&y=%20#frag HTTP/1.1\r\nHost: Example.test:8080\r\nX-Custom-Name:  Some Value\r\nconnection: close\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nx-method: GET\r\n")
  assert string.contains(text, "\r\nx-path: /a/b\r\n")
  assert string.contains(text, "\r\nx-query: x=1&y=%20\r\n")
  assert string.contains(text, "\r\nx-host: Example.test\r\n")
  assert string.contains(text, "\r\nx-port: 8080\r\n")
  // lowercase names, values as sent
  assert string.contains(
    text,
    "\r\nx-headers: host=Example.test:8080;x-custom-name=Some Value;connection=close\r\n",
  )
  assert string.contains(text, "\r\nx-peer: yes\r\n")
  assert string.contains(text, "\r\ncontent-length: 5\r\n")
  assert string.contains(text, "\r\ndate: ")
  assert string.ends_with(text, "\r\n\r\nhello")
}

pub fn pipelined_requests_are_answered_in_order_test() {
  let #(text, closed) =
    exchange([
      "GET /1 HTTP/1.1\r\nhost: a\r\n\r\nGET /2 HTTP/1.1\r\nhost: a\r\n\r\nGET /3 HTTP/1.1\r\nho",
      "st: a\r\n\r\n",
    ])
  assert responses(text) == 3
  let assert [_, first, second, third] = string.split(text, "x-path: ")
  assert string.starts_with(first, "/1\r\n")
  assert string.starts_with(second, "/2\r\n")
  assert string.starts_with(third, "/3\r\n")
  // kept alive until the idle timeout
  assert closed
  assert !string.contains(text, "connection: close")
}

pub fn keep_alive_by_version_test() {
  // HTTP/1.0: closed unless asked to keep the connection
  let #(text, closed) =
    exchange(["GET / HTTP/1.0\r\n\r\nGET / HTTP/1.0\r\n\r\n"])
  assert responses(text) == 1
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert closed
  let #(text, _) =
    exchange([
      "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\nGET / HTTP/1.0\r\n\r\n",
    ])
  assert responses(text) == 2
  assert string.contains(text, "\r\nconnection: keep-alive\r\n")
  // HTTP/1.1: kept unless the client closes it
  let #(text, _) =
    exchange([
      "GET / HTTP/1.1\r\nhost: a\r\nconnection: keep-alive, close\r\n\r\nGET / HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert responses(text) == 1
  assert string.contains(text, "\r\nconnection: close\r\n")
  // repeated Connection headers are one list
  let #(text, _) =
    exchange([
      "GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\nconnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert responses(text) == 1
  assert string.contains(text, "\r\nconnection: close\r\n")
}

/// A request whose body is not read is answered, then the connection is
/// closed without resetting it while the client still sends its body: the
/// client reads the whole response.
pub fn unread_bodies_do_not_reset_the_response_test() {
  let port = start()
  let part = string.repeat("x", 65_536) |> bit_array.from_string
  let #(received, reset) =
    upload(
      port,
      "POST /form HTTP/1.1\r\nhost: a\r\ncontent-length: 1048576\r\n\r\n",
      part,
      15,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert !reset
  // and a rejected request
  let #(received, reset) =
    upload(port, "POST /form HTTP/1.1\r\nhost: a\r\nbad line\r\n\r\n", part, 15)
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 400 ")
  assert !reset
}

pub fn idle_connections_are_closed_test() {
  let #(text, closed) = exchange([])
  assert text == ""
  assert closed
  // an incomplete head gets a 408
  let #(text, closed) = exchange(["GET / HTTP/1.1\r\nhost: a\r\n"])
  assert string.starts_with(text, "HTTP/1.1 408 Request Timeout\r\n")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert closed
}

pub fn idle_connections_hibernate_then_serve_test() {
  // 200 ms between the requests: the connection hibernates after half of
  // its 300 ms idle timeout, then answers the next one, then is closed
  let #(received, closed) =
    paced_session(
      start(),
      list.map(
        [
          "GET /1 HTTP/1.1\r\nhost: a\r\n\r\n",
          "GET /2 HTTP/1.1\r\nhost: a\r\n\r\n",
        ],
        bit_array.from_string,
      ),
      200,
      1000,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert responses(text) == 2
  assert string.contains(text, "x-path: /2\r\n")
  assert closed
}

pub fn requests_with_a_body_close_the_connection_test() {
  let #(text, closed) =
    exchange([
      "POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 41\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert responses(text) == 1
  assert !string.contains(text, "/smuggled")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert closed
  let #(text, _) =
    exchange([
      "POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
    ])
  assert string.contains(text, "\r\nconnection: close\r\n")
  // an empty body is no body
  let #(text, _) =
    exchange([
      "POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 0\r\n\r\nGET / HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert responses(text) == 2
}

pub fn head_responses_have_no_body_test() {
  let #(text, _) =
    exchange(["HEAD / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n"])
  assert string.contains(text, "\r\ncontent-length: 5\r\n")
  assert string.ends_with(text, "\r\n\r\n")
}

pub fn invalid_requests_are_rejected_test() {
  let rejected = fn(request, status) {
    let #(text, closed) = exchange([request])
    assert string.starts_with(text, "HTTP/1.1 " <> status <> " ")
    assert string.contains(text, "\r\nconnection: close\r\n")
    assert closed
  }
  // HTTP/1.1 needs a host, and only one
  rejected("GET / HTTP/1.1\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a\r\nhost: b\r\n\r\n", "400")
  // only the characters of a URI, in an absolute path
  rejected("GET /a\\b HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /é HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=\"x\" HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=<x> HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=\\x HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=\u{7f} HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=\tb HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  // no CR or LF in a target, so none can reach a `location` header
  rejected("GET /?a=1\rlocation:x HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET /?a=1\nlocation:x HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("GET http://a/ HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("OPTIONS * HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  // no control characters (or folded lines) in header values
  rejected("GET / HTTP/1.1\r\nhost: a\r\nx: a\r\n b\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a\u{1}\r\n\r\n", "400")
  // a Host is a host name, an IPv4 or bracketed IPv6 address, and a port
  rejected("GET / HTTP/1.1\r\nhost: a b\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a/b\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: u@a\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: café.test\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a:b\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a:65536\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a:80:81\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: [::1\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: [x]\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: [::1]x\r\n\r\n", "400")
  // longer than any DNS name
  rejected(
    "GET / HTTP/1.1\r\nhost: " <> string.repeat("a.", 128) <> "\r\n\r\n",
    "400",
  )
  rejected("HTTP/1.1 200 OK\r\n\r\n", "400")
  rejected("GET / HTTP/2.0\r\nhost: a\r\n\r\n", "505")
  // longer than max_head_bytes (1024)
  rejected("GET /" <> string.repeat("a", 1100), "414")
  rejected(
    "GET / HTTP/1.1\r\nhost: a\r\nx: " <> string.repeat("a", 1100),
    "431",
  )
}

pub fn host_authorities_are_parsed_test() {
  let host = fn(value) {
    let #(text, _) =
      exchange([
        "GET / HTTP/1.1\r\nhost: " <> value <> "\r\nconnection: close\r\n\r\n",
      ])
    assert string.starts_with(text, "HTTP/1.1 200 ")
    let assert Ok(#(_, rest)) = string.split_once(text, "\r\nx-host: ")
    let assert Ok(#(name, rest)) = string.split_once(rest, "\r\n")
    let assert Ok(#(_, rest)) = string.split_once(rest, "x-port: ")
    let assert Ok(#(port, _)) = string.split_once(rest, "\r\n")
    #(name, port)
  }
  assert host("[::1]:8080") == #("[::1]", "8080")
  assert host("[2001:db8::7]") == #("[2001:db8::7]", "80")
  assert host("192.0.2.1:81") == #("192.0.2.1", "81")
  assert host("a.test:") == #("a.test", "80")
  assert host("a_b.test") == #("a_b.test", "80")
  let longest = string.repeat("a", 255)
  assert host(longest <> ":1") == #(longest, "1")
}

/// Characters browsers send unescaped in queries, outside RFC 3986.
pub fn browser_query_characters_are_accepted_test() {
  let #(text, _) =
    exchange([
      "GET /p[1]?a[]=1&b={x}|y^z`w HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nx-path: /p[1]\r\n")
  assert string.contains(text, "\r\nx-query: a[]=1&b={x}|y^z`w\r\n")
}

pub fn handler_crashes_get_500_test() {
  let #(text, closed) = exchange(["GET /crash HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.starts_with(text, "HTTP/1.1 500 ")
  assert closed
}

pub fn other_methods_reach_the_handler_test() {
  let #(text, _) =
    exchange([
      "PATCH / HTTP/1.1\r\nhost: a\r\n\r\nPURGE / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n",
    ])
  assert string.contains(text, "\r\nx-method: PATCH\r\n")
  assert string.contains(text, "\r\nx-method: PURGE\r\n")
}

pub fn blank_lines_before_a_request_are_ignored_test() {
  let #(text, _) =
    exchange(["\r\nGET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n"])
  assert string.starts_with(text, "HTTP/1.1 200 ")
}

@external(erlang, "test_net_ffi", "parse_outcome")
fn parse_outcome(head: BitArray) -> String

pub fn every_partial_head_waits_for_more_test() {
  let head =
    "\r\nGET /a?b=1#c HTTP/1.1\r\nHost: a:81\r\nX-Name:  é v \t\r\nx-bare: lf\nconnection: keep-alive\r\n\r\n"
  let bytes = bit_array.from_string(head)
  let size = bit_array.byte_size(bytes)
  assert parse_outcome(bytes) == "ok"
  int.range(0, size, Nil, fn(_, n) {
    let assert Ok(prefix) = bit_array.slice(bytes, 0, n)
    assert parse_outcome(prefix) == "more"
  })
}

pub fn header_values_are_trimmed_test() {
  let #(text, _) =
    exchange([
      "GET /a#x?y HTTP/1.1\nhost: a\nX-Name: \t é v \t\nconnection: close\n\n",
    ])
  assert string.contains(text, "\r\nx-path: /a\r\n")
  assert string.contains(text, "\r\nx-query: -\r\n")
  assert string.contains(
    text,
    "\r\nx-headers: host=a;x-name=é v;connection=close\r\n",
  )
}

pub fn lowercase_methods_are_other_methods_test() {
  let #(text, _) =
    exchange(["get / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n"])
  assert string.contains(text, "\r\nx-method: get\r\n")
}

pub fn malformed_header_names_are_rejected_test() {
  assert parse_outcome(<<"GET / HTTP/1.1\r\nhost : a\r\n\r\n":utf8>>)
    == "error:400"
  assert parse_outcome(<<"GET / HTTP/1.1\r\n: a\r\n\r\n":utf8>>) == "error:400"
  assert parse_outcome(<<"GET / HTTP/1.1\r\nhost: a\rb\r\n\r\n":utf8>>)
    == "error:400"
  assert parse_outcome(<<"GET / HTTP/1.1\r\nhost: a\r\nx: \u{7f}\r\n\r\n":utf8>>)
    == "error:400"
  // invalid UTF-8
  assert parse_outcome(<<
      "GET / HTTP/1.1\r\nhost: a\r\nx: ":utf8,
      255,
      254,
      253,
      252,
      "\r\n\r\n":utf8,
    >>)
    == "error:400"
  assert parse_outcome(<<"GET / HTTP/1.1 \r\nhost: a\r\n\r\n":utf8>>)
    == "error:400"
  assert parse_outcome(<<"GET / HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>) == "ok"
}

@external(erlang, "test_net_ffi", "half_closed")
fn half_closed(port: Int, data: BitArray, wait_ms: Int) -> #(BitArray, Bool)

/// A client that shuts down its side after its requests still gets every
/// response, then the connection is closed.
pub fn half_closed_clients_get_their_responses_test() {
  let #(received, closed) =
    half_closed(
      start(),
      <<
        "GET /1 HTTP/1.1\r\nhost: a\r\n\r\nGET /2 HTTP/1.1\r\nhost: a\r\n\r\n":utf8,
      >>,
      1000,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert responses(text) == 2
  assert string.contains(text, "x-path: /2\r\n")
  assert closed
}

@external(erlang, "test_net_ffi", "trickle")
fn trickle(port: Int, data: BitArray, gap_ms: Int) -> #(BitArray, Bool)

type Socket

@external(erlang, "test_net_ffi", "upload")
fn upload(
  port: Int,
  head: String,
  part: BitArray,
  parts: Int,
) -> #(BitArray, Bool)

@external(erlang, "test_net_ffi", "open")
fn open(port: Int) -> Socket

@external(erlang, "test_net_ffi", "send")
fn send(socket: Socket, data: BitArray) -> Nil

@external(erlang, "test_net_ffi", "read")
fn read(socket: Socket, wait_ms: Int) -> #(BitArray, Bool)

@external(erlang, "test_net_ffi", "close")
fn close(socket: Socket) -> Nil

@external(erlang, "test_net_ffi", "connection_process")
fn connection_process(socket: Socket) -> process.Pid

@external(erlang, "test_net_ffi", "poke")
fn poke(pid: process.Pid) -> Nil

@external(erlang, "test_net_ffi", "hibernated")
fn hibernated(pid: process.Pid) -> Bool

@external(erlang, "test_net_ffi", "reductions")
fn reductions(pid: process.Pid) -> Int

@external(erlang, "test_net_ffi", "suspend")
fn suspend(pid: process.Pid) -> Nil

@external(erlang, "test_net_ffi", "resume")
fn resume(pid: process.Pid) -> Nil

@external(erlang, "test_net_ffi", "queued")
fn queued(pid: process.Pid) -> Int

@external(erlang, "test_net_ffi", "start_capped")
fn start_capped(
  handler: fn(Request(proxy_http.Peer)) -> proxy_http.Outcome,
  cap: Int,
) -> Int

fn get(socket: Socket, wait_ms: Int) -> #(String, Bool) {
  send(socket, <<"GET / HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
  let #(received, closed) = read(socket, wait_ms)
  let assert Ok(text) = bit_array.to_string(received)
  #(text, closed)
}

/// A head sent a byte at a time, each one within the idle timeout, still
/// has to arrive within it (slowloris).
pub fn trickled_heads_time_out_test() {
  let #(received, closed) =
    trickle(
      start(),
      <<"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n":utf8>>,
      150,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 408 Request Timeout\r\n")
  assert closed
}

pub fn heads_split_across_packets_are_parsed_test() {
  // sent 50 ms apart: well within the deadline of a head, however loaded
  // the machine running the tests
  let port = start_with_idle_timeout(5000)
  let #(text, _) =
    exchange_on(port, [
      "GET /a?b", "=1 HTTP/1.1\r", "\nHost: x\r\nX-Long: ", "value\r\n",
      "connection: close\r\n\r", "\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nx-path: /a\r\n")
  assert string.contains(text, "\r\nx-query: b=1\r\n")
  assert string.contains(
    text,
    "\r\nx-headers: host=x;x-long=value;connection=close\r\n",
  )
  // a header line per packet, the empty line split after its CR, a bare LF
  let #(text, _) =
    exchange_on(port, [
      "GET /lines HTTP/1.1\r\n", "host: x\r\n", "a: 1\r\n", "b: 2\n", "\r", "\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nx-headers: host=x;a=1;b=2\r\n")
  let #(text, _) = exchange_on(port, ["GET /lf HTTP/1.1\n", "host: x\n", "\n"])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  // an invalid request line is refused before the rest of the head comes
  let #(text, _) = exchange_on(port, ["GET / HTTP/9.9\r\n", "host: x\r\n"])
  assert string.starts_with(text, "HTTP/1.1 ")
  assert !string.starts_with(text, "HTTP/1.1 408 ")
  // an invalid header line, once the head ends
  let #(text, _) =
    exchange_on(port, [
      "GET / HTTP/1.1\r\n",
      "host: x\r\n",
      "bad line\r\n",
      "\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 400 ")
  // and the 414 and 431 of a head sent in small parts
  let #(text, _) =
    exchange_on(port, ["GET /", ..list.repeat(string.repeat("a", 300), 4)])
  assert string.starts_with(text, "HTTP/1.1 414 ")
  let #(text, _) =
    exchange_on(port, [
      "GET / HTTP/1.1\r\nhost: a\r\nx: ",
      ..list.repeat(string.repeat("a", 300), 4)
    ])
  assert string.starts_with(text, "HTTP/1.1 431 ")
}

/// A message the connection does not expect wakes it from hibernation,
/// without restarting its idle timeout.
pub fn stray_messages_do_not_extend_the_idle_timeout_test() {
  let socket = open(start())
  let #(text, _) = get(socket, 100)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  // hibernated after 150 ms
  process.sleep(100)
  poke(connection_process(socket))
  let #(text, closed) = read(socket, 1000)
  close(socket)
  assert text == <<>>
  assert closed
}

/// While the node drains, idle kept-alive connections are closed within a
/// second, not at the end of their idle timeout.
pub fn idle_connections_are_closed_when_draining_test() {
  let port = start_with_idle_timeout(10_000)
  let socket = open(port)
  let #(text, _) = get(socket, 100)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  // hibernated after 1 s
  process.sleep(1100)
  let #(text, closed) = support.with_draining(fn() { read(socket, 1500) })
  close(socket)
  assert text == <<>>
  assert closed
  // and one that has not hibernated yet
  let socket = open(port)
  let #(_, _) = get(socket, 100)
  let #(_, closed) = support.with_draining(fn() { read(socket, 1500) })
  close(socket)
  assert closed
}

/// Over its connection cap, the listener closes new connections at once,
/// and serves again once others are closed.
pub fn connections_over_the_cap_are_closed_test() {
  let port = start_capped(echo_handler, 2)
  let first = open(port)
  let second = open(port)
  assert string.starts_with(get(first, 100).0, "HTTP/1.1 200 OK\r\n")
  assert string.starts_with(get(second, 100).0, "HTTP/1.1 200 OK\r\n")
  let third = open(port)
  assert get(third, 500) == #("", True)
  close(third)
  close(first)
  process.sleep(100)
  let fourth = open(port)
  assert string.starts_with(get(fourth, 100).0, "HTTP/1.1 200 OK\r\n")
  close(second)
  close(fourth)
}

/// A hibernated connection sleeps until its idle timeout or a message: it
/// does not wake up to check whether the node drains (the listener tells
/// it), which would cost 50 000 wake-ups a second for 50 000 connections.
pub fn idle_connections_stay_hibernated_test() {
  let socket = open(start_with_idle_timeout(10_000))
  let #(text, _) = get(socket, 100)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  // hibernated after 1 s
  process.sleep(1100)
  let pid = connection_process(socket)
  assert hibernated(pid)
  let before = reductions(pid)
  process.sleep(2000)
  assert hibernated(pid)
  // a wake-up costs a dozen reductions; reading them may count one
  assert reductions(pid) - before < 4
  close(socket)
}

/// A request already received when the drain wakes an idle connection up
/// is answered, not dropped (the handler closes the connection after it).
pub fn requests_received_before_draining_are_answered_test() {
  let socket = open(start_with_idle_timeout(10_000))
  let #(text, _) = get(socket, 100)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  process.sleep(1100)
  let pid = connection_process(socket)
  // the `drain` lands in its mailbox ahead of the request
  suspend(pid)
  let #(text, _) =
    support.with_draining(fn() {
      support.wait_until(fn() { queued(pid) == 1 }, 1000)
      send(socket, <<"GET /next HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
      support.wait_until(fn() { queued(pid) == 2 }, 1000)
      resume(pid)
      read(socket, 1000)
    })
  close(socket)
  let assert Ok(text) = bit_array.to_string(text)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\nx-path: /next\r\n")
}
