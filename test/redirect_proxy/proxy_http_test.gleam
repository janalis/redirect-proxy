//// The HTTP/1.1 server of the redirect listener, at the protocol level.

import gleam/bit_array
import gleam/bytes_tree
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{Response}
import gleam/int
import gleam/list
import gleam/option
import gleam/string
import redirect_proxy/proxy/http as proxy_http

@external(erlang, "test_net_ffi", "session")
fn session(port: Int, chunks: List(BitArray), wait_ms: Int) -> #(BitArray, Bool)

/// Answers 200 with what it received in headers; `/crash` crashes.
fn echo_handler(req: Request(proxy_http.Peer)) {
  case req.path {
    "/crash" -> panic as "handler crash (expected by the test)"
    _ -> Nil
  }
  Response(
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
  )
}

fn start() -> Int {
  let assert Ok(started) =
    proxy_http.start(
      "127.0.0.1",
      0,
      echo_handler,
      proxy_http.Options(idle_timeout_ms: 300, max_head_bytes: 1024, peer: True),
    )
  started.data
}

fn exchange(chunks: List(String)) -> #(String, Bool) {
  let #(received, closed) =
    session(start(), list.map(chunks, bit_array.from_string), 1000)
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
}

pub fn idle_connections_are_closed_test() {
  let #(text, closed) = exchange([])
  assert text == ""
  assert closed
  // an incomplete head too
  let #(text, closed) = exchange(["GET / HTTP/1.1\r\nhost: a\r\n"])
  assert text == ""
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
  rejected("GET http://a/ HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  rejected("OPTIONS * HTTP/1.1\r\nhost: a\r\n\r\n", "400")
  // no control characters (or folded lines) in header values
  rejected("GET / HTTP/1.1\r\nhost: a\r\nx: a\r\n b\r\n\r\n", "400")
  rejected("GET / HTTP/1.1\r\nhost: a\u{1}\r\n\r\n", "400")
  rejected("HTTP/1.1 200 OK\r\n\r\n", "400")
  rejected("GET / HTTP/2.0\r\nhost: a\r\n\r\n", "505")
  // longer than max_head_bytes (1024)
  rejected("GET /" <> string.repeat("a", 1100), "414")
  rejected(
    "GET / HTTP/1.1\r\nhost: a\r\nx: " <> string.repeat("a", 1100),
    "431",
  )
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
