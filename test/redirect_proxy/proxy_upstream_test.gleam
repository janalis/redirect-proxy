//// Forwarding to an upstream (`server.upstream`), at the protocol level:
//// the HTTP/1.1 server of the redirect listener with a handler that leaves
//// every request but `/answered` to a test upstream
//// (test/test_upstream_ffi.erl).

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process
import gleam/http/request.{type Request}
import gleam/http/response.{Response}
import gleam/list
import gleam/option
import gleam/string
import redirect_proxy/config
import redirect_proxy/proxy/http as proxy_http
import redirect_proxy/proxy/server

@external(erlang, "test_net_ffi", "session")
fn session(port: Int, chunks: List(BitArray), wait_ms: Int) -> #(BitArray, Bool)

@external(erlang, "test_net_ffi", "paced_session")
fn paced_session(
  port: Int,
  chunks: List(BitArray),
  gap_ms: Int,
  wait_ms: Int,
) -> #(BitArray, Bool)

@external(erlang, "test_net_ffi", "reset_after")
fn reset_after(port: Int, data: BitArray, wait_ms: Int) -> Nil

@external(erlang, "test_net_ffi", "half_closed")
fn half_closed(port: Int, data: BitArray, wait_ms: Int) -> #(BitArray, Bool)

type Socket

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

@external(erlang, "test_net_ffi", "hibernated")
fn hibernated(pid: process.Pid) -> Bool

type Counter

@external(erlang, "test_upstream_ffi", "start")
fn start_upstream() -> #(Int, Counter)

@external(erlang, "test_upstream_ffi", "start_tls")
fn start_tls_upstream() -> #(Int, Counter)

@external(erlang, "test_upstream_ffi", "connections")
fn connections(counter: Counter) -> Int

@external(erlang, "test_upstream_ffi", "closed_port")
fn closed_port() -> Int

type Proxy {
  Proxy(
    port: Int,
    upstream: Counter,
    done: process.Subject(proxy_http.Forwarded),
  )
}

fn upstream(port: Int) -> proxy_http.Upstream {
  proxy_http.Upstream(
    tls: False,
    host: "127.0.0.1",
    port:,
    timeout_ms: 500,
    tls_verify: True,
    max_body_bytes: 0,
  )
}

fn handler(
  done: process.Subject(proxy_http.Forwarded),
) -> fn(Request(proxy_http.Peer)) -> proxy_http.Outcome {
  fn(req: Request(proxy_http.Peer)) {
    case req.path {
      "/answered" ->
        proxy_http.Answer(Response(200, [], bytes_tree.from_string("local")))
      path ->
        proxy_http.Forward(
          close: path == "/drain",
          headers: [
            #("x-forwarded-for", "192.0.2.1"),
            #("x-forwarded-proto", "http"),
          ],
          drop: ["forwarded", "x-real-ip"],
          done: process.send(done, _),
        )
    }
  }
}

fn start_with(up: proxy_http.Upstream, counter: Counter) -> Proxy {
  start_idle(up, counter, 300)
}

fn start_idle(
  up: proxy_http.Upstream,
  counter: Counter,
  idle_ms: Int,
) -> Proxy {
  let done = process.new_subject()
  let assert Ok(started) =
    proxy_http.start(
      "127.0.0.1",
      0,
      handler(done),
      proxy_http.Options(
        idle_timeout_ms: idle_ms,
        max_head_bytes: 4096,
        peer: True,
        upstream: option.Some(up),
      ),
    )
  Proxy(port: started.data, upstream: counter, done:)
}

fn start() -> Proxy {
  let #(port, counter) = start_upstream()
  start_with(upstream(port), counter)
}

fn exchange(proxy: Proxy, chunks: List(String)) -> #(String, Bool) {
  let #(received, closed) =
    session(proxy.port, list.map(chunks, bit_array.from_string), 800)
  let assert Ok(text) = bit_array.to_string(received)
  #(text, closed)
}

/// Like exchange/2, with 200 ms between the chunks: for an upstream that
/// does something 20 ms after a response (/idle-close, /linger), even one
/// that needs a TLS handshake first.
fn paced_exchange(proxy: Proxy, chunks: List(String)) -> #(String, Bool) {
  let #(received, closed) =
    paced_session(proxy.port, list.map(chunks, bit_array.from_string), 200, 800)
  let assert Ok(text) = bit_array.to_string(received)
  #(text, closed)
}

fn forwarded(proxy: Proxy) -> proxy_http.Forwarded {
  let assert Ok(f) = process.receive(proxy.done, 1000)
  f
}

fn count(text: String, part: String) -> Int {
  list.length(string.split(text, part)) - 1
}

pub fn get_is_forwarded_with_its_query_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "GET /a/b?x=1&y=%20 HTTP/1.1\r\nHost: site.test\r\nAccept: */*\r\nconnection: close\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\r\n\r\nGET /a/b?x=1&y=%20\nconn=1\n")
  // the client's host, the handler's x-forwarded-* headers
  assert string.contains(text, "\nhost: site.test\naccept: */*\n")
  assert string.contains(text, "\nx-forwarded-for: 192.0.2.1\n")
  assert string.contains(text, "\nx-forwarded-proto: http\n")
  assert string.contains(text, "\nframing=none\nbody=")
  assert string.contains(text, "\r\ncontent-type: text/plain\r\n")
  assert count(text, "\r\ndate: ") == 1
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert closed
  let f = forwarded(proxy)
  assert f.status == 200
  assert f.error == option.None
  let assert Ok(#(_, body)) = string.split_once(text, "\r\n\r\n")
  assert f.bytes == string.byte_size(body)
}

pub fn answered_requests_are_not_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /answered HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n",
    ])
  assert string.ends_with(text, "\r\n\r\nlocal")
  assert connections(proxy.upstream) == 0
}

pub fn content_length_bodies_are_forwarded_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "POST /form HTTP/1.1\r\nhost: a\r\ncontent-length: 11\r\n\r\nhello",
      " world",
      "GET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "POST /form\n")
  assert string.contains(text, "\ncontent-length: 11\n")
  assert string.contains(text, "framing=length\nbody=hello world")
  // the connection stays open: the body was read
  assert string.contains(text, "GET /next\nconn=1\n")
  assert !string.contains(text, "connection: close")
  assert closed
}

pub fn chunked_bodies_are_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "POST /up HTTP/1.1\r\nhost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhel",
      "lo\r\n6\r\n world\r\n0\r\nx-trailer: 1\r\n\r\nGET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "\ntransfer-encoding: chunked\n")
  assert string.contains(text, "framing=chunked\nbody=hello world")
  assert string.contains(text, "GET /next\nconn=1\n")
}

pub fn bodies_over_the_limit_get_413_test() {
  let #(port, counter) = start_upstream()
  let proxy =
    start_with(
      proxy_http.Upstream(..upstream(port), max_body_bytes: 10),
      counter,
    )
  // a length over the limit: refused before anything is sent upstream
  let #(text, closed) =
    exchange(proxy, [
      "POST /form HTTP/1.1\r\nhost: a\r\ncontent-length: 11\r\n\r\nhello world",
    ])
  assert string.starts_with(text, "HTTP/1.1 413 ")
  assert closed
  assert connections(counter) == 0
  let f = forwarded(proxy)
  assert f.status == 413
  // a chunked body, once it has grown over the limit
  let #(text, closed) =
    exchange(proxy, [
      "POST /up HTTP/1.1\r\nhost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 413 ")
  assert closed
  // up to the limit
  let #(text, _) =
    exchange(proxy, [
      "POST /up HTTP/1.1\r\nhost: a\r\nTransfer-Encoding: chunked\r\nconnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
    ])
  assert string.contains(text, "framing=chunked\nbody=helloworld")
}

/// A body must keep coming: the idle timeout (300 ms here) between two
/// packets, not the upstream's.
pub fn stalled_bodies_get_408_test() {
  let #(port, counter) = start_upstream()
  let proxy =
    start_with(proxy_http.Upstream(..upstream(port), timeout_ms: 5000), counter)
  let #(text, closed) =
    exchange(proxy, [
      "POST /form HTTP/1.1\r\nhost: a\r\ncontent-length: 11\r\n\r\nhello",
    ])
  assert string.starts_with(text, "HTTP/1.1 408 ")
  assert closed
}

pub fn upstream_connections_are_reused_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /1 HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /2 HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /answered HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /3 HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert count(text, "\nconn=1\n") == 3
  assert string.contains(text, "local")
  assert connections(proxy.upstream) == 1
}

pub fn pipelined_requests_are_answered_in_order_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /1 HTTP/1.1\r\nhost: a\r\n\r\nGET /answered HTTP/1.1\r\nhost: a\r\n\r\nPOST /2 HTTP/1.1\r\nhost: a\r\ncontent-length: 2\r\n\r\nhiGET /3 HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  let assert [_, first, second, third, fourth] =
    string.split(text, "HTTP/1.1 200 OK")
  assert string.contains(first, "GET /1\n")
  assert string.contains(second, "local")
  assert string.contains(third, "POST /2\n")
  assert string.contains(third, "body=hi")
  assert string.contains(fourth, "GET /3\n")
  assert connections(proxy.upstream) == 1
}

pub fn closed_upstream_connections_are_replaced_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /once HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /again HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "GET /once\nconn=1\n")
  assert string.contains(text, "GET /again\nconn=2\n")
}

/// A kept-alive upstream connection the upstream closes while it is idle:
/// the next request, even one that could not be sent again, goes on a new
/// one.
pub fn idle_upstream_connections_closed_by_the_upstream_are_replaced_test() {
  let proxy = start()
  let #(text, _) =
    paced_exchange(proxy, [
      "GET /idle-close HTTP/1.1\r\nhost: a\r\n\r\n",
      "POST /after HTTP/1.1\r\nhost: a\r\ncontent-length: 2\r\n\r\nhi",
      "GET /again HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "GET /idle-close\nconn=1\n")
  assert string.contains(text, "POST /after\nconn=2\n")
  assert string.contains(text, "body=hi")
  assert string.contains(text, "GET /again\nconn=2\n")
  assert count(text, "HTTP/1.1 200 OK\r\n") == 3
  assert connections(proxy.upstream) == 2
}

/// The message of a kept upstream connection the upstream closes does not
/// keep the idle client connection from hibernating: before it hibernates
/// (closed after 20 ms), or once it has (after 1.3 s).
pub fn idle_upstream_closes_do_not_keep_connections_awake_test() {
  let #(port, counter) = start_upstream()
  let proxy = start_idle(upstream(port), counter, 10_000)
  let socket = open(proxy.port)
  send(socket, <<"GET /idle-close HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
  let #(first, _) = read(socket, 100)
  let assert Ok(first) = bit_array.to_string(first)
  assert string.contains(first, "GET /idle-close\nconn=1\n")
  // hibernated 1 s after the close
  process.sleep(1300)
  let pid = connection_process(socket)
  assert hibernated(pid)
  // the next request goes on a new upstream connection
  send(socket, <<"GET /idle-close-late HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
  let #(second, _) = read(socket, 100)
  let assert Ok(second) = bit_array.to_string(second)
  assert string.contains(second, "GET /idle-close-late\nconn=2\n")
  // hibernated after 1 s, then woken by the close at 1.3 s: hibernated again
  process.sleep(1600)
  assert hibernated(pid)
  send(socket, <<"GET /last HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
  let #(third, _) = read(socket, 100)
  let assert Ok(third) = bit_array.to_string(third)
  assert string.contains(third, "GET /last\nconn=3\n")
  close(socket)
  assert connections(counter) == 3
}

/// Bytes an idle upstream connection sends unasked are not taken for the
/// response to the next request: the connection is not reused.
pub fn unsolicited_upstream_bytes_are_not_relayed_test() {
  let proxy = start()
  let #(text, _) =
    paced_exchange(proxy, [
      "GET /linger HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert !string.contains(text, "bogus")
  assert string.contains(text, "GET /linger\nconn=1\n")
  assert string.contains(text, "GET /next\nconn=2\n")
  assert count(text, "HTTP/1.1 200 OK\r\n") == 2
}

pub fn chunked_responses_are_relayed_test() {
  let proxy = start()
  let #(text, _) = exchange(proxy, ["GET /chunked HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.contains(text, "\r\ntransfer-encoding: chunked\r\n")
  // the chunks again, without extensions or trailers
  assert string.ends_with(
    text,
    "\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
  )
  assert forwarded(proxy).bytes == 11
  // decoded for an HTTP/1.0 client, then the connection closed
  let #(text, closed) =
    exchange(proxy, [
      "GET /chunked HTTP/1.0\r\nconnection: keep-alive\r\n\r\n",
    ])
  assert !string.contains(text, "transfer-encoding")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert string.ends_with(text, "\r\n\r\nhello world")
  assert closed
}

/// The head and the bytes read with it are sent together, but before the
/// rest of the body is waited for.
pub fn responses_are_relayed_as_they_come_test() {
  let proxy = start()
  let socket = open(proxy.port)
  send(socket, <<"GET /stream HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>)
  let #(first, _) = read(socket, 120)
  let assert Ok(first) = bit_array.to_string(first)
  assert string.starts_with(first, "HTTP/1.1 200 OK\r\n")
  assert string.ends_with(first, "\r\n\r\n5\r\nhello\r\n")
  let #(rest, _) = read(socket, 300)
  close(socket)
  assert rest == <<"6\r\n world\r\n0\r\n\r\n":utf8>>
  assert forwarded(proxy).bytes == 11
}

pub fn close_delimited_responses_close_the_connection_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "GET /close HTTP/1.1\r\nhost: a\r\n\r\nGET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert string.ends_with(text, "\r\n\r\nuntil the end")
  assert closed
}

pub fn head_and_304_responses_have_no_body_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "HEAD /page HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /not-modified HTTP/1.1\r\nhost: a\r\nif-none-match: \"x\"\r\n\r\n",
      "GET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  let assert [_, head, not_modified, next] = string.split(text, "HTTP/1.1 ")
  assert string.contains(head, "\r\ncontent-length: ")
  assert string.ends_with(head, "\r\n\r\n")
  assert string.starts_with(not_modified, "304 Not Modified\r\n")
  assert string.ends_with(not_modified, "\r\n\r\n")
  assert string.contains(next, "GET /next\n")
}

pub fn hop_by_hop_headers_are_not_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /hop HTTP/1.1\r\nhost: a\r\nConnection: X-Private, keep-alive, Content-Length\r\nX-Private: secret\r\nKeep-Alive: 300\r\nTE: trailers\r\nProxy-Connection: keep-alive\r\nUpgrade: h2c\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Host: evil.test\r\nX-Other: kept\r\n\r\n",
      "GET /echo HTTP/1.1\r\nhost: a\r\nConnection: X-Private\r\nX-Private: secret\r\nTE: trailers\r\nX-Forwarded-For: 6.6.6.6\r\nX-Other: kept\r\n\r\n",
    ])
  let assert [_, hop, echoed] = string.split(text, "HTTP/1.1 ")
  // the response's
  assert string.contains(hop, "\r\nX-Kept: yes\r\n")
  assert !string.contains(hop, "X-Secret")
  assert !string.contains(hop, "Keep-Alive")
  assert !string.contains(hop, "Connection")
  // the request's
  assert string.contains(echoed, "\nx-other: kept\n")
  assert !string.contains(echoed, "x-private")
  assert !string.contains(echoed, "connection")
  assert !string.contains(echoed, "\nte: ")
  assert !string.contains(echoed, "6.6.6.6")
  assert string.contains(echoed, "\nx-forwarded-for: 192.0.2.1\n")
}

/// Some servers read `_` in a header name as `-`: the `_` spellings of the
/// framing and hop-by-hop headers would give them a second framing.
pub fn underscore_framing_headers_are_not_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "POST /echo HTTP/1.1\r\nhost: a\r\nContent_Length: 40\r\nTransfer_Encoding: chunked\r\nKeep_Alive: 1\r\nconnection_: x\r\nT_E: x\r\nX_Other: kept\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\nx_other: kept\n")
  assert !string.contains(text, "content_length")
  assert !string.contains(text, "transfer_encoding")
  assert !string.contains(text, "keep_alive")
  assert string.contains(text, "\nconnection_: x\n")
  assert string.contains(text, "\nt_e: x\n")
}

pub fn the_upstream_date_is_kept_test() {
  let proxy = start()
  let #(text, _) = exchange(proxy, ["GET /date HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert count(string.lowercase(text), "\r\ndate: ") == 1
  assert string.contains(text, "\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n")
}

pub fn interim_responses_are_relayed_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, ["GET /early-hints HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.starts_with(
    text,
    "HTTP/1.1 103 Early Hints\r\nlink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\n",
  )
}

/// At most 10 interim responses before the final one.
pub fn endless_interim_responses_are_a_502_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, ["GET /many-hints HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.contains(text, "HTTP/1.1 502 Bad Gateway\r\n")
  assert count(text, "HTTP/1.1 103 ") == 10
  assert !string.contains(text, "200 OK")
}

pub fn expect_continue_is_answered_here_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "PUT /file HTTP/1.1\r\nhost: a\r\nExpect: 100-continue\r\ncontent-length: 5\r\n\r\n",
      "hello",
    ])
  assert string.starts_with(
    text,
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK",
  )
  assert count(text, "100 Continue") == 1
  assert !string.contains(text, "expect")
  assert string.contains(text, "body=hello")
}

pub fn ambiguous_bodies_are_rejected_test() {
  let rejected = fn(head) {
    let proxy = start()
    let #(text, closed) = exchange(proxy, [head <> "\r\n0\r\n\r\n"])
    assert string.starts_with(text, "HTTP/1.1 400 Bad Request\r\n")
    assert string.contains(text, "\r\nconnection: close\r\n")
    assert closed
    assert connections(proxy.upstream) == 0
    assert forwarded(proxy).status == 400
  }
  rejected(
    "POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n",
  )
  rejected("POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5x\r\n")
  rejected("POST / HTTP/1.1\r\nhost: a\r\ncontent-length: -1\r\n")
  rejected(
    "POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\ncontent-length: 6\r\n",
  )
  rejected("POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: gzip\r\n")
  rejected(
    "POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked, chunked\r\n",
  )
  // and invalid chunks
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 400 ")
  assert closed
}

fn assert_failed(text: String, closed: Bool, status: String) {
  assert string.starts_with(text, "HTTP/1.1 " <> status <> " ")
  assert string.contains(text, "\r\ncontent-length: 0\r\n")
  assert string.contains(text, "\r\ncache-control: no-store\r\n")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert closed
}

pub fn an_unreachable_upstream_is_a_502_test() {
  let #(_, counter) = start_upstream()
  let proxy = start_with(upstream(closed_port()), counter)
  let #(text, closed) = exchange(proxy, ["GET / HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "502")
  assert forwarded(proxy)
    == proxy_http.Forwarded(502, 0, option.Some(proxy_http.Unreachable))
}

pub fn a_slow_upstream_is_a_504_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, ["GET /slow HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "504")
  assert forwarded(proxy).error == option.Some(proxy_http.TimedOut)
}

pub fn an_upstream_closing_without_a_response_is_a_502_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, ["GET /abrupt HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "502")
  assert forwarded(proxy).error == option.Some(proxy_http.InvalidResponse)
}

pub fn draining_closes_after_the_response_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "GET /drain HTTP/1.1\r\nhost: a\r\n\r\nGET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert !string.contains(text, "/next")
  assert closed
}

pub fn upgrades_are_tunnelled_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.1\r\nhost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
      "ping",
      "pong",
    ])
  assert string.starts_with(text, "HTTP/1.1 101 Switching Protocols\r\n")
  assert string.contains(text, "\r\nconnection: upgrade\r\n")
  assert string.contains(text, "\r\nupgrade: websocket\r\n")
  assert string.ends_with(text, "\r\n\r\npingpong")
  // without `Connection: upgrade`, an ordinary request
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.1\r\nhost: a\r\nUpgrade: websocket\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(text, "upgrade")
}

/// HTTP/2 over cleartext (`Upgrade: h2c`) is not offered to the upstream:
/// the request is forwarded as an ordinary one.
pub fn h2c_upgrades_are_not_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.1\r\nhost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: H2C\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\nconnection: close\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  let text = string.lowercase(text)
  assert !string.contains(text, "upgrade")
  assert !string.contains(text, "h2c")
  assert !string.contains(text, "http2-settings")
  // among other protocols too
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.1\r\nhost: a\r\nConnection: upgrade\r\nUpgrade: websocket, h2c\r\nconnection: close\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(string.lowercase(text), "upgrade")
}

/// A 101 switching to another protocol than the one asked for is not
/// tunnelled.
pub fn mismatched_101_is_a_502_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "GET /ws-h2c HTTP/1.1\r\nhost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      "ping",
    ])
  assert_failed(text, closed, "502")
  assert forwarded(proxy).error == option.Some(proxy_http.InvalidResponse)
  // the protocol is compared without case
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.1\r\nhost: a\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n",
      "ping",
    ])
  assert string.starts_with(text, "HTTP/1.1 101 Switching Protocols\r\n")
  assert string.ends_with(text, "\r\n\r\nping")
}

pub fn https_upstreams_test() {
  let #(port, counter) = start_tls_upstream()
  // a TLS handshake can take longer than the usual 500 ms on a loaded
  // machine (a timeout would be a 502, not this test's subject)
  let proxy =
    start_with(
      proxy_http.Upstream(
        ..upstream(port),
        tls: True,
        tls_verify: False,
        timeout_ms: 3000,
      ),
      counter,
    )
  let #(text, _) =
    exchange(proxy, [
      "POST /tls HTTP/1.1\r\nhost: a\r\ncontent-length: 2\r\n\r\nhi",
      "GET /again HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "POST /tls\nconn=1\n")
  assert string.contains(text, "body=hi")
  assert string.contains(text, "GET /again\nconn=1\n")
  // closed by the upstream, or sent unasked bytes, while idle: replaced
  let #(text, _) =
    paced_exchange(proxy, [
      "GET /idle-close HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /linger HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /last HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "GET /idle-close\nconn=2\n")
  assert string.contains(text, "GET /linger\nconn=3\n")
  assert string.contains(text, "GET /last\nconn=4\n")
  assert !string.contains(text, "bogus")
  // a self-signed certificate is refused when it is verified
  let proxy =
    start_with(proxy_http.Upstream(..upstream(port), tls: True), counter)
  let #(text, closed) = exchange(proxy, ["GET / HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "502")
  assert forwarded(proxy).error == option.Some(proxy_http.Unreachable)
}

// Review follow-ups

pub fn http_1_0_chunked_requests_are_rejected_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, [
      "POST /up HTTP/1.0\r\nconnection: keep-alive\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\nGET /next HTTP/1.0\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 400 ")
  assert !string.contains(text, "/next")
  assert closed
  assert connections(proxy.upstream) == 0
}

pub fn chunks_are_parsed_strictly_test() {
  let rejected = fn(body) {
    let proxy = start()
    let #(text, closed) =
      exchange(proxy, [
        "POST /up HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n"
        <> body,
      ])
    assert string.starts_with(text, "HTTP/1.1 400 ")
    assert closed
  }
  // bare LF ending the size line, or the chunk data
  rejected("2\nhi\r\n0\r\n\r\n")
  rejected("2\r\nhi\n0\r\n\r\n")
  // a lone CR, or a control character, in an extension
  rejected("2;a=\rb\r\nhi\r\n0\r\n\r\n")
  rejected("2;a\u{1}\r\nhi\r\n0\r\n\r\n")
  rejected("2;a=\"x\u{1}\"\r\nhi\r\n0\r\n\r\n")
  // junk around the size, absurd sizes
  rejected(" 2\r\nhi\r\n0\r\n\r\n")
  rejected("+2\r\nhi\r\n0\r\n\r\n")
  rejected("0x2\r\nhi\r\n0\r\n\r\n")
  rejected("2 x\r\nhi\r\n0\r\n\r\n")
  rejected("1000000000000000\r\nhi\r\n0\r\n\r\n")
  // trailers: CRLF lines without control characters
  rejected("2\r\nhi\r\n0\r\nx: 1\n\r\n")
  rejected("2\r\nhi\r\n0\r\nx: \u{1}\r\n\r\n")
  rejected("2\r\nhi\r\n0\r\n\n")
  // well-formed extensions and trailers are fine
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "POST /up HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n2 ; name = \"q \\\" v\" ; flag\r\nhi\r\n0\r\nx-t: 1\r\n\r\n",
    ])
  assert string.contains(text, "framing=chunked\nbody=hi")
}

pub fn invalid_chunked_responses_are_cut_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, ["GET /bad-chunk HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(text, "zz")
  assert closed
  assert forwarded(proxy).error == option.Some(proxy_http.InvalidResponse)
}

pub fn half_closed_clients_get_their_response_test() {
  let proxy = start()
  let #(received, closed) =
    half_closed(
      proxy.port,
      <<"GET /half HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>,
      1000,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "GET /half\n")
  assert closed
  assert forwarded(proxy).status == 200
}

pub fn unsent_responses_are_logged_as_499_test() {
  // the client resets the connection while a large response is sent
  let proxy = start()
  reset_after(proxy.port, <<"GET /big HTTP/1.1\r\nhost: a\r\n\r\n":utf8>>, 200)
  let f = forwarded(proxy)
  assert f.status == 499
  assert f.error == option.None
  assert f.bytes < 8_000_000
}

pub fn dropped_headers_are_not_forwarded_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /echo HTTP/1.1\r\nhost: a\r\nForwarded: for=6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nX-Forwarded-Port: 443\r\nconnection: close\r\n\r\n",
    ])
  assert !string.contains(text, "6.6.6.6")
  // not dropped by this handler
  assert string.contains(text, "\nx-forwarded-port: 443\n")
}

pub fn connection_cannot_strip_response_framing_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /conn-length HTTP/1.1\r\nhost: a\r\n\r\n",
      "GET /next HTTP/1.1\r\nhost: a\r\n\r\n",
    ])
  assert string.contains(text, "\r\ncontent-length: 2\r\n")
  assert !string.contains(text, "Connection")
  assert string.contains(text, "\r\n\r\nokHTTP/1.1 200 OK\r\n")
  assert string.contains(text, "GET /next\n")
}

pub fn control_characters_in_response_heads_are_a_502_test() {
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, ["GET /bad-reason HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "502")
  let proxy = start()
  let #(text, closed) =
    exchange(proxy, ["GET /ctl-header HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert_failed(text, closed, "502")
  assert forwarded(proxy).error == option.Some(proxy_http.InvalidResponse)
}

pub fn other_transfer_codings_are_kept_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, ["GET /gzip-chunked HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.contains(text, "\r\ntransfer-encoding: gzip, chunked\r\n")
  assert string.ends_with(text, "\r\n\r\n2\r\nzz\r\n0\r\n\r\n")
  // a final coding other than chunked: until the end of the connection
  let #(text, closed) =
    exchange(proxy, ["GET /gzip-close HTTP/1.1\r\nhost: a\r\n\r\n"])
  assert string.contains(text, "\r\ntransfer-encoding: gzip\r\n")
  assert string.contains(text, "\r\nconnection: close\r\n")
  assert string.ends_with(text, "\r\n\r\nzz")
  assert closed
  // an HTTP/1.0 client cannot get them
  let #(text, closed) = exchange(proxy, ["GET /gzip-chunked HTTP/1.0\r\n\r\n"])
  assert_failed(text, closed, "502")
}

pub fn http_1_0_requests_do_not_upgrade_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "GET /ws HTTP/1.0\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n",
    ])
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(text, "upgrade")
}

pub fn content_length_is_sent_once_test() {
  let proxy = start()
  let #(text, _) =
    exchange(proxy, [
      "POST /form HTTP/1.1\r\nhost: a\r\nContent-Length: 2, 2\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
    ])
  assert count(text, "\ncontent-length: 2\n") == 1
  assert !string.contains(text, "2, 2")
  assert string.contains(text, "\ncontent-length: 2\nframing=length\nbody=hi")
  // and an empty body keeps its length
  let #(text, _) =
    exchange(proxy, [
      "POST /form HTTP/1.1\r\nhost: a\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    ])
  assert string.contains(text, "\ncontent-length: 0\nframing=length\nbody=")
}

/// The redirect listener's own handler (`proxy/server`) in front of the
/// test upstream, with these trusted proxies (`access_log`), and the
/// identity headers of `auth.header` with its trusted proxies (`identity`).
fn start_server(trusted: List(String), identity: List(String)) -> Int {
  let #(port, _) = start_upstream()
  let d = config.default().server
  let cfg =
    config.ServerConfig(
      ..d,
      upstream: "http://127.0.0.1:" <> string.inspect(port),
    )
  let assert Ok(started) =
    proxy_http.start(
      "127.0.0.1",
      0,
      server.handler_with_identity(
        cfg,
        "",
        option.None,
        trusted,
        ["X-Forwarded-User", "x-auth-role", ""],
        identity,
      ),
      server.http_options(cfg, option.None, trusted),
    )
  started.data
}

const identity_request =
  "GET /echo HTTP/1.1\r\nhost: a\r\nX-Client-IP: 6.6.6.1\r\nTrue-Client-IP: 6.6.6.2\r\nX_Real_IP: 6.6.6.3\r\nX_Forwarded-For: 6.6.6.4\r\nx-forwarded_proto: https\r\nX-Forwarded-User: alice\r\nX_Auth_Role: admin\r\nX-Other: kept\r\nconnection: close\r\n\r\n"

/// Headers that name the client from untrusted peers: an upstream could
/// take them for the proxy's, so they are dropped, along with their
/// variants spelled with `_` (which some servers read as `-`).
pub fn identity_headers_from_untrusted_peers_are_dropped_test() {
  let #(received, _) =
    session(
      start_server([], ["10.0.0.0/8"]),
      [bit_array.from_string(identity_request)],
      800,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(text, "6.6.6.")
  assert !string.contains(text, "https")
  assert !string.contains(text, "alice")
  assert !string.contains(text, "admin")
  assert string.contains(text, "\nx-other: kept\n")
  assert string.contains(text, "\nx-forwarded-for: 127.0.0.1\n")
  // trusted proxies pass them on, but for the `_` variants of the
  // headers this server sets
  let #(received, _) =
    session(
      start_server(["127.0.0.1/32"], []),
      [bit_array.from_string(identity_request)],
      800,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.contains(text, "\nx-client-ip: 6.6.6.1\n")
  assert string.contains(text, "\ntrue-client-ip: 6.6.6.2\n")
  assert string.contains(text, "\nx_real_ip: 6.6.6.3\n")
  assert string.contains(text, "\nx-forwarded-user: alice\n")
  assert string.contains(text, "\nx_auth_role: admin\n")
  assert !string.contains(text, "6.6.6.4")
  assert !string.contains(text, "https")
}

/// The identity headers of `auth.header` are taken from its own trusted
/// proxies too (an authenticating proxy in front of both), but not the
/// other headers naming the client.
pub fn identity_headers_from_auth_proxies_are_kept_test() {
  let #(received, _) =
    session(
      start_server([], ["10.0.0.0/8", "127.0.0.1/32"]),
      [bit_array.from_string(identity_request)],
      800,
    )
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.contains(text, "\nx-forwarded-user: alice\n")
  assert string.contains(text, "\nx_auth_role: admin\n")
  assert !string.contains(text, "6.6.6.")
  assert !string.contains(text, "https")
}
