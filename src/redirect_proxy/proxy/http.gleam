//// The HTTP/1.1 server of the redirect listener (`redirect_proxy_http.erl`):
//// a minimal server for small requests and small responses, without the
//// per-request costs of a general purpose one. With an upstream it also
//// forwards the requests the handler does not answer (a reverse proxy).

import gleam/bytes_tree.{type BytesTree}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/option.{type Option}
import gleam/otp/actor
import gleam/otp/supervision.{type ChildSpecification}
import gleam/result
import mist

/// The body of a request: the client address, when it was asked for
/// (`Options.peer`).
pub type Peer =
  Result(mist.IpAddress, Nil)

/// What the handler does with a request.
pub type Outcome {
  /// The server sends this response.
  Answer(Response(BytesTree))
  /// The server forwards the request to the upstream (`Options.upstream`)
  /// and relays its response. `headers` replace the client's headers of
  /// the same names, and the client's headers named in `drop` (lower case)
  /// are not forwarded; with `close` the client connection is closed after
  /// the response (draining). `done` is called once the exchange is over,
  /// from the connection process.
  Forward(
    close: Bool,
    headers: List(#(String, String)),
    drop: List(String),
    done: fn(Forwarded) -> Nil,
  )
}

/// How a forwarded request went: the status sent to the client (the
/// upstream's, or the server's 400 / 408 / 502 / 504; 499 when the client
/// went away before its request was complete), the bytes of the response
/// body sent, and what failed on the upstream side.
pub type Forwarded {
  Forwarded(status: Int, bytes: Int, error: Option(UpstreamError))
}

pub type UpstreamError {
  /// No connection (refused, unresolvable, TLS handshake failed): 502.
  Unreachable
  /// No response head, or no progress, within `Upstream.timeout_ms`: 504
  /// (or a truncated response once its head was relayed).
  TimedOut
  /// The connection closed before a complete response, or the response was
  /// not valid HTTP/1.1: 502 (or a truncated response).
  InvalidResponse
}

pub type Handler =
  fn(Request(Peer)) -> Outcome

/// The website requests are forwarded to.
pub type Upstream {
  Upstream(
    tls: Bool,
    host: String,
    port: Int,
    /// The wait for a response head, and the idle timeout of a read or a
    /// write while a request is forwarded (and of upgraded connections).
    timeout_ms: Int,
    /// Check the certificate of an https upstream against the system CAs.
    tls_verify: Bool,
  )
}

pub type Options {
  Options(
    /// How long a connection may stay idle, or take to send a request head.
    idle_timeout_ms: Int,
    /// Longest request head (request line and headers): longer requests get
    /// 414 (request line) or 431 (headers).
    max_head_bytes: Int,
    /// Whether requests carry the client address (the access log and
    /// forwarded requests need it).
    peer: Bool,
    upstream: Option(Upstream),
  )
}

/// A supervised listener; `on_start` gets the bound port.
pub fn supervised(
  handler: Handler,
  address: String,
  port: Int,
  options: Options,
  on_start: fn(Int) -> Nil,
) -> ChildSpecification(Int) {
  supervision.worker(fn() {
    start(address, port, handler, options)
    |> result.map(fn(started) {
      on_start(started.data)
      started
    })
  })
}

@external(erlang, "redirect_proxy_http", "start")
pub fn start(
  address: String,
  port: Int,
  handler: Handler,
  options: Options,
) -> Result(actor.Started(Int), actor.StartError)
