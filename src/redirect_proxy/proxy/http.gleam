//// The HTTP/1.1 server of the redirect listener (`redirect_proxy_http.erl`):
//// a minimal server for small requests and small responses, without the
//// per-request costs of a general purpose one.

import gleam/bytes_tree.{type BytesTree}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/otp/actor
import gleam/otp/supervision.{type ChildSpecification}
import gleam/result
import mist

/// The body of a request: the client address, when it was asked for
/// (`Options.peer`).
pub type Peer =
  Result(mist.IpAddress, Nil)

pub type Handler =
  fn(Request(Peer)) -> Response(BytesTree)

pub type Options {
  Options(
    /// How long a connection may stay idle, or take to send a request head.
    idle_timeout_ms: Int,
    /// Longest request head (request line and headers): longer requests get
    /// 414 (request line) or 431 (headers).
    max_head_bytes: Int,
    /// Whether requests carry the client address (the access log needs it).
    peer: Bool,
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
