//// `/healthz` and `/readyz`, answered alike by the admin listener and the
//// API's own listener.

import redirect_proxy/ffi
import wisp.{type Response}

/// `/healthz`: the process is up.
pub fn live() -> Response {
  plain(200, "ok")
}

/// `/readyz`: 503 while draining before a stop, so that load balancers move
/// away.
pub fn ready() -> Response {
  case ffi.draining() {
    True -> plain(503, "draining")
    False -> plain(200, "ready")
  }
}

fn plain(status: Int, body: String) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "text/plain; charset=utf-8")
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.string_body(body)
}
