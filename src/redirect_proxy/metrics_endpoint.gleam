//// `GET /metrics`, on the admin listener (or the API's when the admin is
//// disabled), and `server.metrics_path` on the redirect listener: public
//// unless `admin.metrics_token` is set (always, on the redirect listener),
//// then it needs
//// `Authorization: Bearer <token>` (Prometheus `authorization` /
//// `bearer_token_file`).

import gleam/http/request
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/metrics
import wisp.{type Request, type Response}

pub fn respond(req: Request, token: String) -> Response {
  case authorized(req, token) {
    True ->
      wisp.response(200)
      |> wisp.set_header("content-type", "text/plain; version=0.0.4")
      |> wisp.set_header("cache-control", "no-store")
      |> wisp.string_body(metrics.render_prometheus())
    False ->
      wisp.response(401)
      |> wisp.set_header("www-authenticate", "Bearer realm=\"metrics\"")
      |> wisp.set_header("cache-control", "no-store")
      |> wisp.string_body("Authentication required")
  }
}

/// True when `token` is "" or the request carries it as a bearer token.
pub fn authorized(req: request.Request(body), token: String) -> Bool {
  case token {
    "" -> True
    _ ->
      case request.get_header(req, "authorization") {
        Ok(value) ->
          case string.split_once(string.trim(value), " ") {
            Ok(#(scheme, given)) ->
              string.lowercase(scheme) == "bearer"
              && ffi.secure_compare(<<string.trim(given):utf8>>, <<token:utf8>>)
            Error(Nil) -> False
          }
        Error(Nil) -> False
      }
  }
}
