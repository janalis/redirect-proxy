import gleam/http
import redirect_proxy/metrics_endpoint
import wisp/simulate

/// Without a token, the metrics are only served on the loopback interface:
/// a listener on other addresses answers 404 rather than serve them to
/// anyone who can reach it.
pub fn metrics_need_a_token_beyond_loopback_test() {
  let req = simulate.request(http.Get, "/metrics")
  assert metrics_endpoint.respond_on(req, "", "127.0.0.1").status == 200
  assert metrics_endpoint.respond_on(req, "", "::1").status == 200
  assert metrics_endpoint.respond_on(req, "", "0.0.0.0").status == 404
  assert metrics_endpoint.respond_on(req, "", "10.1.2.3").status == 404
  let token = "a-metrics-token-of-some-length"
  assert metrics_endpoint.respond_on(req, token, "0.0.0.0").status == 401
  let authorized = simulate.header(req, "authorization", "Bearer " <> token)
  assert metrics_endpoint.respond_on(authorized, token, "0.0.0.0").status == 200
}
