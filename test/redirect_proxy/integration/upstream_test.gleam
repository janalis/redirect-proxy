//// End-to-end tests of `server.upstream`: the redirect listener in front
//// of a website (test/test_upstream_ffi.erl).

import gleam/bit_array
import gleam/http
import gleam/int
import gleam/list
import gleam/string
import integration_support.{
  access_lines, boot, get, location, raw_exchange, send,
}
import redirect_proxy/config
import redirect_proxy/metrics

type Counter

@external(erlang, "test_upstream_ffi", "start")
fn start_upstream() -> #(Int, Counter)

@external(erlang, "test_upstream_ffi", "connections")
fn connections(counter: Counter) -> Int

@external(erlang, "test_upstream_ffi", "closed_port")
fn closed_port() -> Int

fn boot_with(port: Int, trusted: List(String)) {
  let d = config.default()
  boot(
    config.Config(
      ..d,
      server: config.ServerConfig(
        ..d.server,
        upstream: "http://127.0.0.1:" <> int.to_string(port),
        upstream_timeout: 1,
        health_path: "/_health",
      ),
      access_log: config.AccessLogConfig(
        ..d.access_log,
        trusted_proxies: trusted,
      ),
    ),
  )
}

pub fn rules_answer_and_the_rest_is_forwarded_test() {
  let #(port, counter) = start_upstream()
  let env = boot_with(port, [])
  let requests = metrics.get(metrics.UpstreamRequests)

  // rules, and the health path, are answered here
  let resp = get(env.redirect <> "/old", [])
  assert resp.status == 301
  assert location(resp) == "https://example.com/new"
  assert get(env.redirect <> "/_health", []).body == "ok"
  assert connections(counter) == 0

  // anything else goes to the website
  let resp =
    get(env.redirect <> "/page?x=1", [
      #("host", "www.site.test"),
      #("x-forwarded-for", "6.6.6.6"),
      #("x-forwarded-proto", "https"),
    ])
  assert resp.status == 200
  assert string.starts_with(resp.body, "GET /page?x=1\n")
  assert string.contains(resp.body, "\nhost: www.site.test\n")
  // the peer is not a trusted proxy: its x-forwarded-* are replaced
  assert string.contains(resp.body, "\nx-forwarded-for: 127.0.0.1\n")
  assert string.contains(resp.body, "\nx-forwarded-proto: http\n")
  assert string.contains(resp.body, "\nx-forwarded-host: www.site.test\n")
  assert !string.contains(resp.body, "6.6.6.6")

  // whatever the method
  let resp = send(http.Options, env.redirect <> "/api", [], "")
  assert string.starts_with(resp.body, "OPTIONS /api\n")
  let assert Ok(#(_, redirect_port)) =
    string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(redirect_port) = int.parse(redirect_port)
  let assert Ok(received) =
    raw_exchange(redirect_port, [
      <<"PURGE /cache HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n":utf8>>,
    ])
    |> bit_array.to_string
  assert string.contains(received, "\r\n\r\nPURGE /cache\n")
  let resp = send(http.Post, env.redirect <> "/old/form", [], "a=1")
  assert string.contains(resp.body, "framing=length\nbody=a=1")

  assert metrics.get(metrics.UpstreamRequests) - requests == 4
  // logged with the upstream's status and bytes, without a rule id
  let lines = access_lines(env.dir, 7)
  let assert Ok(line) =
    list.find(lines, fn(l) { string.contains(l, "\"GET /page HTTP/1.1\" 200 ") })
  assert !string.contains(line, "\" 200 0 ")
}

pub fn trusted_proxies_keep_their_forwarded_headers_test() {
  let #(port, _) = start_upstream()
  let env = boot_with(port, ["127.0.0.1/32"])
  let resp =
    get(env.redirect <> "/page", [
      #("host", "internal:8080"),
      #("x-forwarded-for", "203.0.113.7"),
      #("x-forwarded-proto", "https"),
      #("x-forwarded-host", "www.site.test"),
    ])
  assert string.contains(
    resp.body,
    "\nx-forwarded-for: 203.0.113.7, 127.0.0.1\n",
  )
  assert string.contains(resp.body, "\nx-forwarded-proto: https\n")
  assert string.contains(resp.body, "\nx-forwarded-host: www.site.test\n")
  assert string.contains(resp.body, "\nhost: internal:8080\n")
}

pub fn upstream_failures_test() {
  let env = boot_with(closed_port(), [])
  let unreachable = metrics.get(metrics.UpstreamUnreachable)
  let resp = get(env.redirect <> "/page", [])
  assert resp.status == 502
  assert resp.body == ""
  assert metrics.get(metrics.UpstreamUnreachable) - unreachable == 1
  // rules still work
  assert get(env.redirect <> "/old", []).status == 301

  let #(port, _) = start_upstream()
  let env = boot_with(port, [])
  let timeouts = metrics.get(metrics.UpstreamTimeouts)
  assert get(env.redirect <> "/slow", []).status == 504
  assert metrics.get(metrics.UpstreamTimeouts) - timeouts == 1
}
