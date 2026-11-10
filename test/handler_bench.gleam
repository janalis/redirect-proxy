//// Per-request CPU of the redirect listener, in-process: the head parse and
//// the handler (lookup, metrics, response), best-of-N ns and reductions,
//// with the rules of `scripts/bench.sh` (`make bench-handler`).

import gleam/bit_array
import gleam/http/request.{type Request}
import gleam/int
import gleam/io
import gleam/list
import gleam/option
import mist
import redirect_proxy/access_log
import redirect_proxy/config
import redirect_proxy/listener
import redirect_proxy/matcher
import redirect_proxy/proxy/http as proxy_http
import redirect_proxy/proxy/server
import redirect_proxy/rule.{Exact, Prefix, Regex}
import redirect_proxy/snapshot

@external(erlang, "handler_bench_ffi", "best_ns")
fn best_ns(f: fn() -> a, n: Int, rounds: Int) -> Int

@external(erlang, "handler_bench_ffi", "reductions")
fn reductions(f: fn() -> a, n: Int) -> Int

@external(erlang, "handler_bench_ffi", "profile")
fn profile(f: fn() -> a) -> Nil

@external(erlang, "handler_bench_ffi", "start_access_log")
fn start_access_log() -> Nil

@external(erlang, "handler_bench_ffi", "parse")
fn parse(head: BitArray) -> Request(proxy_http.Peer)

fn new_rule(id, kind, source, target, status) {
  rule.Rule(
    ..rule.blank(),
    id: "rule-" <> int.to_string(id),
    host: "*",
    kind:,
    source:,
    target:,
    status:,
  )
}

fn rules() {
  let n = int.to_string
  list.flatten([
    int.range(0, 10_000, [], fn(acc, i) {
      [
        new_rule(
          i,
          Exact,
          "/exact/" <> n(i),
          "https://new.example.com/e/" <> n(i),
          301,
        ),
        ..acc
      ]
    }),
    int.range(0, 1000, [], fn(acc, i) {
      [
        new_rule(
          20_000 + i,
          Prefix,
          "/prefix/" <> n(i) <> "/",
          "https://new.example.com/p/" <> n(i) <> "/$1",
          302,
        ),
        ..acc
      ]
    }),
    int.range(0, 500, [], fn(acc, i) {
      [
        new_rule(
          30_000 + i,
          Regex,
          "^/regex/" <> n(i) <> "/(\\d+)$",
          "https://new.example.com/r/" <> n(i) <> "/$1",
          308,
        ),
        ..acc
      ]
    }),
  ])
}

fn head(path: String) -> BitArray {
  head_with(path, "")
}

fn head_with(path: String, extra: String) -> BitArray {
  bit_array.from_string(
    "GET "
    <> path
    <> " HTTP/1.1\r\nhost: server:8080\r\nuser-agent: oha/1.16.0\r\naccept: */*\r\n"
    <> extra
    <> "\r\n",
  )
}

/// The handler with the redirect listener's access log on (the default
/// format; the logger discards the lines, no handler is installed), with
/// `trusted` as both the access log's and the handler's trusted proxies.
fn logged_handler(trusted: List(String)) -> proxy_http.Handler {
  let d = config.default()
  let assert Ok(settings) =
    access_log.settings(
      config.AccessLogConfig(..d.access_log, trusted_proxies: trusted),
      listener.RedirectListener,
    )
  server.handler(d.server, "", option.Some(settings), trusted)
}

/// An exact hit with the access log on, from `peer`, with the `trusted`
/// proxies and `extra` header lines.
fn logged(
  name: String,
  peer: mist.IpAddress,
  trusted: List(String),
  extra: String,
) -> Nil {
  let handler = logged_handler(trusted)
  let raw = head_with("/exact/9999", extra)
  let with_peer = fn(req: Request(proxy_http.Peer)) {
    request.Request(..req, body: Ok(peer))
  }
  let req = with_peer(parse(raw))
  let h = best_ns(fn() { handler(req) }, 50_000, 15)
  let r = reductions(fn() { handler(with_peer(parse(raw))) }, 50_000)
  case name {
    "logged-forwarded" -> profile(fn() { handler(req) })
    _ -> Nil
  }
  io.println(
    name
    <> ": handler "
    <> int.to_string(h)
    <> " ns, "
    <> int.to_string(r)
    <> " reductions",
  )
}

pub fn main() -> Nil {
  snapshot.publish(matcher.build(rules()))
  let handler = server.handler(config.default().server, "", option.None, [])
  [
    #("exact", "/exact/9999"),
    #("prefix", "/prefix/999/some/page"),
    #("regex", "/regex/499/42"),
    #("miss", "/nothing/here"),
  ]
  |> list.each(fn(s) {
    let #(name, path) = s
    let raw = head(path)
    let req = parse(raw)
    let p = best_ns(fn() { parse(raw) }, 50_000, 15)
    let h = best_ns(fn() { handler(req) }, 50_000, 15)
    let both = fn() { handler(parse(raw)) }
    let r = reductions(both, 50_000)
    case name {
      "exact" -> profile(fn() { handler(req) })
      _ -> Nil
    }
    io.println(
      name
      <> ": parse "
      <> int.to_string(p)
      <> " ns, handler "
      <> int.to_string(h)
      <> " ns, "
      <> int.to_string(r)
      <> " reductions",
    )
  })
  start_access_log()
  let proxies = ["10.0.0.0/8", "192.168.0.0/16", "fd00::/8", "::1/128"]
  // the access log on, default settings: no trusted proxy
  logged("logged", mist.IpV4(192, 0, 2, 1), [], "")
  // a peer that is not one of the trusted proxies
  logged("logged-untrusted", mist.IpV4(192, 0, 2, 1), proxies, "")
  // a trusted proxy forwarding the client address (two hops)
  logged(
    "logged-forwarded",
    mist.IpV4(10, 0, 0, 1),
    proxies,
    "x-forwarded-for: 203.0.113.9, 10.0.0.2\r\n",
  )
  // an IPv6 trusted proxy forwarding an IPv4-mapped client address
  logged(
    "logged-forwarded-v6",
    mist.IpV6(0, 0, 0, 0, 0, 0, 0, 1),
    proxies,
    "x-forwarded-for: ::ffff:203.0.113.9\r\n",
  )
}
