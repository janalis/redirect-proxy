//// The public redirect listener. Deliberately minimal: no body reads, no
//// framework, one lock-free snapshot read and a single response, served by
//// a dedicated HTTP/1.1 server (`proxy/http`). With `server.upstream`, the
//// requests no rule answers are left to that server, which forwards them.

import gleam/bytes_tree.{type BytesTree}
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import mist
import redirect_proxy/access_log
import redirect_proxy/config.{type ServerConfig}
import redirect_proxy/ffi
import redirect_proxy/listener
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/metrics_endpoint
import redirect_proxy/proxy/http as proxy_http
import redirect_proxy/rule
import redirect_proxy/snapshot

/// Settings of the listener's HTTP server.
pub fn http_options(
  config: ServerConfig,
  access: Option(access_log.Settings),
  trusted_proxies: List(String),
) -> proxy_http.Options {
  let upstream = case config.parse_upstream(config.upstream) {
    Ok(url) if config.upstream != "" ->
      option.Some(proxy_http.Upstream(
        tls: url.tls,
        host: url.host,
        port: url.port,
        timeout_ms: config.upstream_timeout * 1000,
        tls_verify: config.upstream_tls_verify,
      ))
    _ -> option.None
  }
  proxy_http.Options(
    idle_timeout_ms: 10_000,
    // the query string and the headers do not count in `max_path_bytes`
    max_head_bytes: config.max_path_bytes + 65_536,
    // `X-Forwarded-For`, and `https_redirect` behind trusted proxies, need
    // the client address
    peer: option.is_some(access)
      || option.is_some(upstream)
      || { config.https_redirect && trusted_proxies != [] },
    upstream:,
  )
}

/// What the listener does with a request: answer it (with the id of the
/// matched rule, "" when none), or leave it to the upstream.
type Routed {
  Answered(Response(BytesTree), String)
  Unanswered
}

/// The request handler. With access log settings each request is logged,
/// with the id of the matched rule. With `server.upstream`, the requests no
/// rule answers (whatever their method) are forwarded to it; the
/// `x-forwarded-*` values of the peers in `trusted_proxies` are kept.
///
/// The server closes the connection after an answered request with a body:
/// the body is never read, and on a kept-alive connection its bytes would be
/// parsed as the next request (request smuggling behind a reverse proxy that
/// reuses connections). The body of a forwarded request is forwarded.
pub fn handler(
  config: ServerConfig,
  metrics_token: String,
  access: Option(access_log.Settings),
  trusted_proxies: List(String),
) -> proxy_http.Handler {
  let not_found_body = bytes_tree.from_string(config.not_found_body)
  let permanent_cache =
    "public, max-age=" <> int.to_string(config.cache_max_age)
  let upstream = config.upstream != ""
  fn(req: Request(proxy_http.Peer)) {
    let started = ffi.monotonic_micros()
    let routed = case
      config.metrics_path != "" && req.path == config.metrics_path
    {
      True -> Answered(metrics_response(req, metrics_token), "")
      False ->
        route(
          config,
          upstream,
          trusted_proxies,
          req,
          not_found_body,
          permanent_cache,
        )
    }
    case routed {
      Answered(resp, rule_id) -> {
        // while the node drains before stopping (SIGTERM), connections are
        // closed after each response so that clients reconnect to another
        // instance
        let resp = case ffi.draining() {
          False -> resp
          True -> response.set_header(resp, "connection", "close")
        }
        let finished = ffi.monotonic_micros()
        metrics.observe(listener.RedirectListener, finished - started)
        metrics.response(resp.status)
        case access {
          option.None -> Nil
          option.Some(settings) -> {
            let duration_us = finished - started
            access_log.record(
              settings,
              req,
              req.body,
              resp,
              bytes_tree.byte_size(resp.body),
              rule_id,
              ffi.now_micros() - duration_us,
              duration_us,
            )
          }
        }
        proxy_http.Answer(resp)
      }
      Unanswered -> forward(req, started, access, trusted_proxies)
    }
  }
}

/// Leaves the request to the upstream. Its time is recorded in
/// `redirect_proxy_upstream_duration_seconds`, not in the redirect
/// listener's histogram, and the access log line gets the upstream's status
/// and the full duration once the response is relayed.
fn forward(
  req: Request(proxy_http.Peer),
  started: Int,
  access: Option(access_log.Settings),
  trusted_proxies: List(String),
) -> proxy_http.Outcome {
  metrics.incr(metrics.UpstreamRequests)
  let trusted = trusted_peer(req, trusted_proxies)
  proxy_http.Forward(
    close: ffi.draining(),
    headers: forwarded_headers(req, trusted),
    drop: case trusted {
      True -> []
      False -> untrusted_headers
    },
    done: fn(forwarded: proxy_http.Forwarded) {
      let duration_us = ffi.monotonic_micros() - started
      // an upgraded connection (101) lasts as long as the client keeps it:
      // counted, but its lifetime is not a response time (the access log
      // has it)
      case forwarded.status {
        101 -> Nil
        _ -> metrics.observe_upstream(duration_us)
      }
      metrics.response(forwarded.status)
      case forwarded.error {
        option.None -> Nil
        option.Some(proxy_http.Unreachable) ->
          metrics.incr(metrics.UpstreamUnreachable)
        option.Some(proxy_http.TimedOut) ->
          metrics.incr(metrics.UpstreamTimeouts)
        option.Some(proxy_http.InvalidResponse) ->
          metrics.incr(metrics.UpstreamInvalidResponses)
      }
      case access {
        option.None -> Nil
        option.Some(settings) ->
          access_log.record(
            settings,
            req,
            req.body,
            Response(forwarded.status, [], Nil),
            forwarded.bytes,
            "",
            ffi.now_micros() - duration_us,
            duration_us,
          )
      }
    },
  )
}

/// The other forwarding headers: passed on from a trusted proxy, dropped
/// from any other peer (they could be forged).
const untrusted_headers = [
  "forwarded", "x-real-ip", "x-forwarded-port", "x-forwarded-prefix",
  "x-forwarded-server", "x-forwarded-ssl",
]

/// Whether the peer is one of `access_log.trusted_proxies`.
fn trusted_peer(
  req: Request(proxy_http.Peer),
  trusted_proxies: List(String),
) -> Bool {
  case trusted_proxies, req.body {
    [], _ | _, Error(Nil) -> False
    _, Ok(ip) -> {
      let peer = mist.ip_address_to_string(ip)
      list.any(trusted_proxies, ffi.ip_in_cidr(peer, _))
    }
  }
}

/// `X-Forwarded-For` (the client address, appended to the incoming list
/// when the peer is a trusted proxy), `X-Forwarded-Proto` and
/// `X-Forwarded-Host` (the incoming values from a trusted proxy, else `http`
/// and the `Host`). Values from other peers are dropped: they could be
/// forged.
pub fn forwarded_headers(
  req: Request(proxy_http.Peer),
  trusted: Bool,
) -> List(#(String, String)) {
  let peer = case req.body {
    Ok(ip) -> mist.ip_address_to_string(ip)
    Error(Nil) -> ""
  }
  let incoming = fn(name) {
    case trusted {
      True -> list.key_find(req.headers, name)
      False -> Error(Nil)
    }
  }
  let prior_for = case trusted {
    True ->
      list.filter_map(req.headers, fn(h) {
        case h.0 == "x-forwarded-for" {
          True -> Ok(h.1)
          False -> Error(Nil)
        }
      })
    False -> []
  }
  let for = case prior_for, peer {
    [], "" -> []
    [], _ -> [#("x-forwarded-for", peer)]
    _, _ -> [
      #("x-forwarded-for", string.join(list.append(prior_for, [peer]), ", ")),
    ]
  }
  let host = case incoming("x-forwarded-host") {
    Ok(host) -> [#("x-forwarded-host", host)]
    Error(Nil) ->
      case list.key_find(req.headers, "host") {
        Ok(host) -> [#("x-forwarded-host", host)]
        Error(Nil) -> []
      }
  }
  list.flatten([
    for,
    [
      #(
        "x-forwarded-proto",
        incoming("x-forwarded-proto") |> result.unwrap("http"),
      ),
    ],
    host,
  ])
}

fn route(
  config: ServerConfig,
  upstream: Bool,
  trusted_proxies: List(String),
  req: Request(proxy_http.Peer),
  not_found_body: BytesTree,
  permanent_cache: String,
) -> Routed {
  case config.health_path != "" && req.path == config.health_path {
    True -> Answered(health(), "")
    False -> {
      metrics.incr(metrics.Requests)
      case string.byte_size(req.path) > config.max_path_bytes {
        True -> Answered(empty(414), "")
        False ->
          case config.https_redirect && !forwarded_https(req, trusted_proxies) {
            True -> Answered(to_https(req, permanent_cache), "")
            False ->
              route_rules(
                config,
                upstream,
                req,
                not_found_body,
                permanent_cache,
              )
          }
      }
    }
  }
}

/// `server.metrics_path`: the metrics of a replica that has no admin or API
/// listener, with the bearer token (`admin.metrics_token`).
fn metrics_response(
  req: Request(proxy_http.Peer),
  token: String,
) -> Response(BytesTree) {
  let #(status, body) = case metrics_endpoint.authorized(req, token) {
    True -> #(200, metrics.render_prometheus())
    False -> #(401, "Authentication required")
  }
  let resp =
    response.new(status)
    |> response.set_header("cache-control", "no-store")
    |> response.set_body(bytes_tree.from_string(body))
  case status {
    200 ->
      response.set_header(resp, "content-type", "text/plain; version=0.0.4")
    _ ->
      resp
      |> response.set_header("content-type", "text/plain; charset=utf-8")
      |> response.set_header("www-authenticate", "Bearer realm=\"metrics\"")
  }
}

/// `server.health_path`: for load balancers that can only probe the traffic
/// port. Not counted as a request, like the admin's /readyz.
fn health() -> Response(BytesTree) {
  let #(status, body) = case ffi.draining() {
    False -> #(200, "ok")
    True -> #(503, "draining")
  }
  response.new(status)
  |> response.set_header("content-type", "text/plain; charset=utf-8")
  |> response.set_header("cache-control", "no-store")
  |> response.set_body(bytes_tree.from_string(body))
}

/// A TLS proxy in front forwarded an HTTPS request. With
/// `access_log.trusted_proxies`, only theirs count; without, any peer's
/// (a client sending the header itself only skips the upgrade).
fn forwarded_https(
  req: Request(proxy_http.Peer),
  trusted_proxies: List(String),
) -> Bool {
  case list.key_find(req.headers, "x-forwarded-proto") {
    Ok(_) if trusted_proxies != [] ->
      trusted_peer(req, trusted_proxies) && https_proto(req)
    Ok(_) -> https_proto(req)
    Error(Nil) -> False
  }
}

fn https_proto(req: Request(proxy_http.Peer)) -> Bool {
  case list.key_find(req.headers, "x-forwarded-proto") {
    Ok(proto) ->
      // the first value: the client side of the first proxy
      case string.split(proto, ",") {
        // `wss`: Traefik's value for a WebSocket upgrade over TLS
        [first, ..] ->
          case string.lowercase(string.trim(first)) {
            "https" | "wss" -> True
            _ -> False
          }
        [] -> False
      }
    Error(Nil) -> False
  }
}

/// The same URL over HTTPS: 301, or 308 so that other methods than GET and
/// HEAD are repeated as they were. A request without a usable host name
/// gets a 400.
fn to_https(
  req: Request(proxy_http.Peer),
  permanent_cache: String,
) -> Response(BytesTree) {
  let host =
    list.key_find(req.headers, "host")
    |> result.unwrap(req.host)
    |> matcher.normalise_request_host
  case rule.is_host_name(host) {
    False -> empty(400)
    True -> {
      let query = case req.query {
        option.Some(q) if q != "" -> "?" <> q
        _ -> ""
      }
      let status = case req.method {
        http.Get | http.Head -> 301
        _ -> 308
      }
      metrics.incr(metrics.Redirects)
      redirect(status, "https://" <> host <> req.path <> query, permanent_cache)
    }
  }
}

fn empty(status: Int) -> Response(BytesTree) {
  response.new(status)
  |> response.set_header("cache-control", "no-store")
  |> response.set_body(bytes_tree.new())
}

fn route_rules(
  config: ServerConfig,
  upstream: Bool,
  req: Request(proxy_http.Peer),
  not_found_body: BytesTree,
  permanent_cache: String,
) -> Routed {
  // header names are lower case: `request.get_header` would lower-case
  // the name on every request
  let host = list.key_find(req.headers, "host") |> result.unwrap(req.host)
  case req.method {
    http.Get | http.Head | http.Post | http.Put | http.Delete | http.Patch -> {
      // one read of the published matcher for both the lookup and the hit
      let current = snapshot.current()
      case find(current, config, host, req.path, option.unwrap(req.query, "")) {
        Ok(m) -> {
          metrics.incr(metrics.Redirects)
          matcher.record_hit(current, m.rule.id)
          Answered(
            redirect(
              m.rule.status,
              matcher.location(m, option_to_result(req.query)),
              permanent_cache,
            ),
            m.rule.id,
          )
        }
        Error(Nil) if upstream -> Unanswered
        Error(Nil) -> Answered(unmatched(config, not_found_body), "")
      }
    }
    _ if upstream -> Unanswered
    http.Options ->
      Answered(
        response.new(204)
          |> response.set_header("allow", allowed_methods)
          |> response.set_body(bytes_tree.new()),
        "",
      )
    _ ->
      Answered(
        response.new(405)
          |> response.set_header("allow", allowed_methods)
          |> response.set_body(bytes_tree.new()),
        "",
      )
  }
}

fn option_to_result(query: option.Option(String)) -> Result(String, Nil) {
  case query {
    option.Some(q) -> Ok(q)
    option.None -> Error(Nil)
  }
}

fn redirect(
  status: Int,
  location: String,
  permanent_cache: String,
) -> Response(BytesTree) {
  let cache = case status {
    301 | 308 -> permanent_cache
    _ -> "no-store"
  }
  Response(
    status,
    [#("location", location), #("cache-control", cache)],
    bytes_tree.new(),
  )
}

fn unmatched(
  config: ServerConfig,
  not_found_body: BytesTree,
) -> Response(BytesTree) {
  case config.fallback_url {
    "" -> {
      metrics.incr(metrics.NotFound)
      Response(
        404,
        [
          #("content-type", "text/plain; charset=utf-8"),
          #("cache-control", "no-store"),
        ],
        not_found_body,
      )
    }
    url -> {
      metrics.incr(metrics.FallbackRedirects)
      Response(
        302,
        [#("location", url), #("cache-control", "no-store")],
        bytes_tree.new(),
      )
    }
  }
}

const allowed_methods = "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS"

fn find(
  current: matcher.Matcher,
  config: ServerConfig,
  host: String,
  path: String,
  query: String,
) -> Result(matcher.Match, Nil) {
  // `//` parses as an empty authority and an empty path
  let path = case path {
    "" -> "/"
    p -> p
  }
  case config.trailing_slash {
    "ignore" -> matcher.lookup_tolerant_query(current, host, path, query)
    _ -> matcher.lookup_query(current, host, path, query)
  }
}
