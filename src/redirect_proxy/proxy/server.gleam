//// The public redirect listener. Deliberately minimal: no body reads, no
//// framework, one lock-free snapshot read and a single response, served by
//// a dedicated HTTP/1.1 server (`proxy/http`).

import gleam/bytes_tree.{type BytesTree}
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gleam/string
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
) -> proxy_http.Options {
  proxy_http.Options(
    idle_timeout_ms: 10_000,
    // the query string and the headers do not count in `max_path_bytes`
    max_head_bytes: config.max_path_bytes + 65_536,
    peer: option.is_some(access),
  )
}

/// The request handler. With access log settings each request is logged,
/// with the id of the matched rule.
///
/// The server closes the connection after a request with a body: the body
/// is never read, and on a kept-alive connection its bytes would be parsed as
/// the next request (request smuggling behind a reverse proxy that reuses
/// connections).
pub fn handler(
  config: ServerConfig,
  metrics_token: String,
  access: Option(access_log.Settings),
) -> proxy_http.Handler {
  let not_found_body = bytes_tree.from_string(config.not_found_body)
  let permanent_cache =
    "public, max-age=" <> int.to_string(config.cache_max_age)
  fn(req: Request(proxy_http.Peer)) {
    let started = ffi.monotonic_micros()
    let #(resp, rule_id) = case
      config.metrics_path != "" && req.path == config.metrics_path
    {
      True -> #(metrics_response(req, metrics_token), "")
      False -> respond(config, req, not_found_body, permanent_cache)
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
    resp
  }
}

/// The response and the id of the matched rule ("" when none). While the
/// node drains before stopping (SIGTERM), connections are closed after each
/// response so that clients reconnect to another instance.
fn respond(
  config: ServerConfig,
  req: Request(proxy_http.Peer),
  not_found_body: BytesTree,
  permanent_cache: String,
) -> #(Response(BytesTree), String) {
  let #(resp, rule_id) = route(config, req, not_found_body, permanent_cache)
  case ffi.draining() {
    False -> #(resp, rule_id)
    True -> #(response.set_header(resp, "connection", "close"), rule_id)
  }
}

fn route(
  config: ServerConfig,
  req: Request(proxy_http.Peer),
  not_found_body: BytesTree,
  permanent_cache: String,
) -> #(Response(BytesTree), String) {
  case config.health_path != "" && req.path == config.health_path {
    True -> #(health(), "")
    False -> {
      metrics.incr(metrics.Requests)
      case string.byte_size(req.path) > config.max_path_bytes {
        True -> #(empty(414), "")
        False ->
          case config.https_redirect && !forwarded_https(req) {
            True -> #(to_https(req, permanent_cache), "")
            False -> route_rules(config, req, not_found_body, permanent_cache)
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

/// A TLS proxy in front forwarded an HTTPS request.
fn forwarded_https(req: Request(proxy_http.Peer)) -> Bool {
  case request.get_header(req, "x-forwarded-proto") {
    Ok(proto) ->
      // the first value: the client side of the first proxy
      case string.split(proto, ",") {
        [first, ..] -> string.lowercase(string.trim(first)) == "https"
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
    request.get_header(req, "host")
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
  req: Request(proxy_http.Peer),
  not_found_body: BytesTree,
  permanent_cache: String,
) -> #(Response(BytesTree), String) {
  let host = request.get_header(req, "host") |> result.unwrap(req.host)
  case req.method {
    http.Get | http.Head | http.Post | http.Put | http.Delete | http.Patch -> {
      // one read of the published matcher for both the lookup and the hit
      let current = snapshot.current()
      case find(current, config, host, req.path, option.unwrap(req.query, "")) {
        Ok(m) -> {
          metrics.incr(metrics.Redirects)
          matcher.record_hit(current, m.rule.id)
          #(
            redirect(
              m.rule.status,
              matcher.location(m, option_to_result(req.query)),
              permanent_cache,
            ),
            m.rule.id,
          )
        }
        Error(Nil) -> #(unmatched(config, not_found_body), "")
      }
    }
    http.Options -> #(
      response.new(204)
        |> response.set_header("allow", allowed_methods)
        |> response.set_body(bytes_tree.new()),
      "",
    )
    _ -> #(
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
