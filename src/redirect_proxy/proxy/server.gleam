//// The public redirect listener. Deliberately minimal: no body reads, no
//// framework, one lock-free snapshot read and a single response.

import gleam/bytes_tree
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gleam/string
import mist
import redirect_proxy/access_log
import redirect_proxy/config.{type ServerConfig}
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/snapshot

/// The request handler. With access log settings each request is logged,
/// with the id of the matched rule.
pub fn handler(
  config: ServerConfig,
  access: Option(access_log.Settings),
) -> fn(Request(mist.Connection)) -> Response(mist.ResponseData) {
  let not_found_body = bytes_tree.from_string(config.not_found_body)
  let permanent_cache =
    "public, max-age=" <> int.to_string(config.cache_max_age)
  case access {
    option.None -> fn(req) {
      respond(config, req, not_found_body, permanent_cache).0
    }
    option.Some(settings) -> fn(req) {
      let time_us = ffi.now_micros()
      let started = ffi.monotonic_micros()
      let #(resp, rule_id) =
        respond(config, req, not_found_body, permanent_cache)
      access_log.record(settings, req, resp, rule_id, time_us, started)
      resp
    }
  }
}

/// The response and the id of the matched rule ("" when none).
fn respond(
  config: ServerConfig,
  req: Request(mist.Connection),
  not_found_body: bytes_tree.BytesTree,
  permanent_cache: String,
) -> #(Response(mist.ResponseData), String) {
  metrics.incr(metrics.Requests)
  let host = request.get_header(req, "host") |> result.unwrap(req.host)
  case req.method {
    http.Get | http.Head | http.Post | http.Put | http.Delete | http.Patch ->
      case matcher.lookup(snapshot.current(), host, req.path) {
        Ok(m) -> {
          metrics.incr(metrics.Redirects)
          metrics.hit(m.rule.id)
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
    http.Options -> #(
      response.new(204)
        |> response.set_header("allow", "GET, HEAD, POST, PUT, DELETE, PATCH")
        |> response.set_body(mist.Bytes(bytes_tree.new())),
      "",
    )
    _ -> #(
      response.new(405)
        |> response.set_body(mist.Bytes(bytes_tree.new())),
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
) -> Response(mist.ResponseData) {
  let cache = case status {
    301 | 308 -> permanent_cache
    _ -> "no-store"
  }
  response.new(status)
  |> response.set_header("location", location)
  |> response.set_header("cache-control", cache)
  |> response.set_body(mist.Bytes(bytes_tree.new()))
}

fn unmatched(
  config: ServerConfig,
  not_found_body: bytes_tree.BytesTree,
) -> Response(mist.ResponseData) {
  case config.fallback_url {
    "" -> {
      metrics.incr(metrics.NotFound)
      response.new(404)
      |> response.set_header("content-type", "text/plain; charset=utf-8")
      |> response.set_header("cache-control", "no-store")
      |> response.set_body(mist.Bytes(not_found_body))
    }
    url -> {
      metrics.incr(metrics.FallbackRedirects)
      response.new(302)
      |> response.set_header("location", url)
      |> response.set_header("cache-control", "no-store")
      |> response.set_body(mist.Bytes(bytes_tree.new()))
    }
  }
}

/// Starts the redirect listener under its own supervisor.
pub fn start(
  config: ServerConfig,
  access: Option(access_log.Settings),
  on_started: fn(Int) -> Nil,
) -> Result(Nil, String) {
  mist.new(handler(config, access))
  |> mist.bind(config.listen)
  |> mist.port(config.port)
  |> mist.after_start(fn(port, _scheme, _ip) { on_started(port) })
  |> mist.start
  |> result.replace(Nil)
  |> result.map_error(fn(e) {
    "cannot start redirect listener on "
    <> config.listen
    <> ":"
    <> int.to_string(config.port)
    <> ": "
    <> string.inspect(e)
  })
}
