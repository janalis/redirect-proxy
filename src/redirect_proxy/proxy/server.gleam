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
import redirect_proxy/access_log_format
import redirect_proxy/config.{type ServerConfig}
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/snapshot

pub fn handler(
  config: ServerConfig,
  access: Option(access_log.Settings),
) -> fn(Request(mist.Connection)) -> Response(mist.ResponseData) {
  let not_found_body = bytes_tree.from_string(config.not_found_body)
  let not_found_bytes = bytes_tree.byte_size(not_found_body)
  let permanent_cache =
    "public, max-age=" <> int.to_string(config.cache_max_age)
  let respond = fn(req: Request(mist.Connection), host: String) {
    respond(config, req, host, not_found_body, not_found_bytes, permanent_cache)
  }
  case access {
    option.None -> fn(req: Request(mist.Connection)) {
      respond(req, host(req)).0
    }
    option.Some(settings) -> fn(req: Request(mist.Connection)) {
      let time_us = ffi.now_micros()
      let started = ffi.monotonic_micros()
      let host = host(req)
      let #(resp, outcome) = respond(req, host)
      log(settings, req, host, resp.status, outcome, time_us, started)
      resp
    }
  }
}

/// What the access log needs to know about a response.
type Outcome {
  Outcome(rule_id: String, location: String, bytes: Int)
}

fn host(req: Request(mist.Connection)) -> String {
  request.get_header(req, "host") |> result.unwrap(req.host)
}

fn respond(
  config: ServerConfig,
  req: Request(mist.Connection),
  host: String,
  not_found_body: bytes_tree.BytesTree,
  not_found_bytes: Int,
  permanent_cache: String,
) -> #(Response(mist.ResponseData), Outcome) {
  metrics.incr(metrics.Requests)
  case req.method {
    http.Get | http.Head | http.Post | http.Put | http.Delete | http.Patch ->
      case matcher.lookup(snapshot.current(), host, req.path) {
        Ok(m) -> {
          metrics.incr(metrics.Redirects)
          metrics.hit(m.rule.id)
          let location = matcher.location(m, option_to_result(req.query))
          #(
            redirect(m.rule.status, location, permanent_cache),
            Outcome(rule_id: m.rule.id, location:, bytes: 0),
          )
        }
        Error(Nil) -> unmatched(config, not_found_body, not_found_bytes)
      }
    http.Options -> #(
      response.new(204)
        |> response.set_header("allow", "GET, HEAD, POST, PUT, DELETE, PATCH")
        |> response.set_body(mist.Bytes(bytes_tree.new())),
      no_outcome,
    )
    _ -> #(
      response.new(405)
        |> response.set_body(mist.Bytes(bytes_tree.new())),
      no_outcome,
    )
  }
}

const no_outcome = Outcome(rule_id: "", location: "", bytes: 0)

fn log(
  settings: access_log.Settings,
  req: Request(mist.Connection),
  host: String,
  status: Int,
  outcome: Outcome,
  time_us: Int,
  started: Int,
) -> Nil {
  let peer = case mist.get_connection_info(req.body) {
    Ok(info) -> mist.ip_address_to_string(info.ip_address)
    Error(Nil) -> ""
  }
  access_log.record(
    settings,
    access_log_format.Entry(
      client_ip: access_log.client_ip(settings, peer, req.headers),
      method: http.method_to_string(req.method),
      host:,
      path: req.path,
      query: option.unwrap(req.query, ""),
      protocol: "HTTP/1.1",
      status:,
      bytes: case req.method {
        http.Head -> 0
        _ -> outcome.bytes
      },
      headers: req.headers,
      location: outcome.location,
      rule_id: outcome.rule_id,
      time_us:,
      duration_us: ffi.monotonic_micros() - started,
    ),
  )
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
  not_found_bytes: Int,
) -> #(Response(mist.ResponseData), Outcome) {
  case config.fallback_url {
    "" -> {
      metrics.incr(metrics.NotFound)
      #(
        response.new(404)
          |> response.set_header("content-type", "text/plain; charset=utf-8")
          |> response.set_header("cache-control", "no-store")
          |> response.set_body(mist.Bytes(not_found_body)),
        Outcome(..no_outcome, bytes: not_found_bytes),
      )
    }
    url -> {
      metrics.incr(metrics.FallbackRedirects)
      #(
        response.new(302)
          |> response.set_header("location", url)
          |> response.set_header("cache-control", "no-store")
          |> response.set_body(mist.Bytes(bytes_tree.new())),
        Outcome(..no_outcome, location: url),
      )
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
