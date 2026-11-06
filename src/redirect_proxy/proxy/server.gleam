//// The public redirect listener. Deliberately minimal: no body reads, no
//// framework, one lock-free snapshot read and a single response.

import gleam/bytes_tree
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/option.{type Option}
import gleam/result
import mist
import redirect_proxy/access_log
import redirect_proxy/config.{type ServerConfig}
import redirect_proxy/ffi
import redirect_proxy/listener
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
  fn(req) {
    let time_us = ffi.now_micros()
    let started = ffi.monotonic_micros()
    let #(resp, rule_id) = respond(config, req, not_found_body, permanent_cache)
    metrics.observe(listener.RedirectListener, ffi.monotonic_micros() - started)
    metrics.response(resp.status)
    case access {
      option.None -> Nil
      option.Some(settings) ->
        access_log.record(settings, req, resp, rule_id, time_us, started)
    }
    resp
  }
}

/// The response and the id of the matched rule ("" when none). While the
/// node drains before stopping (SIGTERM), connections are closed after each
/// response so that clients reconnect to another instance.
fn respond(
  config: ServerConfig,
  req: Request(mist.Connection),
  not_found_body: bytes_tree.BytesTree,
  permanent_cache: String,
) -> #(Response(mist.ResponseData), String) {
  let #(resp, rule_id) = route(config, req, not_found_body, permanent_cache)
  case ffi.draining() {
    False -> #(resp, rule_id)
    True -> #(response.set_header(resp, "connection", "close"), rule_id)
  }
}

fn route(
  config: ServerConfig,
  req: Request(mist.Connection),
  not_found_body: bytes_tree.BytesTree,
  permanent_cache: String,
) -> #(Response(mist.ResponseData), String) {
  metrics.incr(metrics.Requests)
  let host = request.get_header(req, "host") |> result.unwrap(req.host)
  case req.method {
    http.Get | http.Head | http.Post | http.Put | http.Delete | http.Patch ->
      case find(config, host, req.path) {
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
        |> response.set_header("allow", allowed_methods)
        |> response.set_body(mist.Bytes(bytes_tree.new())),
      "",
    )
    _ -> #(
      response.new(405)
        |> response.set_header("allow", allowed_methods)
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

const allowed_methods = "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS"

fn find(
  config: ServerConfig,
  host: String,
  path: String,
) -> Result(matcher.Match, Nil) {
  case config.trailing_slash {
    "ignore" -> matcher.lookup_tolerant(snapshot.current(), host, path)
    _ -> matcher.lookup(snapshot.current(), host, path)
  }
}
