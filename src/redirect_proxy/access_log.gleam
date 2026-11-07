//// Access (traffic) logs of the redirect, admin and API listeners.
////
//// Each request process renders its own line; one dedicated `logger_std_h`
//// handler per output (stdout, stderr or a file) batches the writes. The
//// handlers never block request processes: under extreme overload they drop
//// lines instead.

import gleam/bytes_tree
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import mist
import redirect_proxy/access_log_format.{type Format} as fmt
import redirect_proxy/config.{type AccessLogConfig}
import redirect_proxy/ffi
import redirect_proxy/listener.{
  type Listener, AdminListener, ApiListener, RedirectListener,
}
import redirect_proxy/metrics

pub type Settings {
  Settings(
    listener: Listener,
    format: Format,
    log_query: Bool,
    anonymize_ip: Bool,
    trusted_proxies: List(String),
    /// Address headers logged by `format` whose addresses are truncated
    /// (empty when addresses are not truncated, or none is logged).
    anonymized_headers: List(String),
  )
}

/// Request-time settings of each listener (`None`: not logged).
pub type Loggers {
  Loggers(
    redirect: Option(Settings),
    admin: Option(Settings),
    api: Option(Settings),
  )
}

pub fn settings(
  cfg: AccessLogConfig,
  listener: Listener,
) -> Result(Settings, String) {
  use format <- result.try(fmt.parse(
    config.access_log_format(cfg, listener),
    cfg.escape,
  ))
  Ok(
    Settings(
      listener:,
      format:,
      log_query: cfg.log_query,
      anonymize_ip: cfg.anonymize_ip == "truncate",
      trusted_proxies: cfg.trusted_proxies,
      anonymized_headers: case cfg.anonymize_ip {
        "truncate" -> fmt.logged_address_headers(format)
        _ -> []
      },
    ),
  )
}

/// Installs one handler per distinct output of the enabled listeners and
/// returns their request-time settings. Replaces any previous handlers.
pub fn start(cfg: AccessLogConfig) -> Result(Loggers, String) {
  let enabled = list.filter(listener.all, config.access_log_enabled(cfg, _))
  let groups =
    list.fold(enabled, [], fn(groups, l) {
      let output = config.access_log_output(cfg, l)
      case list.key_find(groups, output) {
        Ok(ls) -> list.key_set(groups, output, list.append(ls, [l]))
        Error(Nil) -> list.append(groups, [#(output, [l])])
      }
    })
  use Nil <- result.try(ffi.access_log_start(
    groups,
    cfg.max_bytes,
    cfg.max_files,
    cfg.compress,
  ))
  let get = fn(l) {
    case list.contains(enabled, l) {
      False -> Ok(option.None)
      True -> settings(cfg, l) |> result.map(option.Some)
    }
  }
  use redirect <- result.try(get(RedirectListener))
  use admin <- result.try(get(AdminListener))
  use api <- result.try(get(ApiListener))
  Ok(Loggers(redirect:, admin:, api:))
}

/// Removes every access log handler.
pub fn stop() -> Nil {
  ffi.access_log_stop()
}

/// Wraps a listener's handler so that each request is timed (request
/// duration metric) and logged. `choose` tells the listener a request belongs
/// to and its log settings (the admin listener also serves the API when they
/// share a port).
pub fn wrap(
  handle: fn(Request(mist.Connection)) -> Response(mist.ResponseData),
  choose: fn(Request(mist.Connection)) -> #(Listener, Option(Settings)),
) -> fn(Request(mist.Connection)) -> Response(mist.ResponseData) {
  fn(req) {
    let #(listener, settings) = choose(req)
    let time_us = ffi.now_micros()
    let started = ffi.monotonic_micros()
    let resp = handle(req)
    let duration_us = ffi.monotonic_micros() - started
    metrics.observe(listener, duration_us)
    case settings {
      option.None -> Nil
      option.Some(settings) -> {
        let peer =
          mist.get_connection_info(req.body)
          |> result.map(fn(info) { info.ip_address })
        record(
          settings,
          req,
          peer,
          resp,
          body_size(resp.body),
          "",
          time_us,
          duration_us,
        )
      }
    }
    resp
  }
}

/// Whether a request to the admin listener is an API call.
pub fn is_api_path(path: String) -> Bool {
  path == "/api"
  || path == "/oauth"
  || string.starts_with(path, "/api/")
  || string.starts_with(path, "/oauth/")
}

/// Logs one served request: `peer` is the address of the connection,
/// `bytes` the size of the response body, `time_us` when the request arrived
/// (`ffi.now_micros()`) and `duration_us` how long it took.
pub fn record(
  settings: Settings,
  req: Request(body),
  peer: Result(mist.IpAddress, Nil),
  resp: Response(response_body),
  bytes: Int,
  rule_id: String,
  time_us: Int,
  duration_us: Int,
) -> Nil {
  let client = case peer, settings {
    // the peer is the client: anonymise its address without formatting it
    Ok(ip), Settings(anonymize_ip: True, trusted_proxies: [], ..) ->
      ffi.anonymize_peer(ip)
    Ok(ip), _ -> client_ip(settings, mist.ip_address_to_string(ip), req.headers)
    Error(Nil), _ -> client_ip(settings, "", req.headers)
  }
  let entry =
    fmt.Entry(
      listener: listener.name(settings.listener),
      client_ip: client,
      method: http.method_to_string(req.method),
      // header names are lower case (`request.get_header` lower-cases the
      // name it is given on every call)
      host: list.key_find(req.headers, "host") |> result.unwrap(req.host),
      path: req.path,
      query: option.unwrap(req.query, ""),
      protocol: "HTTP/1.1",
      status: resp.status,
      bytes: case req.method {
        http.Head -> 0
        _ -> bytes
      },
      headers: case settings.anonymized_headers {
        [] -> req.headers
        names ->
          list.map(req.headers, fn(h) {
            case list.contains(names, h.0) {
              True -> #(h.0, fmt.anonymize_header(h.1))
              False -> h
            }
          })
      },
      location: list.key_find(resp.headers, "location") |> result.unwrap(""),
      rule_id:,
      time_us:,
      duration_us:,
    )
  fmt.render(settings.format, settings.log_query, entry)
  |> ffi.access_log_emit(settings.listener, _)
}

fn body_size(body: mist.ResponseData) -> Int {
  case body {
    mist.Bytes(tree) -> bytes_tree.byte_size(tree)
    mist.File(length:, ..) -> length
    mist.Chunked | mist.Websocket | mist.ServerSentEvents -> 0
  }
}

/// Resolves the client address as configured (trusted proxies, anonymisation).
pub fn client_ip(
  settings: Settings,
  peer: String,
  headers: List(#(String, String)),
) -> String {
  let ip = fmt.client_ip(peer, headers, settings.trusted_proxies)
  case settings.anonymize_ip {
    True -> fmt.anonymize(ip)
    False -> ip
  }
}
