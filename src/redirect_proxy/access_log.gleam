//// Access (traffic) log of the redirect listener.
////
//// Each request process renders its own line; a dedicated `logger_std_h`
//// handler batches the writes to stdout, stderr or a file. The handler never
//// blocks request processes: under extreme overload it drops lines instead.

import gleam/result
import redirect_proxy/access_log_format.{type Entry, type Format} as fmt
import redirect_proxy/config.{type AccessLogConfig}
import redirect_proxy/ffi

pub type Settings {
  Settings(
    format: Format,
    log_query: Bool,
    anonymize_ip: Bool,
    trusted_proxies: List(String),
  )
}

pub fn settings(cfg: AccessLogConfig) -> Result(Settings, String) {
  use format <- result.try(fmt.parse(cfg.format, cfg.escape))
  Ok(Settings(
    format:,
    log_query: cfg.log_query,
    anonymize_ip: cfg.anonymize_ip == "truncate",
    trusted_proxies: cfg.trusted_proxies,
  ))
}

/// Installs (or, when disabled, removes) the access log handler.
pub fn start(cfg: AccessLogConfig) -> Result(Nil, String) {
  case cfg.enabled {
    False -> Ok(ffi.access_log_stop())
    True ->
      ffi.access_log_start(
        cfg.output,
        cfg.max_bytes,
        cfg.max_files,
        cfg.compress,
      )
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

pub fn record(settings: Settings, entry: Entry) -> Nil {
  fmt.render(settings.format, settings.log_query, entry)
  |> ffi.access_log_emit
}
