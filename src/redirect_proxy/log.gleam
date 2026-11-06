//// Thin wrapper over the Erlang logger.

import logging

/// Sets the application log level. The level applies to the application log
/// handler only, so that the access log (emitted at `info`, see
/// `access_log`) keeps working with `RP_LOG_LEVEL=warning`.
pub fn configure(level: String) -> Nil {
  configure_with(level, "text")
}

/// `configure`, with the format of the application log: "text" or "json"
/// (one JSON object per line).
pub fn configure_with(level: String, format: String) -> Nil {
  logging.configure()
  case format {
    "json" -> use_json()
    _ -> Nil
  }
  let level = case level {
    "debug" -> logging.Debug
    "warning" -> logging.Warning
    "error" -> logging.Error
    "critical" | "none" -> logging.Critical
    _ -> logging.Info
  }
  let primary = case level {
    logging.Debug -> logging.Debug
    _ -> logging.Info
  }
  set_levels(primary, level)
}

@external(erlang, "redirect_proxy_log_json", "use")
fn use_json() -> Nil

@external(erlang, "redirect_proxy_access_ffi", "set_levels")
fn set_levels(primary: logging.LogLevel, default: logging.LogLevel) -> Nil

pub fn info(message: String) -> Nil {
  logging.log(logging.Info, message)
}

pub fn warning(message: String) -> Nil {
  logging.log(logging.Warning, message)
}

pub fn error(message: String) -> Nil {
  logging.log(logging.Error, message)
}

pub fn debug(message: String) -> Nil {
  logging.log(logging.Debug, message)
}
