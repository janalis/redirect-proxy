//// Thin wrapper over the Erlang logger.

import logging

pub fn configure(level: String) -> Nil {
  logging.configure()
  logging.set_level(case level {
    "debug" -> logging.Debug
    "warning" -> logging.Warning
    "error" -> logging.Error
    "critical" | "none" -> logging.Critical
    _ -> logging.Info
  })
}

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
