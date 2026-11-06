//// Loads the configuration: file, environment, checks.

import envoy
import gleam/dict.{type Dict}
import gleam/result
import gleam/string
import redirect_proxy/config.{type Config} as _
import redirect_proxy/config/env.{apply_env, env_errors} as _
import redirect_proxy/config/file.{from_toml, read_toml} as _
import redirect_proxy/config/validate.{validate} as _
import tom.{type Toml}

/// Loads the configuration. When `path` is empty only defaults and
/// environment variables are used.
pub fn load(path: String) -> Result(Config, String) {
  use toml <- result.try(read_toml(path))
  load_parsed(toml)
}

fn load_parsed(toml: Dict(String, Toml)) -> Result(Config, String) {
  use config <- result.try(from_toml(toml))
  use Nil <- result.try(case env_errors(envoy.get) {
    [] -> Ok(Nil)
    errors -> Error(string.join(errors, "; "))
  })
  let config = apply_env(config, envoy.get)
  use config <- result.try(validate(config))
  Ok(config)
}
