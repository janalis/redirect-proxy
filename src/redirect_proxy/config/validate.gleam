//// Checks of a loaded configuration, and `check-config` warnings.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/access_log_format
import redirect_proxy/config.{
  type AccessLogConfig, type Config, access_log_format, access_log_output,
  api_dedicated, api_on_admin, api_port,
} as _
import redirect_proxy/config/env as config_env
import redirect_proxy/config/file.{unknown_keys} as _
import redirect_proxy/ffi
import redirect_proxy/listener
import tom.{type Toml}

fn is_http_url(url: String) -> Bool {
  let lower = string.lowercase(url)
  { string.starts_with(lower, "http://") && string.length(url) > 7 }
  || { string.starts_with(lower, "https://") && string.length(url) > 8 }
}

/// Things that are allowed but probably wrong, reported by `check-config`:
/// unknown keys, an admin listening beyond the loopback interface, and the
/// `runtime_warnings`.
pub fn warnings(toml: Dict(String, Toml), config: Config) -> List(String) {
  let unknown =
    unknown_keys(toml)
    |> list.map(fn(key) { "unknown setting " <> key <> " (ignored)" })
  let exposed = case config.admin.enabled && !is_loopback(config.admin.listen) {
    True -> [
      "the admin listens on "
      <> config.admin.listen
      <> ": keep it behind a firewall or a reverse proxy (it also serves /metrics without authentication)",
    ]
    False -> []
  }
  list.flatten([unknown, exposed, runtime_warnings(config)])
}

/// Warnings also logged when the server starts.
pub fn runtime_warnings(config: Config) -> List(String) {
  let oidc = config.oidc
  case
    oidc.enabled
    && oidc.allowed_emails == []
    && oidc.allowed_domains == []
    && oidc.allowed_groups == []
  {
    True -> [
      "auth.oidc has no allowed_emails, allowed_domains or allowed_groups: every account of the provider can sign in to the admin",
    ]
    False -> []
  }
}

fn is_loopback(address: String) -> Bool {
  address == "localhost"
  || address == "::1"
  || string.starts_with(address, "127.")
}

pub fn validate(config: Config) -> Result(Config, String) {
  let port_ok = fn(p) { p >= 0 && p < 65_536 }
  use <- bool.guard(
    !port_ok(config.server.port),
    Error("server.port must be between 0 and 65535"),
  )
  use <- bool.guard(
    !port_ok(config.admin.port),
    Error("admin.port must be between 0 and 65535"),
  )
  use <- bool.guard(
    config.admin.enabled
      && config.server.port == config.admin.port
      && config.server.port != 0,
    Error("server.port and admin.port must differ"),
  )
  use <- bool.guard(
    config.storage.backups < 0,
    Error("storage.backups must be >= 0"),
  )
  use <- bool.guard(
    config.server.shutdown_grace < 0 || config.server.shutdown_grace > 60,
    Error("server.shutdown_grace must be between 0 and 60 seconds"),
  )
  use <- bool.guard(
    !list.contains(config_env.log_levels, config.log.level),
    Error(
      "log.level must be one of " <> string.join(config_env.log_levels, ", "),
    ),
  )
  use <- bool.guard(
    !list.contains(config_env.log_formats, config.log.format),
    Error("log.format must be \"text\" or \"json\""),
  )
  use <- bool.guard(
    !list.contains(["strict", "ignore"], config.server.trailing_slash),
    Error("server.trailing_slash must be \"strict\" or \"ignore\""),
  )
  use <- bool.guard(
    config.admin.session_ttl < 60,
    Error("admin.session_ttl must be at least 60 seconds"),
  )
  use <- bool.guard(
    config.admin.session_ttl > 604_800,
    Error("admin.session_ttl must be at most 7 days (604800 seconds)"),
  )
  use <- bool.guard(
    config.server.cache_max_age < 0,
    Error("server.cache_max_age must be >= 0"),
  )
  use <- bool.guard(
    config.server.fallback_url != "" && !is_http_url(config.server.fallback_url),
    Error("server.fallback_url must be an http:// or https:// URL"),
  )
  use <- bool.guard(
    !is_http_url(config.admin.public_url),
    Error("admin.public_url must be an http:// or https:// URL"),
  )
  use <- bool.guard(
    config.admin.session_idle_timeout != 0
      && config.admin.session_idle_timeout < 60,
    Error("admin.session_idle_timeout must be 0 (off) or at least 60 seconds"),
  )
  use <- bool.guard(
    config.admin.secret_key_base != ""
      && string.length(config.admin.secret_key_base) < 64,
    Error("admin.secret_key_base must be at least 64 characters long"),
  )
  use <- bool.guard(
    config.oidc.enabled
      && {
      config.oidc.issuer == ""
      || config.oidc.client_id == ""
      || config.oidc.client_secret == ""
    },
    Error("auth.oidc requires issuer, client_id and client_secret when enabled"),
  )
  use <- bool.guard(
    config.header_auth.enabled && config.header_auth.trusted_proxies == [],
    Error("auth.header requires at least one trusted proxy CIDR"),
  )
  use <- bool.guard(
    !list.all(config.header_auth.trusted_proxies, ffi.valid_cidr),
    Error("auth.header.trusted_proxies contains an invalid CIDR"),
  )
  use <- bool.guard(
    config.admin.enabled
      && !config.local_auth.enabled
      && !config.oidc.enabled
      && !config.header_auth.enabled,
    Error("at least one admin authentication method must be enabled"),
  )
  use <- bool.guard(
    !port_ok(config.api.port),
    Error("api.port must be between 0 and 65535"),
  )
  use <- bool.guard(
    api_dedicated(config)
      && api_port(config) != 0
      && api_port(config) == config.server.port,
    Error("api.port must differ from server.port"),
  )
  use <- bool.guard(
    api_on_admin(config)
      && config.api.listen != ""
      && config.api.listen != config.admin.listen,
    Error(
      "api.listen must equal admin.listen when the API shares admin.port (or use another api.port)",
    ),
  )
  use <- bool.guard(
    config.api.token_ttl < 60 || config.api.token_ttl > 86_400,
    Error("api.token_ttl must be between 60 and 86400 seconds"),
  )
  use <- bool.guard(
    config.api.max_body_bytes < 1024,
    Error("api.max_body_bytes must be at least 1024"),
  )
  use <- bool.guard(
    config.api.oauth.enabled
      && { config.api.oauth.issuer == "" || config.api.oauth.audience == "" },
    Error("api.oauth requires issuer and audience when enabled"),
  )
  validate_access_log(config.access_log)
  |> result.replace(config)
}

fn validate_access_log(al: AccessLogConfig) -> Result(Nil, String) {
  use <- bool.guard(
    !list.contains(["truncate", "none"], al.anonymize_ip),
    Error("access_log.anonymize_ip must be \"truncate\" or \"none\""),
  )
  use <- bool.guard(
    !list.contains(["default", "json", "none"], al.escape),
    Error("access_log.escape must be \"default\", \"json\" or \"none\""),
  )
  use <- bool.guard(
    string.trim(al.output) == "",
    Error("access_log.output must be stdout, stderr or a file path"),
  )
  use <- bool.guard(
    !list.all(al.trusted_proxies, ffi.valid_cidr),
    Error("access_log.trusted_proxies contains an invalid CIDR"),
  )
  use <- bool.guard(
    al.max_bytes < 0,
    Error("access_log.max_bytes must be >= 0"),
  )
  use <- bool.guard(
    al.max_files < 1,
    Error("access_log.max_files must be at least 1"),
  )
  use Nil <- result.try(
    access_log_format.parse(al.format, al.escape)
    |> result.map_error(fn(e) { "access_log.format: " <> e })
    |> result.replace(Nil),
  )
  list.try_each(listener.all, fn(listener) {
    let name = "access_log." <> listener.name(listener)
    use <- bool.guard(
      string.trim(access_log_output(al, listener)) == "",
      Error(name <> ".output must be stdout, stderr or a file path"),
    )
    access_log_format.parse(access_log_format(al, listener), al.escape)
    |> result.map_error(fn(e) { name <> ".format: " <> e })
    |> result.replace(Nil)
  })
}
