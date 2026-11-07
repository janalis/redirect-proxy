//// The TOML configuration file: parsing and known keys.

import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/config.{
  type Config, type ListenerLogConfig, AccessLogConfig, AdminConfig, ApiConfig,
  ApiOAuthConfig, Config, HeaderAuthConfig, ListenerLogConfig, LocalAuthConfig,
  LogConfig, OidcConfig, ServerConfig, StorageConfig, default,
} as _
import simplifile
import tom.{type Toml}

/// Parses a configuration file ("" for none).
pub fn read_toml(path: String) -> Result(Dict(String, Toml), String) {
  case path {
    "" -> Ok(dict.new())
    _ -> {
      use content <- result.try(
        simplifile.read(path)
        |> result.map_error(fn(e) {
          "cannot read " <> path <> ": " <> simplifile.describe_error(e)
        }),
      )
      tom.parse(content)
      |> result.map_error(fn(e) {
        "invalid TOML in " <> path <> ": " <> string.inspect(e)
      })
    }
  }
}

/// Every key `from_toml` reads. Used to warn about unknown keys, such as a
/// typo'd `[auth.odic]` section, which would otherwise be silently ignored.
pub const known_keys = [
  "access_log.admin.enabled",
  "access_log.admin.format",
  "access_log.admin.output",
  "access_log.anonymize_ip",
  "access_log.api.enabled",
  "access_log.api.format",
  "access_log.api.output",
  "access_log.compress",
  "access_log.enabled",
  "access_log.escape",
  "access_log.format",
  "access_log.log_query",
  "access_log.max_bytes",
  "access_log.max_files",
  "access_log.output",
  "access_log.redirect.enabled",
  "access_log.redirect.format",
  "access_log.redirect.output",
  "access_log.trusted_proxies",
  "admin.enabled",
  "admin.listen",
  "admin.port",
  "admin.public_url",
  "admin.secret_key_base",
  "admin.session_idle_timeout",
  "admin.metrics_token",
  "admin.session_ttl",
  "api.enabled",
  "api.listen",
  "api.max_body_bytes",
  "api.require_if_match",
  "api.oauth.audience",
  "api.oauth.enabled",
  "api.oauth.issuer",
  "api.oauth.ops_scope",
  "api.oauth.audit_scope",
  "api.oauth.read_scope",
  "api.oauth.require_at_jwt",
  "api.oauth.scope_claim",
  "api.oauth.write_scope",
  "api.port",
  "api.public_url",
  "api.token_ttl",
  "auth.header.email_header",
  "auth.header.enabled",
  "auth.header.trusted_proxies",
  "auth.header.user_header",
  "auth.local.enabled",
  "auth.oidc.allowed_domains",
  "auth.oidc.allowed_emails",
  "auth.oidc.allowed_groups",
  "auth.oidc.button_label",
  "auth.oidc.client_id",
  "auth.oidc.client_secret",
  "auth.oidc.enabled",
  "auth.oidc.groups_claim",
  "auth.oidc.admin_groups",
  "auth.oidc.editor_groups",
  "auth.oidc.viewer_groups",
  "auth.oidc.default_role",
  "auth.header.role_header",
  "auth.header.default_role",
  "auth.oidc.issuer",
  "auth.oidc.logout_at_provider",
  "auth.oidc.scopes",
  "server.cache_max_age",
  "server.fallback_url",
  "server.health_path",
  "server.metrics_path",
  "server.https_redirect",
  "server.max_path_bytes",
  "log.format",
  "log.level",
  "server.listen",
  "server.not_found_body",
  "server.port",
  "server.shutdown_grace",
  "server.trailing_slash",
  "storage.backups",
  "storage.data_dir",
  "storage.watch_interval",
  "storage.audit_max_bytes",
  "storage.audit_files",
]

/// The keys of a parsed configuration file that are not configuration keys.
pub fn unknown_keys(t: Dict(String, Toml)) -> List(String) {
  leaf_keys(t, "")
  |> list.filter(fn(key) { !list.contains(known_keys, key) })
  |> list.sort(string.compare)
}

fn leaf_keys(t: Dict(String, Toml), prefix: String) -> List(String) {
  dict.to_list(t)
  |> list.flat_map(fn(entry) {
    let #(name, value) = entry
    let key = prefix <> name
    case value {
      tom.Table(sub) | tom.InlineTable(sub) -> leaf_keys(sub, key <> ".")
      _ -> [key]
    }
  })
}

pub fn from_toml(t: Dict(String, Toml)) -> Result(Config, String) {
  let d = default()
  use server_listen <- result.try(str(t, ["server", "listen"], d.server.listen))
  use server_port <- result.try(integer(t, ["server", "port"], d.server.port))
  use cache_max_age <- result.try(integer(
    t,
    ["server", "cache_max_age"],
    d.server.cache_max_age,
  ))
  use shutdown_grace <- result.try(integer(
    t,
    ["server", "shutdown_grace"],
    d.server.shutdown_grace,
  ))
  use trailing_slash <- result.try(str(
    t,
    ["server", "trailing_slash"],
    d.server.trailing_slash,
  ))
  use fallback_url <- result.try(str(
    t,
    ["server", "fallback_url"],
    d.server.fallback_url,
  ))
  use not_found_body <- result.try(str(
    t,
    ["server", "not_found_body"],
    d.server.not_found_body,
  ))
  use health_path <- result.try(str(
    t,
    ["server", "health_path"],
    d.server.health_path,
  ))
  use metrics_path <- result.try(str(
    t,
    ["server", "metrics_path"],
    d.server.metrics_path,
  ))
  use max_path_bytes <- result.try(integer(
    t,
    ["server", "max_path_bytes"],
    d.server.max_path_bytes,
  ))
  use https_redirect <- result.try(boolean(
    t,
    ["server", "https_redirect"],
    d.server.https_redirect,
  ))
  use watch_interval <- result.try(integer(
    t,
    ["storage", "watch_interval"],
    d.storage.watch_interval,
  ))
  use audit_max_bytes <- result.try(integer(
    t,
    ["storage", "audit_max_bytes"],
    d.storage.audit_max_bytes,
  ))
  use audit_files <- result.try(integer(
    t,
    ["storage", "audit_files"],
    d.storage.audit_files,
  ))
  use admin_enabled <- result.try(boolean(
    t,
    ["admin", "enabled"],
    d.admin.enabled,
  ))
  use admin_listen <- result.try(str(t, ["admin", "listen"], d.admin.listen))
  use admin_port <- result.try(integer(t, ["admin", "port"], d.admin.port))
  use public_url <- result.try(str(
    t,
    ["admin", "public_url"],
    d.admin.public_url,
  ))
  use secret_key_base <- result.try(str(
    t,
    ["admin", "secret_key_base"],
    d.admin.secret_key_base,
  ))
  use session_ttl <- result.try(integer(
    t,
    ["admin", "session_ttl"],
    d.admin.session_ttl,
  ))
  use session_idle_timeout <- result.try(integer(
    t,
    ["admin", "session_idle_timeout"],
    d.admin.session_idle_timeout,
  ))
  use metrics_token <- result.try(str(
    t,
    ["admin", "metrics_token"],
    d.admin.metrics_token,
  ))
  use data_dir <- result.try(str(t, ["storage", "data_dir"], d.storage.data_dir))
  use backups <- result.try(integer(
    t,
    ["storage", "backups"],
    d.storage.backups,
  ))
  use local_enabled <- result.try(boolean(
    t,
    ["auth", "local", "enabled"],
    d.local_auth.enabled,
  ))
  let o = d.oidc
  use oidc_enabled <- result.try(boolean(
    t,
    ["auth", "oidc", "enabled"],
    o.enabled,
  ))
  use issuer <- result.try(str(t, ["auth", "oidc", "issuer"], o.issuer))
  use client_id <- result.try(str(t, ["auth", "oidc", "client_id"], o.client_id))
  use client_secret <- result.try(str(
    t,
    ["auth", "oidc", "client_secret"],
    o.client_secret,
  ))
  use scopes <- result.try(strings(t, ["auth", "oidc", "scopes"], o.scopes))
  use allowed_emails <- result.try(strings(
    t,
    ["auth", "oidc", "allowed_emails"],
    o.allowed_emails,
  ))
  use allowed_domains <- result.try(strings(
    t,
    ["auth", "oidc", "allowed_domains"],
    o.allowed_domains,
  ))
  use allowed_groups <- result.try(strings(
    t,
    ["auth", "oidc", "allowed_groups"],
    o.allowed_groups,
  ))
  use groups_claim <- result.try(str(
    t,
    ["auth", "oidc", "groups_claim"],
    o.groups_claim,
  ))
  use button_label <- result.try(str(
    t,
    ["auth", "oidc", "button_label"],
    o.button_label,
  ))
  use logout_at_provider <- result.try(boolean(
    t,
    ["auth", "oidc", "logout_at_provider"],
    o.logout_at_provider,
  ))
  use admin_groups <- result.try(strings(
    t,
    ["auth", "oidc", "admin_groups"],
    o.admin_groups,
  ))
  use editor_groups <- result.try(strings(
    t,
    ["auth", "oidc", "editor_groups"],
    o.editor_groups,
  ))
  use viewer_groups <- result.try(strings(
    t,
    ["auth", "oidc", "viewer_groups"],
    o.viewer_groups,
  ))
  use oidc_default_role <- result.try(str(
    t,
    ["auth", "oidc", "default_role"],
    o.default_role,
  ))
  let h = d.header_auth
  use header_enabled <- result.try(boolean(
    t,
    ["auth", "header", "enabled"],
    h.enabled,
  ))
  use user_header <- result.try(str(
    t,
    ["auth", "header", "user_header"],
    h.user_header,
  ))
  use email_header <- result.try(str(
    t,
    ["auth", "header", "email_header"],
    h.email_header,
  ))
  use trusted_proxies <- result.try(strings(
    t,
    ["auth", "header", "trusted_proxies"],
    h.trusted_proxies,
  ))
  use role_header <- result.try(str(
    t,
    ["auth", "header", "role_header"],
    h.role_header,
  ))
  use header_default_role <- result.try(str(
    t,
    ["auth", "header", "default_role"],
    h.default_role,
  ))
  let a = d.api
  use api_enabled <- result.try(boolean(t, ["api", "enabled"], a.enabled))
  use api_listen <- result.try(str(t, ["api", "listen"], a.listen))
  use api_port <- result.try(integer(t, ["api", "port"], a.port))
  use api_public_url <- result.try(str(t, ["api", "public_url"], a.public_url))
  use token_ttl <- result.try(integer(t, ["api", "token_ttl"], a.token_ttl))
  use max_body_bytes <- result.try(integer(
    t,
    ["api", "max_body_bytes"],
    a.max_body_bytes,
  ))
  use require_if_match <- result.try(boolean(
    t,
    ["api", "require_if_match"],
    a.require_if_match,
  ))
  let ao = a.oauth
  use ao_enabled <- result.try(boolean(
    t,
    ["api", "oauth", "enabled"],
    ao.enabled,
  ))
  use ao_issuer <- result.try(str(t, ["api", "oauth", "issuer"], ao.issuer))
  use ao_audience <- result.try(str(
    t,
    ["api", "oauth", "audience"],
    ao.audience,
  ))
  use ao_scope_claim <- result.try(str(
    t,
    ["api", "oauth", "scope_claim"],
    ao.scope_claim,
  ))
  use ao_require_at_jwt <- result.try(boolean(
    t,
    ["api", "oauth", "require_at_jwt"],
    ao.require_at_jwt,
  ))
  use read_scope <- result.try(str(
    t,
    ["api", "oauth", "read_scope"],
    ao.read_scope,
  ))
  use write_scope <- result.try(str(
    t,
    ["api", "oauth", "write_scope"],
    ao.write_scope,
  ))
  use ops_scope <- result.try(str(
    t,
    ["api", "oauth", "ops_scope"],
    ao.ops_scope,
  ))
  use audit_scope <- result.try(str(
    t,
    ["api", "oauth", "audit_scope"],
    ao.audit_scope,
  ))
  let al = d.access_log
  let ak = fn(k) { ["access_log", k] }
  use al_enabled <- result.try(boolean(t, ak("enabled"), al.enabled))
  use al_format <- result.try(str(t, ak("format"), al.format))
  use al_escape <- result.try(str(t, ak("escape"), al.escape))
  use al_output <- result.try(str(t, ak("output"), al.output))
  use al_anonymize <- result.try(str(t, ak("anonymize_ip"), al.anonymize_ip))
  use al_log_query <- result.try(boolean(t, ak("log_query"), al.log_query))
  use al_proxies <- result.try(strings(
    t,
    ak("trusted_proxies"),
    al.trusted_proxies,
  ))
  use al_max_bytes <- result.try(integer(t, ak("max_bytes"), al.max_bytes))
  use al_max_files <- result.try(integer(t, ak("max_files"), al.max_files))
  use al_compress <- result.try(boolean(t, ak("compress"), al.compress))
  use al_redirect <- result.try(listener_from_toml(t, "redirect", al.redirect))
  use al_admin <- result.try(listener_from_toml(t, "admin", al.admin))
  use al_api <- result.try(listener_from_toml(t, "api", al.api))
  use log_level <- result.try(str(t, ["log", "level"], d.log.level))
  use log_format <- result.try(str(t, ["log", "format"], d.log.format))
  Ok(Config(
    log: LogConfig(
      level: string.lowercase(log_level),
      format: string.lowercase(log_format),
    ),
    access_log: AccessLogConfig(
      enabled: al_enabled,
      format: al_format,
      escape: al_escape,
      output: al_output,
      anonymize_ip: al_anonymize,
      log_query: al_log_query,
      trusted_proxies: al_proxies,
      max_bytes: al_max_bytes,
      max_files: al_max_files,
      compress: al_compress,
      redirect: al_redirect,
      admin: al_admin,
      api: al_api,
    ),
    api: ApiConfig(
      enabled: api_enabled,
      listen: api_listen,
      port: api_port,
      public_url: api_public_url,
      token_ttl:,
      max_body_bytes:,
      require_if_match:,
      oauth: ApiOAuthConfig(
        enabled: ao_enabled,
        issuer: ao_issuer,
        audience: ao_audience,
        scope_claim: ao_scope_claim,
        require_at_jwt: ao_require_at_jwt,
        read_scope:,
        write_scope:,
        ops_scope:,
        audit_scope:,
      ),
    ),
    server: ServerConfig(
      listen: server_listen,
      port: server_port,
      cache_max_age:,
      shutdown_grace:,
      trailing_slash: string.lowercase(trailing_slash),
      fallback_url:,
      not_found_body:,
      health_path:,
      metrics_path:,
      max_path_bytes:,
      https_redirect:,
    ),
    admin: AdminConfig(
      enabled: admin_enabled,
      listen: admin_listen,
      port: admin_port,
      public_url:,
      secret_key_base:,
      session_ttl:,
      session_idle_timeout:,
      metrics_token:,
    ),
    storage: StorageConfig(
      data_dir:,
      backups:,
      watch_interval:,
      audit_max_bytes:,
      audit_files:,
    ),
    local_auth: LocalAuthConfig(enabled: local_enabled),
    oidc: OidcConfig(
      enabled: oidc_enabled,
      issuer:,
      client_id:,
      client_secret:,
      scopes:,
      allowed_emails:,
      allowed_domains:,
      allowed_groups:,
      groups_claim:,
      button_label:,
      logout_at_provider:,
      admin_groups:,
      editor_groups:,
      viewer_groups:,
      default_role: oidc_default_role,
    ),
    header_auth: HeaderAuthConfig(
      enabled: header_enabled,
      user_header: string.lowercase(user_header),
      email_header: string.lowercase(email_header),
      trusted_proxies:,
      role_header: string.lowercase(role_header),
      default_role: header_default_role,
    ),
  ))
}

fn listener_from_toml(
  t: Dict(String, Toml),
  name: String,
  d: ListenerLogConfig,
) -> Result(ListenerLogConfig, String) {
  let key = fn(k) { ["access_log", name, k] }
  use enabled <- result.try(boolean(t, key("enabled"), d.enabled))
  use format <- result.try(str(t, key("format"), d.format))
  use output <- result.try(str(t, key("output"), d.output))
  Ok(ListenerLogConfig(enabled:, format:, output:))
}

fn describe(key: List(String), expected: String) -> String {
  "config: " <> string.join(key, ".") <> " must be " <> expected
}

fn str(
  t: Dict(String, Toml),
  key: List(String),
  default: String,
) -> Result(String, String) {
  case tom.get_string(t, key) {
    Ok(v) -> Ok(v)
    Error(tom.NotFound(_)) -> Ok(default)
    Error(_) -> Error(describe(key, "a string"))
  }
}

fn integer(
  t: Dict(String, Toml),
  key: List(String),
  default: Int,
) -> Result(Int, String) {
  case tom.get_int(t, key) {
    Ok(v) -> Ok(v)
    Error(tom.NotFound(_)) -> Ok(default)
    Error(_) -> Error(describe(key, "an integer"))
  }
}

fn boolean(
  t: Dict(String, Toml),
  key: List(String),
  default: Bool,
) -> Result(Bool, String) {
  case tom.get_bool(t, key) {
    Ok(v) -> Ok(v)
    Error(tom.NotFound(_)) -> Ok(default)
    Error(_) -> Error(describe(key, "a boolean"))
  }
}

fn strings(
  t: Dict(String, Toml),
  key: List(String),
  default: List(String),
) -> Result(List(String), String) {
  case tom.get_array(t, key) {
    Ok(values) ->
      values
      |> list.try_map(tom.as_string)
      |> result.replace_error(describe(key, "an array of strings"))
    Error(tom.NotFound(_)) -> Ok(default)
    Error(_) -> Error(describe(key, "an array of strings"))
  }
}
