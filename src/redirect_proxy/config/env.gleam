//// `RP_*` environment variable overrides and `_FILE` secrets.

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/config.{
  type Config, type ListenerLogConfig, AccessLogConfig, AdminConfig, ApiConfig,
  ApiOAuthConfig, Config, HeaderAuthConfig, ListenerLogConfig, LocalAuthConfig,
  LogConfig, OidcConfig, ServerConfig, StorageConfig,
} as _
import simplifile

/// Integer and boolean overrides of `apply_env`. A value that does not parse
/// is a load error (`env_errors`) instead of being silently ignored, which
/// would leave e.g. the admin enabled after `RP_ADMIN_ENABLED=flase`.
pub const int_env_vars = [
  "RP_ACCESS_LOG_MAX_BYTES",
  "RP_ACCESS_LOG_MAX_FILES",
  "RP_ADMIN_PORT",
  "RP_ADMIN_SESSION_IDLE_TIMEOUT",
  "RP_ADMIN_SESSION_TTL",
  "RP_API_MAX_BODY_BYTES",
  "RP_API_PORT",
  "RP_API_TOKEN_TTL",
  "RP_SERVER_CACHE_MAX_AGE",
  "RP_SERVER_MAX_CONNECTIONS_PER_IP",
  "RP_SERVER_MAX_PATH_BYTES",
  "RP_SERVER_MAX_REQUEST_BODY_BYTES",
  "RP_SERVER_PORT",
  "RP_SERVER_SHUTDOWN_GRACE",
  "RP_SERVER_UPSTREAM_TIMEOUT",
  "RP_STORAGE_AUDIT_FILES",
  "RP_STORAGE_AUDIT_MAX_BYTES",
  "RP_STORAGE_BACKUPS",
  "RP_STORAGE_WATCH_INTERVAL",
]

pub const bool_env_vars = [
  "RP_ACCESS_LOG_ADMIN_ENABLED",
  "RP_ACCESS_LOG_API_ENABLED",
  "RP_ACCESS_LOG_COMPRESS",
  "RP_ACCESS_LOG_ENABLED",
  "RP_ACCESS_LOG_LOG_QUERY",
  "RP_ACCESS_LOG_REDIRECT_ENABLED",
  "RP_ADMIN_ENABLED",
  "RP_API_ENABLED",
  "RP_API_OAUTH_ENABLED",
  "RP_API_OAUTH_REQUIRE_AT_JWT",
  "RP_API_REQUIRE_IF_MATCH",
  "RP_AUTH_HEADER_ENABLED",
  "RP_AUTH_LOCAL_ENABLED",
  "RP_AUTH_OIDC_ALLOW_ANY_ACCOUNT",
  "RP_AUTH_OIDC_ENABLED",
  "RP_AUTH_OIDC_LOGOUT_AT_PROVIDER",
  "RP_SERVER_HTTPS_REDIRECT",
  "RP_SERVER_UPSTREAM_TLS_VERIFY",
]

/// An integer override (surrounding spaces ignored).
fn parse_int(value: String) -> Result(Int, Nil) {
  int.parse(string.trim(value))
}

/// A boolean override: true/false, yes/no, on/off, 1/0, in any case.
fn parse_bool(value: String) -> Result(Bool, Nil) {
  case string.lowercase(string.trim(value)) {
    "1" | "true" | "yes" | "on" -> Ok(True)
    "0" | "false" | "no" | "off" -> Ok(False)
    _ -> Error(Nil)
  }
}

/// The overrides of `int_env_vars`, `bool_env_vars` and `RP_LOG_LEVEL` whose
/// value is invalid, described.
pub fn env_errors(get: fn(String) -> Result(String, Nil)) -> List(String) {
  let ints =
    list.filter_map(int_env_vars, fn(name) {
      case get(name) {
        Ok(value) ->
          case parse_int(value) {
            Ok(_) -> Error(Nil)
            Error(Nil) ->
              Ok(name <> ": expected an integer, got \"" <> value <> "\"")
          }
        Error(Nil) -> Error(Nil)
      }
    })
  let bools =
    list.filter_map(bool_env_vars, fn(name) {
      case get(name) {
        Ok(value) ->
          case parse_bool(value) {
            Ok(_) -> Error(Nil)
            Error(Nil) ->
              Ok(name <> ": expected true or false, got \"" <> value <> "\"")
          }
        Error(Nil) -> Error(Nil)
      }
    })
  let level = case get("RP_LOG_LEVEL") {
    Ok(level) ->
      case list.contains(log_levels, string.lowercase(string.trim(level))) {
        True -> []
        False -> [
          "RP_LOG_LEVEL: expected one of "
          <> string.join(log_levels, ", ")
          <> ", got \""
          <> level
          <> "\"",
        ]
      }
    Error(Nil) -> []
  }
  let secrets =
    list.filter_map(secret_env_vars, fn(name) {
      case get(name), get(name <> "_FILE") {
        Ok(_), Ok(_) -> Ok(name <> " and " <> name <> "_FILE are both set")
        _, Ok(path) ->
          case read_secret_file(path) {
            Ok(_) -> Error(Nil)
            Error(reason) -> Ok(name <> "_FILE: " <> reason)
          }
        _, _ -> Error(Nil)
      }
    })
  let format = case get("RP_LOG_FORMAT") {
    Ok(format) ->
      case list.contains(log_formats, string.lowercase(string.trim(format))) {
        True -> []
        False -> [
          "RP_LOG_FORMAT: expected text or json, got \"" <> format <> "\"",
        ]
      }
    Error(Nil) -> []
  }
  list.flatten([ints, bools, level, format, secrets])
}

/// Secrets that can also be given as a file with `<NAME>_FILE`, so that they
/// do not appear in the process environment (`docker inspect`,
/// `/proc/<pid>/environ`).
pub const secret_env_vars = [
  "RP_ADMIN_METRICS_TOKEN",
  "RP_ADMIN_SECRET_KEY_BASE",
  "RP_AUTH_OIDC_CLIENT_SECRET",
  "RP_BOOTSTRAP_ADMIN_PASSWORD",
]

/// The content of a secret file, without its trailing line break.
pub fn read_secret_file(path: String) -> Result(String, String) {
  case simplifile.read(path) {
    Ok(content) ->
      Ok(case string.ends_with(content, "\r\n") {
        True -> string.drop_end(content, 2)
        False ->
          case string.ends_with(content, "\n") {
            True -> string.drop_end(content, 1)
            False -> content
          }
      })
    Error(e) ->
      Error("cannot read " <> path <> ": " <> simplifile.describe_error(e))
  }
}

pub const log_formats = ["text", "json"]

pub const log_levels = ["debug", "info", "warning", "error", "critical", "none"]

/// Applies `RP_*` environment variable overrides. `get` is injectable for
/// testing. Values are checked by `env_errors` first: add new integer and
/// boolean variables to `int_env_vars` / `bool_env_vars`.
pub fn apply_env(
  config: Config,
  get: fn(String) -> Result(String, Nil),
) -> Config {
  let s = fn(name, current) { get(name) |> result.unwrap(current) }
  // NAME, or the content of the file named by NAME_FILE (Docker and
  // Kubernetes secrets), without its trailing line break
  let secret = fn(name, current) {
    case get(name <> "_FILE") {
      Ok(path) -> read_secret_file(path) |> result.unwrap(current)
      Error(Nil) -> s(name, current)
    }
  }
  let i = fn(name, current) {
    get(name) |> result.try(parse_int) |> result.unwrap(current)
  }
  let b = fn(name, current) {
    get(name) |> result.try(parse_bool) |> result.unwrap(current)
  }
  let l = fn(name, current) {
    case get(name) {
      Ok(value) ->
        value
        |> string.split(",")
        |> list.map(string.trim)
        |> list.filter(fn(v) { v != "" })
      Error(Nil) -> current
    }
  }
  let Config(
    server:,
    admin:,
    storage:,
    local_auth:,
    oidc:,
    header_auth:,
    api:,
    access_log:,
    log:,
  ) = config
  Config(
    log: LogConfig(
      level: s("RP_LOG_LEVEL", log.level) |> string.trim |> string.lowercase,
      format: s("RP_LOG_FORMAT", log.format) |> string.trim |> string.lowercase,
    ),
    access_log: AccessLogConfig(
      enabled: b("RP_ACCESS_LOG_ENABLED", access_log.enabled),
      format: s("RP_ACCESS_LOG_FORMAT", access_log.format),
      escape: s("RP_ACCESS_LOG_ESCAPE", access_log.escape),
      output: s("RP_ACCESS_LOG_OUTPUT", access_log.output),
      anonymize_ip: s("RP_ACCESS_LOG_ANONYMIZE_IP", access_log.anonymize_ip),
      log_query: b("RP_ACCESS_LOG_LOG_QUERY", access_log.log_query),
      trusted_proxies: l(
        "RP_ACCESS_LOG_TRUSTED_PROXIES",
        access_log.trusted_proxies,
      ),
      max_bytes: i("RP_ACCESS_LOG_MAX_BYTES", access_log.max_bytes),
      max_files: i("RP_ACCESS_LOG_MAX_FILES", access_log.max_files),
      compress: b("RP_ACCESS_LOG_COMPRESS", access_log.compress),
      redirect: listener_env(access_log.redirect, "REDIRECT", s, b),
      admin: listener_env(access_log.admin, "ADMIN", s, b),
      api: listener_env(access_log.api, "API", s, b),
    ),
    api: ApiConfig(
      enabled: b("RP_API_ENABLED", api.enabled),
      listen: s("RP_API_LISTEN", api.listen),
      port: i("RP_API_PORT", api.port),
      public_url: s("RP_API_PUBLIC_URL", api.public_url),
      token_ttl: i("RP_API_TOKEN_TTL", api.token_ttl),
      max_body_bytes: i("RP_API_MAX_BODY_BYTES", api.max_body_bytes),
      require_if_match: b("RP_API_REQUIRE_IF_MATCH", api.require_if_match),
      oauth: ApiOAuthConfig(
        enabled: b("RP_API_OAUTH_ENABLED", api.oauth.enabled),
        issuer: s("RP_API_OAUTH_ISSUER", api.oauth.issuer),
        audience: s("RP_API_OAUTH_AUDIENCE", api.oauth.audience),
        scope_claim: s("RP_API_OAUTH_SCOPE_CLAIM", api.oauth.scope_claim),
        require_at_jwt: b(
          "RP_API_OAUTH_REQUIRE_AT_JWT",
          api.oauth.require_at_jwt,
        ),
        read_scope: s("RP_API_OAUTH_READ_SCOPE", api.oauth.read_scope),
        write_scope: s("RP_API_OAUTH_WRITE_SCOPE", api.oauth.write_scope),
        ops_scope: s("RP_API_OAUTH_OPS_SCOPE", api.oauth.ops_scope),
        audit_scope: s("RP_API_OAUTH_AUDIT_SCOPE", api.oauth.audit_scope),
      ),
    ),
    server: ServerConfig(
      listen: s("RP_SERVER_LISTEN", server.listen),
      port: i("RP_SERVER_PORT", server.port),
      cache_max_age: i("RP_SERVER_CACHE_MAX_AGE", server.cache_max_age),
      shutdown_grace: i("RP_SERVER_SHUTDOWN_GRACE", server.shutdown_grace),
      trailing_slash: s("RP_SERVER_TRAILING_SLASH", server.trailing_slash)
        |> string.lowercase,
      fallback_url: s("RP_SERVER_FALLBACK_URL", server.fallback_url),
      not_found_body: s("RP_SERVER_NOT_FOUND_BODY", server.not_found_body),
      health_path: s("RP_SERVER_HEALTH_PATH", server.health_path),
      metrics_path: s("RP_SERVER_METRICS_PATH", server.metrics_path),
      max_path_bytes: i("RP_SERVER_MAX_PATH_BYTES", server.max_path_bytes),
      max_request_body_bytes: i(
        "RP_SERVER_MAX_REQUEST_BODY_BYTES",
        server.max_request_body_bytes,
      ),
      max_connections_per_ip: i(
        "RP_SERVER_MAX_CONNECTIONS_PER_IP",
        server.max_connections_per_ip,
      ),
      https_redirect: b("RP_SERVER_HTTPS_REDIRECT", server.https_redirect),
      upstream: s("RP_SERVER_UPSTREAM", server.upstream),
      upstream_timeout: i("RP_SERVER_UPSTREAM_TIMEOUT", server.upstream_timeout),
      upstream_tls_verify: b(
        "RP_SERVER_UPSTREAM_TLS_VERIFY",
        server.upstream_tls_verify,
      ),
    ),
    admin: AdminConfig(
      enabled: b("RP_ADMIN_ENABLED", admin.enabled),
      listen: s("RP_ADMIN_LISTEN", admin.listen),
      port: i("RP_ADMIN_PORT", admin.port),
      public_url: s("RP_ADMIN_PUBLIC_URL", admin.public_url),
      secret_key_base: secret("RP_ADMIN_SECRET_KEY_BASE", admin.secret_key_base),
      session_ttl: i("RP_ADMIN_SESSION_TTL", admin.session_ttl),
      session_idle_timeout: i(
        "RP_ADMIN_SESSION_IDLE_TIMEOUT",
        admin.session_idle_timeout,
      ),
      metrics_token: secret("RP_ADMIN_METRICS_TOKEN", admin.metrics_token),
    ),
    storage: StorageConfig(
      data_dir: s("RP_STORAGE_DATA_DIR", storage.data_dir),
      backups: i("RP_STORAGE_BACKUPS", storage.backups),
      watch_interval: i("RP_STORAGE_WATCH_INTERVAL", storage.watch_interval),
      audit_max_bytes: i("RP_STORAGE_AUDIT_MAX_BYTES", storage.audit_max_bytes),
      audit_files: i("RP_STORAGE_AUDIT_FILES", storage.audit_files),
    ),
    local_auth: LocalAuthConfig(enabled: b(
      "RP_AUTH_LOCAL_ENABLED",
      local_auth.enabled,
    )),
    oidc: OidcConfig(
      enabled: b("RP_AUTH_OIDC_ENABLED", oidc.enabled),
      issuer: s("RP_AUTH_OIDC_ISSUER", oidc.issuer),
      client_id: s("RP_AUTH_OIDC_CLIENT_ID", oidc.client_id),
      client_secret: secret("RP_AUTH_OIDC_CLIENT_SECRET", oidc.client_secret),
      scopes: l("RP_AUTH_OIDC_SCOPES", oidc.scopes),
      allowed_emails: l("RP_AUTH_OIDC_ALLOWED_EMAILS", oidc.allowed_emails),
      allowed_domains: l("RP_AUTH_OIDC_ALLOWED_DOMAINS", oidc.allowed_domains),
      allowed_groups: l("RP_AUTH_OIDC_ALLOWED_GROUPS", oidc.allowed_groups),
      allow_any_account: b(
        "RP_AUTH_OIDC_ALLOW_ANY_ACCOUNT",
        oidc.allow_any_account,
      ),
      groups_claim: s("RP_AUTH_OIDC_GROUPS_CLAIM", oidc.groups_claim),
      button_label: s("RP_AUTH_OIDC_BUTTON_LABEL", oidc.button_label),
      logout_at_provider: b(
        "RP_AUTH_OIDC_LOGOUT_AT_PROVIDER",
        oidc.logout_at_provider,
      ),
      admin_groups: l("RP_AUTH_OIDC_ADMIN_GROUPS", oidc.admin_groups),
      editor_groups: l("RP_AUTH_OIDC_EDITOR_GROUPS", oidc.editor_groups),
      viewer_groups: l("RP_AUTH_OIDC_VIEWER_GROUPS", oidc.viewer_groups),
      default_role: s("RP_AUTH_OIDC_DEFAULT_ROLE", oidc.default_role),
    ),
    header_auth: HeaderAuthConfig(
      enabled: b("RP_AUTH_HEADER_ENABLED", header_auth.enabled),
      user_header: s("RP_AUTH_HEADER_USER_HEADER", header_auth.user_header)
        |> string.lowercase,
      email_header: s("RP_AUTH_HEADER_EMAIL_HEADER", header_auth.email_header)
        |> string.lowercase,
      trusted_proxies: l(
        "RP_AUTH_HEADER_TRUSTED_PROXIES",
        header_auth.trusted_proxies,
      ),
      role_header: s("RP_AUTH_HEADER_ROLE_HEADER", header_auth.role_header)
        |> string.lowercase,
      default_role: s("RP_AUTH_HEADER_DEFAULT_ROLE", header_auth.default_role),
    ),
  )
}

fn listener_env(
  l: ListenerLogConfig,
  name: String,
  s: fn(String, String) -> String,
  b: fn(String, Bool) -> Bool,
) -> ListenerLogConfig {
  let var = fn(k) { "RP_ACCESS_LOG_" <> name <> "_" <> k }
  ListenerLogConfig(
    enabled: b(var("ENABLED"), l.enabled),
    format: s(var("FORMAT"), l.format),
    output: s(var("OUTPUT"), l.output),
  )
}
