//// Configuration types, defaults and derived paths. Loading is done by
//// `config/loader`: the TOML file (`config/file`), then `RP_*` environment
//// overrides (`config/env`), then checks (`config/validate`).

import gleam/int
import redirect_proxy/listener.{
  type Listener, AdminListener, ApiListener, RedirectListener,
}

pub type Config {
  Config(
    server: ServerConfig,
    admin: AdminConfig,
    storage: StorageConfig,
    local_auth: LocalAuthConfig,
    oidc: OidcConfig,
    header_auth: HeaderAuthConfig,
    api: ApiConfig,
    access_log: AccessLogConfig,
    log: LogConfig,
  )
}

/// The application log (not the access log).
pub type LogConfig {
  LogConfig(
    /// debug, info, warning, error, critical or none.
    level: String,
    /// "text", or "json" for one JSON object per line.
    format: String,
  )
}

/// Access (traffic) logs of the listeners.
pub type AccessLogConfig {
  AccessLogConfig(
    /// Master switch for every listener.
    enabled: Bool,
    /// Default format of every listener: a preset (`combined`, `common`,
    /// `json`) or a template with nginx style `$variables`.
    format: String,
    /// Escaping of variable values in custom templates: `default` (nginx
    /// `\xHH`), `json` or `none`. Presets choose their own.
    escape: String,
    /// `stdout`, `stderr` or a file path.
    output: String,
    /// `truncate` (IPv4 /24, IPv6 /48) or `none`.
    anonymize_ip: String,
    /// Whether query strings are logged (request, referer, location).
    log_query: Bool,
    /// Peers whose `X-Forwarded-For` / `X-Real-IP` headers are trusted.
    trusted_proxies: List(String),
    /// Size based rotation of file output (0: no rotation).
    max_bytes: Int,
    max_files: Int,
    compress: Bool,
    redirect: ListenerLogConfig,
    admin: ListenerLogConfig,
    api: ListenerLogConfig,
  )
}

/// Per listener access log settings. Empty `format` / `output` inherit the
/// `access_log` defaults.
pub type ListenerLogConfig {
  ListenerLogConfig(enabled: Bool, format: String, output: String)
}

pub fn listener_log(
  cfg: AccessLogConfig,
  listener: Listener,
) -> ListenerLogConfig {
  case listener {
    RedirectListener -> cfg.redirect
    AdminListener -> cfg.admin
    ApiListener -> cfg.api
  }
}

/// Effective format of a listener's access log.
pub fn access_log_format(cfg: AccessLogConfig, listener: Listener) -> String {
  case listener_log(cfg, listener).format {
    "" -> cfg.format
    format -> format
  }
}

/// Effective output of a listener's access log.
pub fn access_log_output(cfg: AccessLogConfig, listener: Listener) -> String {
  case listener_log(cfg, listener).output {
    "" -> cfg.output
    output -> output
  }
}

/// Whether a listener's requests are logged.
pub fn access_log_enabled(cfg: AccessLogConfig, listener: Listener) -> Bool {
  cfg.enabled && listener_log(cfg, listener).enabled
}

pub type ServerConfig {
  ServerConfig(
    listen: String,
    port: Int,
    /// `Cache-Control: max-age` sent with permanent (301/308) redirects.
    cache_max_age: Int,
    /// Optional URL unmatched requests are redirected to (302).
    fallback_url: String,
    /// Body sent with 404 responses.
    not_found_body: String,
    /// On SIGTERM, seconds during which /readyz answers 503 and connections
    /// are closed after each response, before the node stops.
    shutdown_grace: Int,
    /// "strict": `/docs/` and `/docs` are different paths; "ignore": a miss
    /// is retried with the trailing slash added or removed.
    trailing_slash: String,
    /// Optional path answered by the redirect listener itself before any
    /// rule: 200 while serving, 503 while draining before a stop ("": off).
    health_path: String,
    /// Requests whose path is longer than this many bytes get a 414.
    max_path_bytes: Int,
    /// Plain HTTP requests are redirected to the same URL over HTTPS before
    /// any rule (requests a proxy marks `X-Forwarded-Proto: https` are not).
    https_redirect: Bool,
  )
}

pub type AdminConfig {
  AdminConfig(
    enabled: Bool,
    listen: String,
    port: Int,
    /// Public base URL of the admin (used to build the OIDC redirect URI).
    public_url: String,
    /// Secret used to sign cookies. Generated and persisted in the data
    /// directory when empty.
    secret_key_base: String,
    session_ttl: Int,
    /// A session unused for this many seconds ends (0: never).
    session_idle_timeout: Int,
    /// Bearer token required by `/metrics` ("": public).
    metrics_token: String,
  )
}

pub type StorageConfig {
  StorageConfig(
    data_dir: String,
    backups: Int,
    /// Seconds between checks of the redirections file for changes made
    /// outside the server (0: never, reload with SIGHUP instead).
    watch_interval: Int,
    /// Size at which `audit.jsonl` is rotated (0: never).
    audit_max_bytes: Int,
    /// Rotated audit files kept (`audit.jsonl.1` is the newest).
    audit_files: Int,
  )
}

pub type LocalAuthConfig {
  LocalAuthConfig(enabled: Bool)
}

pub type OidcConfig {
  OidcConfig(
    enabled: Bool,
    issuer: String,
    client_id: String,
    client_secret: String,
    scopes: List(String),
    allowed_emails: List(String),
    allowed_domains: List(String),
    allowed_groups: List(String),
    groups_claim: String,
    button_label: String,
    /// On logout, also end the session at the provider (its
    /// `end_session_endpoint`), then come back to the login page.
    logout_at_provider: Bool,
    /// Groups (`groups_claim`) given a role: the highest one a user's
    /// groups give applies.
    admin_groups: List(String),
    editor_groups: List(String),
    viewer_groups: List(String),
    /// The role of a user in none of these groups: admin, editor or viewer.
    default_role: String,
  )
}

pub type ApiConfig {
  ApiConfig(
    enabled: Bool,
    /// Address of the API listener. Empty: same as `admin.listen`.
    listen: String,
    /// Port of the API. `0` or `admin.port`: the API shares the admin
    /// listener. Any other port: the API gets its own listener (and the admin
    /// listener no longer serves `/api`).
    port: Int,
    /// Externally visible base URL of the API (documentation and examples).
    /// Defaults to the admin public URL when the API shares its listener.
    public_url: String,
    /// Lifetime of access tokens issued by the built-in token endpoint.
    token_ttl: Int,
    /// Maximum request body size of API calls (bulk imports).
    max_body_bytes: Int,
    oauth: ApiOAuthConfig,
  )
}

/// Validation of JWT access tokens issued by an external OAuth2/OIDC server.
pub type ApiOAuthConfig {
  ApiOAuthConfig(
    enabled: Bool,
    issuer: String,
    audience: String,
    scope_claim: String,
    read_scope: String,
    write_scope: String,
    ops_scope: String,
    audit_scope: String,
  )
}

pub type HeaderAuthConfig {
  HeaderAuthConfig(
    enabled: Bool,
    user_header: String,
    email_header: String,
    trusted_proxies: List(String),
    /// A header with the role of the user (viewer, editor or admin); "":
    /// every proxy user gets `default_role`.
    role_header: String,
    default_role: String,
  )
}

pub fn default() -> Config {
  Config(
    server: ServerConfig(
      listen: "0.0.0.0",
      port: 8080,
      cache_max_age: 3600,
      shutdown_grace: 5,
      trailing_slash: "strict",
      fallback_url: "",
      not_found_body: "Not Found",
      health_path: "",
      max_path_bytes: 8192,
      https_redirect: False,
    ),
    admin: AdminConfig(
      enabled: True,
      listen: "127.0.0.1",
      port: 8081,
      public_url: "http://localhost:8081",
      secret_key_base: "",
      session_ttl: 28_800,
      session_idle_timeout: 3600,
      metrics_token: "",
    ),
    storage: StorageConfig(
      data_dir: "./data",
      backups: 10,
      watch_interval: 0,
      audit_max_bytes: 10_485_760,
      audit_files: 5,
    ),
    local_auth: LocalAuthConfig(enabled: True),
    oidc: OidcConfig(
      enabled: False,
      issuer: "",
      client_id: "",
      client_secret: "",
      scopes: ["openid", "email", "profile"],
      allowed_emails: [],
      allowed_domains: [],
      allowed_groups: [],
      groups_claim: "groups",
      admin_groups: [],
      editor_groups: [],
      viewer_groups: [],
      default_role: "admin",
      button_label: "Sign in with SSO",
      logout_at_provider: False,
    ),
    header_auth: HeaderAuthConfig(
      enabled: False,
      user_header: "x-forwarded-user",
      email_header: "x-forwarded-email",
      trusted_proxies: ["127.0.0.1/32", "::1/128"],
      role_header: "",
      default_role: "admin",
    ),
    api: ApiConfig(
      enabled: True,
      listen: "",
      port: 0,
      public_url: "",
      token_ttl: 3600,
      max_body_bytes: 10_485_760,
      oauth: ApiOAuthConfig(
        enabled: False,
        issuer: "",
        audience: "redirect-proxy",
        scope_claim: "scope",
        read_scope: "redirects:read",
        write_scope: "redirects:write",
        ops_scope: "redirects:ops",
        audit_scope: "audit:read",
      ),
    ),
    log: LogConfig(level: "info", format: "text"),
    access_log: AccessLogConfig(
      enabled: True,
      format: "combined",
      escape: "default",
      output: "stdout",
      anonymize_ip: "truncate",
      log_query: False,
      trusted_proxies: [],
      max_bytes: 0,
      max_files: 7,
      compress: True,
      redirect: inherit,
      admin: inherit,
      api: inherit,
    ),
  )
}

const inherit = ListenerLogConfig(enabled: True, format: "", output: "")

pub fn rules_path(config: Config) -> String {
  config.storage.data_dir <> "/redirects.json"
}

pub fn users_path(config: Config) -> String {
  config.storage.data_dir <> "/users.json"
}

pub fn audit_path(config: Config) -> String {
  config.storage.data_dir <> "/audit.jsonl"
}

pub fn backups_dir(config: Config) -> String {
  config.storage.data_dir <> "/backups"
}

/// Effective port of the API (`api.port`, or `admin.port` when 0).
pub fn api_port(config: Config) -> Int {
  case config.api.port {
    0 -> config.admin.port
    port -> port
  }
}

/// Effective address of the API (`api.listen`, or `admin.listen` when empty).
pub fn api_listen(config: Config) -> String {
  case config.api.listen {
    "" -> config.admin.listen
    listen -> listen
  }
}

/// Whether the API runs on its own listener: it uses another port than the
/// admin UI, or the admin UI is disabled.
pub fn api_dedicated(config: Config) -> Bool {
  config.api.enabled
  && { !config.admin.enabled || api_port(config) != config.admin.port }
}

/// Whether the admin listener also serves the API (same port).
pub fn api_on_admin(config: Config) -> Bool {
  config.api.enabled && config.admin.enabled && !api_dedicated(config)
}

/// Base URL clients use to reach the API.
pub fn api_public_url(config: Config) -> String {
  case config.api.public_url, api_dedicated(config) {
    "", False -> config.admin.public_url
    "", True -> "http://localhost:" <> int.to_string(api_port(config))
    url, _ -> url
  }
}

pub fn api_clients_path(config: Config) -> String {
  config.storage.data_dir <> "/api_clients.json"
}

pub fn secret_path(config: Config) -> String {
  config.storage.data_dir <> "/secret_key_base"
}

/// Whether the redirect listener ignores trailing slashes on a miss.
pub fn ignore_trailing_slash(config: Config) -> Bool {
  config.server.trailing_slash == "ignore"
}
