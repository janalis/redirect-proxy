//// Configuration: TOML file with `RP_*` environment variable overrides.

import envoy
import gleam/bool
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/access_log_format
import redirect_proxy/ffi
import redirect_proxy/listener.{
  type Listener, AdminListener, ApiListener, RedirectListener,
}
import simplifile
import tom.{type Toml}

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
  )
}

pub type StorageConfig {
  StorageConfig(data_dir: String, backups: Int)
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
  )
}

pub type HeaderAuthConfig {
  HeaderAuthConfig(
    enabled: Bool,
    user_header: String,
    email_header: String,
    trusted_proxies: List(String),
  )
}

pub fn default() -> Config {
  Config(
    server: ServerConfig(
      listen: "0.0.0.0",
      port: 8080,
      cache_max_age: 3600,
      shutdown_grace: 5,
      fallback_url: "",
      not_found_body: "Not Found",
    ),
    admin: AdminConfig(
      enabled: True,
      listen: "127.0.0.1",
      port: 8081,
      public_url: "http://localhost:8081",
      secret_key_base: "",
      session_ttl: 28_800,
      session_idle_timeout: 3600,
    ),
    storage: StorageConfig(data_dir: "./data", backups: 10),
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
      button_label: "Sign in with SSO",
    ),
    header_auth: HeaderAuthConfig(
      enabled: False,
      user_header: "x-forwarded-user",
      email_header: "x-forwarded-email",
      trusted_proxies: ["127.0.0.1/32", "::1/128"],
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
      ),
    ),
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

/// Loads the configuration. When `path` is empty only defaults and
/// environment variables are used.
pub fn load(path: String) -> Result(Config, String) {
  use toml <- result.try(read_toml(path))
  load_parsed(toml)
}

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
  "admin.session_ttl",
  "api.enabled",
  "api.listen",
  "api.max_body_bytes",
  "api.oauth.audience",
  "api.oauth.enabled",
  "api.oauth.issuer",
  "api.oauth.ops_scope",
  "api.oauth.read_scope",
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
  "auth.oidc.issuer",
  "auth.oidc.scopes",
  "server.cache_max_age",
  "server.fallback_url",
  "server.listen",
  "server.not_found_body",
  "server.port",
  "server.shutdown_grace",
  "storage.backups",
  "storage.data_dir",
]

fn is_http_url(url: String) -> Bool {
  let lower = string.lowercase(url)
  { string.starts_with(lower, "http://") && string.length(url) > 7 }
  || { string.starts_with(lower, "https://") && string.length(url) > 8 }
}

/// Things that are allowed but probably wrong, reported by `check-config`:
/// unknown keys and an admin listening beyond the loopback interface.
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
  list.append(unknown, exposed)
}

fn is_loopback(address: String) -> Bool {
  address == "localhost"
  || address == "::1"
  || string.starts_with(address, "127.")
}

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
  Ok(Config(
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
      oauth: ApiOAuthConfig(
        enabled: ao_enabled,
        issuer: ao_issuer,
        audience: ao_audience,
        scope_claim: ao_scope_claim,
        read_scope:,
        write_scope:,
        ops_scope:,
      ),
    ),
    server: ServerConfig(
      listen: server_listen,
      port: server_port,
      cache_max_age:,
      shutdown_grace:,
      fallback_url:,
      not_found_body:,
    ),
    admin: AdminConfig(
      enabled: admin_enabled,
      listen: admin_listen,
      port: admin_port,
      public_url:,
      secret_key_base:,
      session_ttl:,
      session_idle_timeout:,
    ),
    storage: StorageConfig(data_dir:, backups:),
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
    ),
    header_auth: HeaderAuthConfig(
      enabled: header_enabled,
      user_header: string.lowercase(user_header),
      email_header: string.lowercase(email_header),
      trusted_proxies:,
    ),
  ))
}

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
  "RP_SERVER_PORT",
  "RP_SERVER_SHUTDOWN_GRACE",
  "RP_STORAGE_BACKUPS",
]

pub const bool_env_vars = [
  "RP_ACCESS_LOG_COMPRESS",
  "RP_ACCESS_LOG_ENABLED",
  "RP_ACCESS_LOG_LOG_QUERY",
  "RP_ADMIN_ENABLED",
  "RP_API_ENABLED",
  "RP_API_OAUTH_ENABLED",
  "RP_AUTH_HEADER_ENABLED",
  "RP_AUTH_LOCAL_ENABLED",
  "RP_AUTH_OIDC_ENABLED",
]

/// The overrides of `int_env_vars`, `bool_env_vars` and `RP_LOG_LEVEL` whose
/// value is invalid, described.
pub fn env_errors(get: fn(String) -> Result(String, Nil)) -> List(String) {
  let ints =
    list.filter_map(int_env_vars, fn(name) {
      case get(name) {
        Ok(value) ->
          case int.parse(string.trim(value)) {
            Ok(_) -> Error(Nil)
            Error(Nil) ->
              Ok(name <> ": expected an integer, got \"" <> value <> "\"")
          }
        Error(Nil) -> Error(Nil)
      }
    })
  let bools =
    list.filter_map(bool_env_vars, fn(name) {
      case get(name) |> result.map(fn(v) { string.lowercase(string.trim(v)) }) {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") -> Error(Nil)
        Ok("0") | Ok("false") | Ok("no") | Ok("off") -> Error(Nil)
        Ok(_) -> {
          let assert Ok(value) = get(name)
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
  list.flatten([ints, bools, level, secrets])
}

/// Secrets that can also be given as a file with `<NAME>_FILE`, so that they
/// do not appear in the process environment (`docker inspect`,
/// `/proc/<pid>/environ`).
pub const secret_env_vars = [
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
    get(name)
    |> result.try(fn(v) { int.parse(string.trim(v)) })
    |> result.unwrap(current)
  }
  let b = fn(name, current) {
    case get(name) |> result.map(fn(v) { string.lowercase(string.trim(v)) }) {
      Ok("1") | Ok("true") | Ok("yes") | Ok("on") -> True
      Ok("0") | Ok("false") | Ok("no") | Ok("off") -> False
      _ -> current
    }
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
  ) = config
  Config(
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
      oauth: ApiOAuthConfig(
        enabled: b("RP_API_OAUTH_ENABLED", api.oauth.enabled),
        issuer: s("RP_API_OAUTH_ISSUER", api.oauth.issuer),
        audience: s("RP_API_OAUTH_AUDIENCE", api.oauth.audience),
        scope_claim: s("RP_API_OAUTH_SCOPE_CLAIM", api.oauth.scope_claim),
        read_scope: s("RP_API_OAUTH_READ_SCOPE", api.oauth.read_scope),
        write_scope: s("RP_API_OAUTH_WRITE_SCOPE", api.oauth.write_scope),
        ops_scope: s("RP_API_OAUTH_OPS_SCOPE", api.oauth.ops_scope),
      ),
    ),
    server: ServerConfig(
      listen: s("RP_SERVER_LISTEN", server.listen),
      port: i("RP_SERVER_PORT", server.port),
      cache_max_age: i("RP_SERVER_CACHE_MAX_AGE", server.cache_max_age),
      shutdown_grace: i("RP_SERVER_SHUTDOWN_GRACE", server.shutdown_grace),
      fallback_url: s("RP_SERVER_FALLBACK_URL", server.fallback_url),
      not_found_body: s("RP_SERVER_NOT_FOUND_BODY", server.not_found_body),
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
    ),
    storage: StorageConfig(
      data_dir: s("RP_STORAGE_DATA_DIR", storage.data_dir),
      backups: i("RP_STORAGE_BACKUPS", storage.backups),
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
      groups_claim: s("RP_AUTH_OIDC_GROUPS_CLAIM", oidc.groups_claim),
      button_label: s("RP_AUTH_OIDC_BUTTON_LABEL", oidc.button_label),
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
    ),
  )
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

// --- data files -------------------------------------------------------------

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

// --- TOML helpers -----------------------------------------------------------

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
