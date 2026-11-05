//// Configuration: TOML file with `RP_*` environment variable overrides.

import envoy
import gleam/bool
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/ffi
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
  )
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
  )
}

/// Loads the configuration. When `path` is empty only defaults and
/// environment variables are used.
pub fn load(path: String) -> Result(Config, String) {
  use toml <- result.try(case path {
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
  })
  use config <- result.try(from_toml(toml))
  let config = apply_env(config, envoy.get)
  use config <- result.try(validate(config))
  Ok(config)
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
  Ok(Config(
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

/// Applies `RP_*` environment variable overrides. `get` is injectable for
/// testing.
pub fn apply_env(
  config: Config,
  get: fn(String) -> Result(String, Nil),
) -> Config {
  let s = fn(name, current) { get(name) |> result.unwrap(current) }
  let i = fn(name, current) {
    get(name) |> result.try(int.parse) |> result.unwrap(current)
  }
  let b = fn(name, current) {
    case get(name) |> result.map(string.lowercase) {
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
  let Config(server:, admin:, storage:, local_auth:, oidc:, header_auth:, api:) =
    config
  Config(
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
      fallback_url: s("RP_SERVER_FALLBACK_URL", server.fallback_url),
      not_found_body: s("RP_SERVER_NOT_FOUND_BODY", server.not_found_body),
    ),
    admin: AdminConfig(
      enabled: b("RP_ADMIN_ENABLED", admin.enabled),
      listen: s("RP_ADMIN_LISTEN", admin.listen),
      port: i("RP_ADMIN_PORT", admin.port),
      public_url: s("RP_ADMIN_PUBLIC_URL", admin.public_url),
      secret_key_base: s("RP_ADMIN_SECRET_KEY_BASE", admin.secret_key_base),
      session_ttl: i("RP_ADMIN_SESSION_TTL", admin.session_ttl),
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
      ..oidc,
      enabled: b("RP_AUTH_OIDC_ENABLED", oidc.enabled),
      issuer: s("RP_AUTH_OIDC_ISSUER", oidc.issuer),
      client_id: s("RP_AUTH_OIDC_CLIENT_ID", oidc.client_id),
      client_secret: s("RP_AUTH_OIDC_CLIENT_SECRET", oidc.client_secret),
      scopes: l("RP_AUTH_OIDC_SCOPES", oidc.scopes),
      allowed_emails: l("RP_AUTH_OIDC_ALLOWED_EMAILS", oidc.allowed_emails),
      allowed_domains: l("RP_AUTH_OIDC_ALLOWED_DOMAINS", oidc.allowed_domains),
      allowed_groups: l("RP_AUTH_OIDC_ALLOWED_GROUPS", oidc.allowed_groups),
    ),
    header_auth: HeaderAuthConfig(
      ..header_auth,
      enabled: b("RP_AUTH_HEADER_ENABLED", header_auth.enabled),
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
    config.admin.session_ttl < 60,
    Error("admin.session_ttl must be at least 60 seconds"),
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
  Ok(config)
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
