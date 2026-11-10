//// Checks of a loaded configuration, and `check-config` warnings.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/access_log_format
import redirect_proxy/config.{
  type AccessLogConfig, type Config, access_log_format, access_log_output,
  api_dedicated, api_listen, api_on_admin, api_port, parse_upstream,
} as _
import redirect_proxy/config/env as config_env
import redirect_proxy/config/file.{unknown_keys} as _
import redirect_proxy/ffi
import redirect_proxy/listener
import redirect_proxy/metrics_endpoint
import redirect_proxy/role
import tom.{type Toml}

fn is_http_url(url: String) -> Bool {
  let lower = string.lowercase(url)
  { string.starts_with(lower, "http://") && string.length(url) > 7 }
  || { string.starts_with(lower, "https://") && string.length(url) > 8 }
}

/// An `http://` URL whose host is not the loopback interface.
/// A URL whose host is not this machine's (`localhost` or a loopback
/// address): the admin is reached through something else.
fn remote_url(url: String) -> Bool {
  case uri.parse(url) {
    Ok(uri.Uri(host: Some(host), ..)) ->
      string.lowercase(host) != "localhost" && !ffi.is_loopback_address(host)
    _ -> False
  }
}

fn plain_http_remote(url: String) -> Bool {
  case uri.parse(url) {
    Ok(uri.Uri(scheme: Some(scheme), host: Some(host), ..)) ->
      string.lowercase(scheme) == "http" && !ffi.is_loopback_address(host)
    _ -> False
  }
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
      <> ": keep it behind a firewall or a reverse proxy",
    ]
    False -> []
  }
  list.flatten([unknown, exposed, runtime_warnings(config)])
}

/// Warnings also logged when the server starts.
pub fn runtime_warnings(config: Config) -> List(String) {
  let oidc = config.oidc
  let admin = config.admin
  list.flatten([
    case open_oidc(config) {
      True -> [
        "auth.oidc has no allowed_emails, allowed_domains or allowed_groups and allow_any_account is set: every account of the provider can sign in to the admin",
      ]
      False -> []
    },
    case
      admin.session_idle_timeout > 0
      && admin.session_idle_timeout >= admin.session_ttl
    {
      True -> [
        "admin.session_idle_timeout is not shorter than admin.session_ttl: sessions end at session_ttl before they can be idle that long",
      ]
      False -> []
    },
    case
      oidc.enabled
      && oidc.default_role == "admin"
      && {
        oidc.admin_groups != []
        || oidc.editor_groups != []
        || oidc.viewer_groups != []
      }
    {
      True -> [
        "auth.oidc.default_role is admin while role groups are set: users in none of these groups are administrators; set default_role = \"viewer\" (or editor)",
      ]
      False -> []
    },
    case oidc.enabled && plain_http_remote(oidc.issuer) {
      True -> [
        "auth.oidc.issuer is plain http:// on another host: its signing keys and tokens can be changed in transit; use https://",
      ]
      False -> []
    },
    case
      config.api.oauth.enabled && plain_http_remote(config.api.oauth.issuer)
    {
      True -> [
        "api.oauth.issuer is plain http:// on another host: its signing keys can be changed in transit, letting anyone on the path forge access tokens; use https://",
      ]
      False -> []
    },
    case
      oidc.enabled
      && !config.local_auth.enabled
      && oidc.admin_groups == []
      && oidc.default_role != "admin"
      && !header_gives_admin(config)
    {
      True -> [
        "auth.oidc gives no one the admin role and local accounts are disabled: nobody can manage users or API clients; set admin_groups (or default_role = \"admin\")",
      ]
      False -> []
    },
    case
      config.header_auth.enabled
      && !config.local_auth.enabled
      && !oidc_gives_admin(config)
      && !header_gives_admin(config)
    {
      True -> [
        "auth.header gives no one the admin role and local accounts are disabled: nobody can manage users or API clients; set role_header (or default_role = \"admin\")",
      ]
      False -> []
    },
    case
      config.api.oauth.enabled
      && oidc.enabled
      && config.api.oauth.audience == oidc.client_id
    {
      True -> [
        "api.oauth.audience is the auth.oidc client_id: use an audience of its own for API access tokens, so that tokens issued for the admin sign-in are not meant for the API",
      ]
      False -> []
    },
    case
      admin.enabled
      && remote_url(admin.public_url)
      && config.access_log.trusted_proxies == []
    {
      True -> [
        "admin.public_url is not on this machine but access_log.trusted_proxies is empty: behind a reverse proxy every client has the proxy's address, so one client's failed sign-ins throttle sign-ins, API tokens and API calls for all; list the proxy's addresses in trusted_proxies",
      ]
      False -> []
    },
    case metrics_hidden(config) {
      True -> [
        "/metrics is not served: its listener is not on the loopback interface and admin.metrics_token is empty; set a token (at least 16 characters) for Prometheus to send",
      ]
      False -> []
    },
    case config.server.shutdown_grace >= 10 {
      True -> [
        "server.shutdown_grace is "
        <> int.to_string(config.server.shutdown_grace)
        <> " seconds: allow longer than that before the service manager kills the server (docker stop waits 10 seconds by default, the systemd unit 15)",
      ]
      False -> []
    },
  ])
}

/// `/metrics` is turned off for want of a token: its listener (the admin's,
/// or the API's without the admin) is not on the loopback interface.
fn metrics_hidden(config: Config) -> Bool {
  let listen = case config.admin.enabled, config.api.enabled {
    True, _ -> Ok(config.admin.listen)
    False, True -> Ok(api_listen(config))
    False, False -> Error(Nil)
  }
  case listen {
    Ok(listen) ->
      config.admin.metrics_token == ""
      && !metrics_endpoint.served_without_token(listen)
    Error(Nil) -> False
  }
}

/// OIDC sign-in with no list of who may sign in.
fn open_oidc(config: Config) -> Bool {
  let oidc = config.oidc
  oidc.enabled
  && oidc.allowed_emails == []
  && oidc.allowed_domains == []
  && oidc.allowed_groups == []
}

fn is_loopback(address: String) -> Bool {
  ffi.is_loopback_address(address)
}

pub fn validate(config: Config) -> Result(Config, String) {
  let port_ok = fn(p) { p >= 0 && p < 65_536 }
  let listen_ok = fn(name, address) {
    case ffi.valid_listen_address(address) {
      True -> Ok(Nil)
      False ->
        Error(
          name <> " must be an IP address or \"localhost\", not " <> address,
        )
    }
  }
  use Nil <- result.try(listen_ok("server.listen", config.server.listen))
  use Nil <- result.try(case config.admin.enabled {
    True -> listen_ok("admin.listen", config.admin.listen)
    False -> Ok(Nil)
  })
  use Nil <- result.try(case config.api.listen {
    "" -> Ok(Nil)
    address -> listen_ok("api.listen", address)
  })
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
    config.server.health_path != ""
      && !string.starts_with(config.server.health_path, "/"),
    Error("server.health_path must be empty or start with /"),
  )
  use <- bool.guard(
    config.server.metrics_path != ""
      && !string.starts_with(config.server.metrics_path, "/"),
    Error("server.metrics_path must be empty or start with /"),
  )
  use <- bool.guard(
    config.server.metrics_path != ""
      && config.server.metrics_path == config.server.health_path,
    Error("server.metrics_path and server.health_path must differ"),
  )
  // the redirect listener is public
  use <- bool.guard(
    config.server.metrics_path != "" && config.admin.metrics_token == "",
    Error(
      "server.metrics_path needs admin.metrics_token: the redirect listener is public",
    ),
  )
  use <- bool.guard(
    config.server.max_path_bytes < 256,
    Error("server.max_path_bytes must be at least 256"),
  )
  use <- bool.guard(
    config.server.max_request_body_bytes < 0,
    Error("server.max_request_body_bytes must be 0 (no limit) or more"),
  )
  // in seconds, turned into an Erlang timer: past about 49 days it would
  // crash the store at startup
  use <- bool.guard(
    config.storage.watch_interval < 0 || config.storage.watch_interval > 86_400,
    Error("storage.watch_interval must be between 0 (off) and 86400 seconds"),
  )
  use <- bool.guard(
    role.from_string(config.oidc.default_role) == Error(Nil),
    Error("auth.oidc.default_role must be viewer, editor or admin"),
  )
  use <- bool.guard(
    role.from_string(config.header_auth.default_role) == Error(Nil),
    Error("auth.header.default_role must be viewer, editor or admin"),
  )
  use <- bool.guard(
    config.storage.audit_max_bytes != 0
      && config.storage.audit_max_bytes < 65_536,
    Error("storage.audit_max_bytes must be 0 (never rotate) or at least 65536"),
  )
  use <- bool.guard(
    config.storage.audit_files < 0 || config.storage.audit_files > 100,
    Error("storage.audit_files must be between 0 and 100"),
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
  use Nil <- result.try(case config.server.upstream {
    "" -> Ok(Nil)
    url -> parse_upstream(url) |> result.replace(Nil)
  })
  use <- bool.guard(
    config.server.upstream != "" && config.server.fallback_url != "",
    Error(
      "server.upstream and server.fallback_url cannot both be set: unmatched requests go to the upstream",
    ),
  )
  use <- bool.guard(
    config.server.upstream_timeout < 1 || config.server.upstream_timeout > 3600,
    Error("server.upstream_timeout must be between 1 and 3600 seconds"),
  )
  use <- bool.guard(
    !is_http_url(config.admin.public_url),
    Error("admin.public_url must be an http:// or https:// URL"),
  )
  use <- bool.guard(
    config.api.public_url != "" && !is_http_url(config.api.public_url),
    Error("api.public_url must be empty or an http:// or https:// URL"),
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
    config.admin.metrics_token != ""
      && string.length(config.admin.metrics_token) < 16,
    Error("admin.metrics_token must be at least 16 characters long"),
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
    config.oidc.enabled && !is_http_url(config.oidc.issuer),
    Error("auth.oidc.issuer must be an http:// or https:// URL"),
  )
  use <- bool.guard(
    open_oidc(config) && !config.oidc.allow_any_account,
    Error(
      "auth.oidc needs allowed_emails, allowed_domains or allowed_groups (or allow_any_account = true): otherwise every account of the provider can sign in to the admin",
    ),
  )
  use <- bool.guard(
    config.header_auth.enabled
      && string.trim(config.header_auth.user_header) == ""
      && string.trim(config.header_auth.email_header) == "",
    Error(
      "auth.header needs user_header or email_header: with neither, nobody can sign in",
    ),
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
  use <- bool.guard(
    config.api.oauth.enabled && !is_http_url(config.api.oauth.issuer),
    Error("api.oauth.issuer must be an http:// or https:// URL"),
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
  // a tiny size would rotate, and gzip, on almost every line
  use <- bool.guard(
    al.max_bytes < 0 || { al.max_bytes > 0 && al.max_bytes < 65_536 },
    Error("access_log.max_bytes must be 0 (never rotate) or at least 65536"),
  )
  use <- bool.guard(
    al.max_files < 1 || al.max_files > 100,
    Error("access_log.max_files must be between 1 and 100"),
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

fn oidc_gives_admin(config: Config) -> Bool {
  config.oidc.enabled
  && { config.oidc.admin_groups != [] || config.oidc.default_role == "admin" }
}

/// A role header can give the admin role; without it, `default_role` does.
fn header_gives_admin(config: Config) -> Bool {
  config.header_auth.enabled
  && {
    config.header_auth.role_header != ""
    || config.header_auth.default_role == "admin"
  }
}
