import gleam/dict
import gleam/list
import gleam/string
import redirect_proxy/config
import redirect_proxy/config/env as config_env
import redirect_proxy/config/file as config_file
import redirect_proxy/config/validate as config_validate
import redirect_proxy/listener
import simplifile
import support
import tom

pub fn defaults_test() {
  let assert Ok(cfg) = config_file.from_toml(dict.new())
  assert cfg == config.default()
  let assert Ok(_) = config_validate.validate(cfg)
}

pub fn from_toml_test() {
  let assert Ok(t) =
    tom.parse(
      "
[server]
port = 9000
fallback_url = \"https://example.com\"

[admin]
listen = \"0.0.0.0\"
session_ttl = 600

[storage]
data_dir = \"/var/lib/rp\"
backups = 3

[auth.oidc]
enabled = true
issuer = \"https://idp.test\"
client_id = \"rp\"
client_secret = \"s3cret\"
allowed_domains = [\"example.com\"]

[auth.header]
enabled = true
trusted_proxies = [\"10.0.0.0/8\"]
user_header = \"X-Remote-User\"
",
    )
  let assert Ok(cfg) = config_file.from_toml(t)
  assert cfg.server.port == 9000
  assert cfg.server.fallback_url == "https://example.com"
  assert cfg.admin.listen == "0.0.0.0"
  assert cfg.admin.session_ttl == 600
  assert cfg.storage.data_dir == "/var/lib/rp"
  assert cfg.storage.backups == 3
  assert cfg.oidc.enabled
  assert cfg.oidc.allowed_domains == ["example.com"]
  assert cfg.oidc.scopes == ["openid", "email", "profile"]
  assert cfg.header_auth.trusted_proxies == ["10.0.0.0/8"]
  assert cfg.header_auth.user_header == "x-remote-user"
  let assert Ok(_) = config_validate.validate(cfg)
  assert config.rules_path(cfg) == "/var/lib/rp/redirects.json"
}

pub fn wrong_type_test() {
  let assert Ok(t) = tom.parse("[server]\nport = \"eighty\"")
  let assert Error(message) = config_file.from_toml(t)
  assert string.contains(message, "server.port")
}

pub fn env_overrides_test() {
  let env = [
    #("RP_SERVER_PORT", "1234"),
    #("RP_ADMIN_ENABLED", "false"),
    #("RP_AUTH_OIDC_ALLOWED_GROUPS", "admins, ops ,"),
    #("RP_STORAGE_DATA_DIR", "/data"),
    #("RP_ADMIN_PORT", "not-a-number"),
  ]
  let cfg =
    config_env.apply_env(config.default(), fn(name) { list.key_find(env, name) })
  assert cfg.server.port == 1234
  assert !cfg.admin.enabled
  assert cfg.oidc.allowed_groups == ["admins", "ops"]
  assert cfg.storage.data_dir == "/data"
  // invalid values keep the current setting
  assert cfg.admin.port == 8081
}

pub fn validation_errors_test() {
  let d = config.default()
  let invalid = [
    config.Config(..d, server: config.ServerConfig(..d.server, port: 70_000)),
    config.Config(..d, server: config.ServerConfig(..d.server, port: 8081)),
    config.Config(
      ..d,
      admin: config.AdminConfig(..d.admin, secret_key_base: "short"),
    ),
    config.Config(..d, oidc: config.OidcConfig(..d.oidc, enabled: True)),
    config.Config(
      ..d,
      header_auth: config.HeaderAuthConfig(
        ..d.header_auth,
        enabled: True,
        trusted_proxies: [],
      ),
    ),
    config.Config(
      ..d,
      header_auth: config.HeaderAuthConfig(..d.header_auth, trusted_proxies: [
        "not-a-cidr",
      ]),
    ),
    config.Config(..d, local_auth: config.LocalAuthConfig(enabled: False)),
    config.Config(
      ..d,
      server: config.ServerConfig(..d.server, health_path: "health"),
    ),
    config.Config(
      ..d,
      server: config.ServerConfig(..d.server, max_path_bytes: 10),
    ),
    config.Config(
      ..d,
      storage: config.StorageConfig(..d.storage, watch_interval: -1),
    ),
  ]
  list.each(invalid, fn(cfg) {
    let assert Error(_) = config_validate.validate(cfg)
  })
}

pub fn access_log_test() {
  let d = config.default()
  assert d.access_log.enabled
  assert d.access_log.format == "combined"
  assert d.access_log.output == "stdout"
  assert d.access_log.anonymize_ip == "truncate"
  assert !d.access_log.log_query

  let assert Ok(t) =
    tom.parse(
      "
[access_log]
format = '$remote_addr $status'
output = \"/var/log/rp/access.log\"
anonymize_ip = \"none\"
log_query = true
trusted_proxies = [\"10.0.0.0/8\"]
max_bytes = 1048576

[access_log.admin]
output = \"/var/log/rp/admin.log\"
format = \"json\"

[access_log.api]
enabled = false
",
    )
  let assert Ok(cfg) = config_file.from_toml(t)
  assert cfg.access_log.format == "$remote_addr $status"
  assert cfg.access_log.output == "/var/log/rp/access.log"
  assert cfg.access_log.log_query
  assert cfg.access_log.trusted_proxies == ["10.0.0.0/8"]
  assert cfg.access_log.max_bytes == 1_048_576
  let al = cfg.access_log
  assert config.access_log_output(al, listener.RedirectListener)
    == "/var/log/rp/access.log"
  assert config.access_log_output(al, listener.AdminListener)
    == "/var/log/rp/admin.log"
  assert config.access_log_format(al, listener.AdminListener) == "json"
  assert config.access_log_format(al, listener.RedirectListener)
    == "$remote_addr $status"
  assert config.access_log_enabled(al, listener.AdminListener)
  assert !config.access_log_enabled(al, listener.ApiListener)
  let assert Ok(_) = config_validate.validate(cfg)

  let env = [
    #("RP_ACCESS_LOG_ENABLED", "false"),
    #("RP_ACCESS_LOG_FORMAT", "json"),
    #("RP_ACCESS_LOG_OUTPUT", "stderr"),
    #("RP_ACCESS_LOG_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"),
    #("RP_ACCESS_LOG_API_OUTPUT", "/logs/api.log"),
    #("RP_ACCESS_LOG_ADMIN_ENABLED", "false"),
  ]
  let cfg = config_env.apply_env(d, fn(name) { list.key_find(env, name) })
  assert !cfg.access_log.enabled
  assert cfg.access_log.format == "json"
  assert cfg.access_log.output == "stderr"
  assert cfg.access_log.trusted_proxies == ["127.0.0.1/32", "::1/128"]
  assert cfg.access_log.api.output == "/logs/api.log"
  assert !cfg.access_log.admin.enabled
  // the master switch wins
  assert !config.access_log_enabled(cfg.access_log, listener.RedirectListener)
}

pub fn access_log_validation_test() {
  let d = config.default()
  let with = fn(f) { config.Config(..d, access_log: f(d.access_log)) }
  let invalid = [
    with(fn(a) { config.AccessLogConfig(..a, format: "$unknown") }),
    with(fn(a) { config.AccessLogConfig(..a, format: "") }),
    with(fn(a) { config.AccessLogConfig(..a, escape: "html") }),
    with(fn(a) { config.AccessLogConfig(..a, anonymize_ip: "hash") }),
    with(fn(a) { config.AccessLogConfig(..a, output: " ") }),
    with(fn(a) { config.AccessLogConfig(..a, trusted_proxies: ["nope"]) }),
    with(fn(a) { config.AccessLogConfig(..a, max_bytes: -1) }),
    with(fn(a) { config.AccessLogConfig(..a, max_files: 0) }),
    with(fn(a) { config.AccessLogConfig(..a, max_files: 101) }),
    with(fn(a) { config.AccessLogConfig(..a, max_bytes: 1) }),
    with(fn(a) {
      config.AccessLogConfig(
        ..a,
        admin: config.ListenerLogConfig(..a.admin, format: "$nope"),
      )
    }),
    with(fn(a) {
      config.AccessLogConfig(
        ..a,
        api: config.ListenerLogConfig(..a.api, output: " "),
      )
    }),
  ]
  list.each(invalid, fn(cfg) {
    let assert Error(message) = config_validate.validate(cfg)
    assert string.starts_with(message, "access_log.")
  })
}

pub fn invalid_env_values_are_errors_test() {
  let env = [
    #("RP_ADMIN_ENABLED", "flase"),
    #("RP_SERVER_PORT", "80a"),
    #("RP_LOG_LEVEL", "verbose"),
    #("RP_API_ENABLED", " TRUE "),
    #("RP_ADMIN_PORT", " 9000 "),
  ]
  let errors = config_env.env_errors(fn(name) { list.key_find(env, name) })
  assert errors
    == [
      "RP_SERVER_PORT: expected an integer, got \"80a\"",
      "RP_ADMIN_ENABLED: expected true or false, got \"flase\"",
      "RP_LOG_LEVEL: expected one of debug, info, warning, error, critical, none, got \"verbose\"",
    ]
  // valid values (case and surrounding spaces aside) are applied
  let cfg =
    config_env.apply_env(config.default(), fn(name) { list.key_find(env, name) })
  assert cfg.api.enabled == True
  assert cfg.admin.port == 9000
}

pub fn every_listed_env_var_is_checked_test() {
  // each variable is reported when its value is garbage
  let garbage = fn(_name) { Ok("garbage") }
  let reported = config_env.env_errors(garbage)
  assert list.length(reported)
    == list.length(config_env.int_env_vars)
    + list.length(config_env.bool_env_vars)
    // RP_LOG_LEVEL and RP_LOG_FORMAT
    + 2
    + list.length(config_env.secret_env_vars)
  // and every integer or boolean override of apply_env is listed
  let assert Ok(source) = simplifile.read("src/redirect_proxy/config/env.gleam")
  let assert Ok(#(_, body)) = string.split_once(source, "pub fn apply_env(")
  let used = fn(prefix) {
    body
    |> string.split(prefix <> "(")
    |> list.drop(1)
    |> list.filter_map(fn(chunk) {
      case string.split_once(string.trim_start(chunk), "\"") {
        Ok(#("", rest)) ->
          case string.split_once(rest, "\"") {
            Ok(#(name, _)) -> Ok(name)
            Error(Nil) -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    })
    |> list.filter(fn(name) { string.starts_with(name, "RP_") })
    |> list.unique
    |> list.sort(string.compare)
  }
  assert used(" i") == config_env.int_env_vars
  assert used(" b") == config_env.bool_env_vars
  // a secret read from a file that cannot be read must be reported, not
  // silently replaced by the default (an empty metrics token is public)
  list.each(used(" secret"), fn(name) {
    assert list.contains(config_env.secret_env_vars, name)
  })
}

pub fn secrets_from_files_test() {
  let dir = support.temp_dir()
  let path = dir <> "/client_secret"
  let assert Ok(Nil) = simplifile.write(path, "s3cret\n")
  let env = [#("RP_AUTH_OIDC_CLIENT_SECRET_FILE", path)]
  let get = fn(name) { list.key_find(env, name) }
  assert config_env.env_errors(get) == []
  let cfg = config_env.apply_env(config.default(), get)
  assert cfg.oidc.client_secret == "s3cret"

  // an unreadable file, or both forms at once, are errors
  let missing = [#("RP_ADMIN_SECRET_KEY_BASE_FILE", dir <> "/nope")]
  let assert [reason] =
    config_env.env_errors(fn(n) { list.key_find(missing, n) })
  assert string.starts_with(
    reason,
    "RP_ADMIN_SECRET_KEY_BASE_FILE: cannot read",
  )
  let both = [
    #("RP_AUTH_OIDC_CLIENT_SECRET", "x"),
    #("RP_AUTH_OIDC_CLIENT_SECRET_FILE", path),
  ]
  assert config_env.env_errors(fn(n) { list.key_find(both, n) })
    == [
      "RP_AUTH_OIDC_CLIENT_SECRET and RP_AUTH_OIDC_CLIENT_SECRET_FILE are both set",
    ]
}

pub fn every_setting_has_an_env_override_test() {
  let env = [
    #("RP_AUTH_OIDC_GROUPS_CLAIM", "roles"),
    #("RP_AUTH_OIDC_BUTTON_LABEL", "Sign in with Corp"),
    #("RP_AUTH_HEADER_USER_HEADER", "X-Auth-User"),
    #("RP_AUTH_HEADER_EMAIL_HEADER", "X-Auth-Email"),
  ]
  let cfg =
    config_env.apply_env(config.default(), fn(name) { list.key_find(env, name) })
  assert cfg.oidc.groups_claim == "roles"
  assert cfg.oidc.button_label == "Sign in with Corp"
  assert cfg.header_auth.user_header == "x-auth-user"
  assert cfg.header_auth.email_header == "x-auth-email"
}

pub fn example_config_has_no_unknown_keys_test() {
  // config.example.toml documents every setting
  let assert Ok(toml) = config_file.read_toml("config.example.toml")
  assert config_file.unknown_keys(toml) == []
}

pub fn every_known_key_is_read_test() {
  // a value of the wrong type is reported for every listed key, so none of
  // them is listed by mistake
  list.each(config_file.known_keys, fn(key) {
    let assert Ok(#(section, leaf)) = split_last(key)
    let source = "[" <> section <> "]\n" <> leaf <> " = { nested = 1 }\n"
    let assert Ok(toml) = tom.parse(source)
    let assert Error(_) = config_file.from_toml(toml)
  })
}

fn split_last(key: String) -> Result(#(String, String), Nil) {
  case list.reverse(string.split(key, ".")) {
    [leaf, ..rest] if rest != [] ->
      Ok(#(string.join(list.reverse(rest), "."), leaf))
    _ -> Error(Nil)
  }
}

pub fn warnings_test() {
  let assert Ok(toml) =
    tom.parse("[auth.odic]\nenabled = true\n[admin]\nlisten = \"0.0.0.0\"\n")
  let assert Ok(cfg) = config_file.from_toml(toml)
  let assert [typo, exposed] = config_validate.warnings(toml, cfg)
  assert typo == "unknown setting auth.odic.enabled (ignored)"
  assert string.starts_with(exposed, "the admin listens on 0.0.0.0")
  let assert Ok(fine) = tom.parse("[admin]\nlisten = \"127.0.0.1\"\n")
  let assert Ok(cfg) = config_file.from_toml(fine)
  assert config_validate.warnings(fine, cfg) == []
}

pub fn value_checks_test() {
  let d = config.default()
  let assert Error(_) =
    config_validate.validate(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, cache_max_age: -1),
      ),
    )
  let assert Error(_) =
    config_validate.validate(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, fallback_url: "javascript:x"),
      ),
    )
  let assert Error(_) =
    config_validate.validate(
      config.Config(..d, admin: config.AdminConfig(..d.admin, public_url: "")),
    )
  let assert Error(_) =
    config_validate.validate(
      config.Config(
        ..d,
        admin: config.AdminConfig(..d.admin, session_ttl: 604_801),
      ),
    )
  let assert Ok(_) =
    config_validate.validate(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, fallback_url: "https://x.test/"),
      ),
    )
}

pub fn operability_settings_test() {
  let assert Ok(t) =
    tom.parse(
      "
[server]
health_path = \"/_health\"
max_path_bytes = 4096

[storage]
watch_interval = 5
",
    )
  let assert Ok(cfg) = config_file.from_toml(t)
  assert cfg.server.health_path == "/_health"
  assert cfg.server.max_path_bytes == 4096
  assert cfg.storage.watch_interval == 5
  let assert Ok(_) = config_validate.validate(cfg)

  let env = [
    #("RP_SERVER_HEALTH_PATH", "/lb"),
    #("RP_SERVER_MAX_PATH_BYTES", "2048"),
    #("RP_STORAGE_WATCH_INTERVAL", "2"),
  ]
  let cfg = config_env.apply_env(cfg, fn(name) { list.key_find(env, name) })
  assert cfg.server.health_path == "/lb"
  assert cfg.server.max_path_bytes == 2048
  assert cfg.storage.watch_interval == 2
}

/// Mistakes `check-config` used to accept and the server only hit at boot
/// (or never).
pub fn more_value_checks_test() {
  let d = config.default()
  let refused = fn(cfg) {
    let assert Error(message) = config_validate.validate(cfg)
    message
  }
  let server = fn(listen) {
    config.Config(..d, server: config.ServerConfig(..d.server, listen:))
  }
  assert string.starts_with(refused(server("0.0.0.O")), "server.listen")
  let assert Ok(_) = config_validate.validate(server("::"))
  let assert Ok(_) = config_validate.validate(server("localhost"))
  let api = config.ApiConfig(..d.api, listen: "my-host")
  assert string.starts_with(refused(config.Config(..d, api:)), "api.listen")
  let api = config.ApiConfig(..d.api, public_url: "api.example.com")
  assert string.starts_with(refused(config.Config(..d, api:)), "api.public_url")
  let header =
    config.HeaderAuthConfig(
      ..config.default().header_auth,
      enabled: True,
      trusted_proxies: ["10.0.0.0/8"],
      user_header: "",
      email_header: " ",
    )
  assert string.starts_with(
    refused(config.Config(..d, header_auth: header)),
    "auth.header needs",
  )
  let oidc =
    config.OidcConfig(
      ..d.oidc,
      enabled: True,
      issuer: "accounts.example.com",
      client_id: "c",
      client_secret: "s",
    )
  assert string.starts_with(
    refused(config.Config(..d, oidc:)),
    "auth.oidc.issuer",
  )
  // nobody listed as allowed to sign in: every account of the provider
  // could, unless that is what is meant
  let oidc = config.OidcConfig(..oidc, issuer: "https://idp.example.com")
  assert string.starts_with(
    refused(config.Config(..d, oidc:)),
    "auth.oidc needs allowed_emails",
  )
  let open = config.OidcConfig(..oidc, allow_any_account: True)
  let assert Ok(_) = config_validate.validate(config.Config(..d, oidc: open))
  let listed = config.OidcConfig(..oidc, allowed_groups: ["staff"])
  let assert Ok(_) = config_validate.validate(config.Config(..d, oidc: listed))
  // a timer of more than about 49 days crashed the store at startup
  let storage = config.StorageConfig(..d.storage, watch_interval: 5_000_000)
  assert string.starts_with(
    refused(config.Config(..d, storage:)),
    "storage.watch_interval",
  )
}

pub fn more_warnings_test() {
  let d = config.default()
  assert config_validate.runtime_warnings(d) == []
  let cfg =
    config.Config(
      ..d,
      server: config.ServerConfig(..d.server, shutdown_grace: 20),
      admin: config.AdminConfig(
        ..d.admin,
        session_ttl: 600,
        session_idle_timeout: 600,
      ),
    )
  let assert [idle, grace] = config_validate.runtime_warnings(cfg)
  assert string.starts_with(idle, "admin.session_idle_timeout")
  assert string.starts_with(grace, "server.shutdown_grace is 20")
  // the API accepting tokens meant for the admin sign-in
  let shared =
    config.Config(
      ..d,
      oidc: config.OidcConfig(..d.oidc, enabled: True, client_id: "rp-admin"),
      api: config.ApiConfig(
        ..d.api,
        oauth: config.ApiOAuthConfig(
          ..d.api.oauth,
          enabled: True,
          audience: "rp-admin",
        ),
      ),
    )
  assert list.any(config_validate.runtime_warnings(shared), string.starts_with(
    _,
    "api.oauth.audience is the auth.oidc client_id",
  ))
  // loopback addresses in every form are not reported as exposed
  let assert Ok(toml) = tom.parse("")
  list.each(["[::1]", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"], fn(listen) {
    let cfg = config.Config(..d, admin: config.AdminConfig(..d.admin, listen:))
    assert config_validate.warnings(toml, cfg) == []
  })
}

pub fn metrics_token_must_be_long_enough_test() {
  let d = config.default()
  let with = fn(token) {
    config.Config(
      ..d,
      admin: config.AdminConfig(..d.admin, metrics_token: token),
    )
  }
  let assert Error(message) = config_validate.validate(with("short"))
  assert string.contains(message, "metrics_token")
  let assert Ok(_) = config_validate.validate(with("sixteen-chars-ok"))
  let assert Ok(_) = config_validate.validate(with(""))
}

pub fn admin_default_role_with_role_groups_warns_test() {
  let d = config.default()
  let with = fn(default_role) {
    config.Config(
      ..d,
      oidc: config.OidcConfig(
        ..d.oidc,
        enabled: True,
        allowed_domains: ["example.com"],
        editor_groups: ["web"],
        default_role:,
      ),
    )
  }
  assert list.any(
    config_validate.runtime_warnings(with("admin")),
    string.starts_with(_, "auth.oidc.default_role is admin"),
  )
  assert !list.any(
    config_validate.runtime_warnings(with("viewer")),
    string.starts_with(_, "auth.oidc.default_role"),
  )
}

/// SSO only, and no way to become an admin: the server says so at startup.
pub fn no_admin_role_warns_test() {
  let d = config.default()
  let with = fn(local, admin_groups, default_role) {
    config.Config(
      ..d,
      local_auth: config.LocalAuthConfig(enabled: local),
      oidc: config.OidcConfig(
        ..d.oidc,
        enabled: True,
        allowed_domains: ["example.com"],
        admin_groups:,
        default_role:,
      ),
    )
  }
  let warns = fn(cfg) {
    list.any(config_validate.runtime_warnings(cfg), string.starts_with(
      _,
      "auth.oidc gives no one the admin role",
    ))
  }
  assert warns(with(False, [], "viewer"))
  assert !warns(with(True, [], "viewer"))
  assert !warns(with(False, ["ops"], "viewer"))
  assert !warns(with(False, [], "admin"))
  // proxy headers without a role header: the same
  let proxy = fn(role_header) {
    config.Config(
      ..d,
      local_auth: config.LocalAuthConfig(enabled: False),
      header_auth: config.HeaderAuthConfig(
        ..d.header_auth,
        enabled: True,
        role_header:,
      ),
    )
  }
  let proxy_warns = fn(cfg) {
    list.any(config_validate.runtime_warnings(cfg), string.starts_with(
      _,
      "auth.header gives no one the admin role",
    ))
  }
  assert proxy_warns(proxy(""))
  assert !proxy_warns(proxy("x-forwarded-role"))
}

/// Signing keys fetched over plain HTTP from another host can be changed in
/// transit: the server warns (the loopback interface is fine).
pub fn plain_http_issuer_warns_test() {
  let d = config.default()
  let with = fn(issuer) {
    config.Config(
      ..d,
      api: config.ApiConfig(
        ..d.api,
        oauth: config.ApiOAuthConfig(
          ..d.api.oauth,
          enabled: True,
          issuer:,
          audience: "rp",
        ),
      ),
    )
  }
  let warns = fn(issuer) {
    list.any(config_validate.runtime_warnings(with(issuer)), string.starts_with(
      _,
      "api.oauth.issuer is plain http://",
    ))
  }
  assert warns("http://idp.internal:8080/realms/x")
  assert !warns("https://idp.example.com")
  assert !warns("http://127.0.0.1:9000")
  assert !warns("http://localhost:9000")
  assert !warns("http://[::1]:9000")
}

/// The redirect listener is public: its metrics path needs the token.
pub fn metrics_path_needs_a_token_test() {
  let d = config.default()
  let with = fn(path, token) {
    config.Config(
      ..d,
      admin: config.AdminConfig(..d.admin, metrics_token: token),
      server: config.ServerConfig(..d.server, metrics_path: path),
    )
  }
  let assert Error(message) = config_validate.validate(with("/_metrics", ""))
  assert string.contains(message, "admin.metrics_token")
  let assert Error(_) =
    config_validate.validate(with("_metrics", "a-long-metrics-token"))
  let assert Ok(_) =
    config_validate.validate(with("/_metrics", "a-long-metrics-token"))
  let assert Ok(_) = config_validate.validate(with("", ""))
}

pub fn upstream_settings_test() {
  let assert Ok(t) =
    tom.parse(
      "
[server]
upstream = \"https://site.internal:8443\"
upstream_timeout = 30
upstream_tls_verify = false
",
    )
  let assert Ok(cfg) = config_file.from_toml(t)
  assert cfg.server.upstream == "https://site.internal:8443"
  assert cfg.server.upstream_timeout == 30
  assert !cfg.server.upstream_tls_verify
  let d = config.default()
  assert d.server.upstream == ""
  assert d.server.upstream_timeout == 60
  assert d.server.upstream_tls_verify
  let env = [
    #("RP_SERVER_UPSTREAM", "http://127.0.0.1:3000"),
    #("RP_SERVER_UPSTREAM_TIMEOUT", "5"),
    #("RP_SERVER_UPSTREAM_TLS_VERIFY", "no"),
  ]
  let cfg = config_env.apply_env(d, fn(name) { list.key_find(env, name) })
  assert cfg.server.upstream == "http://127.0.0.1:3000"
  assert cfg.server.upstream_timeout == 5
  assert !cfg.server.upstream_tls_verify
}

pub fn upstream_urls_test() {
  assert config.parse_upstream("http://127.0.0.1:3000")
    == Ok(config.UpstreamUrl(tls: False, host: "127.0.0.1", port: 3000))
  assert config.parse_upstream("HTTPS://Site.Test/")
    == Ok(config.UpstreamUrl(tls: True, host: "Site.Test", port: 443))
  assert config.parse_upstream("http://site.test")
    == Ok(config.UpstreamUrl(tls: False, host: "site.test", port: 80))
  assert config.parse_upstream("http://[::1]:8080")
    == Ok(config.UpstreamUrl(tls: False, host: "::1", port: 8080))
  let invalid = fn(url) {
    let d = config.default()
    let assert Error(message) =
      config_validate.validate(
        config.Config(
          ..d,
          server: config.ServerConfig(..d.server, upstream: url),
        ),
      )
    assert string.starts_with(message, "server.upstream must be")
  }
  invalid("127.0.0.1:3000")
  invalid("ftp://site.test")
  invalid("http://")
  invalid("http://site.test/app")
  invalid("http://site.test/?a=1")
  invalid("http://site.test/#top")
  invalid("http://user:secret@site.test")
  invalid("http://site.test:0")
  invalid("http://site.test:70000")
}

pub fn upstream_checks_test() {
  let d = config.default()
  let with = fn(server) {
    config_validate.validate(config.Config(..d, server:))
  }
  let assert Ok(_) =
    with(config.ServerConfig(..d.server, upstream: "http://127.0.0.1:3000/"))
  // unmatched requests go either to the upstream or to the fallback URL
  let assert Error(message) =
    with(
      config.ServerConfig(
        ..d.server,
        upstream: "http://127.0.0.1:3000",
        fallback_url: "https://home.test/",
      ),
    )
  assert string.contains(message, "fallback_url")
  let assert Error(_) =
    with(
      config.ServerConfig(
        ..d.server,
        upstream: "http://127.0.0.1:3000",
        upstream_timeout: 0,
      ),
    )
}
