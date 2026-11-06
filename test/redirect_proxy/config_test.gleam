import gleam/dict
import gleam/list
import gleam/string
import redirect_proxy/config
import redirect_proxy/listener
import simplifile
import tom

pub fn defaults_test() {
  let assert Ok(cfg) = config.from_toml(dict.new())
  assert cfg == config.default()
  let assert Ok(_) = config.validate(cfg)
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
  let assert Ok(cfg) = config.from_toml(t)
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
  let assert Ok(_) = config.validate(cfg)
  assert config.rules_path(cfg) == "/var/lib/rp/redirects.json"
}

pub fn wrong_type_test() {
  let assert Ok(t) = tom.parse("[server]\nport = \"eighty\"")
  let assert Error(message) = config.from_toml(t)
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
    config.apply_env(config.default(), fn(name) { list.key_find(env, name) })
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
  ]
  list.each(invalid, fn(cfg) {
    let assert Error(_) = config.validate(cfg)
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
  let assert Ok(cfg) = config.from_toml(t)
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
  let assert Ok(_) = config.validate(cfg)

  let env = [
    #("RP_ACCESS_LOG_ENABLED", "false"),
    #("RP_ACCESS_LOG_FORMAT", "json"),
    #("RP_ACCESS_LOG_OUTPUT", "stderr"),
    #("RP_ACCESS_LOG_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"),
    #("RP_ACCESS_LOG_API_OUTPUT", "/logs/api.log"),
    #("RP_ACCESS_LOG_ADMIN_ENABLED", "false"),
  ]
  let cfg = config.apply_env(d, fn(name) { list.key_find(env, name) })
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
    let assert Error(message) = config.validate(cfg)
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
  let errors = config.env_errors(fn(name) { list.key_find(env, name) })
  assert errors
    == [
      "RP_SERVER_PORT: expected an integer, got \"80a\"",
      "RP_ADMIN_ENABLED: expected true or false, got \"flase\"",
      "RP_LOG_LEVEL: expected one of debug, info, warning, error, critical, none, got \"verbose\"",
    ]
  // valid values (case and surrounding spaces aside) are applied
  let cfg =
    config.apply_env(config.default(), fn(name) { list.key_find(env, name) })
  assert cfg.api.enabled == True
  assert cfg.admin.port == 9000
}

pub fn every_listed_env_var_is_checked_test() {
  // each variable is reported when its value is garbage
  let garbage = fn(_name) { Ok("garbage") }
  let reported = config.env_errors(garbage)
  assert list.length(reported)
    == list.length(config.int_env_vars) + list.length(config.bool_env_vars) + 1
  // and every integer or boolean override of apply_env is listed
  let assert Ok(source) = simplifile.read("src/redirect_proxy/config.gleam")
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
  assert used(" i") == config.int_env_vars
  assert used(" b") == config.bool_env_vars
}
