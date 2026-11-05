import gleam/dict
import gleam/list
import gleam/string
import redirect_proxy/config
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
