//// `RP_*` overrides with an injected getter, and `_FILE` secrets
//// (config_test covers the common overrides and error messages).

import gleam/list
import gleam/string
import redirect_proxy/config
import redirect_proxy/config/env as config_env
import simplifile
import support

fn getter(env: List(#(String, String))) -> fn(String) -> Result(String, Nil) {
  fn(name) { list.key_find(env, name) }
}

fn apply(env: List(#(String, String))) -> config.Config {
  config_env.apply_env(config.default(), getter(env))
}

fn secret_file(content: String) -> String {
  let path = support.temp_dir() <> "/secret"
  let assert Ok(Nil) = simplifile.write(path, content)
  path
}

// --- apply_env ------------------------------------------------------------------

pub fn no_variables_change_nothing_test() {
  let cfg = config.default()
  assert config_env.apply_env(cfg, fn(_) { Error(Nil) }) == cfg
  assert config_env.env_errors(fn(_) { Error(Nil) }) == []
}

/// Every spelling of a boolean, in any case and with spaces around it.
pub fn boolean_spellings_test() {
  list.each(["1", "true", "YES", " On "], fn(value) {
    let env = [#("RP_ADMIN_ENABLED", value), #("RP_API_ENABLED", value)]
    assert config_env.env_errors(getter(env)) == []
    let cfg = apply(env)
    assert cfg.admin.enabled && cfg.api.enabled
  })
  list.each(["0", "FALSE", "no", " off "], fn(value) {
    let env = [#("RP_ADMIN_ENABLED", value)]
    assert config_env.env_errors(getter(env)) == []
    assert !apply(env).admin.enabled
  })
  // anything else is an error and keeps the current value
  list.each(["", "y", "2", "enabled", "truee"], fn(value) {
    let env = [#("RP_SERVER_HTTPS_REDIRECT", value)]
    let assert [message] = config_env.env_errors(getter(env))
    assert string.ends_with(message, "got \"" <> value <> "\"")
    assert apply(env).server.https_redirect
      == config.default().server.https_redirect
  })
}

pub fn integer_values_test() {
  assert apply([#("RP_SERVER_PORT", " 8443 ")]).server.port == 8443
  // a negative number parses: its range is checked by validation
  assert apply([#("RP_SERVER_PORT", "-1")]).server.port == -1
  list.each(["", " ", "4.2", "1e3", "0x50", "8080a"], fn(value) {
    let env = [#("RP_SERVER_PORT", value)]
    assert config_env.env_errors(getter(env))
      == ["RP_SERVER_PORT: expected an integer, got \"" <> value <> "\""]
    assert apply(env).server.port == 8080
  })
}

pub fn log_level_and_format_are_trimmed_and_lowered_test() {
  let env = [#("RP_LOG_LEVEL", " DEBUG "), #("RP_LOG_FORMAT", "Json ")]
  assert config_env.env_errors(getter(env)) == []
  let cfg = apply(env)
  assert cfg.log.level == "debug"
  assert cfg.log.format == "json"
  let env = [#("RP_LOG_FORMAT", "xml")]
  assert config_env.env_errors(getter(env))
    == ["RP_LOG_FORMAT: expected text or json, got \"xml\""]
}

/// Lists are split on commas, trimmed, and empty items dropped; a variable
/// set to nothing clears the list.
pub fn list_values_test() {
  assert apply([#("RP_AUTH_OIDC_SCOPES", "openid,,groups , ")]).oidc.scopes
    == ["openid", "groups"]
  assert apply([#("RP_AUTH_OIDC_SCOPES", "")]).oidc.scopes == []
  assert apply([#("RP_AUTH_OIDC_SCOPES", " , ")]).oidc.scopes == []
  assert apply([]).oidc.scopes == ["openid", "email", "profile"]
}

/// Strings are taken as written (an empty one too), except header names
/// and the trailing slash mode, which are lower-cased.
pub fn string_values_test() {
  let cfg =
    apply([
      #("RP_SERVER_LISTEN", ""),
      #("RP_AUTH_OIDC_BUTTON_LABEL", " Se connecter · ログイン "),
      #("RP_SERVER_TRAILING_SLASH", "Ignore"),
      #("RP_AUTH_HEADER_ROLE_HEADER", "X-Role"),
    ])
  assert cfg.server.listen == ""
  assert cfg.oidc.button_label == " Se connecter · ログイン "
  assert cfg.server.trailing_slash == "ignore"
  assert cfg.header_auth.role_header == "x-role"
}

pub fn listener_access_log_overrides_test() {
  let cfg =
    apply([
      #("RP_ACCESS_LOG_REDIRECT_FORMAT", "$status"),
      #("RP_ACCESS_LOG_REDIRECT_OUTPUT", "/logs/redirect.log"),
      #("RP_ACCESS_LOG_API_ENABLED", "no"),
    ])
  let d = config.default().access_log
  assert cfg.access_log.redirect
    == config.ListenerLogConfig(
      ..d.redirect,
      format: "$status",
      output: "/logs/redirect.log",
    )
  assert cfg.access_log.api == config.ListenerLogConfig(..d.api, enabled: False)
  assert cfg.access_log.admin == d.admin
}

// --- secrets ----------------------------------------------------------------------

/// Every secret applied by `apply_env` can come from a file.
pub fn every_secret_reads_its_file_test() {
  let path = secret_file("from-file\n")
  let from_file = fn(name) { apply([#(name <> "_FILE", path)]) }
  assert from_file("RP_ADMIN_SECRET_KEY_BASE").admin.secret_key_base
    == "from-file"
  assert from_file("RP_ADMIN_METRICS_TOKEN").admin.metrics_token == "from-file"
  assert from_file("RP_AUTH_OIDC_CLIENT_SECRET").oidc.client_secret
    == "from-file"
  // and from the variable itself
  assert apply([#("RP_ADMIN_METRICS_TOKEN", "inline")]).admin.metrics_token
    == "inline"
}

/// Both set is an error; were it applied anyway, the file would win.
pub fn file_wins_over_the_variable_test() {
  let path = secret_file("from-file")
  let env = [
    #("RP_ADMIN_METRICS_TOKEN", "inline"),
    #("RP_ADMIN_METRICS_TOKEN_FILE", path),
  ]
  assert apply(env).admin.metrics_token == "from-file"
  assert config_env.env_errors(getter(env))
    == [
      "RP_ADMIN_METRICS_TOKEN and RP_ADMIN_METRICS_TOKEN_FILE are both set",
    ]
  // even when the file cannot be read: the conflict is what is reported
  let env = [
    #("RP_ADMIN_METRICS_TOKEN", "inline"),
    #("RP_ADMIN_METRICS_TOKEN_FILE", path <> ".missing"),
  ]
  assert config_env.env_errors(getter(env))
    == [
      "RP_ADMIN_METRICS_TOKEN and RP_ADMIN_METRICS_TOKEN_FILE are both set",
    ]
}

/// An unreadable file keeps the current value (and is reported by
/// `env_errors`, so the server does not start with it).
pub fn unreadable_secret_file_keeps_the_value_test() {
  let missing = support.temp_dir() <> "/nope"
  let env = [#("RP_AUTH_OIDC_CLIENT_SECRET_FILE", missing)]
  assert apply(env).oidc.client_secret == ""
  let assert [message] = config_env.env_errors(getter(env))
  assert string.starts_with(
    message,
    "RP_AUTH_OIDC_CLIENT_SECRET_FILE: cannot read " <> missing <> ": ",
  )
  // the bootstrap password is checked too, though applied elsewhere
  let env = [#("RP_BOOTSTRAP_ADMIN_PASSWORD_FILE", missing)]
  let assert [message] = config_env.env_errors(getter(env))
  assert string.starts_with(message, "RP_BOOTSTRAP_ADMIN_PASSWORD_FILE: ")
}

/// One trailing line break (LF or CRLF) is dropped, nothing else. CRLF used
/// to drop the character before it too (`string.drop_end` counts
/// graphemes, and CRLF is a single one).
pub fn secret_file_line_break_test() {
  let read = fn(content) { config_env.read_secret_file(secret_file(content)) }
  assert read("ab\r\n") == Ok("ab")
  assert read("pässwörd\r\n") == Ok("pässwörd")
  assert read("日本\n") == Ok("日本")
  assert read("ab\n") == Ok("ab")
  assert read("ab") == Ok("ab")
  assert read("") == Ok("")
  assert read("\n") == Ok("")
  assert read("\r\n") == Ok("")
  assert read("ab\n\n") == Ok("ab\n")
  assert read("ab\r\n\r\n") == Ok("ab\r\n")
  assert read("a\nb\n") == Ok("a\nb")
  // spaces and a lone CR are content
  assert read(" ab \n") == Ok(" ab ")
  assert read("ab\r") == Ok("ab\r")
  assert read("e\u{0301}\r\n") == Ok("e\u{0301}")
}

pub fn secret_file_error_names_the_path_test() {
  let dir = support.temp_dir()
  let assert Error(message) = config_env.read_secret_file(dir <> "/nope")
  assert string.starts_with(message, "cannot read " <> dir <> "/nope: ")
  // a directory is not a secret
  let assert Error(message) = config_env.read_secret_file(dir)
  assert string.starts_with(message, "cannot read " <> dir <> ": ")
}
