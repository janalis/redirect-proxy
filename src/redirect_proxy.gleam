//// Command line entry point.

import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/app
import redirect_proxy/config.{type Config}
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/password
import redirect_proxy/rule
import redirect_proxy/store
import redirect_proxy/users
import simplifile

// x-release-please-start-version
/// Updated automatically by release-please.
pub const version = "0.1.1"

// x-release-please-end

const usage =
  "redirect-proxy - high performance HTTP redirect server

Usage:
  redirect-proxy [serve] [--config FILE]   Start the redirect and admin listeners
  redirect-proxy check-config [--config FILE]
  redirect-proxy user add <username> [--config FILE]
  redirect-proxy user passwd <username> [--config FILE]
  redirect-proxy user delete <username> [--config FILE]
  redirect-proxy user list [--config FILE]
  redirect-proxy rules validate [FILE] [--config FILE]
  redirect-proxy rules export [--config FILE]
  redirect-proxy rules import <FILE> [--replace] [--config FILE]
  redirect-proxy version
  redirect-proxy help

The configuration file defaults to $RP_CONFIG. Every setting can be
overridden with RP_* environment variables (see README). Passwords for
`user add`/`user passwd` are read from $RP_PASSWORD or prompted for.
"

pub fn main() -> Nil {
  let level = envoy.get("RP_LOG_LEVEL") |> result.unwrap("info")
  log.configure(level)
  case run(ffi.plain_arguments()) {
    Ok(Nil) -> Nil
    Error(message) -> {
      io.println_error("error: " <> message)
      ffi.halt(1)
    }
  }
}

/// Executes a command line. Exposed for tests.
pub fn run(args: List(String)) -> Result(Nil, String) {
  let #(config_path, args) = extract_option(args, "--config")
  let config_path =
    result.lazy_or(config_path, fn() { envoy.get("RP_CONFIG") })
    |> result.unwrap("")
  case args {
    [] | ["serve"] -> serve(config_path)
    ["check-config"] -> check_config(config_path)
    ["user", "add", username] -> user_add(config_path, username)
    ["user", "passwd", username] -> user_passwd(config_path, username)
    ["user", "delete", username] -> user_delete(config_path, username)
    ["user", "list"] -> user_list(config_path)
    ["rules", "validate"] -> rules_validate(config_path, "")
    ["rules", "validate", file] -> rules_validate(config_path, file)
    ["rules", "export"] -> rules_export(config_path)
    ["rules", "import", file] -> rules_import(config_path, file, store.Merge)
    ["rules", "import", file, "--replace"]
    | ["rules", "import", "--replace", file] ->
      rules_import(config_path, file, store.Replace)
    ["version"] | ["--version"] | ["-v"] -> {
      io.println("redirect-proxy " <> version)
      Ok(Nil)
    }
    ["help"] | ["--help"] | ["-h"] -> {
      io.print(usage)
      Ok(Nil)
    }
    _ -> Error("unknown command: " <> string.join(args, " ") <> "\n\n" <> usage)
  }
}

fn extract_option(
  args: List(String),
  name: String,
) -> #(Result(String, Nil), List(String)) {
  case args {
    [] -> #(Error(Nil), [])
    [flag, value, ..rest] if flag == name -> #(Ok(value), rest)
    [first, ..rest] ->
      case string.split_once(first, "=") {
        Ok(#(flag, value)) if flag == name -> #(Ok(value), rest)
        _ -> {
          let #(found, remaining) = extract_option(rest, name)
          #(found, [first, ..remaining])
        }
      }
  }
}

fn load(config_path: String) -> Result(Config, String) {
  config.load(config_path)
}

fn serve(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  log.info("starting redirect-proxy " <> version)
  use running <- result.try(app.start(cfg))
  log.info(
    "ready: redirects on port "
    <> int.to_string(running.redirect_port)
    <> case cfg.admin.enabled {
      True -> ", admin on port " <> int.to_string(running.admin_port)
      False -> ", admin disabled"
    },
  )
  process.sleep_forever()
  Ok(Nil)
}

fn check_config(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  io.println("configuration OK")
  io.println("  data directory: " <> cfg.storage.data_dir)
  io.println(
    "  redirect listener: "
    <> cfg.server.listen
    <> ":"
    <> int.to_string(cfg.server.port),
  )
  io.println(case cfg.admin.enabled {
    True ->
      "  admin listener: "
      <> cfg.admin.listen
      <> ":"
      <> int.to_string(cfg.admin.port)
    False -> "  admin listener: disabled"
  })
  let methods =
    [
      #(cfg.local_auth.enabled, "local"),
      #(cfg.oidc.enabled, "oidc"),
      #(cfg.header_auth.enabled, "header"),
    ]
    |> list.filter(fn(m) { m.0 })
    |> list.map(fn(m) { m.1 })
  io.println("  authentication: " <> string.join(methods, ", "))
  Ok(Nil)
}

// --- users ------------------------------------------------------------------

fn read_new_password() -> Result(String, String) {
  case envoy.get("RP_PASSWORD") {
    Ok(pass) -> password.validate_strength(pass) |> result.replace(pass)
    Error(Nil) -> {
      use first <- result.try(
        ffi.read_password("New password: ")
        |> result.replace_error("cannot read password"),
      )
      use Nil <- result.try(password.validate_strength(first))
      use second <- result.try(
        ffi.read_password("Repeat password: ")
        |> result.replace_error("cannot read password"),
      )
      case first == second {
        True -> Ok(first)
        False -> Error("passwords do not match")
      }
    }
  }
}

fn user_add(config_path: String, username: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use Nil <- result.try(users.validate_username(users.normalise(username)))
  use pass <- result.try(read_new_password())
  use user <- result.try(users.create(
    app.users_settings(cfg),
    username,
    password.hash(pass),
    "cli",
  ))
  io.println("user " <> user.username <> " created")
  Ok(Nil)
}

fn user_passwd(config_path: String, username: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use pass <- result.try(read_new_password())
  use Nil <- result.try(users.set_password(
    app.users_settings(cfg),
    username,
    password.hash(pass),
    "cli",
  ))
  io.println("password of " <> users.normalise(username) <> " changed")
  Ok(Nil)
}

fn user_delete(config_path: String, username: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use Nil <- result.try(users.delete(app.users_settings(cfg), username, "cli"))
  io.println("user " <> users.normalise(username) <> " deleted")
  Ok(Nil)
}

fn user_list(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use all <- result.try(users.list(app.users_settings(cfg)))
  list.each(all, fn(u) { io.println(u.username <> "\t" <> u.created_at) })
  Ok(Nil)
}

// --- rules ------------------------------------------------------------------

fn rules_validate(config_path: String, file: String) -> Result(Nil, String) {
  use path <- result.try(case file {
    "" -> load(config_path) |> result.map(config.rules_path)
    f -> Ok(f)
  })
  use content <- result.try(
    simplifile.read(path)
    |> result.map_error(fn(e) {
      "cannot read " <> path <> ": " <> simplifile.describe_error(e)
    }),
  )
  use rules <- result.try(rule.file_from_string(content))
  use valid <- result.try(
    store.validate_all(rules) |> result.map_error(string.join(_, "\n")),
  )
  io.println(
    path <> ": " <> int.to_string(list.length(valid)) <> " valid rule(s)",
  )
  Ok(Nil)
}

fn rules_export(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use content <- result.try(
    simplifile.read(config.rules_path(cfg))
    |> result.map_error(simplifile.describe_error),
  )
  use rules <- result.try(rule.file_from_string(content))
  io.println(store.export(rules))
  Ok(Nil)
}

fn rules_import(
  config_path: String,
  file: String,
  mode: store.ImportMode,
) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use content <- result.try(
    simplifile.read(file)
    |> result.map_error(fn(e) {
      "cannot read " <> file <> ": " <> simplifile.describe_error(e)
    }),
  )
  use incoming <- result.try(rule.file_from_string(content))
  use Nil <- result.try(
    simplifile.create_directory_all(cfg.storage.data_dir)
    |> result.map_error(simplifile.describe_error),
  )
  app.init_tables()
  use started <- result.try(
    store.start(app.store_settings(cfg), process.new_name("rp_cli_store"))
    |> result.map_error(fn(e) { string.inspect(e) }),
  )
  use count <- result.try(
    store.import_rules(started.data, incoming, mode, "cli")
    |> result.map_error(string.join(_, "\n")),
  )
  io.println(
    int.to_string(count)
    <> " rule(s) imported into "
    <> config.rules_path(cfg)
    <> ". Send SIGHUP to a running server (or use \"Reload from disk\") to apply.",
  )
  Ok(Nil)
}
