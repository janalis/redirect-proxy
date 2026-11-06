//// Command line entry point.

import envoy
import gleam/dict
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config.{type Config}
import redirect_proxy/config/file as config_file
import redirect_proxy/config/loader as config_loader
import redirect_proxy/config/validate as config_validate
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/password
import redirect_proxy/rule
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules
import redirect_proxy/users
import simplifile

// x-release-please-start-version
/// Updated automatically by release-please.
pub const version = "0.4.0"

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
  redirect-proxy client add <name> [--scope SCOPE]... [--config FILE]
  redirect-proxy client list|rotate <client_id>|delete <client_id> [--config FILE]
  redirect-proxy rules validate [FILE] [--config FILE]
  redirect-proxy rules export [--config FILE]
  redirect-proxy rules import <FILE> [--replace] [--config FILE]
  redirect-proxy version
  redirect-proxy help

The configuration file defaults to $RP_CONFIG. Every setting can be
overridden with RP_* environment variables (see README). Passwords for
`user add`/`user passwd` are read from $RP_PASSWORD or prompted for.
API client scopes: redirects:read, redirects:write (default), redirects:ops.
"

pub fn main() -> Nil {
  // until the configuration is loaded (`serve` applies its [log] section)
  let level = envoy.get("RP_LOG_LEVEL") |> result.unwrap("info")
  let format = envoy.get("RP_LOG_FORMAT") |> result.unwrap("text")
  log.configure_with(string.lowercase(level), string.lowercase(format))
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
    ["client", "add", name, ..flags] -> client_add(config_path, name, flags)
    ["client", "list"] -> client_list(config_path)
    ["client", "rotate", client_id] -> client_rotate(config_path, client_id)
    ["client", "delete", client_id] -> client_delete(config_path, client_id)
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
  config_loader.load(config_path)
}

fn serve(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  log.configure_with(cfg.log.level, cfg.log.format)
  log.info("starting redirect-proxy " <> version)
  use running <- result.try(app.start(cfg))
  log.info(
    "ready: redirects on port "
    <> int.to_string(running.redirect_port)
    <> case cfg.admin.enabled {
      True -> ", admin on port " <> int.to_string(running.admin_port)
      False -> ", admin disabled"
    }
    <> case cfg.api.enabled, config.api_dedicated(cfg) {
      False, _ -> ", API disabled"
      True, True -> ", API on port " <> int.to_string(running.api_port)
      True, False -> ", API on the admin listener"
    },
  )
  process.sleep_forever()
  Ok(Nil)
}

fn check_config(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  io.println("configuration OK")
  let toml = config_file.read_toml(config_path) |> result.unwrap(dict.new())
  let writable = case data_dir_writable(cfg.storage.data_dir) {
    Ok(Nil) -> []
    Error(reason) -> [reason]
  }
  list.append(config_validate.warnings(toml, cfg), writable)
  |> list.each(fn(w) { io.println("  warning: " <> w) })
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
  io.println(case cfg.api.enabled, config.api_dedicated(cfg) {
    False, _ -> "  API: disabled"
    True, True ->
      "  API listener: "
      <> config.api_listen(cfg)
      <> ":"
      <> int.to_string(config.api_port(cfg))
    True, False -> "  API: served by the admin listener (same port)"
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

fn data_dir_writable(dir: String) -> Result(Nil, String) {
  let probe = dir <> "/.check-config-" <> int.to_string(ffi.now_millis())
  let written =
    simplifile.create_directory_all(dir)
    |> result.try(fn(_) { simplifile.write(probe, "") })
  let _ = simplifile.delete(probe)
  written
  |> result.map_error(fn(e) {
    "the data directory "
    <> dir
    <> " is not writable: "
    <> simplifile.describe_error(e)
  })
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

// --- API clients ------------------------------------------------------------

fn client_add(
  config_path: String,
  name: String,
  flags: List(String),
) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use names <- result.try(scope_flags(flags, []))
  use scopes <- result.try(case names {
    [] -> Ok([scope.Write])
    _ ->
      list.try_map(names, fn(n) {
        scope.from_string(n) |> result.replace_error("unknown scope: " <> n)
      })
  })
  use #(client, secret) <- result.try(clients.create(
    app.clients_settings(cfg),
    name,
    scopes,
    "cli",
  ))
  io.println("client_id:     " <> client.client_id)
  io.println("client_secret: " <> secret)
  io.println("scopes:        " <> scope.join(client.scopes))
  io.println("The secret is shown only once; store it now.")
  Ok(Nil)
}

fn scope_flags(
  flags: List(String),
  acc: List(String),
) -> Result(List(String), String) {
  case flags {
    [] -> Ok(list.reverse(acc))
    ["--scope", value, ..rest] -> scope_flags(rest, [value, ..acc])
    ["--scope=" <> value, ..rest] -> scope_flags(rest, [value, ..acc])
    [other, ..] -> Error("unexpected argument: " <> other)
  }
}

fn client_list(config_path: String) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use all <- result.try(clients.list(app.clients_settings(cfg)))
  list.each(all, fn(c) {
    io.println(
      c.client_id
      <> "\t"
      <> c.name
      <> "\t"
      <> scope.join(c.scopes)
      <> "\tlast used: "
      <> case c.last_used_at {
        "" -> "never"
        at -> at
      },
    )
  })
  Ok(Nil)
}

fn client_rotate(
  config_path: String,
  client_id: String,
) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use secret <- result.try(clients.rotate(
    app.clients_settings(cfg),
    client_id,
    "cli",
  ))
  io.println("client_secret: " <> secret)
  io.println("Access tokens issued with the previous secret are revoked.")
  Ok(Nil)
}

fn client_delete(
  config_path: String,
  client_id: String,
) -> Result(Nil, String) {
  use cfg <- result.try(load(config_path))
  use Nil <- result.try(clients.delete(
    app.clients_settings(cfg),
    client_id,
    "cli",
  ))
  io.println("API client " <> client_id <> " deleted")
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
    store_rules.validate_all(rules) |> result.map_error(string.join(_, "\n")),
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
  io.println(store_rules.export(rules))
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
