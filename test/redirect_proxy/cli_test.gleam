import envoy
import gleam/string
import redirect_proxy
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/config/loader as config_loader
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/rule
import redirect_proxy/users
import simplifile
import support

fn setup() -> #(String, String) {
  let dir = support.temp_dir()
  let config_path = dir <> "/config.toml"
  let assert Ok(Nil) =
    simplifile.write(
      config_path,
      "[storage]\ndata_dir = \"" <> dir <> "/data\"\n",
    )
  #(dir, config_path)
}

pub fn version_and_help_test() {
  let assert Ok(Nil) = redirect_proxy.run(["version"])
  let assert Ok(Nil) = redirect_proxy.run(["help"])
  let assert Error(message) = redirect_proxy.run(["frobnicate"])
  assert string.contains(message, "unknown command")
}

pub fn check_config_test() {
  let #(dir, config_path) = setup()
  let assert Ok(Nil) =
    redirect_proxy.run(["check-config", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["check-config", "--config=" <> config_path])
  let assert Error(_) =
    redirect_proxy.run(["check-config", "--config", dir <> "/missing.toml"])
}

pub fn user_commands_test() {
  let #(dir, config_path) = setup()
  envoy.set("RP_PASSWORD", "cli-password-123")
  let assert Ok(Nil) =
    redirect_proxy.run(["user", "add", "Carol", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["user", "add", "dave", "--config", config_path])
  let assert Error(_) =
    redirect_proxy.run(["user", "add", "carol", "--config", config_path])
  envoy.set("RP_PASSWORD", "another-password-456")
  let assert Ok(Nil) =
    redirect_proxy.run(["user", "passwd", "carol", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["user", "list", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["user", "delete", "dave", "--config", config_path])
  envoy.set("RP_PASSWORD", "short")
  let assert Error(_) =
    redirect_proxy.run(["user", "add", "eve", "--config", config_path])
  envoy.unset("RP_PASSWORD")

  let settings =
    users.Settings(
      path: dir <> "/data/users.json",
      audit_path: dir <> "/data/audit.jsonl",
    )
  let assert Ok(carol) = users.get(settings, "carol")
  assert password.verify("another-password-456", carol.password_hash)
  let assert Error(Nil) = users.get(settings, "dave")
}

pub fn rules_commands_test() {
  let #(dir, config_path) = setup()
  let import_file = dir <> "/import.json"
  let assert Ok(Nil) =
    simplifile.write(
      import_file,
      "[{\"source\": \"/a\", \"target\": \"/b\"}, {\"source\": \"/c\", \"target\": \"/d\"}]",
    )
  let assert Ok(Nil) = redirect_proxy.run(["rules", "validate", import_file])
  let assert Ok(Nil) =
    redirect_proxy.run(["rules", "import", import_file, "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["rules", "validate", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["rules", "export", "--config", config_path])

  let assert Ok(content) = simplifile.read(dir <> "/data/redirects.json")
  let assert Ok(rules) = rule.file_from_string(content)
  assert list_length(rules) == 2

  let assert Ok(Nil) =
    simplifile.write(
      import_file,
      "[{\"source\": \"/only\", \"target\": \"/one\"}]",
    )
  let assert Ok(Nil) =
    redirect_proxy.run([
      "rules", "import", import_file, "--replace", "--config", config_path,
    ])
  let assert Ok(content) = simplifile.read(dir <> "/data/redirects.json")
  let assert Ok([only]) = rule.file_from_string(content)
  assert only.source == "/only"

  let assert Ok(Nil) = simplifile.write(import_file, "[{\"source\": \"bad\"}]")
  let assert Error(_) = redirect_proxy.run(["rules", "validate", import_file])
  let _ = config.default()
}

fn list_length(items: List(a)) -> Int {
  case items {
    [] -> 0
    [_, ..rest] -> 1 + list_length(rest)
  }
}

pub fn client_commands_test() {
  let #(dir, config_path) = setup()
  let assert Ok(Nil) =
    redirect_proxy.run([
      "client", "add", "ci", "--scope", "redirects:read",
      "--scope=redirects:ops", "--config", config_path,
    ])
  let assert Ok(Nil) =
    redirect_proxy.run(["client", "add", "default", "--config", config_path])
  let assert Error(_) =
    redirect_proxy.run([
      "client", "add", "bad", "--scope", "admin", "--config", config_path,
    ])
  let assert Error(_) =
    redirect_proxy.run(["client", "add", "bad", "oops", "--config", config_path])
  let assert Ok(Nil) =
    redirect_proxy.run(["client", "list", "--config", config_path])

  let settings =
    clients.Settings(
      path: dir <> "/data/api_clients.json",
      audit_path: dir <> "/data/audit.jsonl",
    )
  let assert Ok([ci, default]) = clients.list(settings)
  assert ci.scopes == [scope.Read, scope.Ops]
  assert default.scopes == [scope.Write]

  let assert Ok(Nil) =
    redirect_proxy.run([
      "client",
      "rotate",
      ci.client_id,
      "--config",
      config_path,
    ])
  let assert Ok(rotated) = clients.get(settings, ci.client_id)
  assert rotated.secret_hash != ci.secret_hash
  let assert Ok(Nil) =
    redirect_proxy.run([
      "client",
      "delete",
      ci.client_id,
      "--config",
      config_path,
    ])
  let assert Error(_) =
    redirect_proxy.run([
      "client",
      "delete",
      ci.client_id,
      "--config",
      config_path,
    ])
}

pub fn bootstrap_admin_test() {
  let #(_dir, config_path) = setup()
  let assert Ok(cfg) = config_loader.load(config_path)
  let settings = app.users_settings(cfg)
  envoy.set("RP_BOOTSTRAP_ADMIN_USERNAME", "boot")
  envoy.set("RP_BOOTSTRAP_ADMIN_PASSWORD", "bootstrap-password")
  app.bootstrap_admin(cfg)
  assert users.count(settings) == 1
  let assert Ok(user) = users.get(settings, "boot")
  assert password.verify("bootstrap-password", user.password_hash)
  // once an administrator exists, nothing more is created or changed
  envoy.set("RP_BOOTSTRAP_ADMIN_PASSWORD", "another-password")
  app.bootstrap_admin(cfg)
  envoy.unset("RP_BOOTSTRAP_ADMIN_USERNAME")
  envoy.unset("RP_BOOTSTRAP_ADMIN_PASSWORD")
  assert users.count(settings) == 1
  let assert Ok(same) = users.get(settings, "boot")
  assert same.password_hash == user.password_hash
}

pub fn user_role_command_test() {
  let #(dir, config_path) = setup()
  let settings =
    app.users_settings(
      config.Config(
        ..config.default(),
        storage: config.StorageConfig(
          ..config.default().storage,
          data_dir: dir <> "/data",
        ),
      ),
    )
  envoy.set("RP_PASSWORD", "cli-password-123")
  let assert Ok(Nil) =
    redirect_proxy.run([
      "user", "add", "frank", "--role", "viewer", "--config", config_path,
    ])
  envoy.unset("RP_PASSWORD")
  let assert Ok(frank) = users.get(settings, "frank")
  assert frank.role == role.Viewer
  let assert Ok(Nil) =
    redirect_proxy.run([
      "user",
      "role",
      "frank",
      "editor",
      "--config",
      config_path,
    ])
  let assert Ok(frank) = users.get(settings, "frank")
  assert frank.role == role.Editor
  let assert Error(_) =
    redirect_proxy.run([
      "user",
      "role",
      "frank",
      "owner",
      "--config",
      config_path,
    ])
  let assert Error(_) =
    redirect_proxy.run([
      "user",
      "role",
      "nobody",
      "admin",
      "--config",
      config_path,
    ])
  // the last administrator cannot be demoted
  let assert Ok(Nil) =
    redirect_proxy.run([
      "user",
      "role",
      "frank",
      "admin",
      "--config",
      config_path,
    ])
  let assert Error(message) =
    redirect_proxy.run([
      "user",
      "role",
      "frank",
      "viewer",
      "--config",
      config_path,
    ])
  assert string.contains(message, "last administrator")
}
