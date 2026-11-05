import envoy
import gleam/string
import redirect_proxy
import redirect_proxy/config
import redirect_proxy/password
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
