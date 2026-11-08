//// Keeps the documented environment variables, metrics and commands
//// (README.md and docs/), and config.example.toml, in step with the code.

import gleam/dict
import gleam/list
import gleam/option
import gleam/regexp
import gleam/string
import redirect_proxy/config/file as config_file
import redirect_proxy/metrics
import simplifile
import tom

/// The README and the pages of docs/, as one text. The site's installed
/// packages and build output are not documentation.
fn documentation() -> String {
  let assert Ok(readme) = simplifile.read("README.md")
  let assert Ok(pages) = simplifile.get_files("docs")
  pages
  |> list.filter(string.ends_with(_, ".md"))
  |> list.filter(fn(path) {
    !string.starts_with(path, "docs/node_modules/")
    && !string.starts_with(path, "docs/.vitepress/")
  })
  |> list.sort(string.compare)
  |> list.map(fn(path) {
    let assert Ok(page) = simplifile.read(path)
    page
  })
  |> list.prepend(readme)
  |> string.join("\n")
}

/// Every `RP_…` variable the code reads is documented.
pub fn every_env_var_is_documented_test() {
  let readme = documentation()
  let documented = documented_vars(readme)
  let missing =
    code_literals()
    // "RP_ACCESS_LOG_" <> listener <> … builds the per-listener variables
    |> list.filter(fn(var) { !string.ends_with(var, "_") })
    |> list.filter(fn(var) { !list.contains(documented, var) })
  assert missing == []
}

/// Every `RP_…` variable written out in the documentation is read by the code: a
/// literal, a per-listener name built from a literal prefix, or a `_FILE`
/// variant of a secret.
pub fn every_documented_env_var_exists_test() {
  let readme = documentation()
  let literals = code_literals()
  let known = fn(var) {
    list.contains(literals, var)
    || list.any(literals, fn(literal) {
      string.ends_with(literal, "_") && string.starts_with(var, literal)
    })
    || {
      string.ends_with(var, "_FILE")
      && list.contains(literals, string.drop_end(var, 5))
    }
  }
  let unknown =
    written_vars(readme)
    |> list.unique
    |> list.filter(fn(var) { !known(var) })
  assert unknown == []
}

/// The `"RP_…"` string literals of every source file.
fn code_literals() -> List(String) {
  let assert Ok(files) = simplifile.get_files("src")
  let assert Ok(literal) = regexp.from_string("\"(RP_[A-Z0-9_]+)\"")
  files
  |> list.filter(string.ends_with(_, ".gleam"))
  |> list.flat_map(fn(path) {
    let assert Ok(code) = simplifile.read(path)
    regexp.scan(literal, code)
    |> list.filter_map(fn(m) {
      case m.submatches {
        [option] -> option_value(option)
        _ -> Error(Nil)
      }
    })
  })
  |> list.unique
}

/// The README abbreviates related variables on one line: after
/// `RP_AUTH_OIDC_ENABLED`, `_ISSUER` stands for `RP_AUTH_OIDC_ISSUER`, and
/// `RP_ACCESS_LOG_{REDIRECT,ADMIN}_ENABLED` lists one variable per listener.
pub fn documented_vars_expands_shorthands_test() {
  let vars =
    documented_vars(
      "| `RP_AUTH_OIDC_ENABLED`, `_ISSUER` | x |\n| `RP_A_{B,C}_ON`, `_OFF` |",
    )
  assert list.contains(vars, "RP_AUTH_OIDC_ISSUER")
  assert list.contains(vars, "RP_A_B_ON")
  assert list.contains(vars, "RP_A_C_OFF")
  // a suffix only extends the variables of its own line
  assert !list.contains(vars, "RP_AUTH_OIDC_OFF")
}

fn option_value(option) -> Result(String, Nil) {
  case option {
    option.Some(value) -> Ok(value)
    option.None -> Error(Nil)
  }
}

/// The variables written out in full (braces expanded) in code spans.
fn written_vars(readme: String) -> List(String) {
  string.split(readme, "\n")
  |> list.flat_map(fn(line) { code_spans(line) |> full_vars })
}

fn code_spans(line: String) -> List(String) {
  // code spans are the odd pieces between backticks
  string.split(line, "`")
  |> list.index_map(fn(piece, i) { #(piece, i % 2 == 1) })
  |> list.filter_map(fn(p) {
    case p.1 {
      True -> Ok(p.0)
      False -> Error(Nil)
    }
  })
}

fn full_vars(spans: List(String)) -> List(String) {
  spans
  |> list.filter(fn(span) {
    string.starts_with(span, "RP_")
    // a name, not an example assignment like `RP_X=1` or a pattern
    && !string.contains(span, "=")
    && !string.contains(span, "<")
  })
  |> list.flat_map(expand_braces)
}

fn documented_vars(readme: String) -> List(String) {
  string.split(readme, "\n")
  |> list.flat_map(fn(line) {
    let spans = code_spans(line)
    let full = full_vars(spans)
    let abbreviated =
      spans
      |> list.filter(string.starts_with(_, "_"))
      |> list.flat_map(fn(suffix) {
        list.flat_map(full, fn(var) {
          prefixes(var) |> list.map(fn(prefix) { prefix <> suffix })
        })
      })
    list.append(full, abbreviated)
  })
}

/// `RP_A_{B,C}_D` → `RP_A_B_D`, `RP_A_C_D`.
fn expand_braces(var: String) -> List(String) {
  case string.split_once(var, "{") {
    Error(Nil) -> [var]
    Ok(#(before, rest)) ->
      case string.split_once(rest, "}") {
        Error(Nil) -> [var]
        Ok(#(choices, after)) ->
          string.split(choices, ",")
          |> list.flat_map(fn(choice) {
            expand_braces(before <> choice <> after)
          })
      }
  }
}

/// `RP_A_B_C` → `RP_A_B`, `RP_A`, `RP`.
fn prefixes(var: String) -> List(String) {
  let parts = string.split(var, "_")
  list.length(parts)
  |> shorter_prefixes(parts, _)
}

fn shorter_prefixes(parts: List(String), n: Int) -> List(String) {
  case n > 1 {
    True -> {
      let prefix = list.take(parts, n - 1) |> string.join("_")
      [prefix, ..shorter_prefixes(parts, n - 1)]
    }
    False -> []
  }
}

/// Every metric `/metrics` exports is documented, by its full name.
pub fn every_metric_is_documented_test() {
  metrics.init()
  let docs = documentation()
  let exported =
    metrics.render_prometheus()
    |> string.split("\n")
    |> list.filter_map(fn(line) {
      case string.split(line, " ") {
        ["#", "TYPE", name, ..] -> Ok(name)
        _ -> Error(Nil)
      }
    })
  assert list.length(exported) > 20
  let missing =
    list.filter(exported, fn(name) { !string.contains(docs, "`" <> name) })
  assert missing == []
}

/// Every command of the `help` usage has a section, with an example, in
/// docs/guide/cli.md.
pub fn every_command_is_documented_test() {
  let assert Ok(cli) = simplifile.read("docs/guide/cli.md")
  let commands = usage_commands()
  // serve, check-config, version, help and the user, client and rules
  // subcommands
  assert list.length(commands) >= 15
  let missing =
    list.filter(commands, fn(command) {
      !string.contains(cli, "redirect-proxy " <> command)
      || !string.contains(cli, "## `" <> command <> "`")
    })
  assert missing == []
}

/// The commands of the usage text in src/redirect_proxy.gleam: for each
/// `redirect-proxy …` line, its words (`client list|rotate <client_id>…`
/// gives `client list` and `client rotate`).
fn usage_commands() -> List(String) {
  let assert Ok(source) = simplifile.read("src/redirect_proxy.gleam")
  let assert Ok(#(_, after)) = string.split_once(source, "\nUsage:\n")
  let assert Ok(#(lines, _)) = string.split_once(after, "\n\n")
  string.split(lines, "\n")
  |> list.flat_map(fn(line) {
    // a description follows the command after two spaces or more
    let command = case string.split_once(string.trim(line), "  ") {
      Ok(#(command, _description)) -> command
      Error(Nil) -> string.trim(line)
    }
    case string.split(command, " ") {
      ["redirect-proxy", ..tokens] ->
        case command_words(tokens) {
          [] -> []
          [command] -> [command]
          [command, ..subcommands] ->
            list.map(subcommands, fn(sub) { command <> " " <> sub })
        }
      _ -> []
    }
  })
  |> list.unique
}

fn command_words(tokens: List(String)) -> List(String) {
  let assert Ok(word) = regexp.from_string("^[a-z][a-z-]*$")
  tokens
  |> list.flat_map(string.split(_, "|"))
  |> list.map(fn(piece) {
    // `[serve]`: an optional command word
    case string.starts_with(piece, "[") && string.ends_with(piece, "]") {
      True -> piece |> string.drop_start(1) |> string.drop_end(1)
      False -> piece
    }
  })
  |> list.filter(regexp.check(word, _))
}

pub fn usage_commands_test() {
  let commands = usage_commands()
  assert list.contains(commands, "serve")
  assert list.contains(commands, "client rotate")
  assert list.contains(commands, "rules import")
  assert list.contains(commands, "user role")
  // arguments and options are not commands
  assert !list.contains(commands, "rules replace")
  assert !list.contains(commands, "client client_id")
}

/// Every key the configuration file may hold is in config.example.toml,
/// and the example holds no other.
pub fn every_config_key_is_in_the_example_test() {
  let assert Ok(example) = config_file.read_toml("config.example.toml")
  let present = toml_keys(example, "")
  let missing =
    list.filter(config_file.known_keys, fn(key) { !list.contains(present, key) })
  assert missing == []
  assert config_file.unknown_keys(example) == []
}

fn toml_keys(t: dict.Dict(String, tom.Toml), prefix: String) -> List(String) {
  dict.to_list(t)
  |> list.flat_map(fn(entry) {
    let #(name, value) = entry
    case value {
      tom.Table(sub) | tom.InlineTable(sub) ->
        toml_keys(sub, prefix <> name <> ".")
      _ -> [prefix <> name]
    }
  })
}
