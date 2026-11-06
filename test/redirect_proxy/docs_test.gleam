//// Keeps the README's environment variable table in step with the code.

import gleam/list
import gleam/option
import gleam/regexp
import gleam/string
import simplifile

/// Every `RP_…` variable read in config/env.gleam is named in the README.
pub fn every_env_var_is_documented_test() {
  let assert Ok(code) = simplifile.read("src/redirect_proxy/config/env.gleam")
  let assert Ok(readme) = simplifile.read("README.md")
  let assert Ok(literal) = regexp.from_string("\"(RP_[A-Z0-9_]+)\"")
  let used =
    regexp.scan(literal, code)
    |> list.filter_map(fn(m) {
      case m.submatches {
        [option] -> option_value(option)
        _ -> Error(Nil)
      }
    })
    // "RP_ACCESS_LOG_" <> listener <> … builds the per-listener variables
    |> list.filter(fn(var) { !string.ends_with(var, "_") })
    |> list.unique
  let documented = documented_vars(readme)
  let missing = list.filter(used, fn(var) { !list.contains(documented, var) })
  assert missing == []
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

fn documented_vars(readme: String) -> List(String) {
  string.split(readme, "\n")
  |> list.flat_map(fn(line) {
    // code spans are the odd pieces between backticks
    let spans =
      string.split(line, "`")
      |> list.index_map(fn(piece, i) { #(piece, i % 2 == 1) })
      |> list.filter_map(fn(p) {
        case p.1 {
          True -> Ok(p.0)
          False -> Error(Nil)
        }
      })
    let full =
      spans
      |> list.filter(string.starts_with(_, "RP_"))
      |> list.flat_map(expand_braces)
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
