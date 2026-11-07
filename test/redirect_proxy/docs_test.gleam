//// Keeps the documented environment variables and metrics (README.md and
//// docs/) in step with the code.

import gleam/list
import gleam/option
import gleam/regexp
import gleam/string
import redirect_proxy/metrics
import simplifile

/// The README and the pages of docs/, as one text.
fn documentation() -> String {
  let assert Ok(readme) = simplifile.read("README.md")
  let assert Ok(pages) = simplifile.get_files("docs")
  pages
  |> list.filter(string.ends_with(_, ".md"))
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
