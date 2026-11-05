//// API permissions. Built-in clients use the canonical names below; tokens
//// from an external authorization server are mapped through the configured
//// scope names (`api.oauth.*_scope`).

import gleam/list
import gleam/string
import redirect_proxy/config.{type ApiOAuthConfig}

pub type Scope {
  /// List, read, export and test redirections.
  Read
  /// Create, update, delete and import redirections (implies `Read`).
  Write
  /// Operational actions such as reloading the redirections file.
  Ops
}

pub const all = [Read, Write, Ops]

pub fn to_string(scope: Scope) -> String {
  case scope {
    Read -> "redirects:read"
    Write -> "redirects:write"
    Ops -> "redirects:ops"
  }
}

pub fn from_string(value: String) -> Result(Scope, Nil) {
  case value {
    "redirects:read" -> Ok(Read)
    "redirects:write" -> Ok(Write)
    "redirects:ops" -> Ok(Ops)
    _ -> Error(Nil)
  }
}

/// Parses a space (or comma) separated scope list, ignoring unknown scopes.
pub fn parse_list(value: String) -> List(Scope) {
  value
  |> string.replace(",", " ")
  |> string.split(" ")
  |> list.filter_map(from_string)
  |> list.unique
}

pub fn join(scopes: List(Scope)) -> String {
  scopes |> list.map(to_string) |> string.join(" ")
}

/// Whether a set of granted scopes satisfies a required one.
pub fn allows(granted: List(Scope), required: Scope) -> Bool {
  list.contains(granted, required)
  || { required == Read && list.contains(granted, Write) }
}

/// Maps scope names found in an external access token to API scopes.
pub fn from_external(cfg: ApiOAuthConfig, names: List(String)) -> List(Scope) {
  [
    #(cfg.read_scope, Read),
    #(cfg.write_scope, Write),
    #(cfg.ops_scope, Ops),
  ]
  |> list.filter(fn(pair) { list.contains(names, pair.0) })
  |> list.map(fn(pair) { pair.1 })
}

/// The name an external token must carry for a scope (used in error hints).
pub fn external_name(cfg: ApiOAuthConfig, scope: Scope) -> String {
  case scope {
    Read -> cfg.read_scope
    Write -> cfg.write_scope
    Ops -> cfg.ops_scope
  }
}
