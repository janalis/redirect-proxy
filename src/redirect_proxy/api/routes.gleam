//// The operations of the REST API under `/api/`, in one place. The router
//// dispatches with a pattern match, and reads this table for what follows
//// from it: the `Allow` header of a 405, and the path template a request
//// is matched to (deprecations). A test checks it against the router and
//// the OpenAPI document.

import gleam/http.{type Method, Delete, Get, Patch, Post, Put}
import gleam/list
import gleam/string

pub type Operation {
  Operation(method: Method, template: String)
}

/// Every operation that needs a bearer token (`/api/openapi.json` and the
/// token endpoint are public and routed apart).
pub const operations = [
  Operation(Get, "/api/redirects"),
  Operation(Post, "/api/redirects"),
  Operation(Get, "/api/redirects/export"),
  Operation(Post, "/api/redirects/import"),
  Operation(Post, "/api/redirects/bulk"),
  Operation(Get, "/api/redirects/{id}"),
  Operation(Put, "/api/redirects/{id}"),
  Operation(Patch, "/api/redirects/{id}"),
  Operation(Delete, "/api/redirects/{id}"),
  Operation(Post, "/api/reload"),
  Operation(Get, "/api/test"),
  Operation(Get, "/api/audit"),
]

/// The template of the path segments after `/api/` (`["redirects", "42"]` is
/// `/api/redirects/{id}`): literal segments win over `{id}`.
pub fn template(segments: List(String)) -> Result(String, Nil) {
  let templates = list.unique(list.map(operations, fn(o) { o.template }))
  let path = "/api/" <> string.join(segments, "/")
  case list.contains(templates, path) {
    True -> Ok(path)
    False ->
      list.find(templates, fn(t) {
        matches(string.split(t, "/") |> list.drop(2), segments)
      })
  }
}

fn matches(template: List(String), segments: List(String)) -> Bool {
  case template, segments {
    [], [] -> True
    ["{" <> _, ..t], [s, ..rest] -> s != "" && matches(t, rest)
    [literal, ..t], [s, ..rest] -> literal == s && matches(t, rest)
    _, _ -> False
  }
}

/// The methods of a template, for the `Allow` header of a 405.
pub fn allowed(template: String) -> List(String) {
  operations
  |> list.filter(fn(o) { o.template == template })
  |> list.map(fn(o) { http.method_to_string(o.method) |> string.uppercase })
}
