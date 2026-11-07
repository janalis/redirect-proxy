//// The operations of the REST API under `/api/`, in one place. The router
//// dispatches with a pattern match, and reads this table for what follows
//// from it: the scope a request needs (checked before the dispatch, so that
//// a new operation cannot forget it), the `Allow` header of a 405, and the
//// path template a request is matched to (deprecations). A test checks it
//// against the router and the OpenAPI document.

import gleam/http.{type Method, Delete, Get, Patch, Post, Put}
import gleam/list
import gleam/string
import redirect_proxy/api/scope.{type Scope, Audit, Ops, Read, Write}

pub type Operation {
  Operation(method: Method, template: String, scope: Scope)
}

/// Every operation that needs a bearer token (`/api/openapi.json` and the
/// token endpoint are public and routed apart).
pub const operations = [
  Operation(Get, "/api/redirects", Read),
  Operation(Post, "/api/redirects", Write),
  Operation(Get, "/api/redirects/export", Read),
  Operation(Post, "/api/redirects/import", Write),
  Operation(Post, "/api/redirects/bulk", Write),
  Operation(Get, "/api/redirects/{id}", Read),
  Operation(Put, "/api/redirects/{id}", Write),
  Operation(Patch, "/api/redirects/{id}", Write),
  Operation(Delete, "/api/redirects/{id}", Write),
  Operation(Post, "/api/reload", Ops),
  Operation(Get, "/api/test", Read),
  Operation(Get, "/api/audit", Audit),
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

/// The operation of a method on a template.
pub fn find(method: Method, template: String) -> Result(Operation, Nil) {
  list.find(operations, fn(o) { o.method == method && o.template == template })
}

/// The methods of a template, for the `Allow` header of a 405.
pub fn allowed(template: String) -> List(String) {
  operations
  |> list.filter(fn(o) { o.template == template })
  |> list.map(fn(o) { http.method_to_string(o.method) |> string.uppercase })
}
