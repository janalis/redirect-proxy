//// Deprecation registry. The API has no version prefix: it evolves by adding
//// fields and endpoints, and retires old ones by deprecating them first.
////
//// A deprecated field or route keeps working until a major release. While it
//// is deprecated, responses to requests using it carry a `Deprecation`
//// header (RFC 9745) and, once a removal date is set, a `Sunset` header
//// (RFC 8594). The OpenAPI document flags it with `deprecated: true`.
//// Both read this registry, so they cannot diverge.

import gleam/int
import gleam/list
import gleam/option.{type Option, None}

pub type Target {
  /// A property of a JSON schema (`schema` is the OpenAPI component name).
  Field(schema: String, name: String)
  /// An operation, e.g. `Route("get", "/api/test")`.
  Route(method: String, path: String)
  /// A value of a query parameter of an operation, e.g.
  /// `QueryValue("get", "/api/redirects", "sort", "updated")`. A value
  /// prefixed with `-` (descending) counts as the value.
  QueryValue(method: String, path: String, parameter: String, value: String)
}

pub type Deprecation {
  Deprecation(
    target: Target,
    /// Unix timestamp of the deprecation (RFC 9745 `Deprecation: @<ts>`).
    since: Int,
    /// HTTP-date after which the target may be removed, when decided.
    sunset: Option(String),
    /// What to use instead (documentation).
    replacement: String,
  )
}

/// 2026-11-17, when the sort fields took the names of the JSON fields.
const sort_renamed = 1_794_873_600

/// The current registry.
pub fn registry() -> List(Deprecation) {
  [
    Deprecation(
      target: QueryValue("get", "/api/redirects", "sort", "last_hit"),
      since: sort_renamed,
      sunset: None,
      replacement: "last_hit_at",
    ),
    Deprecation(
      target: QueryValue("get", "/api/redirects", "sort", "updated"),
      since: sort_renamed,
      sunset: None,
      replacement: "updated_at",
    ),
  ]
}

pub fn for_route(
  registry: List(Deprecation),
  method: String,
  path: String,
) -> List(Deprecation) {
  list.filter(registry, fn(d) { d.target == Route(method, path) })
}

pub fn for_fields(
  registry: List(Deprecation),
  schema: String,
  used: List(String),
) -> List(Deprecation) {
  list.filter(registry, fn(d) {
    case d.target {
      Field(s, name) -> s == schema && list.contains(used, name)
      Route(..) | QueryValue(..) -> False
    }
  })
}

/// The deprecations of `value` of the query `parameter` of an operation
/// (`-value` included).
pub fn for_query_value(
  registry: List(Deprecation),
  method: String,
  path: String,
  parameter: String,
  value: String,
) -> List(Deprecation) {
  let value = case value {
    "-" <> rest -> rest
    _ -> value
  }
  list.filter(registry, fn(d) {
    d.target == QueryValue(method, path, parameter, value)
  })
}

/// The deprecated values of the query `parameter` of an operation.
pub fn deprecated_values(
  registry: List(Deprecation),
  method: String,
  path: String,
  parameter: String,
) -> List(Deprecation) {
  list.filter(registry, fn(d) {
    case d.target {
      QueryValue(m, p, name, _) -> m == method && p == path && name == parameter
      Field(..) | Route(..) -> False
    }
  })
}

pub fn is_field_deprecated(
  registry: List(Deprecation),
  schema: String,
  name: String,
) -> Bool {
  list.any(registry, fn(d) { d.target == Field(schema, name) })
}

pub fn is_route_deprecated(
  registry: List(Deprecation),
  method: String,
  path: String,
) -> Bool {
  for_route(registry, method, path) != []
}

/// Response headers announcing the given deprecations (earliest wins).
pub fn headers(used: List(Deprecation)) -> List(#(String, String)) {
  case list.sort(used, fn(a, b) { int.compare(a.since, b.since) }) {
    [] -> []
    [first, ..] -> {
      let sunset =
        used
        |> list.filter_map(fn(d) { option.to_result(d.sunset, Nil) })
        |> list.first
      [#("deprecation", "@" <> int.to_string(first.since))]
      |> list.append(case sunset {
        Ok(date) -> [#("sunset", date)]
        Error(Nil) -> []
      })
    }
  }
}
