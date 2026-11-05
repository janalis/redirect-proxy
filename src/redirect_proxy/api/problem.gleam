//// RFC 9457 problem details responses and small JSON helpers.

import gleam/json.{type Json}
import gleam/list
import gleam/string
import wisp.{type Response}

pub fn json_response(status: Int, body: Json) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "application/json; charset=utf-8")
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.string_body(json.to_string(body))
}

pub fn problem(
  status: Int,
  title: String,
  detail: String,
  extra: List(#(String, Json)),
) -> Response {
  let body =
    json.object([
      #("type", json.string("about:blank")),
      #("title", json.string(title)),
      #("status", json.int(status)),
      #("detail", json.string(detail)),
      ..extra
    ])
  wisp.response(status)
  |> wisp.set_header("content-type", "application/problem+json")
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.string_body(json.to_string(body))
}

pub fn not_found(detail: String) -> Response {
  problem(404, "Not Found", detail, [])
}

pub fn bad_request(detail: String) -> Response {
  problem(400, "Bad Request", detail, [])
}

pub fn method_not_allowed(allowed: List(String)) -> Response {
  problem(
    405,
    "Method Not Allowed",
    "Allowed: " <> string.join(allowed, ", "),
    [],
  )
  |> wisp.set_header("allow", string.join(allowed, ", "))
}

pub fn precondition_failed(current_version: String) -> Response {
  problem(
    412,
    "Precondition Failed",
    "The resource was modified since the version given in If-Match.",
    [#("current_version", json.string(current_version))],
  )
  |> wisp.set_header("etag", etag(current_version))
}

/// 422 with field errors built from the `"field: message"` strings produced
/// by rule validation.
pub fn validation(errors: List(String)) -> Response {
  problem(422, "Unprocessable Content", "The request contains invalid values.", [
    #("errors", json.array(list.map(errors, field_error), fn(j) { j })),
  ])
}

fn field_error(message: String) -> Json {
  let #(field, text) = case string.split_once(message, ": ") {
    Ok(#(field, text)) ->
      case string.contains(field, " ") {
        // "rule #2 (...): source: ..." style messages keep their prefix
        True -> #("", message)
        False -> #(field, text)
      }
    Error(Nil) -> #("", message)
  }
  json.object([#("field", json.string(field)), #("message", json.string(text))])
}

/// 401 with a `WWW-Authenticate: Bearer` challenge (RFC 6750 §3).
pub fn unauthorized(error: String, description: String) -> Response {
  let challenge = case error {
    "" -> "Bearer realm=\"redirect-proxy\""
    _ ->
      "Bearer realm=\"redirect-proxy\", error=\""
      <> error
      <> "\", error_description=\""
      <> quote_safe(description)
      <> "\""
  }
  problem(401, "Unauthorized", description, [])
  |> wisp.set_header("www-authenticate", challenge)
}

/// 403 for a valid token lacking the required scope (RFC 6750 §3.1).
pub fn insufficient_scope(required: String) -> Response {
  problem(
    403,
    "Forbidden",
    "The access token does not grant the " <> required <> " scope.",
    [#("required_scope", json.string(required))],
  )
  |> wisp.set_header(
    "www-authenticate",
    "Bearer realm=\"redirect-proxy\", error=\"insufficient_scope\", scope=\""
      <> required
      <> "\"",
  )
}

pub fn etag(version: String) -> String {
  "\"" <> version <> "\""
}

/// Extracts the version from an `If-Match` header value. `*` is kept as is;
/// weak validators are accepted (`W/"..."`).
pub fn parse_if_match(value: String) -> String {
  let value = string.trim(value)
  let value = case string.starts_with(value, "W/") {
    True -> string.drop_start(value, 2)
    False -> value
  }
  value
  |> string.split(",")
  |> list.first
  |> fn(first) {
    case first {
      Ok(v) -> v
      Error(Nil) -> value
    }
  }
  |> string.trim
  |> string.replace("\"", "")
}

fn quote_safe(value: String) -> String {
  value |> string.replace("\"", "'") |> string.replace("\\", "/")
}
