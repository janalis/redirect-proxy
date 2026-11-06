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

/// Turns wisp's plain-text error responses (malformed or oversized body,
/// wrong content type, a crash) into problem details, or into OAuth errors
/// for the token endpoint, so that every API error has a JSON body.
pub fn from_plain_error(resp: Response, oauth: Bool) -> Response {
  case
    resp.status >= 400,
    list.key_find(resp.headers, "content-type"),
    resp.body
  {
    True, Ok("text/plain"), wisp.Text(detail) -> {
      let converted = case oauth {
        True ->
          json_response(
            resp.status,
            json.object([
              #(
                "error",
                json.string(case resp.status {
                  500 -> "server_error"
                  _ -> "invalid_request"
                }),
              ),
              #("error_description", json.string(detail)),
            ]),
          )
        False ->
          problem(resp.status, status_title(resp.status, detail), detail, [])
      }
      // keep what wisp added, such as `accept` on a 415
      resp.headers
      |> list.filter(fn(h) { h.0 != "content-type" })
      |> list.fold(converted, fn(r, h) { wisp.set_header(r, h.0, h.1) })
    }
    _, _, _ -> resp
  }
}

fn status_title(status: Int, fallback: String) -> String {
  case status {
    400 -> "Bad Request"
    413 -> "Content Too Large"
    415 -> "Unsupported Media Type"
    500 -> "Internal Server Error"
    _ -> fallback
  }
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

pub type IfMatch {
  /// `*`: any current version.
  AnyVersion
  /// The versions of the strong entity tags listed. Weak tags (`W/"..."`)
  /// are left out: `If-Match` uses the strong comparison (RFC 9110), so
  /// they never match.
  Versions(List(String))
}

/// Parses an `If-Match` header value.
pub fn parse_if_match(value: String) -> IfMatch {
  case string.trim(value) {
    "*" -> AnyVersion
    value ->
      value
      |> string.split(",")
      |> list.map(string.trim)
      |> list.filter_map(fn(tag) {
        case string.starts_with(tag, "\"") && string.ends_with(tag, "\"") {
          True if tag != "\"" -> Ok(string.slice(tag, 1, string.length(tag) - 2))
          _ -> Error(Nil)
        }
      })
      |> Versions
  }
}

/// Parses an `If-None-Match` header value. Unlike `If-Match`, it uses the
/// weak comparison (RFC 9110): `W/"v"` matches version `v`.
pub fn parse_if_none_match(value: String) -> IfMatch {
  value
  |> string.split(",")
  |> list.map(fn(tag) {
    case string.trim(tag) {
      "W/" <> strong -> strong
      strong -> strong
    }
  })
  |> string.join(",")
  |> parse_if_match
}

/// The version to require from the store: the current one when `If-Match`
/// lists it (or is `*`), otherwise one that cannot match (412).
pub fn expected_version(condition: IfMatch, current: String) -> String {
  case condition {
    AnyVersion -> "*"
    Versions(versions) ->
      case list.contains(versions, current) {
        True -> current
        False -> "\u{0}no matching entity tag"
      }
  }
}

fn quote_safe(value: String) -> String {
  value |> string.replace("\"", "'") |> string.replace("\\", "/")
}
