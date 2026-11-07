//// Query parameters and results shared by the handlers of the REST API.

import gleam/int
import gleam/list
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/api/problem
import wisp.{type Response}

/// Collections are paged: at most `max_per_page` items a page,
/// `default_per_page` unless the request says otherwise.
pub const max_per_page = 500

pub const default_per_page = 100

/// A positive integer query parameter, or `default` when it is not set.
pub fn positive_param(
  get: fn(String) -> String,
  name: String,
  default: Int,
) -> Result(Int, Response) {
  case get(name) {
    "" -> Ok(default)
    value ->
      case int.parse(value) {
        Ok(n) if n >= 1 -> Ok(n)
        _ -> Error(problem.bad_request(name <> " must be a positive integer."))
      }
  }
}

pub fn result_or_response(
  result: Result(a, Response),
  next: fn(a) -> Response,
) -> Response {
  case result {
    Ok(value) -> next(value)
    Error(response) -> response
  }
}

/// Adds the `Deprecation`, `Sunset` and `Link` headers of what a request
/// used that is deprecated.
pub fn add_deprecation_headers(
  response: Response,
  used: List(Deprecation),
) -> Response {
  list.fold(deprecation.headers(used), response, fn(resp, header) {
    wisp.set_header(resp, header.0, header.1)
  })
}
