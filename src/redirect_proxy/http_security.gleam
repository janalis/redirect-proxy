//// Security response headers of the admin and API listeners. The two sets
//// differ (the admin serves HTML, the API JSON); the code that applies
//// them, and the HTTPS rule for `strict-transport-security`, is shared.

import gleam/list
import gleam/string
import wisp.{type Response}

const hsts = "max-age=31536000"

/// Headers of the admin's HTML pages. `form_action_extra` is appended to
/// the CSP's `form-action` (the OIDC provider's logout origin, or "").
pub fn admin(form_action_extra: String) -> List(#(String, String)) {
  [
    #(
      "content-security-policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        <> "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        <> form_action_extra,
    ),
    #("x-frame-options", "DENY"),
    #("x-content-type-options", "nosniff"),
    #("referrer-policy", "same-origin"),
    #("cross-origin-opener-policy", "same-origin"),
    #("permissions-policy", "camera=(), microphone=(), geolocation=()"),
  ]
}

/// Headers of the API's own listener (JSON only).
pub const api = [
  #("x-content-type-options", "nosniff"),
  #("x-frame-options", "DENY"),
  #("referrer-policy", "no-referrer"),
]

pub fn set(resp: Response, headers: List(#(String, String))) -> Response {
  list.fold(headers, resp, fn(resp, header) {
    wisp.set_header(resp, header.0, header.1)
  })
}

/// Whether `public_url` is HTTPS: its listener then sends HSTS.
pub fn https_url(public_url: String) -> Bool {
  string.starts_with(string.lowercase(public_url), "https://")
}

/// Once a client used HTTPS to reach `public_url`, it must not fall back
/// to HTTP.
pub fn strict_transport_security(
  resp: Response,
  public_url: String,
) -> Response {
  case https_url(public_url) {
    True -> wisp.set_header(resp, "strict-transport-security", hsts)
    False -> resp
  }
}
