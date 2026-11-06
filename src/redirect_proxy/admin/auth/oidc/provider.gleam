//// OpenID Connect providers and OAuth 2.0 authorization servers: discovery,
//// signing keys (JWKS) and JWT signature checks, cached, with failures
//// remembered and concurrent fetches coalesced.

import gleam/bool
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/json
import gleam/result
import gleam/string
import redirect_proxy/config.{type OidcConfig}
import redirect_proxy/ffi
import redirect_proxy/metrics

pub const table = "redirect_proxy_oidc"

const cache_ttl = 3600

pub type Provider {
  Provider(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0), "" when
    /// the provider does not offer it.
    end_session_endpoint: String,
  )
}

pub fn discover(cfg: OidcConfig) -> Result(Provider, String) {
  discover_issuer(cfg.issuer)
}

/// Discovers (and caches for an hour) the metadata of an OpenID Connect
/// provider or OAuth 2.0 authorization server (RFC 8414).
pub fn discover_issuer(issuer: String) -> Result(Provider, String) {
  let cached = fn() {
    let now = ffi.now_seconds()
    case ffi.ets_get(table, "provider:" <> issuer) {
      Ok(#(expires_at, provider)) if expires_at > now -> Ok(provider)
      _ -> Error(Nil)
    }
  }
  case cached() {
    Ok(provider) -> Ok(provider)
    Error(Nil) ->
      guarded_fetch("provider:" <> issuer, fn() {
        // another request may have fetched it while we waited
        case cached() {
          Ok(provider) -> Ok(provider)
          Error(Nil) -> fetch_provider(issuer)
        }
      })
  }
}

/// How long a failed fetch is remembered: while the provider is down,
/// requests fail at once instead of each waiting for a timeout.
const failure_ttl = 30

/// Runs `fetch` for `key` at most once at a time on this node (concurrent
/// callers wait for it, then find its result in the cache), and remembers a
/// failure for `failure_ttl` seconds.
fn guarded_fetch(
  key: String,
  fetch: fn() -> Result(a, String),
) -> Result(a, String) {
  let recent_failure = fn() {
    let now = ffi.now_seconds()
    case ffi.ets_get(table, "failed:" <> key) {
      Ok(#(expires_at, reason)) if expires_at > now -> Ok(reason)
      _ -> Error(Nil)
    }
  }
  case recent_failure() {
    Ok(reason) -> Error(reason)
    Error(Nil) -> {
      use <- ffi.with_lock("oidc-fetch:" <> key)
      case recent_failure() {
        Ok(reason) -> Error(reason)
        Error(Nil) ->
          case fetch() {
            Ok(value) -> Ok(value)
            Error(reason) -> {
              metrics.incr(metrics.IdpFetchFailures)
              ffi.ets_put(table, "failed:" <> key, #(
                ffi.now_seconds() + failure_ttl,
                reason,
              ))
              Error(reason)
            }
          }
      }
    }
  }
}

fn fetch_provider(configured_issuer: String) -> Result(Provider, String) {
  let base = trim_trailing_slash(configured_issuer)
  let url = base <> "/.well-known/openid-configuration"
  use #(url, body) <- result.try(case http_get(url) {
    Ok(body) -> Ok(#(url, body))
    Error(first_error) -> {
      let fallback = base <> "/.well-known/oauth-authorization-server"
      http_get(fallback)
      |> result.map(fn(body) { #(fallback, body) })
      |> result.replace_error(first_error)
    }
  })
  let decoder = {
    use issuer <- decode.field("issuer", decode.string)
    use authorization_endpoint <- decode.optional_field(
      "authorization_endpoint",
      "",
      decode.string,
    )
    use token_endpoint <- decode.optional_field(
      "token_endpoint",
      "",
      decode.string,
    )
    use jwks_uri <- decode.field("jwks_uri", decode.string)
    use end_session_endpoint <- decode.optional_field(
      "end_session_endpoint",
      "",
      decode.string,
    )
    decode.success(Provider(
      issuer:,
      authorization_endpoint:,
      token_endpoint:,
      jwks_uri:,
      end_session_endpoint:,
    ))
  }
  use provider <- result.try(
    json.parse(body, decoder)
    |> result.replace_error("invalid OpenID discovery document at " <> url),
  )
  use <- bool.guard(
    trim_trailing_slash(provider.issuer) != base,
    Error(
      "discovery issuer "
      <> provider.issuer
      <> " does not match configured issuer "
      <> configured_issuer,
    ),
  )
  ffi.ets_put(table, "provider:" <> configured_issuer, #(
    ffi.now_seconds() + cache_ttl,
    provider,
  ))
  Ok(provider)
}

fn jwks(provider: Provider, refresh: Bool) -> Result(String, String) {
  let key = "jwks:" <> provider.jwks_uri
  let cached = fn() {
    let now = ffi.now_seconds()
    case ffi.ets_get(table, key) {
      Ok(#(expires_at, #(fetched_at, body))) -> {
        // A forced refresh (unknown signing key) is honoured at most once a
        // minute so that bogus tokens cannot make us hammer the provider.
        let fresh = case refresh {
          True -> now - fetched_at < 60
          False -> expires_at > now
        }
        case fresh {
          True -> Ok(body)
          False -> Error(Nil)
        }
      }
      Error(Nil) -> Error(Nil)
    }
  }
  case cached() {
    Ok(body) -> Ok(body)
    Error(Nil) ->
      guarded_fetch(key, fn() {
        case cached() {
          Ok(body) -> Ok(body)
          Error(Nil) -> {
            use body <- result.try(http_get(provider.jwks_uri))
            let now = ffi.now_seconds()
            ffi.ets_put(table, key, #(now + cache_ttl, #(now, body)))
            Ok(body)
          }
        }
      })
  }
}

/// Verifies the signature of a JWT against the provider's JWKS and returns
/// its claims as JSON. The JWKS is refreshed once on failure (key rotation).
pub fn verify_signature(
  provider: Provider,
  token: String,
) -> Result(String, String) {
  use keys <- result.try(jwks(provider, False))
  case ffi.jwt_verify(keys, token) {
    Ok(claims) -> Ok(claims)
    Error(_) -> {
      use keys <- result.try(jwks(provider, True))
      ffi.jwt_verify(keys, token)
    }
  }
}

fn http_get(url: String) -> Result(String, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("invalid URL " <> url),
  )
  use resp <- result.try(
    dispatch(request.set_header(req, "accept", "application/json"))
    |> result.map_error(fn(e) { "request to " <> url <> " failed: " <> e }),
  )
  case resp.status {
    200 -> Ok(resp.body)
    status -> Error(url <> " answered HTTP " <> string.inspect(status))
  }
}

/// Sends a request to the provider with a 10 second timeout. Errors that
/// gleam_httpc raises instead of returning (a connection closed by the
/// provider...) are returned too, so that a misbehaving provider fails the
/// login or the API request instead of crashing it.
pub fn dispatch(
  req: request.Request(String),
) -> Result(response.Response(String), String) {
  ffi.rescue(fn() {
    httpc.configure()
    |> httpc.timeout(10_000)
    |> httpc.dispatch(req)
  })
  |> result.try(fn(sent) { sent |> result.map_error(string.inspect) })
}

pub fn trim_trailing_slash(value: String) -> String {
  case string.ends_with(value, "/") {
    True -> string.drop_end(value, 1)
    False -> value
  }
}
