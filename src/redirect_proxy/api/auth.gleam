//// Bearer token authentication of API requests (RFC 6750). Accepts:
////
//// - opaque `rpat_` tokens issued by the built-in token endpoint,
//// - JWT access tokens issued by an external OAuth2/OIDC authorization
////   server (`api.oauth`), verified against its JWKS.
////
//// Cookies are never considered: the API is not exposed to CSRF.

import gleam/bool
import gleam/dynamic/decode
import gleam/http/request
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/oidc
import redirect_proxy/api/clients
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/api/token
import redirect_proxy/config.{type ApiOAuthConfig}
import redirect_proxy/ffi
import wisp

/// An authenticated API caller.
pub type Principal {
  Principal(
    /// Audit log actor: `client:<id>` or `oauth:<subject>`.
    actor: String,
    scopes: List(Scope),
  )
}

pub type AuthError {
  MissingToken
  InvalidToken(reason: String)
}

pub fn authenticate(
  req: wisp.Request,
  oauth: ApiOAuthConfig,
  clients_settings: clients.Settings,
) -> Result(Principal, AuthError) {
  use raw <- result.try(bearer(req))
  case string.starts_with(raw, token.prefix) {
    True -> {
      let invalid = InvalidToken("unknown, expired or revoked access token")
      use grant <- result.try(
        token.lookup(raw) |> result.replace_error(invalid),
      )
      // The client must still exist with the same secret.
      case clients.get(clients_settings, grant.client_id) {
        Ok(client) if client.secret_hash == grant.secret_hash ->
          Ok(Principal(
            actor: "client:" <> grant.client_id,
            scopes: grant.scopes,
          ))
        _ -> Error(invalid)
      }
    }
    False ->
      case oauth.enabled && list.length(string.split(raw, ".")) == 3 {
        True -> external(oauth, raw) |> result.map_error(InvalidToken)
        False -> Error(InvalidToken("unknown or expired access token"))
      }
  }
}

/// Extracts the token of an `Authorization: Bearer <token>` header.
pub fn bearer(req: wisp.Request) -> Result(String, AuthError) {
  case request.get_header(req, "authorization") {
    Error(Nil) -> Error(MissingToken)
    Ok(value) ->
      case string.split_once(string.trim(value), " ") {
        Ok(#(scheme, token)) ->
          case string.lowercase(scheme), string.trim(token) {
            "bearer", "" -> Error(InvalidToken("empty bearer token"))
            "bearer", token -> Ok(token)
            _, _ -> Error(MissingToken)
          }
        Error(Nil) -> Error(MissingToken)
      }
  }
}

fn external(oauth: ApiOAuthConfig, jwt: String) -> Result(Principal, String) {
  use provider <- result.try(
    oidc.discover_issuer(oauth.issuer)
    |> result.replace_error("authorization server unavailable"),
  )
  use claims <- result.try(
    oidc.verify_signature(provider, jwt)
    |> result.replace_error("invalid token signature"),
  )
  check_claims(oauth, provider.issuer, claims, ffi.now_seconds())
}

/// Validates the claims of an external access token. Exposed for tests.
pub fn check_claims(
  oauth: ApiOAuthConfig,
  issuer: String,
  claims_json: String,
  now: Int,
) -> Result(Principal, String) {
  let strings =
    decode.one_of(decode.list(decode.string), [
      decode.string |> decode.map(fn(s) { [s] }),
    ])
  let decoder = {
    use iss <- decode.field("iss", decode.string)
    use exp <- decode.field("exp", decode.int)
    use nbf <- decode.optional_field("nbf", 0, decode.int)
    use aud <- decode.optional_field("aud", [], strings)
    use sub <- decode.optional_field("sub", "", decode.string)
    use client_id <- decode.optional_field("client_id", "", decode.string)
    use azp <- decode.optional_field("azp", "", decode.string)
    use names <- decode.optional_field(oauth.scope_claim, [], scope_names())
    use scp <- decode.optional_field("scp", [], scope_names())
    decode.success(#(iss, exp, nbf, aud, sub, client_id, azp, names, scp))
  }
  use #(iss, exp, nbf, aud, sub, client_id, azp, names, scp) <- result.try(
    json.parse(claims_json, decoder)
    |> result.replace_error("access token is missing required claims"),
  )
  let leeway = 60
  use <- bool.guard(
    trim_slash(iss) != trim_slash(issuer),
    Error("access token issuer mismatch"),
  )
  use <- bool.guard(
    !list.contains(aud, oauth.audience),
    Error("access token audience mismatch"),
  )
  use <- bool.guard(exp + leeway < now, Error("access token expired"))
  use <- bool.guard(nbf - leeway > now, Error("access token not yet valid"))
  let subject = case sub, client_id, azp {
    "", "", a -> a
    "", c, _ -> c
    s, _, _ -> s
  }
  Ok(Principal(
    actor: "oauth:" <> subject,
    scopes: scope.from_external(oauth, list.append(names, scp)),
  ))
}

/// Scope claims are either a space separated string (`scope`, RFC 8693) or
/// an array of strings (`scp`, as issued by Entra ID / Okta).
fn scope_names() -> decode.Decoder(List(String)) {
  decode.one_of(decode.list(decode.string), [
    decode.string
    |> decode.map(fn(s) {
      s |> string.split(" ") |> list.filter(fn(x) { x != "" })
    }),
  ])
}

fn trim_slash(value: String) -> String {
  case string.ends_with(value, "/") {
    True -> string.drop_end(value, 1)
    False -> value
  }
}
