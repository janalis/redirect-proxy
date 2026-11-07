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
import redirect_proxy/admin/auth/oidc/provider as oidc_provider
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
      // The client must still exist with the same secret, and a token
      // never keeps a scope the client has lost since (clients file edited).
      case clients.get(clients_settings, grant.client_id) {
        Ok(client) if client.secret_hash == grant.secret_hash ->
          Ok(Principal(
            actor: "client:" <> grant.client_id,
            scopes: list.filter(grant.scopes, scope.allows(client.scopes, _)),
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
    oidc_provider.discover_issuer(oauth.issuer)
    |> result.replace_error("authorization server unavailable"),
  )
  use claims <- result.try(
    oidc_provider.verify_signature(provider, jwt)
    |> result.replace_error("invalid token signature"),
  )
  use Nil <- result.try(check_type(oauth, ffi.jwt_peek_header(jwt)))
  check_claims(oauth, provider.issuer, claims, ffi.now_seconds())
}

/// With `require_at_jwt`, the token header must say it is an access token
/// (`typ` `at+jwt` or `application/at+jwt`, RFC 9068). Exposed for tests.
pub fn check_type(
  oauth: ApiOAuthConfig,
  header_json: Result(String, Nil),
) -> Result(Nil, String) {
  use <- bool.guard(!oauth.require_at_jwt, Ok(Nil))
  let typ =
    header_json
    |> result.try(fn(header) {
      json.parse(
        header,
        decode.optional_field("typ", "", decode.string, decode.success),
      )
      |> result.replace_error(Nil)
    })
    |> result.unwrap("")
    |> string.lowercase
  case typ {
    "at+jwt" | "application/at+jwt" -> Ok(Nil)
    _ -> Error("the token is not typed as an access token (typ at+jwt)")
  }
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
    use nonce <- decode.optional_field("nonce", "", decode.string)
    decode.success(#(iss, exp, nbf, aud, sub, client_id, azp, names, scp, nonce))
  }
  use #(iss, exp, nbf, aud, sub, client_id, azp, names, scp, nonce) <- result.try(
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
  // an ID token (the admin's SSO sign-in always sends a nonce) is not an
  // access token, even when its audience is the API's
  use <- bool.guard(nonce != "", Error("an ID token is not an access token"))
  use <- bool.guard(exp + leeway < now, Error("access token expired"))
  use <- bool.guard(nbf - leeway > now, Error("access token not yet valid"))
  let subject = case sub, client_id, azp {
    "", "", a -> a
    "", c, _ -> c
    s, _, _ -> s
  }
  // the subject is the actor of the audit log: a caller nobody can tell
  // apart is not accepted
  use <- bool.guard(
    string.trim(subject) == "",
    Error("access token has no subject (sub, client_id or azp)"),
  )
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
