//// OpenID Connect single sign-on: authorization code flow with PKCE (S256),
//// `state` and `nonce`, ID token signature verification against the
//// provider JWKS (erlang-jose) and claim based authorisation.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/config.{type OidcConfig}
import redirect_proxy/ffi
import redirect_proxy/id

const table = "redirect_proxy_oidc"

pub const flow_ttl = 600

/// Login attempts in progress are kept until they complete or expire: cap
/// them so that a loop on /auth/oidc/start cannot fill the memory.
const max_flows = 10_000

const cache_ttl = 3600

pub type Provider {
  Provider(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
  )
}

/// Why a login failed. `Denied` explains itself to the user; the details of
/// `Failed` (provider errors, internal URLs) only go to the log.
pub type Failure {
  Denied(String)
  Failed(String)
}

pub type Identity {
  Identity(
    subject: String,
    username: String,
    email: String,
    groups: List(String),
  )
}

pub fn init() -> Nil {
  ffi.ets_new(table)
}

pub fn redirect_uri(public_url: String) -> String {
  trim_trailing_slash(public_url) <> "/auth/oidc/callback"
}

/// Builds the authorization URL and remembers the PKCE verifier and nonce
/// associated with the generated `state`. Returns the URL and the state,
/// which the caller binds to the browser (cookie) for `complete`.
pub fn begin(
  cfg: OidcConfig,
  public_url: String,
) -> Result(#(String, String), String) {
  use <- bool.guard(
    ffi.ets_size(table) >= max_flows,
    Error("too many login attempts in progress"),
  )
  use provider <- result.try(discover(cfg))
  let state = id.token(24)
  let verifier = id.token(48)
  let nonce = id.token(24)
  let challenge =
    crypto.hash(crypto.Sha256, <<verifier:utf8>>)
    |> bit_array.base64_url_encode(False)
  ffi.ets_put(table, "flow:" <> state, #(
    ffi.now_seconds() + flow_ttl,
    #(verifier, nonce),
  ))
  let query =
    uri.query_to_string([
      #("response_type", "code"),
      #("client_id", cfg.client_id),
      #("redirect_uri", redirect_uri(public_url)),
      #("scope", string.join(cfg.scopes, " ")),
      #("state", state),
      #("nonce", nonce),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
    ])
  let separator = case string.contains(provider.authorization_endpoint, "?") {
    True -> "&"
    False -> "?"
  }
  Ok(#(provider.authorization_endpoint <> separator <> query, state))
}

/// Completes the flow: checks that `state` is the one started in this browser
/// (`browser_state`, from the cookie set at `begin`, so that nobody can sign
/// a victim into their own account with a callback link), exchanges the
/// code, verifies the ID token and checks that the user is allowed in.
pub fn complete(
  cfg: OidcConfig,
  public_url: String,
  query: List(#(String, String)),
  browser_state: Result(String, Nil),
) -> Result(Identity, Failure) {
  use identity <- result.try(
    authenticate(cfg, public_url, query, browser_state)
    |> result.map_error(Failed),
  )
  use Nil <- result.try(authorise(cfg, identity) |> result.map_error(Denied))
  Ok(identity)
}

fn authenticate(
  cfg: OidcConfig,
  public_url: String,
  query: List(#(String, String)),
  browser_state: Result(String, Nil),
) -> Result(Identity, String) {
  use <- bool.guard(
    list.key_find(query, "error") |> result.is_ok,
    Error(
      "identity provider returned an error: "
      <> {
        list.key_find(query, "error_description")
        |> result.lazy_or(fn() { list.key_find(query, "error") })
        |> result.unwrap("")
      },
    ),
  )
  use state <- result.try(
    list.key_find(query, "state") |> result.replace_error("missing state"),
  )
  use code <- result.try(
    list.key_find(query, "code") |> result.replace_error("missing code"),
  )
  use <- bool.guard(
    case browser_state {
      Ok(expected) -> !ffi.secure_compare(<<expected:utf8>>, <<state:utf8>>)
      Error(Nil) -> True
    },
    Error("the login was not started in this browser"),
  )
  use #(verifier, nonce) <- result.try(take_flow(state))
  use provider <- result.try(discover(cfg))
  use id_token <- result.try(exchange(
    cfg,
    provider,
    code,
    verifier,
    redirect_uri(public_url),
  ))
  use claims <- result.try(verify(cfg, provider, id_token))
  check_claims(cfg, provider, claims, nonce)
}

fn take_flow(state: String) -> Result(#(String, String), String) {
  let key = "flow:" <> state
  case ffi.ets_get(table, key) {
    Ok(#(expires_at, flow)) -> {
      // single use
      ffi.ets_delete(table, key)
      case expires_at > ffi.now_seconds() {
        True -> Ok(flow)
        False -> Error("login attempt expired, please try again")
      }
    }
    Error(Nil) -> Error("unknown or already used login state")
  }
}

// --- discovery and JWKS -----------------------------------------------------

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
    decode.success(Provider(
      issuer:,
      authorization_endpoint:,
      token_endpoint:,
      jwks_uri:,
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

// --- token exchange and verification ----------------------------------------

fn exchange(
  cfg: OidcConfig,
  provider: Provider,
  code: String,
  verifier: String,
  redirect: String,
) -> Result(String, String) {
  let body =
    uri.query_to_string([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect),
      #("client_id", cfg.client_id),
      #("client_secret", cfg.client_secret),
      #("code_verifier", verifier),
    ])
  use req <- result.try(
    request.to(provider.token_endpoint)
    |> result.replace_error("invalid token endpoint URL"),
  )
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)
  use resp <- result.try(
    dispatch(req)
    |> result.map_error(fn(e) { "token request failed: " <> e }),
  )
  use <- bool.guard(
    resp.status != 200,
    Error("token endpoint answered HTTP " <> string.inspect(resp.status)),
  )
  json.parse(resp.body, decode.at(["id_token"], decode.string))
  |> result.replace_error("token response does not contain an id_token")
}

fn verify(
  _cfg: OidcConfig,
  provider: Provider,
  id_token: String,
) -> Result(String, String) {
  verify_signature(provider, id_token)
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

/// Validates registered claims (iss, aud, exp, nonce) and extracts the
/// identity. Exposed for tests.
pub fn check_claims(
  cfg: OidcConfig,
  provider: Provider,
  claims_json: String,
  expected_nonce: String,
) -> Result(Identity, String) {
  let audience =
    decode.one_of(decode.list(decode.string), [
      decode.string |> decode.map(fn(a) { [a] }),
    ])
  let groups_decoder =
    decode.one_of(decode.list(decode.string), [
      decode.string |> decode.map(fn(g) { [g] }),
    ])
  let decoder = {
    use iss <- decode.field("iss", decode.string)
    use sub <- decode.field("sub", decode.string)
    use aud <- decode.field("aud", audience)
    use exp <- decode.field("exp", decode.int)
    use nonce <- decode.optional_field("nonce", "", decode.string)
    use email <- decode.optional_field("email", "", decode.string)
    // A missing claim means unverified: some providers (Entra ID...) never
    // send it and let users set any address, which would otherwise pass the
    // e-mail and domain allow-lists.
    use email_verified <- decode.optional_field(
      "email_verified",
      False,
      decode.one_of(decode.bool, [
        decode.string |> decode.map(fn(s) { s == "true" }),
      ]),
    )
    use preferred <- decode.optional_field(
      "preferred_username",
      "",
      decode.string,
    )
    use groups <- decode.optional_field(cfg.groups_claim, [], groups_decoder)
    decode.success(#(
      iss,
      sub,
      aud,
      exp,
      nonce,
      email,
      email_verified,
      preferred,
      groups,
    ))
  }
  use #(iss, sub, aud, exp, nonce, email, email_verified, preferred, groups) <- result.try(
    json.parse(claims_json, decoder)
    |> result.replace_error("ID token is missing required claims"),
  )
  use <- bool.guard(
    trim_trailing_slash(iss) != trim_trailing_slash(provider.issuer),
    Error("ID token issuer mismatch"),
  )
  use <- bool.guard(
    !list.contains(aud, cfg.client_id),
    Error("ID token audience mismatch"),
  )
  use <- bool.guard(exp + 60 < ffi.now_seconds(), Error("ID token expired"))
  use <- bool.guard(
    !ffi.secure_compare(<<nonce:utf8>>, <<expected_nonce:utf8>>),
    Error("ID token nonce mismatch"),
  )
  let email = case email_verified {
    True -> string.lowercase(email)
    False -> ""
  }
  let username = case preferred, email {
    "", "" -> sub
    "", e -> e
    p, _ -> p
  }
  Ok(Identity(subject: sub, username:, email:, groups:))
}

/// Authorisation: with no allow-list configured every authenticated user is
/// accepted; otherwise the user must match one of the lists.
pub fn authorise(cfg: OidcConfig, identity: Identity) -> Result(Nil, String) {
  let no_lists =
    cfg.allowed_emails == []
    && cfg.allowed_domains == []
    && cfg.allowed_groups == []
  let email_ok =
    identity.email != ""
    && list.contains(
      list.map(cfg.allowed_emails, string.lowercase),
      identity.email,
    )
  let domain_ok = case string.split_once(identity.email, "@") {
    Ok(#(_, domain)) ->
      list.contains(list.map(cfg.allowed_domains, string.lowercase), domain)
    Error(Nil) -> False
  }
  let group_ok = list.any(identity.groups, list.contains(cfg.allowed_groups, _))
  case no_lists || email_ok || domain_ok || group_ok {
    True -> Ok(Nil)
    False ->
      Error(
        "your account ("
        <> identity.username
        <> ") is not allowed to access this administration",
      )
  }
}

// --- helpers ----------------------------------------------------------------

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
fn dispatch(
  req: request.Request(String),
) -> Result(response.Response(String), String) {
  ffi.rescue(fn() {
    httpc.configure()
    |> httpc.timeout(10_000)
    |> httpc.dispatch(req)
  })
  |> result.try(fn(sent) { sent |> result.map_error(string.inspect) })
}

fn trim_trailing_slash(value: String) -> String {
  case string.ends_with(value, "/") {
    True -> string.drop_end(value, 1)
    False -> value
  }
}

pub fn purge_expired() -> Int {
  ffi.ets_delete_older(table, ffi.now_seconds())
}
