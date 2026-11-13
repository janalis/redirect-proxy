//// OpenID Connect single sign-on: the authorization code flow with PKCE,
//// ID token checks and authorisation. Provider metadata and keys come from
//// `oidc/provider`.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/oidc/provider.{
  type Provider, discover, dispatch, purge_expired as purge_provider_cache,
  table, trim_trailing_slash, verify_signature,
} as _
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/config.{type OidcConfig}
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/role.{type Role}

pub const flow_ttl = 600

/// The states of the logins completed in the last `flow_ttl` seconds, so that
/// a callback cannot be replayed. Logins in progress are kept by the browser
/// only (the signed flow cookie of `begin`): there is nothing to fill with a
/// loop on /auth/oidc/start, and no cap that would block everyone's SSO.
const used_states = "redirect_proxy_oidc_flows"

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
  ffi.ets_new(used_states)
}

pub fn redirect_uri(public_url: String) -> String {
  trim_trailing_slash(public_url) <> "/auth/oidc/callback"
}

/// The provider's logout URL (RP-Initiated Logout 1.0), coming back to the
/// login page.
pub fn end_session_url(
  cfg: OidcConfig,
  public_url: String,
) -> Result(String, String) {
  use provider <- result.try(discover(cfg))
  use <- bool.guard(
    provider.end_session_endpoint == "",
    Error("the provider has no end_session_endpoint"),
  )
  let separator = case string.contains(provider.end_session_endpoint, "?") {
    True -> "&"
    False -> "?"
  }
  Ok(
    provider.end_session_endpoint
    <> separator
    <> uri.query_to_string([
      #("client_id", cfg.client_id),
      #("post_logout_redirect_uri", trim_trailing_slash(public_url) <> "/login"),
    ]),
  )
}

/// Builds the authorization URL and the login in progress: the generated
/// `state`, the PKCE verifier, the nonce and `next` (where to go after
/// signing in). Returns the URL and the flow, which the caller keeps in the
/// browser (a signed cookie, so that it cannot be forged) for `complete`.
pub fn begin(
  cfg: OidcConfig,
  public_url: String,
  next: String,
) -> Result(#(String, String), String) {
  begin_with_receipt(cfg, public_url, next, ratelimit.Receipt("", 0))
}

pub fn begin_with_receipt(
  cfg: OidcConfig,
  public_url: String,
  next: String,
  receipt: ratelimit.Receipt,
) -> Result(#(String, String), String) {
  use provider <- result.try(discover(cfg))
  let state = id.token(24)
  let verifier = id.token(48)
  let nonce = id.token(24)
  let challenge =
    crypto.hash(crypto.Sha256, <<verifier:utf8>>)
    |> bit_array.base64_url_encode(False)
  let flow =
    Flow(
      state:,
      verifier:,
      nonce:,
      next:,
      expires_at: ffi.now_seconds() + flow_ttl,
      receipt:,
    )
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
  Ok(#(provider.authorization_endpoint <> separator <> query, encode_flow(flow)))
}

/// A login in progress, kept in the browser between `begin` and `complete`.
type Flow {
  Flow(
    state: String,
    verifier: String,
    nonce: String,
    next: String,
    expires_at: Int,
    receipt: ratelimit.Receipt,
  )
}

fn encode_flow(flow: Flow) -> String {
  json.object([
    #("state", json.string(flow.state)),
    #("verifier", json.string(flow.verifier)),
    #("nonce", json.string(flow.nonce)),
    #("next", json.string(flow.next)),
    #("expires_at", json.int(flow.expires_at)),
    #("receipt_key", json.string(flow.receipt.key)),
    #("receipt_generation", json.int(flow.receipt.generation)),
  ])
  |> json.to_string
}

fn decode_flow(value: String) -> Result(Flow, Nil) {
  let decoder = {
    use state <- decode.field("state", decode.string)
    use verifier <- decode.field("verifier", decode.string)
    use nonce <- decode.field("nonce", decode.string)
    use next <- decode.field("next", decode.string)
    use expires_at <- decode.field("expires_at", decode.int)
    use receipt_key <- decode.optional_field("receipt_key", "", decode.string)
    use receipt_generation <- decode.optional_field(
      "receipt_generation",
      0,
      decode.int,
    )
    decode.success(Flow(
      state:,
      verifier:,
      nonce:,
      next:,
      expires_at:,
      receipt: ratelimit.Receipt(receipt_key, receipt_generation),
    ))
  }
  json.parse(value, decoder) |> result.replace_error(Nil)
}

/// The refund receipt is read only after the signed browser flow completes.
pub fn start_receipt(flow: String) -> Result(ratelimit.Receipt, Nil) {
  decode_flow(flow) |> result.map(fn(flow) { flow.receipt })
}

/// Completes the flow: checks that `state` is the one started in this browser
/// (`browser_flow`, from the cookie set at `begin`, so that nobody can sign
/// a victim into their own account with a callback link), exchanges the
/// code, verifies the ID token and checks that the user is allowed in. A
/// state completes once.
pub fn complete(
  cfg: OidcConfig,
  public_url: String,
  query: List(#(String, String)),
  browser_flow: Result(String, Nil),
) -> Result(#(Identity, String), Failure) {
  use #(identity, next) <- result.try(
    authenticate(cfg, public_url, query, browser_flow)
    |> result.map_error(Failed),
  )
  use Nil <- result.try(authorise(cfg, identity) |> result.map_error(Denied))
  Ok(#(identity, next))
}

fn authenticate(
  cfg: OidcConfig,
  public_url: String,
  query: List(#(String, String)),
  browser_flow: Result(String, Nil),
) -> Result(#(Identity, String), String) {
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
  use flow <- result.try(
    browser_flow
    |> result.try(decode_flow)
    |> result.replace_error("the login was not started in this browser"),
  )
  use <- bool.guard(
    !ffi.secure_compare(<<flow.state:utf8>>, <<state:utf8>>),
    Error("the login was not started in this browser"),
  )
  use <- bool.guard(
    flow.expires_at <= ffi.now_seconds(),
    Error("login attempt expired, please try again"),
  )
  use <- bool.guard(
    ffi.ets_get(used_states, state) |> result.is_ok,
    Error("unknown or already used login state"),
  )
  use provider <- result.try(discover(cfg))
  use id_token <- result.try(exchange(
    cfg,
    provider,
    code,
    flow.verifier,
    redirect_uri(public_url),
  ))
  use claims <- result.try(verify(cfg, provider, id_token))
  use identity <- result.try(check_claims(cfg, provider, claims, flow.nonce))
  // single use, also against callbacks racing each other: only the first
  // one to complete records the state
  use <- bool.guard(
    !ffi.ets_insert_new(used_states, state, #(flow.expires_at, Nil)),
    Error("unknown or already used login state"),
  )
  Ok(#(identity, flow.next))
}

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
    use nbf <- decode.optional_field("nbf", 0, decode.int)
    use azp <- decode.optional_field("azp", "", decode.string)
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
      nbf,
      azp,
      nonce,
      email,
      email_verified,
      preferred,
      groups,
    ))
  }
  use
    #(
      iss,
      sub,
      aud,
      exp,
      nbf,
      azp,
      nonce,
      email,
      email_verified,
      preferred,
      groups,
    )
  <- result.try(
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
  // OpenID Connect Core 3.1.3.7: when present, the authorised party must be
  // this client (several providers omit it, even with several audiences)
  use <- bool.guard(
    azp != "" && azp != cfg.client_id,
    Error("ID token authorised party mismatch"),
  )
  let now = ffi.now_seconds()
  use <- bool.guard(exp + 60 < now, Error("ID token expired"))
  use <- bool.guard(nbf - 60 > now, Error("ID token not yet valid"))
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

/// The role of a signed-in user: the highest one their groups give, or
/// `default_role` when they are in none of the role groups.
pub fn role_for(cfg: OidcConfig, identity: Identity) -> Role {
  let in_any = fn(groups) {
    list.any(identity.groups, list.contains(groups, _))
  }
  [
    #(cfg.admin_groups, role.Admin),
    #(cfg.editor_groups, role.Editor),
    #(cfg.viewer_groups, role.Viewer),
  ]
  |> list.filter(fn(entry) { in_any(entry.0) })
  |> list.map(fn(entry) { entry.1 })
  |> role.highest(
    role.from_string(cfg.default_role) |> result.unwrap(role.Viewer),
  )
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

pub fn purge_expired() -> Int {
  let now = ffi.now_seconds()
  purge_provider_cache(now) + ffi.ets_delete_older(used_states, now)
}
