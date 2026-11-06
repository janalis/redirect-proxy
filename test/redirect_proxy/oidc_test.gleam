import gleam/json
import gleam/list
import redirect_proxy/admin/auth/oidc
import redirect_proxy/config
import redirect_proxy/ffi

fn cfg(domains: List(String), groups: List(String)) -> config.OidcConfig {
  config.OidcConfig(
    ..config.default().oidc,
    enabled: True,
    issuer: "https://idp.test",
    client_id: "rp",
    client_secret: "s",
    allowed_domains: domains,
    allowed_groups: groups,
  )
}

const provider =
  oidc.Provider(
    issuer: "https://idp.test",
    authorization_endpoint: "https://idp.test/auth",
    token_endpoint: "https://idp.test/token",
    jwks_uri: "https://idp.test/jwks",
  )

/// The base claims without `key`.
fn claims_without(key: String) -> String {
  base_claims()
  |> list.filter(fn(field) { field.0 != key })
  |> json.object
  |> json.to_string
}

fn base_claims() -> List(#(String, json.Json)) {
  [
    #("iss", json.string("https://idp.test/")),
    #("sub", json.string("42")),
    #("aud", json.array(["rp", "other"], json.string)),
    #("exp", json.int(ffi.now_seconds() + 60)),
    #("nonce", json.string("n")),
    #("email", json.string("Alice@Example.com")),
    #("email_verified", json.bool(True)),
    #("groups", json.string("admins")),
  ]
}

fn claims(overrides: List(#(String, json.Json))) -> String {
  let keys = list.map(overrides, fn(field) { field.0 })
  base_claims()
  |> list.filter(fn(field) { !list.contains(keys, field.0) })
  |> list.append(overrides)
  |> json.object
  |> json.to_string
}

pub fn valid_claims_test() {
  let assert Ok(identity) =
    oidc.check_claims(cfg([], []), provider, claims([]), "n")
  assert identity.subject == "42"
  assert identity.email == "alice@example.com"
  assert identity.username == "alice@example.com"
  assert identity.groups == ["admins"]
}

pub fn preferred_username_test() {
  let assert Ok(identity) =
    oidc.check_claims(
      cfg([], []),
      provider,
      claims([#("preferred_username", json.string("alice"))]),
      "n",
    )
  assert identity.username == "alice"
}

pub fn claim_mismatches_test() {
  let c = cfg([], [])
  let assert Error(_) =
    oidc.check_claims(
      c,
      provider,
      claims([#("iss", json.string("https://evil"))]),
      "n",
    )
  let assert Error(_) =
    oidc.check_claims(
      c,
      provider,
      claims([#("aud", json.string("other"))]),
      "n",
    )
  let assert Error(_) =
    oidc.check_claims(c, provider, claims([#("exp", json.int(1000))]), "n")
  let assert Error(_) =
    oidc.check_claims(c, provider, claims([]), "other-nonce")
  let assert Error(_) = oidc.check_claims(c, provider, "{}", "n")
}

pub fn unverified_email_is_ignored_test() {
  let assert Ok(identity) =
    oidc.check_claims(
      cfg([], []),
      provider,
      claims([#("email_verified", json.bool(False))]),
      "n",
    )
  assert identity.email == ""
  assert identity.username == "42"
  // and so it cannot satisfy a domain allow-list
  let assert Error(_) = oidc.authorise(cfg(["example.com"], []), identity)
}

pub fn missing_email_verified_means_unverified_test() {
  // e.g. Entra ID, where users can set any address: it must not pass the
  // e-mail or domain allow-lists
  let assert Ok(identity) =
    oidc.check_claims(
      cfg(["example.com"], []),
      provider,
      claims_without("email_verified"),
      "n",
    )
  assert identity.email == ""
  let assert Error(_) = oidc.authorise(cfg(["example.com"], []), identity)
  // groups still work
  let assert Ok(Nil) =
    oidc.authorise(cfg(["example.com"], ["admins"]), identity)
}

pub fn authorise_test() {
  let alice =
    oidc.Identity(
      subject: "1",
      username: "alice",
      email: "alice@example.com",
      groups: ["staff"],
    )
  let assert Ok(Nil) = oidc.authorise(cfg([], []), alice)
  let assert Ok(Nil) = oidc.authorise(cfg(["example.com"], []), alice)
  let assert Ok(Nil) = oidc.authorise(cfg(["other.com"], ["staff"]), alice)
  let assert Error(_) = oidc.authorise(cfg(["other.com"], ["admins"]), alice)
  let emails =
    config.OidcConfig(..cfg([], []), allowed_emails: ["ALICE@example.com"])
  let assert Ok(Nil) = oidc.authorise(emails, alice)
}

pub fn redirect_uri_test() {
  assert oidc.redirect_uri("https://admin.test/")
    == "https://admin.test/auth/oidc/callback"
  assert oidc.redirect_uri("https://admin.test")
    == "https://admin.test/auth/oidc/callback"
}
