import gleam/int
import gleam/json
import gleam/list
import gleam/result
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/oidc/provider as oidc_provider
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/config
import redirect_proxy/ffi
import support

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
  oidc_provider.Provider(
    issuer: "https://idp.test",
    authorization_endpoint: "https://idp.test/auth",
    token_endpoint: "https://idp.test/token",
    jwks_uri: "https://idp.test/jwks",
    end_session_endpoint: "",
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
  // issued for another client of the same provider
  let assert Error("ID token authorised party mismatch") =
    oidc.check_claims(
      c,
      provider,
      claims([#("azp", json.string("other"))]),
      "n",
    )
  let assert Ok(_) =
    oidc.check_claims(c, provider, claims([#("azp", json.string("rp"))]), "n")
  let assert Error("ID token not yet valid") =
    oidc.check_claims(
      c,
      provider,
      claims([#("nbf", json.int(ffi.now_seconds() + 3600))]),
      "n",
    )
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

pub fn provider_failures_are_remembered_test() {
  // while the provider is down, requests fail at once instead of each one
  // trying (and waiting for) it again
  let #(port, counter) = counting_server()
  let issuer = "http://127.0.0.1:" <> int.to_string(port)
  let assert Error(_) = oidc_provider.discover_issuer(issuer)
  let first = accepted(counter)
  assert first > 0
  let assert Error(_) = oidc_provider.discover_issuer(issuer)
  let assert Error(_) = oidc_provider.discover_issuer(issuer)
  assert accepted(counter) == first
}

type Counter

@external(erlang, "test_net_ffi", "counting_server")
fn counting_server() -> #(Int, Counter)

@external(erlang, "test_net_ffi", "accepted")
fn accepted(counter: Counter) -> Int

/// While the provider cannot be reached, the metadata and signing keys
/// fetched before are used for a day past their hour, not forgotten.
/// The janitor's purge keeps the metadata a provider outage falls back on
/// (up to a day past its hour), and drops it once it is too old for that.
pub fn purge_keeps_the_metadata_an_outage_falls_back_on_test() {
  let _ = support.boot(config.default())
  let down = "http://127.0.0.1:1/purge-" <> int.to_string(ffi.now_micros())
  let provider =
    oidc_provider.Provider(
      issuer: down,
      authorization_endpoint: down <> "/authorize",
      token_endpoint: down <> "/token",
      jwks_uri: down <> "/jwks",
      end_session_endpoint: "",
    )
  let now = ffi.now_seconds()
  // fetched two hours ago: expired an hour ago, still a fallback
  ffi.ets_put(oidc_provider.table, "provider:" <> down, #(
    now - 3600,
    #(now - 7200, provider),
  ))
  // fetched over a day ago: no longer one
  let old = down <> "/old"
  ffi.ets_put(oidc_provider.table, "provider:" <> old, #(
    now - 90_000,
    #(now - 93_600, provider),
  ))
  let _ = oidc.purge_expired()
  assert oidc_provider.discover_issuer(down) == Ok(provider)
  let gone: Result(#(Int, #(Int, oidc_provider.Provider)), Nil) =
    ffi.ets_get(oidc_provider.table, "provider:" <> old)
  assert gone == Error(Nil)
}

pub fn provider_outage_uses_the_last_good_metadata_test() {
  // the application owns the cache table
  let _ = support.boot(config.default())
  let down = "http://127.0.0.1:1/outage-" <> int.to_string(ffi.now_micros())
  let provider =
    oidc_provider.Provider(
      issuer: down,
      authorization_endpoint: down <> "/authorize",
      token_endpoint: down <> "/token",
      jwks_uri: down <> "/jwks",
      end_session_endpoint: "",
    )
  let now = ffi.now_seconds()
  // fetched two hours ago: expired an hour ago
  ffi.ets_put(oidc_provider.table, "provider:" <> down, #(
    now - 3600,
    #(now - 7200, provider),
  ))
  assert oidc_provider.discover_issuer(down) == Ok(provider)
  let #(jwks, key) = support.keypair()
  ffi.ets_put(oidc_provider.table, "jwks:" <> down <> "/jwks", #(
    now - 3600,
    #(now - 7200, jwks),
  ))
  // the stale keys are used: a token they signed is accepted
  let assert Ok(_) =
    oidc_provider.verify_signature(
      provider,
      support.sign(key, "{\"sub\":\"s\"}"),
    )
  // the failed fetch is remembered: a forced refresh (a token with an
  // unknown key) does not fetch again at once
  let failed: Result(#(Int, String), Nil) =
    ffi.ets_get(oidc_provider.table, "failed:jwks:" <> down <> "/jwks")
  assert result.is_ok(failed)
  // fetched over a day ago: gone
  let old = down <> "/old"
  ffi.ets_put(oidc_provider.table, "provider:" <> old, #(
    now - 90_000,
    #(now - 93_600, provider),
  ))
  let assert Error(_) = oidc_provider.discover_issuer(old)
}

/// OAuth metadata goes before the issuer path; the port must survive too.
pub fn oauth_discovery_with_issuer_paths_test() {
  ffi.ets_new(oidc_provider.table)
  list.each(["", "/", "/tenant", "/tenant/nested", "/tenant/nested/"], fn(path) {
    let #(issuer, _) = support.start_fake_authorization_server_at(path)
    let assert Ok(discovered) = oidc_provider.discover_issuer(issuer)
    assert discovered.issuer == issuer
    assert discovered.jwks_uri == issuer <> "/jwks"
  })
}

pub fn oidc_flow_preserves_original_refund_receipt_test() {
  oidc.init()
  ratelimit.init()
  let #(issuer, _) = support.start_fake_authorization_server()
  let config = config.OidcConfig(..config.default().oidc, issuer:)
  let receipt = ratelimit.record("sso-original-address", 900)
  let assert Ok(#(_, flow)) =
    oidc.begin_with_receipt(config, "http://localhost", "/rules", receipt)
  assert oidc.start_receipt(flow) == Ok(receipt)
  let assert Ok(#(_, legacy_flow)) =
    oidc.begin(config, "http://localhost", "/rules")
  assert oidc.start_receipt(legacy_flow) == Ok(ratelimit.Receipt("", 0))
}
