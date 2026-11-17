import gleam/http
import gleam/http/request
import redirect_proxy/admin/auth/header
import redirect_proxy/config
import wisp/simulate

fn cfg(user_header: String) -> config.HeaderAuthConfig {
  config.HeaderAuthConfig(
    ..config.default().header_auth,
    enabled: True,
    user_header:,
    email_header: "x-forwarded-email",
    trusted_proxies: ["127.0.0.1/32"],
  )
}

fn req(headers: List(#(String, String))) -> request.Request(_) {
  let base = simulate.request(http.Get, "/")
  request.Request(..base, headers: headers)
}

pub fn user_header_identifies_test() {
  let r = req([#("x-forwarded-user", " Alice ")])
  assert header.identify(cfg("x-forwarded-user"), r, "127.0.0.1") == Ok("alice")
  // only from a trusted peer
  assert header.identify(cfg("x-forwarded-user"), r, "10.0.0.1") == Error(Nil)
}

pub fn email_header_is_not_a_fallback_test() {
  // a proxy that only sets the e-mail header may pass a client's user header
  // through: the two are never combined
  let r = req([#("x-forwarded-email", "alice@example.com")])
  assert header.identify(cfg("x-forwarded-user"), r, "127.0.0.1") == Error(Nil)
  // identify by e-mail by emptying user_header
  assert header.identify(cfg(""), r, "127.0.0.1") == Ok("alice@example.com")
  let spoofed =
    req([#("x-forwarded-user", "admin"), #("x-forwarded-email", "a@b.c")])
  assert header.identify(cfg(""), spoofed, "127.0.0.1") == Ok("a@b.c")
}

pub fn duplicated_identity_header_is_refused_test() {
  // a proxy appending to the client's header leaves the client's value first
  let r = req([#("x-forwarded-user", "admin"), #("x-forwarded-user", "alice")])
  assert header.identify(cfg("x-forwarded-user"), r, "127.0.0.1") == Error(Nil)
  // the same, joined on one line
  let joined = req([#("x-forwarded-user", "admin, alice")])
  assert header.identify(cfg("x-forwarded-user"), joined, "127.0.0.1")
    == Error(Nil)
  let empty = req([#("x-forwarded-user", "  ")])
  assert header.identify(cfg("x-forwarded-user"), empty, "127.0.0.1")
    == Error(Nil)
}
