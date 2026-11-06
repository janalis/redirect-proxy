import gleam/erlang/process
import redirect_proxy/admin/auth/session

pub fn idle_sessions_end_test() {
  session.init()
  let s = session.create("alice", session.Local, 3600, "fp")
  let assert Ok(_) = session.get(s.token, 0)
  process.sleep(1100)
  // unused for over a second, with a one second idle timeout
  assert session.get(s.token, 1) == Error(Nil)
  // and it is gone for good
  assert session.get(s.token, 0) == Error(Nil)
}

pub fn fingerprint_follows_the_password_test() {
  let a = session.user_fingerprint("hash-1", "2026-11-06T00:00:00Z")
  assert a == session.user_fingerprint("hash-1", "2026-11-06T00:00:00Z")
  assert a != session.user_fingerprint("hash-2", "2026-11-06T00:00:00Z")
  assert a != session.user_fingerprint("hash-1", "2026-11-06T00:00:01Z")
}

/// Names from SSO or the proxy act under a prefix: they cannot pass for a
/// local user, and deleting a local user does not end their sessions.
pub fn external_names_are_prefixed_test() {
  session.init()
  let local = session.create("alice", session.Local, 60, "")
  let sso = session.create("alice", session.Oidc, 60, "")
  let proxy = session.create("alice", session.Header, 60, "")
  assert local.username == "alice"
  assert sso.username == "sso:alice"
  assert proxy.username == "proxy:alice"
  assert session.display_name(sso) == "alice"
  assert session.display_name(proxy) == "alice"
  session.destroy_user("alice")
  assert session.get(local.token, 0) == Error(Nil)
  let assert Ok(_) = session.get(sso.token, 0)
  let assert Ok(_) = session.get(proxy.token, 0)
}
