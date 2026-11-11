import gleam/list
import redirect_proxy/admin/auth/session
import redirect_proxy/role
import redirect_proxy/users

pub fn idle_sessions_end_test() {
  session.init()
  let s = session.create("alice", session.Local, 3600, "fp", role.Admin)
  let assert Ok(_) = session.get(s.token, 0)
  // still in use within the idle timeout (which counts from this use)
  let assert Ok(_) = session.get_at(s.token, 60, s.last_seen + 59)
  // then unused for over a minute, with a one minute idle timeout
  assert session.get_at(s.token, 60, s.last_seen + 59 + 61) == Error(Nil)
  // and it is gone for good
  assert session.get(s.token, 0) == Error(Nil)
}

pub fn fingerprint_follows_the_password_test() {
  let user = fn(hash, at, credentials) {
    users.User("alice", hash, role.Admin, "", at, credentials)
  }
  // users stored without credentials: the hash and the update time
  let a = users.fingerprint(user("hash-1", "2026-11-06T00:00:00Z", ""))
  assert a == users.fingerprint(user("hash-1", "2026-11-06T00:00:00Z", ""))
  assert a != users.fingerprint(user("hash-2", "2026-11-06T00:00:00Z", ""))
  assert a != users.fingerprint(user("hash-1", "2026-11-06T00:00:01Z", ""))
  // with them, only they count
  assert users.fingerprint(user("hash-1", "x", "c")) == "c"
  assert users.fingerprint(user("hash-2", "y", "c")) == "c"
}

/// Names from SSO or the proxy act under a prefix: they cannot pass for a
/// local user, and deleting a local user does not end their sessions.
pub fn external_names_are_prefixed_test() {
  session.init()
  let local = session.create("alice", session.Local, 60, "", role.Admin)
  let sso = session.create("alice", session.Oidc, 60, "", role.Admin)
  let proxy = session.create("alice", session.Header, 60, "", role.Admin)
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

@external(erlang, "redirect_proxy_ets_ffi", "ets_to_list")
fn ets_to_list(table: String) -> List(#(String, #(Int, session.Session)))

/// The table holds the hash of each token, not the token: a memory dump
/// gives no session to replay.
pub fn tokens_are_not_kept_test() {
  session.init()
  let s = session.create("alice", session.Local, 60, "", role.Admin)
  let entries = ets_to_list("redirect_proxy_sessions")
  assert !list.any(entries, fn(entry) {
    entry.0 == s.token || entry.1.1.token == s.token
  })
  // the session is found by its token, and given back with it
  let assert Ok(found) = session.get(s.token, 0)
  assert found.token == s.token
  session.destroy(s.token)
  assert session.get(s.token, 0) == Error(Nil)
}
