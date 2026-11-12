import gleam/erlang/process
import gleam/list
import redirect_proxy/admin/auth/session
import redirect_proxy/ffi
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

pub fn every_successful_request_refreshes_idle_deadline_test() {
  session.init()
  let s = session.create("alice", session.Local, 3600, "fp", role.Admin)
  let assert Ok(at29) = session.get_at(s.token, 60, s.last_seen + 29)
  assert at29.last_seen == s.last_seen + 29
  let assert Ok(at60) = session.get_at(s.token, 60, s.last_seen + 60)
  assert at60.last_seen == s.last_seen + 60
  // Exactly the idle timeout expires; absolute lifetime still applies.
  assert session.get_at(s.token, 60, s.last_seen + 120) == Error(Nil)
  let s = session.create("alice", session.Local, 60, "fp", role.Admin)
  let assert Ok(_) = session.get_at(s.token, 0, s.last_seen + 59)
  assert session.get_at(s.token, 0, s.expires_at) == Error(Nil)
}

pub fn older_requests_never_move_activity_backwards_test() {
  session.init()
  let s = session.create("alice", session.Local, 3600, "fp", role.Admin)
  let assert Ok(_) = session.get_at(s.token, 60, s.last_seen + 29)
  let assert Ok(older) = session.get_at(s.token, 60, s.last_seen + 10)
  assert older.last_seen == s.last_seen + 29
  let assert Ok(_) = session.get_at(s.token, 60, s.last_seen + 88)
}

pub fn concurrent_activity_keeps_latest_timestamp_test() {
  session.init()
  let s = session.create("alice", session.Local, 3600, "fp", role.Admin)
  let done = process.new_subject()
  list.each(
    list.index_map(list.repeat(Nil, 29), fn(_, i) { i + 1 }),
    fn(offset) {
      process.spawn(fn() {
        process.send(done, session.get_at(s.token, 60, s.last_seen + offset))
      })
    },
  )
  list.each(list.index_map(list.repeat(Nil, 29), fn(_, i) { i + 1 }), fn(_) {
    let assert Ok(Ok(_)) = process.receive(done, 5000)
  })
  let assert Ok(latest) = session.get_at(s.token, 60, s.last_seen)
  assert latest.last_seen == s.last_seen + 29
  session.destroy(s.token)
  assert session.get_at(s.token, 0, s.last_seen + 30) == Error(Nil)
}

/// Deterministic stale-read interleavings underlying activity and expiry.
pub fn stale_activity_cannot_restore_or_delete_sessions_test() {
  session.init()
  let table = "redirect_proxy_session_cas_test"
  ffi.ets_new(table)
  let s = session.create("alice", session.Local, 3600, "fp", role.Admin)
  let old = #(s.expires_at, s)
  let updated = #(
    s.expires_at,
    session.Session(..s, last_seen: s.last_seen + 29),
  )
  ffi.ets_put(table, "key", old)
  assert ffi.ets_replace_if(table, "key", old, updated)
  assert !ffi.ets_replace_if(table, "key", old, old)
  assert !ffi.ets_delete_if(table, "key", old)
  ffi.ets_delete(table, "key")
  assert !ffi.ets_replace_if(table, "key", updated, old)
  let result: Result(#(Int, session.Session), Nil) = ffi.ets_get(table, "key")
  assert result == Error(Nil)
}
