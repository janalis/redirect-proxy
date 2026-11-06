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
