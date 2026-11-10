//// Server-side sessions kept in ETS. The browser only holds a signed,
//// random session token; sessions can be revoked and expire server-side.
//// The table holds the SHA-256 of each token, not the token: a memory or
//// crash dump gives no session to replay.

import gleam/bit_array
import gleam/crypto
import gleam/list
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/role.{type Role}

const table = "redirect_proxy_sessions"

/// The live session of each proxy user and role (`header_session`).
const header_index = "redirect_proxy_header_sessions"

pub type Method {
  Local
  Oidc
  Header
}

pub type Session {
  Session(
    token: String,
    /// Who the session acts as, in the audit log and everywhere else: the
    /// local username, or `sso:<name>` / `proxy:<name>` (see `actor`).
    username: String,
    method: Method,
    /// What the session may do. Local sessions follow the user's role as
    /// stored (see `admin/routes/auth.current_session`).
    role: Role,
    csrf_token: String,
    expires_at: Int,
    /// For local accounts, `user_fingerprint` of the user when the session
    /// was created: the session ends when the user is deleted or changes
    /// password, even from another process (the CLI). "" otherwise.
    fingerprint: String,
    /// Last request made with the session (idle timeout).
    last_seen: Int,
  )
}

/// Changes whenever the password of a local user changes.
pub fn user_fingerprint(password_hash: String, updated_at: String) -> String {
  crypto.hash(crypto.Sha256, <<password_hash:utf8, 0, updated_at:utf8>>)
  |> bit_array.base16_encode
}

/// `last_seen` is only written back when older than this, to avoid an ETS
/// write on every request.
const touch_interval = 30

/// Creates the ETS table. Must be called from a long lived process.
pub fn init() -> Nil {
  ffi.ets_new(table)
  ffi.ets_new(header_index)
}

/// `name` is the local username, the SSO username or the name vouched for by
/// the proxy: the session acts as `actor(method, name)`.
pub fn create(
  name: String,
  method: Method,
  ttl: Int,
  fingerprint: String,
  role: Role,
) -> Session {
  let now = ffi.now_seconds()
  let session =
    Session(
      token: id.token(32),
      username: actor(method, name),
      method:,
      role:,
      csrf_token: id.token(32),
      expires_at: now + ttl,
      fingerprint:,
      last_seen: now,
    )
  // Stored as #(expires_at, session) so that `ets_delete_older` can purge.
  ffi.ets_put(table, key(session.token), #(
    session.expires_at,
    Session(..session, token: ""),
  ))
  session
}

/// The key of a session in the table.
fn key(token: String) -> String {
  crypto.hash(crypto.Sha256, <<token:utf8>>) |> bit_array.base16_encode
}

/// The live session of a token. A session unused for `idle_timeout` seconds
/// (0: no limit) or past its lifetime is destroyed.
pub fn get(token: String, idle_timeout: Int) -> Result(Session, Nil) {
  get_at(token, idle_timeout, ffi.now_seconds())
}

/// `get` at a given time (seconds since the epoch), for tests.
pub fn get_at(
  token: String,
  idle_timeout: Int,
  now: Int,
) -> Result(Session, Nil) {
  let key = key(token)
  case ffi.ets_get(table, key) {
    Ok(#(expires_at, session)) -> {
      let session: Session = session
      let idle = idle_timeout > 0 && now - session.last_seen >= idle_timeout
      case expires_at > now && !idle {
        True -> {
          case now - session.last_seen >= touch_interval {
            True ->
              ffi.ets_put(table, key, #(
                expires_at,
                Session(..session, last_seen: now),
              ))
            False -> Nil
          }
          Ok(Session(..session, token:))
        }
        False -> {
          ffi.ets_delete(table, key)
          Error(Nil)
        }
      }
    }
    Error(Nil) -> Error(Nil)
  }
}

/// The session of a user vouched for by the proxy, with this role: the live
/// one when there is one, else a new one (`True`). A client that drops
/// cookies (a script, a monitoring check) is vouched for on every request:
/// it gets the same session, not one more per request, each with an audit
/// entry, for the whole session lifetime.
pub fn header_session(
  name: String,
  role: Role,
  ttl: Int,
  idle_timeout: Int,
) -> #(Session, Bool) {
  let key = actor(Header, name) <> " " <> role.to_string(role)
  let live = case ffi.ets_get(header_index, key) {
    Ok(#(_, token)) ->
      case get(token, idle_timeout) {
        Ok(s) if s.method == Header && s.role == role -> Ok(s)
        _ -> Error(Nil)
      }
    Error(Nil) -> Error(Nil)
  }
  case live {
    Ok(s) -> #(s, False)
    Error(Nil) -> {
      let s = create(name, Header, ttl, "", role)
      // the token itself: every browser the proxy vouches for gets it (the
      // proxy's sign-in, checked on every request, is what protects it)
      ffi.ets_put(header_index, key, #(s.expires_at, s.token))
      #(s, True)
    }
  }
}

pub fn destroy(token: String) -> Nil {
  ffi.ets_delete(table, key(token))
}

/// The name a session acts as. Names from the identity provider or the proxy
/// are prefixed with the sign-in method: they come from outside, and could
/// otherwise be recorded as a local user, `system` or an API client
/// (`client:…`). Local usernames cannot contain `:`.
pub fn actor(method: Method, name: String) -> String {
  case method {
    Local -> name
    Oidc -> "sso:" <> name
    Header -> "proxy:" <> name
  }
}

/// The name without the sign-in method prefix of `actor`, for display next
/// to the method.
pub fn display_name(session: Session) -> String {
  case session.method, session.username {
    Oidc, "sso:" <> name | Header, "proxy:" <> name -> name
    _, name -> name
  }
}

/// Revokes every session of a local user (e.g. after deletion or password
/// change).
pub fn destroy_user(username: String) -> Nil {
  let entries: List(#(String, #(Int, Session))) = ffi.ets_to_list(table)
  entries
  |> list.each(fn(entry) {
    let #(token, #(_, session)) = entry
    case session.method == Local && session.username == username {
      True -> ffi.ets_delete(table, token)
      False -> Nil
    }
  })
}

pub fn purge_expired() -> Int {
  let now = ffi.now_seconds()
  let _ = ffi.ets_delete_older(header_index, now)
  ffi.ets_delete_older(table, now)
}

pub fn method_to_string(method: Method) -> String {
  case method {
    Local -> "local"
    Oidc -> "sso"
    Header -> "proxy"
  }
}
