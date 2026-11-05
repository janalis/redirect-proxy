//// Server-side sessions kept in ETS. The browser only holds a signed,
//// random session token; sessions can be revoked and expire server-side.

import gleam/list
import redirect_proxy/ffi
import redirect_proxy/id

const table = "redirect_proxy_sessions"

pub type Method {
  Local
  Oidc
  Header
}

pub type Session {
  Session(
    token: String,
    username: String,
    method: Method,
    csrf_token: String,
    expires_at: Int,
  )
}

/// Creates the ETS table. Must be called from a long lived process.
pub fn init() -> Nil {
  ffi.ets_new(table)
}

pub fn create(username: String, method: Method, ttl: Int) -> Session {
  let session =
    Session(
      token: id.token(32),
      username:,
      method:,
      csrf_token: id.token(32),
      expires_at: ffi.now_seconds() + ttl,
    )
  // Stored as #(expires_at, session) so that `ets_delete_older` can purge.
  ffi.ets_put(table, session.token, #(session.expires_at, session))
  session
}

pub fn get(token: String) -> Result(Session, Nil) {
  case ffi.ets_get(table, token) {
    Ok(#(expires_at, session)) ->
      case expires_at > ffi.now_seconds() {
        True -> Ok(session)
        False -> {
          ffi.ets_delete(table, token)
          Error(Nil)
        }
      }
    Error(Nil) -> Error(Nil)
  }
}

pub fn destroy(token: String) -> Nil {
  ffi.ets_delete(table, token)
}

/// Revokes every session of a user (e.g. after deletion or password change).
pub fn destroy_user(username: String) -> Nil {
  let entries: List(#(String, #(Int, Session))) = ffi.ets_to_list(table)
  entries
  |> list.each(fn(entry) {
    let #(token, #(_, session)) = entry
    case session.username == username {
      True -> ffi.ets_delete(table, token)
      False -> Nil
    }
  })
}

pub fn purge_expired() -> Int {
  ffi.ets_delete_older(table, ffi.now_seconds())
}

pub fn method_to_string(method: Method) -> String {
  case method {
    Local -> "local"
    Oidc -> "sso"
    Header -> "proxy"
  }
}
