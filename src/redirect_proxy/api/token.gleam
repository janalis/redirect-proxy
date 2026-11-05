//// Opaque access tokens issued by the built-in token endpoint. Tokens live in
//// ETS keyed by their SHA-256 (a memory dump does not reveal usable tokens)
//// and expire after `api.token_ttl`. They do not survive a restart: clients
//// using the client credentials grant simply request a new one.

import gleam/bit_array
import gleam/crypto
import gleam/list
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/ffi
import redirect_proxy/id

const table = "redirect_proxy_api_tokens"

pub const prefix = "rpat_"

pub type Grant {
  Grant(
    client_id: String,
    scopes: List(Scope),
    expires_at: Int,
    /// Secret hash of the client when the token was issued: rotating the
    /// secret or deleting the client (even from the CLI) invalidates tokens.
    secret_hash: String,
  )
}

pub fn init() -> Nil {
  ffi.ets_new(table)
}

pub fn issue(
  client_id: String,
  secret_hash: String,
  scopes: List(Scope),
  ttl: Int,
) -> String {
  let token = prefix <> id.token(32)
  let expires_at = ffi.now_seconds() + ttl
  ffi.ets_put(table, key(token), #(
    expires_at,
    Grant(client_id:, scopes:, expires_at:, secret_hash:),
  ))
  token
}

pub fn lookup(token: String) -> Result(Grant, Nil) {
  case ffi.ets_get(table, key(token)) {
    Ok(#(expires_at, grant)) ->
      case expires_at > ffi.now_seconds() {
        True -> Ok(grant)
        False -> {
          ffi.ets_delete(table, key(token))
          Error(Nil)
        }
      }
    Error(Nil) -> Error(Nil)
  }
}

/// Revokes every token of a client (secret rotated or client deleted).
pub fn revoke_client(client_id: String) -> Nil {
  let entries: List(#(String, #(Int, Grant))) = ffi.ets_to_list(table)
  list.each(entries, fn(entry) {
    let #(k, #(_, grant)) = entry
    case grant.client_id == client_id {
      True -> ffi.ets_delete(table, k)
      False -> Nil
    }
  })
}

pub fn purge_expired() -> Int {
  ffi.ets_delete_older(table, ffi.now_seconds())
}

fn key(token: String) -> String {
  crypto.hash(crypto.Sha256, <<token:utf8>>)
  |> bit_array.base64_url_encode(False)
}
