//// API clients of the built-in OAuth2 client credentials flow, persisted in
//// `api_clients.json`. Secrets are 256-bit random values shown once; only
//// their SHA-256 is stored (a slow hash adds nothing for random secrets and
//// would make every token request expensive).

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/api/scope.{type Scope}
import redirect_proxy/audit
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/rule
import simplifile

pub type Client {
  Client(
    client_id: String,
    name: String,
    secret_hash: String,
    scopes: List(Scope),
    created_at: String,
    created_by: String,
    last_used_at: String,
  )
}

pub type Settings {
  Settings(path: String, audit_path: String)
}

/// How long a change waits for another process to release the file.
const lock_timeout = 5000

pub fn list(settings: Settings) -> Result(List(Client), String) {
  load(settings.path)
}

pub fn get(settings: Settings, client_id: String) -> Result(Client, Nil) {
  load(settings.path)
  |> result.unwrap([])
  |> list.find(fn(c) { c.client_id == client_id })
}

/// Creates a client and returns it with its plain secret (shown only once).
pub fn create(
  settings: Settings,
  name: String,
  scopes: List(Scope),
  by actor: String,
) -> Result(#(Client, String), String) {
  let name = string.trim(name)
  use Nil <- result.try(validate(name, scopes))
  use <- ffi.locked_file(settings.path, lock_timeout)
  use clients <- result.try(load(settings.path))
  let secret = new_secret()
  let client =
    Client(
      client_id: "rp_" <> id.token(12),
      name:,
      secret_hash: hash(secret),
      scopes: list.unique(scopes),
      created_at: ffi.now_rfc3339(),
      created_by: actor,
      last_used_at: "",
    )
  use Nil <- result.try(save(settings.path, list.append(clients, [client])))
  audit.record(
    settings.audit_path,
    actor,
    "api_client.create",
    client.client_id,
    None,
    Some(public_json(client)),
  )
  Ok(#(client, secret))
}

/// Replaces the secret of a client and returns the new one.
pub fn rotate(
  settings: Settings,
  client_id: String,
  by actor: String,
) -> Result(String, String) {
  use <- ffi.locked_file(settings.path, lock_timeout)
  use clients <- result.try(load(settings.path))
  use <- guard_exists(clients, client_id)
  let secret = new_secret()
  let clients =
    list.map(clients, fn(c) {
      case c.client_id == client_id {
        True -> Client(..c, secret_hash: hash(secret))
        False -> c
      }
    })
  use Nil <- result.try(save(settings.path, clients))
  audit.record(
    settings.audit_path,
    actor,
    "api_client.rotate",
    client_id,
    None,
    None,
  )
  Ok(secret)
}

pub fn delete(
  settings: Settings,
  client_id: String,
  by actor: String,
) -> Result(Nil, String) {
  use <- ffi.locked_file(settings.path, lock_timeout)
  use clients <- result.try(load(settings.path))
  use <- guard_exists(clients, client_id)
  use Nil <- result.try(save(
    settings.path,
    list.filter(clients, fn(c) { c.client_id != client_id }),
  ))
  audit.record(
    settings.audit_path,
    actor,
    "api_client.delete",
    client_id,
    None,
    None,
  )
  Ok(Nil)
}

/// Verifies a client secret in constant time. Records the last use (at most
/// once a minute, to avoid rewriting the file on every token request).
pub fn authenticate(
  settings: Settings,
  client_id: String,
  secret: String,
) -> Result(Client, Nil) {
  let candidate = <<hash(secret):utf8>>
  case get(settings, client_id) {
    Ok(client) ->
      case ffi.secure_compare(candidate, <<client.secret_hash:utf8>>) {
        True -> {
          touch(settings, client)
          Ok(client)
        }
        False -> Error(Nil)
      }
    Error(Nil) -> {
      // same work whether or not the client exists
      let _ = ffi.secure_compare(candidate, candidate)
      Error(Nil)
    }
  }
}

fn touch(settings: Settings, client: Client) -> Nil {
  let now = ffi.now_rfc3339()
  case string.slice(client.last_used_at, 0, 16) == string.slice(now, 0, 16) {
    True -> Nil
    False -> {
      // Best effort: never make a token request wait for another writer.
      let _ = {
        use <- ffi.locked_file(settings.path, 100)
        use clients <- result.try(load(settings.path))
        list.map(clients, fn(c) {
          case c.client_id == client.client_id {
            True -> Client(..c, last_used_at: now)
            False -> c
          }
        })
        |> save(settings.path, _)
      }
      Nil
    }
  }
}

fn guard_exists(
  clients: List(Client),
  client_id: String,
  next: fn() -> Result(a, String),
) -> Result(a, String) {
  case list.any(clients, fn(c) { c.client_id == client_id }) {
    True -> next()
    False -> Error("API client " <> client_id <> " does not exist")
  }
}

pub fn validate(name: String, scopes: List(Scope)) -> Result(Nil, String) {
  case string.length(name), scopes {
    0, _ -> Error("name is required")
    n, _ if n > 100 -> Error("name is too long")
    _, [] -> Error("at least one scope is required")
    _, _ -> Ok(Nil)
  }
}

fn new_secret() -> String {
  "rps_" <> id.token(32)
}

fn hash(secret: String) -> String {
  crypto.hash(crypto.Sha256, <<secret:utf8>>)
  |> bit_array.base64_url_encode(False)
}

/// Client representation without its secret hash.
pub fn public_json(c: Client) -> json.Json {
  json.object([
    #("client_id", json.string(c.client_id)),
    #("name", json.string(c.name)),
    #("scopes", json.array(c.scopes, fn(s) { json.string(scope.to_string(s)) })),
    #("created_at", json.string(c.created_at)),
    #("created_by", json.string(c.created_by)),
    #("last_used_at", json.string(c.last_used_at)),
  ])
}

// --- persistence ------------------------------------------------------------

fn client_decoder() -> decode.Decoder(Client) {
  use client_id <- decode.field("client_id", decode.string)
  use name <- decode.field("name", decode.string)
  use secret_hash <- decode.field("secret_hash", decode.string)
  use scopes <- decode.field("scopes", decode.list(decode.string))
  use created_at <- decode.optional_field("created_at", "", decode.string)
  use created_by <- decode.optional_field("created_by", "", decode.string)
  use last_used_at <- decode.optional_field("last_used_at", "", decode.string)
  decode.success(Client(
    client_id:,
    name:,
    secret_hash:,
    scopes: list.filter_map(scopes, scope.from_string),
    created_at:,
    created_by:,
    last_used_at:,
  ))
}

fn load(path: String) -> Result(List(Client), String) {
  case simplifile.is_file(path) {
    Ok(True) -> {
      use content <- result.try(
        simplifile.read(path) |> result.map_error(simplifile.describe_error),
      )
      json.parse(content, decode.at(["clients"], decode.list(client_decoder())))
      |> result.map_error(fn(e) { path <> ": " <> rule.describe_json_error(e) })
    }
    _ -> Ok([])
  }
}

fn save(path: String, clients: List(Client)) -> Result(Nil, String) {
  let content =
    json.object([
      #("version", json.int(1)),
      #(
        "clients",
        json.array(clients, fn(c) {
          json.object([
            #("client_id", json.string(c.client_id)),
            #("name", json.string(c.name)),
            #("secret_hash", json.string(c.secret_hash)),
            #(
              "scopes",
              json.array(c.scopes, fn(s) { json.string(scope.to_string(s)) }),
            ),
            #("created_at", json.string(c.created_at)),
            #("created_by", json.string(c.created_by)),
            #("last_used_at", json.string(c.last_used_at)),
          ])
        }),
      ),
    ])
    |> json.to_string
  use Nil <- result.try(ffi.atomic_write(path, content <> "\n"))
  let _ = simplifile.set_permissions_octal(path, 0o600)
  Ok(Nil)
}
