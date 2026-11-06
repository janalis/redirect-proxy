//// Local administrator accounts persisted in `users.json`.
////
//// Every change re-reads the file holding a node-wide lock and the
//// cross-process `users.json.lock`, so the server and the CLI never
//// overwrite each other's changes.
//// Password hashing is done by callers, outside the lock.

import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/audit
import redirect_proxy/ffi
import redirect_proxy/role.{type Role}
import redirect_proxy/rule
import simplifile

pub type User {
  User(
    username: String,
    password_hash: String,
    /// What the user may do; `admin` for users stored before roles.
    role: Role,
    created_at: String,
    updated_at: String,
  )
}

pub type Settings {
  Settings(path: String, audit_path: String)
}

/// How long a change waits for another process to release the file.
const lock_timeout = 5000

pub fn list(settings: Settings) -> Result(List(User), String) {
  load(settings.path)
}

pub fn get(settings: Settings, username: String) -> Result(User, Nil) {
  let username = normalise(username)
  load(settings.path)
  |> result.unwrap([])
  |> list.find(fn(u) { u.username == username })
}

pub fn count(settings: Settings) -> Int {
  load(settings.path) |> result.unwrap([]) |> list.length
}

/// Creates an administrator.
pub fn create(
  settings: Settings,
  username: String,
  password_hash: String,
  by actor: String,
) -> Result(User, String) {
  create_with_role(settings, username, password_hash, role.Admin, actor)
}

pub fn create_with_role(
  settings: Settings,
  username: String,
  password_hash: String,
  role: Role,
  by actor: String,
) -> Result(User, String) {
  let username = normalise(username)
  use Nil <- result.try(validate_username(username))
  use <- ffi.locked_file(settings.path, lock_timeout)
  use users <- result.try(load(settings.path))
  case list.any(users, fn(u) { u.username == username }) {
    True -> Error("user " <> username <> " already exists")
    False -> {
      let now = ffi.now_rfc3339()
      let user =
        User(username:, password_hash:, role:, created_at: now, updated_at: now)
      use Nil <- result.try(save(settings.path, list.append(users, [user])))
      audit.record(
        settings.audit_path,
        actor,
        "user.create",
        username,
        None,
        Some(
          json.object([
            #("username", json.string(username)),
            #("role", json.string(role.to_string(role))),
          ]),
        ),
      )
      Ok(user)
    }
  }
}

pub fn set_password(
  settings: Settings,
  username: String,
  password_hash: String,
  by actor: String,
) -> Result(Nil, String) {
  store_password(settings, username, password_hash, actor, "user.password")
}

/// Stores a stronger hash of the same password (more iterations), recorded
/// as such in the audit trail rather than as a password change.
pub fn rehash_password(
  settings: Settings,
  username: String,
  password_hash: String,
) -> Result(Nil, String) {
  store_password(
    settings,
    username,
    password_hash,
    "system",
    "user.password_rehash",
  )
}

fn store_password(
  settings: Settings,
  username: String,
  password_hash: String,
  actor: String,
  action: String,
) -> Result(Nil, String) {
  let username = normalise(username)
  use <- ffi.locked_file(settings.path, lock_timeout)
  use users <- result.try(load(settings.path))
  case list.any(users, fn(u) { u.username == username }) {
    False -> Error("user " <> username <> " does not exist")
    True -> {
      let now = ffi.now_rfc3339()
      let users =
        list.map(users, fn(u) {
          case u.username == username {
            True -> User(..u, password_hash:, updated_at: now)
            False -> u
          }
        })
      use Nil <- result.try(save(settings.path, users))
      audit.record(settings.audit_path, actor, action, username, None, None)
      Ok(Nil)
    }
  }
}

/// Changes the role of a user. The last administrator keeps theirs, so that
/// someone can always manage the users.
pub fn set_role(
  settings: Settings,
  username: String,
  new_role: Role,
  by actor: String,
) -> Result(Nil, String) {
  let username = normalise(username)
  use <- ffi.locked_file(settings.path, lock_timeout)
  use users <- result.try(load(settings.path))
  case list.find(users, fn(u) { u.username == username }) {
    Error(Nil) -> Error("user " <> username <> " does not exist")
    Ok(user) if user.role == new_role -> Ok(Nil)
    Ok(user) -> {
      let changed =
        list.map(users, fn(u) {
          case u.username == username {
            True -> User(..u, role: new_role, updated_at: ffi.now_rfc3339())
            False -> u
          }
        })
      use <- bool.guard(
        !has_admin(changed),
        Error("refusing to remove the role of the last administrator"),
      )
      use Nil <- result.try(save(settings.path, changed))
      audit.record(
        settings.audit_path,
        actor,
        "user.role",
        username,
        Some(json.object([#("role", json.string(role.to_string(user.role)))])),
        Some(json.object([#("role", json.string(role.to_string(new_role)))])),
      )
      Ok(Nil)
    }
  }
}

fn has_admin(users: List(User)) -> Bool {
  list.any(users, fn(u) { u.role == role.Admin })
}

pub fn delete(
  settings: Settings,
  username: String,
  by actor: String,
) -> Result(Nil, String) {
  let username = normalise(username)
  use <- ffi.locked_file(settings.path, lock_timeout)
  use users <- result.try(load(settings.path))
  case list.partition(users, fn(u) { u.username == username }) {
    #([], _) -> Error("user " <> username <> " does not exist")
    #(_, []) -> Error("refusing to delete the last local user")
    #(_, remaining) -> {
      use <- bool.guard(
        !has_admin(remaining),
        Error("refusing to delete the last administrator"),
      )
      use Nil <- result.try(save(settings.path, remaining))
      audit.record(
        settings.audit_path,
        actor,
        "user.delete",
        username,
        None,
        None,
      )
      Ok(Nil)
    }
  }
}

pub fn normalise(username: String) -> String {
  username |> string.trim |> string.lowercase
}

pub fn validate_username(username: String) -> Result(Nil, String) {
  let allowed = "abcdefghijklmnopqrstuvwxyz0123456789._@-"
  let ok =
    string.length(username) >= 2
    && string.length(username) <= 64
    && string.to_graphemes(username)
    |> list.all(fn(c) { string.contains(allowed, c) })
  case ok {
    True -> Ok(Nil)
    False ->
      Error(
        "username must be 2-64 characters among a-z, 0-9, '.', '_', '@' and '-'",
      )
  }
}

// --- persistence ------------------------------------------------------------

fn user_decoder() -> decode.Decoder(User) {
  use username <- decode.field("username", decode.string)
  use password_hash <- decode.field("password_hash", decode.string)
  use role <- decode.optional_field("role", role.Admin, role_decoder())
  use created_at <- decode.optional_field("created_at", "", decode.string)
  use updated_at <- decode.optional_field("updated_at", "", decode.string)
  decode.success(User(
    username:,
    password_hash:,
    role:,
    created_at:,
    updated_at:,
  ))
}

fn role_decoder() -> decode.Decoder(Role) {
  use value <- decode.then(decode.string)
  case role.from_string(value) {
    Ok(r) -> decode.success(r)
    Error(Nil) -> decode.failure(role.Admin, "viewer | editor | admin")
  }
}

fn load(path: String) -> Result(List(User), String) {
  case simplifile.is_file(path) {
    Ok(True) -> {
      use content <- result.try(
        simplifile.read(path) |> result.map_error(simplifile.describe_error),
      )
      json.parse(content, decode.at(["users"], decode.list(user_decoder())))
      |> result.map_error(fn(e) { path <> ": " <> rule.describe_json_error(e) })
    }
    _ -> Ok([])
  }
}

fn save(path: String, users: List(User)) -> Result(Nil, String) {
  let content =
    json.object([
      #("version", json.int(1)),
      #(
        "users",
        json.array(users, fn(u) {
          json.object([
            #("username", json.string(u.username)),
            #("password_hash", json.string(u.password_hash)),
            #("role", json.string(role.to_string(u.role))),
            #("created_at", json.string(u.created_at)),
            #("updated_at", json.string(u.updated_at)),
          ])
        }),
      ),
    ])
    |> json.to_string
  use Nil <- result.try(ffi.atomic_write(path, content <> "\n"))
  // password hashes: readable by the service account only
  let _ = simplifile.set_permissions_octal(path, 0o600)
  Ok(Nil)
}
