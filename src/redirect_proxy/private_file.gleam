//// Small JSON data files holding secrets (`users.json`,
//// `api_clients.json`): `{"version": 1, "<key>": [...]}`, written
//// atomically and readable by the service account only.
////
//// A change re-reads the file under `locked`, so the server and the CLI
//// never overwrite each other's changes.

import gleam/dynamic/decode.{type Decoder}
import gleam/json.{type Json}
import gleam/result
import redirect_proxy/ffi
import redirect_proxy/json_error
import simplifile

/// How long a change waits for another process to release the file.
const lock_timeout = 5000

/// Runs `next` holding the node-wide lock of `path` and `<path>.lock`.
pub fn locked(
  path: String,
  next: fn() -> Result(a, String),
) -> Result(a, String) {
  ffi.locked_file(path, lock_timeout, next)
}

/// The items under `key`; none when the file does not exist.
pub fn load(
  path: String,
  key: String,
  item: Decoder(a),
) -> Result(List(a), String) {
  case simplifile.is_file(path) {
    Ok(True) -> {
      use content <- result.try(
        simplifile.read(path) |> result.map_error(simplifile.describe_error),
      )
      json.parse(content, decode.at([key], decode.list(item)))
      |> result.map_error(fn(e) { path <> ": " <> json_error.describe(e) })
    }
    _ -> Ok([])
  }
}

pub fn save(
  path: String,
  key: String,
  items: List(a),
  encode: fn(a) -> Json,
) -> Result(Nil, String) {
  let content =
    json.object([
      #("version", json.int(1)),
      #(key, json.array(items, encode)),
    ])
    |> json.to_string
  use Nil <- result.try(ffi.atomic_write_private(path, content <> "\n"))
  // secrets: readable by the service account only
  let _ = simplifile.set_permissions_octal(path, 0o600)
  Ok(Nil)
}
