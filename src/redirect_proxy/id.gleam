//// Random identifiers.

import gleam/bit_array
import gleam/crypto
import gleam/string

/// A random RFC 4122 version 4 UUID.
pub fn uuid() -> String {
  let assert <<a:48, _:4, b:12, _:2, c:62>> = crypto.strong_random_bytes(16)
  let s =
    bit_array.base16_encode(<<a:48, 4:4, b:12, 2:2, c:62>>) |> string.lowercase
  string.slice(s, 0, 8)
  <> "-"
  <> string.slice(s, 8, 4)
  <> "-"
  <> string.slice(s, 12, 4)
  <> "-"
  <> string.slice(s, 16, 4)
  <> "-"
  <> string.slice(s, 20, 12)
}

/// A URL-safe random token with `bytes` bytes of entropy.
pub fn token(bytes: Int) -> String {
  crypto.strong_random_bytes(bytes)
  |> bit_array.base64_url_encode(False)
}
