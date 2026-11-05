//// Password hashing with PBKDF2-HMAC-SHA256 (OWASP 2023 recommendation:
//// 600 000 iterations). Encoded as `pbkdf2-sha256$<iterations>$<salt>$<hash>`
//// with unpadded base64 salt and hash.

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/result
import gleam/string
import redirect_proxy/ffi

pub const default_iterations = 600_000

pub const min_length = 12

const key_length = 32

pub fn hash(password: String) -> String {
  hash_with(password, default_iterations)
}

pub fn hash_with(password: String, iterations: Int) -> String {
  let salt = crypto.strong_random_bytes(16)
  let derived =
    ffi.pbkdf2_sha256(<<password:utf8>>, salt, iterations, key_length)
  "pbkdf2-sha256$"
  <> int.to_string(iterations)
  <> "$"
  <> bit_array.base64_encode(salt, False)
  <> "$"
  <> bit_array.base64_encode(derived, False)
}

pub fn verify(password: String, encoded: String) -> Bool {
  case string.split(encoded, "$") {
    ["pbkdf2-sha256", iterations, salt, expected] -> {
      let checked = {
        use iterations <- result.try(int.parse(iterations))
        use salt <- result.try(bit_array.base64_decode(pad(salt)))
        use expected <- result.try(bit_array.base64_decode(pad(expected)))
        let derived =
          ffi.pbkdf2_sha256(
            <<password:utf8>>,
            salt,
            iterations,
            bit_array.byte_size(expected),
          )
        Ok(ffi.secure_compare(derived, expected))
      }
      result.unwrap(checked, False)
    }
    _ -> False
  }
}

/// Burns roughly the same CPU time as a real verification. Used when a user
/// does not exist so that response timing does not leak valid usernames.
pub fn dummy_verify() -> Nil {
  let _ =
    ffi.pbkdf2_sha256(<<"dummy":utf8>>, <<"salt":utf8>>, default_iterations, 32)
  Nil
}

pub fn validate_strength(password: String) -> Result(Nil, String) {
  case string.length(password) >= min_length {
    True -> Ok(Nil)
    False ->
      Error(
        "password must be at least "
        <> int.to_string(min_length)
        <> " characters",
      )
  }
}

fn pad(value: String) -> String {
  case string.length(value) % 4 {
    2 -> value <> "=="
    3 -> value <> "="
    _ -> value
  }
}
