//// Bindings to `redirect_proxy_crypto_ffi`: password hashing, constant-time
//// comparison, and JWT checks (the OIDC id_token).

@external(erlang, "redirect_proxy_crypto_ffi", "pbkdf2_sha256")
pub fn pbkdf2_sha256(
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  length: Int,
) -> BitArray

@external(erlang, "redirect_proxy_crypto_ffi", "secure_compare")
pub fn secure_compare(a: BitArray, b: BitArray) -> Bool

@external(erlang, "redirect_proxy_crypto_ffi", "jwt_verify")
pub fn jwt_verify(jwks_json: String, token: String) -> Result(String, String)

@external(erlang, "redirect_proxy_crypto_ffi", "jwt_peek_header")
pub fn jwt_peek_header(token: String) -> Result(String, Nil)
