import gleam/string
import redirect_proxy/password

pub fn hash_and_verify_test() {
  let hash = password.hash_with("correct horse battery", 1000)
  assert string.starts_with(hash, "pbkdf2-sha256$1000$")
  assert password.verify("correct horse battery", hash)
  assert !password.verify("wrong", hash)
  assert !password.verify("", hash)
}

pub fn salts_are_random_test() {
  assert password.hash_with("same", 10) != password.hash_with("same", 10)
}

pub fn malformed_hashes_never_verify_test() {
  assert !password.verify("x", "")
  assert !password.verify("x", "plain-text")
  assert !password.verify("x", "pbkdf2-sha256$abc$AAAA$AAAA")
  assert !password.verify("x", "pbkdf2-sha256$10$!!!$AAAA")
  assert !password.verify("x", "md5$10$AAAA$AAAA")
}

pub fn strength_test() {
  let assert Error(_) = password.validate_strength("short")
  let assert Ok(Nil) = password.validate_strength("long enough password")
}
