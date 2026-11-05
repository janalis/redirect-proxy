//// Helpers shared by tests.

import envoy
import gleam/result
import redirect_proxy/id
import simplifile

/// Creates a fresh, empty temporary directory.
pub fn temp_dir() -> String {
  let base = envoy.get("TMPDIR") |> result.unwrap("/tmp")
  let dir = base <> "/redirect-proxy-test-" <> id.token(9)
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  dir
}
