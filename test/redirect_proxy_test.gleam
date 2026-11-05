import envoy
import gleam/result
import gleeunit
import redirect_proxy/log

pub fn main() -> Nil {
  // Keep test output readable; set RP_TEST_LOG_LEVEL=debug to see logs.
  log.configure(envoy.get("RP_TEST_LOG_LEVEL") |> result.unwrap("critical"))
  gleeunit.main()
}
