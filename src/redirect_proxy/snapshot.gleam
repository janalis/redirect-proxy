//// Publishes the compiled rule set to `persistent_term` so that every request
//// process can read it without locks, copies or message passing.

import redirect_proxy/ffi
import redirect_proxy/matcher.{type Matcher}

const key = "matcher"

pub fn publish(matcher: Matcher) -> Nil {
  ffi.snapshot_put(key, matcher)
}

pub fn current() -> Matcher {
  case ffi.snapshot_get(key) {
    Ok(matcher) -> matcher
    Error(Nil) -> matcher.empty()
  }
}
