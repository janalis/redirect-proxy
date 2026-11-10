//// Publishes the compiled rule set to `persistent_term` so that every request
//// process can read it without locks, copies or message passing.

import redirect_proxy/ffi
import redirect_proxy/matcher.{type Matcher}

const key = "matcher"

pub fn publish(matcher: Matcher) -> Nil {
  ffi.snapshot_put(key, matcher)
}

/// The published rule set (an empty one, published, until a first one is).
pub fn current() -> Matcher {
  ffi.snapshot_or_init(key, matcher.empty)
}
