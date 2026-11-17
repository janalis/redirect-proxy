//// The process that owns the long-lived ETS tables, started first in the
//// supervision tree (see `app.start`): a store, a listener or the process
//// that started the application can stop without taking them along.

import gleam/erlang/process.{type Pid}
import gleam/otp/actor
import gleam/otp/supervision.{type ChildSpecification}
import gleam/result
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/session
import redirect_proxy/api/token
import redirect_proxy/metrics
import redirect_proxy/ratelimit
import redirect_proxy/store/checker
import redirect_proxy/store/commit

/// The owner, as a child of a supervisor.
pub fn supervised() -> ChildSpecification(Nil) {
  supervision.worker(fn() {
    start_link(create)
    |> result.map(fn(pid) { actor.Started(pid:, data: Nil) })
    |> result.map_error(actor.InitFailed)
  })
}

/// Creates every table (and the metrics counters) in the calling process,
/// which owns them. A table that exists is left as it is.
fn create() -> Nil {
  metrics.init()
  session.init()
  ratelimit.init()
  oidc.init()
  token.init()
  commit.init()
  checker.init()
  memo_init()
  time_cache_init()
}

@external(erlang, "redirect_proxy_tables_ffi", "start_link")
fn start_link(create: fn() -> Nil) -> Result(Pid, String)

@external(erlang, "redirect_proxy_file_ffi", "memo_init")
fn memo_init() -> Nil

@external(erlang, "redirect_proxy_access_ffi", "time_cache_init")
fn time_cache_init() -> Nil
