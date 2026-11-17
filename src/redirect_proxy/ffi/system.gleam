//// Bindings to `redirect_proxy_system_ffi` (time, SIGHUP, CLI helpers,
//// runtime metrics, error rescue) and `redirect_proxy_sigterm` (draining on
//// SIGTERM).

// --- time -------------------------------------------------------------------

@external(erlang, "redirect_proxy_system_ffi", "now_seconds")
pub fn now_seconds() -> Int

@external(erlang, "redirect_proxy_system_ffi", "now_millis")
pub fn now_millis() -> Int

@external(erlang, "redirect_proxy_system_ffi", "now_micros")
pub fn now_micros() -> Int

@external(erlang, "redirect_proxy_system_ffi", "monotonic_micros")
pub fn monotonic_micros() -> Int

@external(erlang, "redirect_proxy_system_ffi", "rfc3339")
pub fn rfc3339(seconds: Int) -> String

/// Seconds since the epoch of an RFC 3339 date-time with a time zone.
@external(erlang, "redirect_proxy_system_ffi", "parse_rfc3339")
pub fn parse_rfc3339(value: String) -> Result(Int, Nil)

pub fn now_rfc3339() -> String {
  rfc3339(now_seconds())
}

// --- signals ----------------------------------------------------------------

@external(erlang, "redirect_proxy_system_ffi", "on_sighup")
pub fn on_sighup(callback: fn() -> Nil) -> Nil

/// On SIGTERM, drain for `grace_ms` (see `draining`) before stopping.
/// `before_stop` runs right before the VM stops (its failures are logged).
@external(erlang, "redirect_proxy_sigterm", "install")
pub fn on_sigterm_drain(grace_ms: Int, before_stop: fn() -> Nil) -> Nil

/// True once SIGTERM was received: the node stops after the grace period.
@external(erlang, "redirect_proxy_sigterm", "draining")
pub fn draining() -> Bool

// --- command line -----------------------------------------------------------

@external(erlang, "redirect_proxy_system_ffi", "plain_arguments")
pub fn plain_arguments() -> List(String)

@external(erlang, "redirect_proxy_system_ffi", "halt")
pub fn halt(code: Int) -> Nil

@external(erlang, "redirect_proxy_system_ffi", "read_password")
pub fn read_password(prompt: String) -> Result(String, Nil)

// --- runtime ----------------------------------------------------------------

/// The version of the redirect_proxy application.
@external(erlang, "redirect_proxy_system_ffi", "app_version")
pub fn app_version() -> String

/// When the VM started, in seconds since the epoch.
@external(erlang, "redirect_proxy_system_ffi", "start_time_seconds")
pub fn start_time_seconds() -> Int

@external(erlang, "redirect_proxy_system_ffi", "memory_bytes")
pub fn memory_bytes() -> Int

@external(erlang, "redirect_proxy_system_ffi", "process_count")
pub fn process_count() -> Int

/// Forces a garbage collection of the calling process.
@external(erlang, "redirect_proxy_system_ffi", "garbage_collect")
pub fn garbage_collect() -> Nil

/// Runs `f`, returning an exception as `Error` with its description.
@external(erlang, "redirect_proxy_system_ffi", "rescue")
pub fn rescue(f: fn() -> a) -> Result(a, String)
