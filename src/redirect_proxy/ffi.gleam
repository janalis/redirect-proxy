//// Typed bindings to the Erlang helpers in `redirect_proxy_ffi.erl`.

import mist
import redirect_proxy/listener.{type Listener}

// --- persistent_term --------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "snapshot_put")
pub fn snapshot_put(key: String, value: a) -> Nil

@external(erlang, "redirect_proxy_ffi", "snapshot_get")
pub fn snapshot_get(key: String) -> Result(a, Nil)

// --- regex ------------------------------------------------------------------

pub type CompiledRegex

pub type RegexError {
  NoMatch
  LimitExceeded
}

@external(erlang, "redirect_proxy_ffi", "regex_compile")
pub fn regex_compile(
  pattern: String,
  case_insensitive: Bool,
) -> Result(CompiledRegex, String)

/// Runs a compiled regex. On success returns every capture, group 0 first.
/// Unset groups are returned as empty strings.
@external(erlang, "redirect_proxy_ffi", "regex_run")
pub fn regex_run(
  regex: CompiledRegex,
  subject: String,
) -> Result(List(String), RegexError)

// --- files ------------------------------------------------------------------

/// Creates the counter of regex runs that exhausted their budget.
@external(erlang, "redirect_proxy_ffi", "regex_limit_init")
pub fn regex_limit_init() -> Nil

/// Regex runs that exhausted their budget since boot.
@external(erlang, "redirect_proxy_ffi", "regex_limit_count")
pub fn regex_limit_count() -> Int

@external(erlang, "redirect_proxy_ffi", "atomic_write")
pub fn atomic_write(path: String, content: String) -> Result(Nil, String)

@external(erlang, "redirect_proxy_ffi", "append_line")
pub fn append_line(path: String, line: String) -> Result(Nil, String)

// --- crypto -----------------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "pbkdf2_sha256")
pub fn pbkdf2_sha256(
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  length: Int,
) -> BitArray

@external(erlang, "redirect_proxy_ffi", "secure_compare")
pub fn secure_compare(a: BitArray, b: BitArray) -> Bool

// --- ets --------------------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "ets_new")
pub fn ets_new(name: String) -> Nil

@external(erlang, "redirect_proxy_ffi", "ets_put")
pub fn ets_put(table: String, key: k, value: v) -> Nil

@external(erlang, "redirect_proxy_ffi", "ets_get")
pub fn ets_get(table: String, key: k) -> Result(v, Nil)

@external(erlang, "redirect_proxy_ffi", "ets_delete")
pub fn ets_delete(table: String, key: k) -> Nil

/// Number of entries in a table.
@external(erlang, "redirect_proxy_ffi", "ets_size")
pub fn ets_size(table: String) -> Int

@external(erlang, "redirect_proxy_ffi", "ets_to_list")
pub fn ets_to_list(table: String) -> List(#(k, v))

/// Deletes every entry whose value is a tuple whose first element (an expiry
/// timestamp) is lower than `now`. Returns the number of deleted entries.
@external(erlang, "redirect_proxy_ffi", "ets_delete_older")
pub fn ets_delete_older(table: String, now: Int) -> Int

// --- counters ---------------------------------------------------------------

pub type Counters

@external(erlang, "redirect_proxy_ffi", "counter_new")
pub fn counter_new(size: Int) -> Counters

@external(erlang, "redirect_proxy_ffi", "counter_add")
pub fn counter_add(ref: Counters, index: Int, amount: Int) -> Nil

@external(erlang, "redirect_proxy_ffi", "counter_get")
pub fn counter_get(ref: Counters, index: Int) -> Int

// --- network ----------------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "ip_in_cidr")
pub fn ip_in_cidr(ip: String, cidr: String) -> Bool

@external(erlang, "redirect_proxy_ffi", "valid_cidr")
pub fn valid_cidr(cidr: String) -> Bool

// --- time -------------------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "now_seconds")
pub fn now_seconds() -> Int

@external(erlang, "redirect_proxy_ffi", "now_millis")
pub fn now_millis() -> Int

@external(erlang, "redirect_proxy_ffi", "rfc3339")
pub fn rfc3339(seconds: Int) -> String

pub fn now_rfc3339() -> String {
  rfc3339(now_seconds())
}

// --- process / os -----------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "on_sighup")
pub fn on_sighup(callback: fn() -> Nil) -> Nil

/// On SIGTERM, drain for `grace_ms` (see `draining`) before stopping.
@external(erlang, "redirect_proxy_sigterm", "install")
pub fn on_sigterm_drain(grace_ms: Int) -> Nil

/// True once SIGTERM was received: the node stops after the grace period.
@external(erlang, "redirect_proxy_sigterm", "draining")
pub fn draining() -> Bool

@external(erlang, "redirect_proxy_ffi", "plain_arguments")
pub fn plain_arguments() -> List(String)

@external(erlang, "redirect_proxy_ffi", "halt")
pub fn halt(code: Int) -> Nil

@external(erlang, "redirect_proxy_ffi", "read_password")
pub fn read_password(prompt: String) -> Result(String, Nil)

@external(erlang, "redirect_proxy_ffi", "memory_bytes")
pub fn memory_bytes() -> Int

@external(erlang, "redirect_proxy_ffi", "process_count")
pub fn process_count() -> Int

// --- jwt --------------------------------------------------------------------

@external(erlang, "redirect_proxy_ffi", "jwt_verify")
pub fn jwt_verify(jwks_json: String, token: String) -> Result(String, String)

@external(erlang, "redirect_proxy_ffi", "jwt_peek_header")
pub fn jwt_peek_header(token: String) -> Result(String, Nil)

// --- locks ------------------------------------------------------------------

/// Runs `f` while holding a node-wide lock named `name`.
@external(erlang, "redirect_proxy_ffi", "with_lock")
pub fn with_lock(name: String, f: fn() -> a) -> a

/// Runs `f` holding `<path>.lock`, an exclusive lock shared by every OS
/// process writing `path` (the server, the CLI). Locks older than 10 seconds
/// are considered stale. Errors when the lock is not acquired in time.
@external(erlang, "redirect_proxy_ffi", "with_file_lock")
pub fn with_file_lock(
  path: String,
  timeout_ms: Int,
  f: fn() -> a,
) -> Result(a, String)

/// Read-modify-write of a data file that other OS processes (the CLI) may
/// write too: holds the node-wide lock of `path`, then `<path>.lock`, for up
/// to `timeout_ms`.
pub fn locked_file(
  path: String,
  timeout_ms: Int,
  f: fn() -> Result(a, String),
) -> Result(a, String) {
  use <- with_lock(path)
  case with_file_lock(path, timeout_ms, f) {
    Ok(result) -> result
    Error(reason) -> Error(reason)
  }
}

/// The first `bytes` bytes of a string (all of it when shorter). The result
/// may end inside a UTF-8 sequence: use it only as a lookup key.
@external(erlang, "redirect_proxy_ffi", "binary_take")
pub fn byte_take(string: String, bytes: Int) -> String

/// A string without its first `bytes` bytes, which must end on a character
/// boundary.
@external(erlang, "redirect_proxy_ffi", "binary_drop")
pub fn byte_drop(string: String, bytes: Int) -> String

/// Removes CR, LF and NUL bytes.
@external(erlang, "redirect_proxy_ffi", "strip_control")
pub fn strip_control(value: String) -> String

/// Forces a garbage collection of the calling process.
@external(erlang, "redirect_proxy_ffi", "garbage_collect")
pub fn garbage_collect() -> Nil

// --- access log -----------------------------------------------------------------

/// Installs one access log handler per output, each accepting the listed
/// listeners.
@external(erlang, "redirect_proxy_access_ffi", "start")
pub fn access_log_start(
  groups: List(#(String, List(Listener))),
  max_bytes: Int,
  max_files: Int,
  compress: Bool,
) -> Result(Nil, String)

@external(erlang, "redirect_proxy_access_ffi", "stop")
pub fn access_log_stop() -> Nil

@external(erlang, "redirect_proxy_access_ffi", "emit")
pub fn access_log_emit(listener: Listener, line: String) -> Nil

@external(erlang, "redirect_proxy_access_ffi", "escape_default")
pub fn escape_default(value: String) -> String

@external(erlang, "redirect_proxy_access_ffi", "escape_json")
pub fn escape_json(value: String) -> String

@external(erlang, "redirect_proxy_access_ffi", "escape_newlines")
pub fn escape_newlines(value: String) -> String

@external(erlang, "redirect_proxy_access_ffi", "time_local")
pub fn time_local(micros: Int) -> String

@external(erlang, "redirect_proxy_access_ffi", "time_iso8601")
pub fn time_iso8601(micros: Int) -> String

@external(erlang, "redirect_proxy_access_ffi", "anonymize_ip")
pub fn anonymize_ip(ip: String) -> String

/// `anonymize_ip` of a peer address, without the string round trip.
@external(erlang, "redirect_proxy_access_ffi", "anonymize_peer")
pub fn anonymize_peer(ip: mist.IpAddress) -> String

@external(erlang, "redirect_proxy_access_ffi", "now_micros")
pub fn now_micros() -> Int

@external(erlang, "redirect_proxy_access_ffi", "monotonic_micros")
pub fn monotonic_micros() -> Int
