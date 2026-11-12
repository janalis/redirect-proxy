//// Typed bindings to the Erlang helpers, `redirect_proxy_<area>_ffi.erl`
//// (snapshot, regex, file, crypto, ets, net, system, text).

import mist
import redirect_proxy/listener.{type Listener}

// --- persistent_term --------------------------------------------------------

@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_put")
pub fn snapshot_put(key: String, value: a) -> Nil

@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_get")
pub fn snapshot_get(key: String) -> Result(a, Nil)

/// The value of `key`, published from `init()` the first time: for values
/// only this function publishes (counters).
@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_or_init")
pub fn snapshot_or_init(key: String, init: fn() -> a) -> a

// --- regex ------------------------------------------------------------------

pub type CompiledRegex

pub type RegexError {
  NoMatch
  LimitExceeded
}

@external(erlang, "redirect_proxy_regex_ffi", "regex_compile")
pub fn regex_compile(
  pattern: String,
  case_insensitive: Bool,
) -> Result(CompiledRegex, String)

/// Runs a compiled regex. On success returns every capture, group 0 first.
/// Unset groups are returned as empty strings.
/// Counts one regex run stopped by a budget (the
/// `redirect_proxy_regex_limit_exceeded_total` metric).
@external(erlang, "redirect_proxy_regex_ffi", "count_regex_limit")
pub fn count_regex_limit() -> Nil

/// Reductions spent by the calling process so far.
@external(erlang, "redirect_proxy_regex_ffi", "reductions")
pub fn reductions() -> Int

@external(erlang, "redirect_proxy_regex_ffi", "regex_run")
pub fn regex_run(
  regex: CompiledRegex,
  subject: String,
) -> Result(List(String), RegexError)

// --- files ------------------------------------------------------------------

/// Creates the counter of regex runs that exhausted their budget.
@external(erlang, "redirect_proxy_regex_ffi", "regex_limit_init")
pub fn regex_limit_init() -> Nil

/// Regex runs that exhausted their budget since boot.
@external(erlang, "redirect_proxy_regex_ffi", "regex_limit_count")
pub fn regex_limit_count() -> Int

/// `compute()` for a file, cached until the file is written again. On an
/// error, the last successful value is returned when there is one.
@external(erlang, "redirect_proxy_file_ffi", "memo_file")
pub fn memo_file(path: String, compute: fn() -> Result(a, e)) -> Result(a, e)

@external(erlang, "redirect_proxy_file_ffi", "atomic_write")
pub fn atomic_write(path: String, content: String) -> Result(Nil, String)

/// `atomic_write` for files holding secrets: a new file is created 0600
/// (an existing one keeps its permissions, but for those of others).
@external(erlang, "redirect_proxy_file_ffi", "atomic_write_private")
pub fn atomic_write_private(
  path: String,
  content: String,
) -> Result(Nil, String)

/// Copies `source` to a new file `dest` created with the permissions of
/// `source` (never more readable, not even while it is written).
@external(erlang, "redirect_proxy_file_ffi", "copy_file_as")
pub fn copy_file_as(source: String, dest: String) -> Result(Nil, String)

/// The first item of a comma-separated header value, trimmed and ASCII
/// lower-cased.
@external(erlang, "redirect_proxy_net_ffi", "first_item")
pub fn first_item(value: String) -> String

@external(erlang, "redirect_proxy_file_ffi", "append_line")
pub fn append_line(path: String, line: String) -> Result(Nil, String)

// --- crypto -----------------------------------------------------------------

@external(erlang, "redirect_proxy_crypto_ffi", "pbkdf2_sha256")
pub fn pbkdf2_sha256(
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  length: Int,
) -> BitArray

@external(erlang, "redirect_proxy_crypto_ffi", "secure_compare")
pub fn secure_compare(a: BitArray, b: BitArray) -> Bool

// --- ets --------------------------------------------------------------------

@external(erlang, "redirect_proxy_ets_ffi", "ets_new")
pub fn ets_new(name: String) -> Nil

@external(erlang, "redirect_proxy_ets_ffi", "ets_put")
pub fn ets_put(table: String, key: k, value: v) -> Nil

@external(erlang, "redirect_proxy_ets_ffi", "ets_get")
pub fn ets_get(table: String, key: k) -> Result(v, Nil)

/// `ets_get` on a table that may not exist yet (a miss then).
@external(erlang, "redirect_proxy_ets_ffi", "ets_find")
pub fn ets_find(table: String, key: k) -> Result(v, Nil)

@external(erlang, "redirect_proxy_ets_ffi", "ets_delete")
pub fn ets_delete(table: String, key: k) -> Nil

/// Replaces a row only while it still holds the exact value read.
@external(erlang, "redirect_proxy_ets_ffi", "ets_replace_if")
pub fn ets_replace_if(table: String, key: String, old: a, new: a) -> Bool

/// Deletes a row only while it still holds the exact value read.
@external(erlang, "redirect_proxy_ets_ffi", "ets_delete_if")
pub fn ets_delete_if(table: String, key: String, old: a) -> Bool

/// Number of entries in a table.
@external(erlang, "redirect_proxy_ets_ffi", "ets_size")
pub fn ets_size(table: String) -> Int

@external(erlang, "redirect_proxy_ets_ffi", "ets_to_list")
pub fn ets_to_list(table: String) -> List(#(k, v))

/// Deletes every entry whose value is a tuple whose first element (an expiry
/// timestamp) is lower than `now`. Returns the number of deleted entries.
/// Adds `key` unless it is already in the table: True when it was added.
/// Atomic: of concurrent callers, one only gets True.
@external(erlang, "redirect_proxy_ets_ffi", "ets_insert_new")
pub fn ets_insert_new(table: String, key: String, value: a) -> Bool

@external(erlang, "redirect_proxy_ets_ffi", "ets_delete_older")
pub fn ets_delete_older(table: String, now: Int) -> Int

/// Counts a failure for `key` in its fixed window (a new window of `window`
/// seconds when there is none or it ended), atomically.
@external(erlang, "redirect_proxy_ets_ffi", "window_record")
pub fn window_record(table: String, key: String, now: Int, window: Int) -> Nil

/// The end of `key`'s window and its failure count.
@external(erlang, "redirect_proxy_ets_ffi", "window_take")
pub fn window_take(
  table: String,
  key: String,
  now: Int,
  window: Int,
  limit: Int,
) -> Result(Nil, Int)

@external(erlang, "redirect_proxy_ets_ffi", "window_forgive")
pub fn window_forgive(table: String, key: String) -> Nil

@external(erlang, "redirect_proxy_ets_ffi", "with_slot")
pub fn with_slot(
  table: String,
  key: String,
  max: Int,
  run: fn() -> a,
) -> Result(a, Nil)

@external(erlang, "redirect_proxy_ets_ffi", "password_check_slots")
pub fn password_check_slots() -> Int

@external(erlang, "redirect_proxy_ets_ffi", "window_get")
pub fn window_get(table: String, key: String) -> Result(#(Int, Int), Nil)

/// Deletes the windows that ended; the number deleted.
@external(erlang, "redirect_proxy_ets_ffi", "window_purge")
pub fn window_purge(table: String, now: Int) -> Int

// --- counters ---------------------------------------------------------------

pub type Counters

@external(erlang, "redirect_proxy_ets_ffi", "counter_new")
pub fn counter_new(size: Int) -> Counters

/// The number of counters of `counters`.
@external(erlang, "redirect_proxy_ets_ffi", "counter_size")
pub fn counter_size(counters: Counters) -> Int

@external(erlang, "redirect_proxy_ets_ffi", "counter_add")
pub fn counter_add(ref: Counters, index: Int, amount: Int) -> Nil

@external(erlang, "redirect_proxy_ets_ffi", "counter_get")
pub fn counter_get(ref: Counters, index: Int) -> Int

@external(erlang, "redirect_proxy_ets_ffi", "counter_put")
pub fn counter_put(ref: Counters, index: Int, value: Int) -> Nil

// --- network ----------------------------------------------------------------

/// The address throttling counts failures for: IPv6 addresses by /64.
/// Whether the text is an IPv4 or IPv6 address (no brackets, port or
/// prefix length).
@external(erlang, "redirect_proxy_net_ffi", "is_ip_address")
pub fn is_ip_address(text: String) -> Bool

@external(erlang, "redirect_proxy_net_ffi", "throttle_address")
pub fn throttle_address(ip: String) -> String

@external(erlang, "redirect_proxy_net_ffi", "ip_in_cidr")
pub fn ip_in_cidr(ip: String, cidr: String) -> Bool

@external(erlang, "redirect_proxy_net_ffi", "valid_cidr")
pub fn valid_cidr(cidr: String) -> Bool

/// An address the HTTP server can listen on: an IP address or "localhost".
@external(erlang, "redirect_proxy_net_ffi", "valid_listen_address")
pub fn valid_listen_address(address: String) -> Bool

/// "localhost" or a loopback IP address (IPv6 possibly in brackets, or
/// IPv4-mapped).
@external(erlang, "redirect_proxy_net_ffi", "is_loopback_address")
pub fn is_loopback_address(address: String) -> Bool

// --- time -------------------------------------------------------------------

@external(erlang, "redirect_proxy_system_ffi", "now_seconds")
pub fn now_seconds() -> Int

@external(erlang, "redirect_proxy_system_ffi", "now_millis")
pub fn now_millis() -> Int

@external(erlang, "redirect_proxy_system_ffi", "rfc3339")
pub fn rfc3339(seconds: Int) -> String

/// Seconds since the epoch of an RFC 3339 date-time with a time zone.
@external(erlang, "redirect_proxy_system_ffi", "parse_rfc3339")
pub fn parse_rfc3339(value: String) -> Result(Int, Nil)

pub fn now_rfc3339() -> String {
  rfc3339(now_seconds())
}

// --- process / os -----------------------------------------------------------

@external(erlang, "redirect_proxy_system_ffi", "on_sighup")
pub fn on_sighup(callback: fn() -> Nil) -> Nil

/// On SIGTERM, drain for `grace_ms` (see `draining`) before stopping.
/// `before_stop` runs right before the VM stops (its failures are logged).
@external(erlang, "redirect_proxy_sigterm", "install")
pub fn on_sigterm_drain(grace_ms: Int, before_stop: fn() -> Nil) -> Nil

/// True once SIGTERM was received: the node stops after the grace period.
@external(erlang, "redirect_proxy_sigterm", "draining")
pub fn draining() -> Bool

@external(erlang, "redirect_proxy_system_ffi", "plain_arguments")
pub fn plain_arguments() -> List(String)

@external(erlang, "redirect_proxy_system_ffi", "halt")
pub fn halt(code: Int) -> Nil

@external(erlang, "redirect_proxy_system_ffi", "read_password")
pub fn read_password(prompt: String) -> Result(String, Nil)

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

// --- jwt --------------------------------------------------------------------

@external(erlang, "redirect_proxy_crypto_ffi", "jwt_verify")
pub fn jwt_verify(jwks_json: String, token: String) -> Result(String, String)

@external(erlang, "redirect_proxy_crypto_ffi", "jwt_peek_header")
pub fn jwt_peek_header(token: String) -> Result(String, Nil)

// --- locks ------------------------------------------------------------------

/// Runs `f` while holding a node-wide lock named `name`.
@external(erlang, "redirect_proxy_file_ffi", "with_lock")
pub fn with_lock(name: String, f: fn() -> a) -> a

/// Runs `f` holding `<path>.lock`, an exclusive lock shared by every OS
/// process writing `path` (the server, the CLI). The lock is refreshed while
/// `f` runs; one not refreshed for 10 seconds is left over by a crashed
/// process and is taken over. Errors when the lock is not acquired in time.
@external(erlang, "redirect_proxy_file_ffi", "with_file_lock")
pub fn with_file_lock(
  path: String,
  timeout_ms: Int,
  f: fn() -> a,
) -> Result(a, String)

/// Why `with_file_lock_detailed` did not acquire the lock.
pub type LockFailure {
  /// Another process holds it: trying again soon may succeed.
  Held(message: String)
  /// It could not be created (a full disk).
  CannotCreate(message: String)
}

/// `with_file_lock`, saying why the lock was not acquired.
@external(erlang, "redirect_proxy_file_ffi", "with_file_lock_detailed")
pub fn with_file_lock_detailed(
  path: String,
  timeout_ms: Int,
  f: fn() -> a,
) -> Result(a, LockFailure)

/// Overrides a delay for tests: `stale_lock_seconds` (10), after which a
/// lock is taken over, and `store_call_timeout` (milliseconds), how long a
/// store call waits.
@external(erlang, "redirect_proxy_file_ffi", "set_tunable")
pub fn set_tunable(name: String, value: Int) -> Nil

/// Restores a delay's default.
@external(erlang, "redirect_proxy_file_ffi", "clear_tunable")
pub fn clear_tunable(name: String) -> Nil

/// A delay's override, or `default`.
@external(erlang, "redirect_proxy_file_ffi", "tunable")
pub fn tunable(name: String, default: Int) -> Int

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

/// One form for equivalent URL paths: escapes of unreserved characters and
/// of valid UTF-8 are decoded, the others are written in upper case.
@external(erlang, "redirect_proxy_text_ffi", "normalise_path")
pub fn normalise_path(path: String) -> String

/// Percent-encodes the non-ASCII bytes of a URL.
/// Whether every byte is ASCII.
@external(erlang, "redirect_proxy_text_ffi", "is_ascii")
pub fn is_ascii(text: String) -> Bool

/// False when `string.trim` would return `text` unchanged for sure: its
/// first and last bytes are visible ASCII characters.
@external(erlang, "redirect_proxy_text_ffi", "needs_trim")
pub fn needs_trim(text: String) -> Bool

/// `list.map(items, encode)`, reusing what the calling process encoded
/// last time for an equal item. Only the last list's encodings are kept.
/// A host without its port (`[::1]:8080` is `[::1]`, `a.test:80` is
/// `a.test`).
/// The owner of `dir` when this OS process runs as root and `dir` belongs
/// to another user (CLI commands would create root-owned files there).
@external(erlang, "redirect_proxy_file_ffi", "data_dir_owner_mismatch")
pub fn data_dir_owner_mismatch(dir: String) -> Result(String, Nil)

@external(erlang, "redirect_proxy_text_ffi", "strip_port")
pub fn strip_port(host: String) -> String

@external(erlang, "redirect_proxy_text_ffi", "encode_cached")
pub fn encode_cached(items: List(a), encode: fn(a) -> String) -> List(String)

/// Raises the error of a store call that timed out.
@external(erlang, "redirect_proxy_system_ffi", "store_timeout")
pub fn store_timeout() -> a

/// Runs `f`, or `unavailable` when a store call in it timed out
/// (`store_timeout`).
@external(erlang, "redirect_proxy_system_ffi", "rescue_store_timeout")
pub fn rescue_store_timeout(f: fn() -> a, unavailable: fn() -> a) -> a

/// Runs `f`, returning an exception as `Error` with its description.
@external(erlang, "redirect_proxy_system_ffi", "rescue")
pub fn rescue(f: fn() -> a) -> Result(a, String)

/// The first `bytes` bytes of a string (all of it when shorter). The result
/// may end inside a UTF-8 sequence: use it only as a lookup key.
@external(erlang, "redirect_proxy_text_ffi", "binary_take")
pub fn byte_take(string: String, bytes: Int) -> String

/// Whether `string` holds the bytes of `pattern`. Unlike `string.contains`,
/// which compares graphemes, it finds `"` in `"` followed by a combining mark.
@external(erlang, "redirect_proxy_text_ffi", "binary_contains")
pub fn byte_contains(string: String, pattern: String) -> Bool

/// Replaces every occurrence of the bytes of `pattern` (see `byte_contains`).
@external(erlang, "redirect_proxy_text_ffi", "binary_replace_all")
pub fn byte_replace(string: String, pattern: String, with: String) -> String

/// A string without its first `bytes` bytes, which must end on a character
/// boundary.
@external(erlang, "redirect_proxy_text_ffi", "binary_drop")
pub fn byte_drop(string: String, bytes: Int) -> String

/// Removes CR, LF and NUL bytes.
/// Removes tabs and line breaks, which browsers drop from URLs.
@external(erlang, "redirect_proxy_text_ffi", "strip_url_whitespace")
pub fn strip_url_whitespace(url: String) -> String

/// `strip_control`, then non-ASCII bytes percent-encoded, in one scan for
/// the usual value that needs neither.
@external(erlang, "redirect_proxy_text_ffi", "header_value")
pub fn header_value(value: String) -> String

@external(erlang, "redirect_proxy_text_ffi", "strip_control")
pub fn strip_control(value: String) -> String

/// Whether a string has no control characters (below 32, and DEL).
@external(erlang, "redirect_proxy_text_ffi", "no_control_chars")
pub fn no_control_chars(value: String) -> Bool

/// Forces a garbage collection of the calling process.
@external(erlang, "redirect_proxy_system_ffi", "garbage_collect")
pub fn garbage_collect() -> Nil

// --- access log -----------------------------------------------------------------

/// Starts one access log writer per output, each taking the lines of the
/// listed listeners. Replaces any previous writers.
@external(erlang, "redirect_proxy_access_ffi", "start")
pub fn access_log_start(
  groups: List(#(String, List(Listener))),
  max_bytes: Int,
  max_files: Int,
  compress: Bool,
) -> Result(Nil, String)

/// Writes the lines still waiting, then stops the writers.
@external(erlang, "redirect_proxy_access_ffi", "stop")
pub fn access_log_stop() -> Nil

/// Returns once the writers have handled every line sent before (tests).
@external(erlang, "redirect_proxy_access_ffi", "sync")
pub fn access_log_sync() -> Nil

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

/// Identifies a version of a file on disk: its inode, modification time and
/// size. Two equal stamps mean the file was very probably not changed.
pub type FileStamp

@external(erlang, "redirect_proxy_file_ffi", "file_stamp")
pub fn file_stamp(path: String) -> FileStamp

/// Whether the file was modified within the last two seconds: a stamp that
/// did not change may then still hide a change of the same size.
@external(erlang, "redirect_proxy_file_ffi", "stamp_is_recent")
pub fn stamp_is_recent(stamp: FileStamp) -> Bool

/// Whether stamp `b` may be of the write of stamp `a`: the same file and
/// size, its time moved forward by a second at most (a write in place may
/// set it again after the content). Times have a one second resolution:
/// the same content written again within that second is not told apart.
@external(erlang, "redirect_proxy_file_ffi", "same_write")
pub fn same_write(a: FileStamp, b: FileStamp) -> Bool

/// Whether a (lower-case) host holds only letters, digits, `-`, `_` and `.`.
@external(erlang, "redirect_proxy_text_ffi", "is_host_name")
pub fn is_host_name(host: String) -> Bool

/// `string.lowercase`, with a fast path for ASCII (request hosts).
@external(erlang, "redirect_proxy_text_ffi", "lowercase_host")
pub fn lowercase_host(host: String) -> String

/// Lowers the ASCII letters only (other bytes are kept as they are).
@external(erlang, "redirect_proxy_text_ffi", "lowercase_ascii")
pub fn lowercase_ascii(text: String) -> String

/// The host part of what follows `scheme://`: before the first `/`, `\`,
/// `?` or `#`, after the last `@`.
@external(erlang, "redirect_proxy_text_ffi", "url_host")
pub fn url_host(rest: String) -> String

/// The lines of some bytes, split on `\n`, not decoded.
@external(erlang, "redirect_proxy_text_ffi", "split_lines")
pub fn split_lines(bits: BitArray) -> List(BitArray)
