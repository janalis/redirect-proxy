//// Typed bindings to the Erlang helpers in `redirect_proxy_ffi.erl`.

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

@external(erlang, "redirect_proxy_ffi", "ets_incr")
pub fn ets_incr(table: String, key: k, amount: Int) -> Int

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

/// Removes CR, LF and NUL bytes.
@external(erlang, "redirect_proxy_ffi", "strip_control")
pub fn strip_control(value: String) -> String

/// Forces a garbage collection of the calling process.
@external(erlang, "redirect_proxy_ffi", "garbage_collect")
pub fn garbage_collect() -> Nil
