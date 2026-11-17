//// Bindings to `redirect_proxy_ets_ffi`: named ETS tables (sessions, rate
//// limiting, failure windows, slots) and atomic counters (metrics).

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

@external(erlang, "redirect_proxy_ets_ffi", "ets_to_list")
pub fn ets_to_list(table: String) -> List(#(k, v))

/// Adds `key` unless it is already in the table: True when it was added.
/// Atomic: of concurrent callers, one only gets True.
@external(erlang, "redirect_proxy_ets_ffi", "ets_insert_new")
pub fn ets_insert_new(table: String, key: String, value: a) -> Bool

/// Deletes every entry whose value is a tuple whose first element (an expiry
/// timestamp) is lower than `now`. Returns the number of deleted entries.
@external(erlang, "redirect_proxy_ets_ffi", "ets_delete_older")
pub fn ets_delete_older(table: String, now: Int) -> Int

// --- failure windows --------------------------------------------------------

/// Counts a failure for `key` in its fixed window (a new window of `window`
/// seconds when there is none or it ended), atomically.
@external(erlang, "redirect_proxy_ets_ffi", "window_record")
pub fn window_record(table: String, key: String, now: Int, window: Int) -> Nil

@external(erlang, "redirect_proxy_ets_ffi", "window_take")
pub fn window_take(
  table: String,
  key: String,
  now: Int,
  window: Int,
  limit: Int,
) -> Result(Nil, Int)

@external(erlang, "redirect_proxy_ets_ffi", "window_take_receipt")
pub fn window_take_receipt(
  table: String,
  key: String,
  now: Int,
  window: Int,
  limit: Int,
) -> Result(Int, Int)

@external(erlang, "redirect_proxy_ets_ffi", "window_record_receipt")
pub fn window_record_receipt(
  table: String,
  key: String,
  now: Int,
  window: Int,
) -> Result(Int, Int)

@external(erlang, "redirect_proxy_ets_ffi", "window_forgive")
pub fn window_forgive(table: String, key: String, generation: Int) -> Nil

/// The end of `key`'s window and its failure count.
@external(erlang, "redirect_proxy_ets_ffi", "window_get")
pub fn window_get(table: String, key: String) -> Result(#(Int, Int), Nil)

/// Deletes the windows that ended; the number deleted.
@external(erlang, "redirect_proxy_ets_ffi", "window_purge")
pub fn window_purge(table: String, now: Int) -> Int

// --- slots ------------------------------------------------------------------

@external(erlang, "redirect_proxy_ets_ffi", "with_slot")
pub fn with_slot(
  table: String,
  key: String,
  max: Int,
  run: fn() -> a,
) -> Result(a, Nil)

@external(erlang, "redirect_proxy_ets_ffi", "password_check_slots")
pub fn password_check_slots() -> Int

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
