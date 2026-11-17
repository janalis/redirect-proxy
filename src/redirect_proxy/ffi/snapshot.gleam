//// Bindings to `redirect_proxy_snapshot_ffi`: values in `persistent_term`,
//// read without a lock from every request process.

@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_put")
pub fn snapshot_put(key: String, value: a) -> Nil

@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_get")
pub fn snapshot_get(key: String) -> Result(a, Nil)

/// The value of `key`, published from `init()` the first time: for values
/// only this function publishes (counters).
@external(erlang, "redirect_proxy_snapshot_ffi", "snapshot_or_init")
pub fn snapshot_or_init(key: String, init: fn() -> a) -> a
