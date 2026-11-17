//// The counters of the metrics.

import gleam/list
import redirect_proxy/ffi/ets as ets_ffi
import redirect_proxy/ffi/snapshot as snapshot_ffi
import redirect_proxy/metrics

/// Counters left by an older version of the code, with fewer slots (in a
/// VM where the application restarts after a hot upgrade), are replaced
/// at start: counting the newer metrics in them fails with badarg.
pub fn counters_too_small_are_replaced_at_start_test() {
  snapshot_ffi.snapshot_put("metrics", ets_ffi.counter_new(19))
  snapshot_ffi.snapshot_put("metrics_latency", ets_ffi.counter_new(60))
  metrics.init()
  let before = metrics.get(metrics.UpstreamRequests)
  metrics.incr(metrics.UpstreamRequests)
  metrics.observe_upstream(5)
  assert metrics.get(metrics.UpstreamRequests) == before + 1
}

/// `bucket` compares with literal bounds, while the exported `le` labels
/// come from `buckets_us`: each bound must end its own bucket, and the
/// next duration start the next one.
pub fn buckets_follow_their_bounds_test() {
  list.index_map(metrics.buckets_us, fn(bound, i) {
    assert metrics.bucket(bound) == i + 1
    assert metrics.bucket(bound + 1) == i + 2
  })
  assert metrics.bucket(0) == 1
}
