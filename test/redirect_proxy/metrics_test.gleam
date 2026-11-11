//// The counters of the metrics.

import redirect_proxy/ffi
import redirect_proxy/metrics

/// Counters left by an older version of the code, with fewer slots (in a
/// VM where the application restarts after a hot upgrade), are replaced
/// at start: counting the newer metrics in them fails with badarg.
pub fn counters_too_small_are_replaced_at_start_test() {
  ffi.snapshot_put("metrics", ffi.counter_new(19))
  ffi.snapshot_put("metrics_latency", ffi.counter_new(60))
  metrics.init()
  let before = metrics.get(metrics.UpstreamRequests)
  metrics.incr(metrics.UpstreamRequests)
  metrics.observe_upstream(5)
  assert metrics.get(metrics.UpstreamRequests) == before + 1
}
