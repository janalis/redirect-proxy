//// Lock-free request counters exposed in the Prometheus text format.

import gleam/float
import gleam/int
import gleam/list
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/listener.{type Listener}
import redirect_proxy/matcher
import redirect_proxy/snapshot

const key = "metrics"

const latency_key = "metrics_latency"

/// Upper bounds of the request duration histogram buckets, in microseconds
/// (0.5 ms to 1 s); one more bucket counts the slower requests.
const buckets_us = [
  500, 1000, 2500, 5000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
  1_000_000,
]

/// Slots per listener in the latency counters: the buckets, +Inf, the sum
/// of durations (µs) and the count.
const latency_slots = 14

pub type Metric {
  Requests
  Redirects
  NotFound
  FallbackRedirects
  AdminRequests
  LoginFailures
  Reloads
  ReloadFailures
  ApiRequests
  TokensIssued
  ApiAuthFailures
  /// Gauges (set, not incremented).
  LastReloadTimestamp
  ReloadDurationMicros
  /// Responses of the redirect listener by status class.
  Responses2xx
  Responses3xx
  Responses4xx
  Responses5xx
  /// The redirections file could not be written (disk full, permissions).
  StorageWriteFailures
  /// Fetches of an identity provider's metadata or keys that failed.
  IdpFetchFailures
}

fn index(metric: Metric) -> Int {
  case metric {
    Requests -> 1
    Redirects -> 2
    NotFound -> 3
    FallbackRedirects -> 4
    AdminRequests -> 5
    LoginFailures -> 6
    Reloads -> 7
    ReloadFailures -> 8
    ApiRequests -> 9
    TokensIssued -> 10
    ApiAuthFailures -> 11
    LastReloadTimestamp -> 12
    ReloadDurationMicros -> 13
    Responses3xx -> 14
    Responses4xx -> 15
    Responses5xx -> 16
    Responses2xx -> 17
    StorageWriteFailures -> 18
    IdpFetchFailures -> 19
  }
}

/// Must be called once at boot.
pub fn init() -> Nil {
  let _ = counters()
  let _ = latency()
  ffi.regex_limit_init()
}

fn latency() -> ffi.Counters {
  case ffi.snapshot_get(latency_key) {
    Ok(c) -> c
    Error(Nil) -> {
      let c = ffi.counter_new(latency_slots * list.length(listener.all))
      ffi.snapshot_put(latency_key, c)
      c
    }
  }
}

fn listener_offset(l: Listener) -> Int {
  case l {
    listener.RedirectListener -> 0
    listener.AdminListener -> latency_slots
    listener.ApiListener -> 2 * latency_slots
  }
}

/// Records how long a request took (lock-free).
pub fn observe(l: Listener, duration_us: Int) -> Nil {
  let c = latency()
  let base = listener_offset(l)
  ffi.counter_add(c, base + bucket(buckets_us, duration_us, 1), 1)
  ffi.counter_add(c, base + latency_slots - 1, duration_us)
  ffi.counter_add(c, base + latency_slots, 1)
}

fn bucket(bounds: List(Int), duration_us: Int, slot: Int) -> Int {
  case bounds {
    [] -> slot
    [bound, ..rest] ->
      case duration_us <= bound {
        True -> slot
        False -> bucket(rest, duration_us, slot + 1)
      }
  }
}

/// Counts a response of the redirect listener by status class.
pub fn response(status: Int) -> Nil {
  case status / 100 {
    2 -> incr(Responses2xx)
    3 -> incr(Responses3xx)
    4 -> incr(Responses4xx)
    5 -> incr(Responses5xx)
    _ -> Nil
  }
}

/// Records a successful load of the redirections file.
pub fn reloaded(duration_us: Int) -> Nil {
  ffi.counter_put(counters(), index(LastReloadTimestamp), ffi.now_seconds())
  ffi.counter_put(counters(), index(ReloadDurationMicros), duration_us)
}

fn counters() -> ffi.Counters {
  case ffi.snapshot_get(key) {
    Ok(c) -> c
    Error(Nil) -> {
      let c = ffi.counter_new(19)
      ffi.snapshot_put(key, c)
      c
    }
  }
}

pub fn incr(metric: Metric) -> Nil {
  ffi.counter_add(counters(), index(metric), 1)
}

pub fn get(metric: Metric) -> Int {
  ffi.counter_get(counters(), index(metric))
}

pub fn hits(rule_id: String) -> Int {
  matcher.hit_count(snapshot.current(), rule_id)
}

fn labelled(
  name: String,
  help: String,
  kind: String,
  values: List(#(String, Int)),
) -> String {
  "# HELP "
  <> name
  <> " "
  <> help
  <> "\n# TYPE "
  <> name
  <> " "
  <> kind
  <> "\n"
  <> {
    values
    |> list.map(fn(v) { name <> "{" <> v.0 <> "} " <> int.to_string(v.1) })
    |> string.join("\n")
  }
}

fn seconds(micros: Int) -> String {
  float.to_string(int.to_float(micros) /. 1_000_000.0)
}

/// `redirect_proxy_request_duration_seconds`, per listener (cumulative
/// buckets, as Prometheus expects).
fn histogram() -> String {
  let name = "redirect_proxy_request_duration_seconds"
  let c = latency()
  let series =
    listener.all
    |> list.map(fn(l) {
      let base = listener_offset(l)
      let label = "listener=\"" <> listener.name(l) <> "\""
      let bounds = list.map(buckets_us, seconds) |> list.append(["+Inf"])
      let #(_, lines) =
        list.index_fold(bounds, #(0, []), fn(acc, bound, i) {
          let #(total, lines) = acc
          let total = total + ffi.counter_get(c, base + i + 1)
          let line =
            name
            <> "_bucket{"
            <> label
            <> ",le=\""
            <> bound
            <> "\"} "
            <> int.to_string(total)
          #(total, [line, ..lines])
        })
      list.flatten([
        list.reverse(lines),
        [
          name
            <> "_sum{"
            <> label
            <> "} "
            <> seconds(ffi.counter_get(c, base + latency_slots - 1)),
          name
            <> "_count{"
            <> label
            <> "} "
            <> int.to_string(ffi.counter_get(c, base + latency_slots)),
        ],
      ])
      |> string.join("\n")
    })
  "# HELP "
  <> name
  <> " Time to serve a request, per listener.\n# TYPE "
  <> name
  <> " histogram\n"
  <> string.join(series, "\n")
}

pub fn render_prometheus() -> String {
  let line = fn(name, help, kind, value) {
    "# HELP "
    <> name
    <> " "
    <> help
    <> "\n# TYPE "
    <> name
    <> " "
    <> kind
    <> "\n"
    <> name
    <> " "
    <> int.to_string(value)
    <> "\n"
  }
  [
    line(
      "redirect_proxy_requests_total",
      "Requests received on the redirect listener.",
      "counter",
      get(Requests),
    ),
    line(
      "redirect_proxy_redirects_total",
      "Requests answered with a matching redirection.",
      "counter",
      get(Redirects),
    ),
    line(
      "redirect_proxy_not_found_total",
      "Requests without a matching rule.",
      "counter",
      get(NotFound),
    ),
    line(
      "redirect_proxy_fallback_redirects_total",
      "Unmatched requests redirected to the fallback URL.",
      "counter",
      get(FallbackRedirects),
    ),
    line(
      "redirect_proxy_admin_requests_total",
      "Requests received on the admin listener.",
      "counter",
      get(AdminRequests),
    ),
    line(
      "redirect_proxy_login_failures_total",
      "Failed admin login attempts.",
      "counter",
      get(LoginFailures),
    ),
    line(
      "redirect_proxy_reloads_total",
      "Successful reloads of the redirections file.",
      "counter",
      get(Reloads),
    ),
    line(
      "redirect_proxy_reload_failures_total",
      "Rejected reloads of the redirections file.",
      "counter",
      get(ReloadFailures),
    ),
    line(
      "redirect_proxy_storage_write_failures_total",
      "Changes not saved because the redirections file could not be written.",
      "counter",
      get(StorageWriteFailures),
    ),
    line(
      "redirect_proxy_idp_fetch_failures_total",
      "Failed fetches of an identity provider's metadata or signing keys (SSO and external API tokens).",
      "counter",
      get(IdpFetchFailures),
    ),
    line(
      "redirect_proxy_api_requests_total",
      "Requests to the REST API and token endpoint.",
      "counter",
      get(ApiRequests),
    ),
    line(
      "redirect_proxy_api_tokens_issued_total",
      "Access tokens issued by the built-in token endpoint.",
      "counter",
      get(TokensIssued),
    ),
    line(
      "redirect_proxy_api_auth_failures_total",
      "Rejected API tokens and client authentications.",
      "counter",
      get(ApiAuthFailures),
    ),
    line(
      "redirect_proxy_regex_limit_exceeded_total",
      "Regex runs stopped by the backtracking budget (counted as no match).",
      "counter",
      ffi.regex_limit_count(),
    ),
    line(
      "redirect_proxy_rules",
      "Enabled redirection rules currently loaded.",
      "gauge",
      matcher.size(snapshot.current()),
    ),
    labelled(
      "redirect_proxy_rules_by_kind",
      "Enabled redirection rules currently loaded, by match kind.",
      "gauge",
      {
        let #(exact, prefix, regex) = matcher.kinds(snapshot.current())
        [
          #("kind=\"exact\"", exact),
          #("kind=\"prefix\"", prefix),
          #("kind=\"regex\"", regex),
        ]
      },
    ),
    labelled(
      "redirect_proxy_responses_total",
      "Responses of the redirect listener, by status class.",
      "counter",
      [
        #("class=\"2xx\"", get(Responses2xx)),
        #("class=\"3xx\"", get(Responses3xx)),
        #("class=\"4xx\"", get(Responses4xx)),
        #("class=\"5xx\"", get(Responses5xx)),
      ],
    ),
    line(
      "redirect_proxy_last_reload_timestamp_seconds",
      "When the redirections file was last loaded successfully.",
      "gauge",
      get(LastReloadTimestamp),
    ),
    "# HELP redirect_proxy_reload_duration_seconds Duration of the last successful load of the redirections file.\n# TYPE redirect_proxy_reload_duration_seconds gauge\nredirect_proxy_reload_duration_seconds "
      <> seconds(get(ReloadDurationMicros))
      <> "\n",
    histogram(),
    "# HELP redirect_proxy_build_info Version of the running server.\n# TYPE redirect_proxy_build_info gauge\nredirect_proxy_build_info{version=\""
      <> ffi.app_version()
      <> "\"} 1\n",
    line(
      "process_start_time_seconds",
      "Start time of the process since the epoch, in seconds.",
      "gauge",
      ffi.start_time_seconds(),
    ),
    line(
      "redirect_proxy_memory_bytes",
      "Memory allocated by the Erlang VM.",
      "gauge",
      ffi.memory_bytes(),
    ),
    line(
      "redirect_proxy_processes",
      "Number of Erlang processes.",
      "gauge",
      ffi.process_count(),
    ),
  ]
  |> list.map(string.trim_end)
  |> string.join("\n")
  |> string.append("\n")
}
