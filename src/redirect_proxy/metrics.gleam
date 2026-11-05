//// Lock-free request counters exposed in the Prometheus text format.

import gleam/int
import gleam/list
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/snapshot

const key = "metrics"

const hits_table = "redirect_proxy_hits"

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
  }
}

/// Must be called once at boot, from a long lived process (it owns the hit
/// counter ETS table).
pub fn init() -> Nil {
  let _ = counters()
  ffi.ets_new(hits_table)
}

fn counters() -> ffi.Counters {
  case ffi.snapshot_get(key) {
    Ok(c) -> c
    Error(Nil) -> {
      let c = ffi.counter_new(16)
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

/// Increments the hit counter of a rule.
pub fn hit(rule_id: String) -> Nil {
  let _ = ffi.ets_incr(hits_table, rule_id, 1)
  Nil
}

pub fn hits(rule_id: String) -> Int {
  case ffi.ets_get(hits_table, rule_id) {
    Ok(count) -> count
    Error(Nil) -> 0
  }
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
      "redirect_proxy_rules",
      "Enabled redirection rules currently loaded.",
      "gauge",
      matcher.size(snapshot.current()),
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
