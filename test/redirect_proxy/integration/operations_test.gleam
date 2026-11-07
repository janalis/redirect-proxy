//// End-to-end tests of operations: probes, draining, signals, metrics,
//// replicas.

import gleam/bit_array
import gleam/erlang/charlist
import gleam/erlang/process
import gleam/http/response
import gleam/int
import gleam/list
import gleam/string
import integration_support.{
  boot, get, location, login, metric, notify_signal, os_cmd, os_pid, post_form,
  raw_exchange, reload_rules, signal_handlers, wait_until,
}
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi
import simplifile
import support

pub fn draining_before_a_stop_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  // a kept-alive connection serves several requests...
  let two_requests = [
    <<"GET /old HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
    <<"GET /old HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
  ]
  let assert Ok(received) =
    bit_array.to_string(raw_exchange(port, two_requests))
  assert list.length(string.split(received, "HTTP/1.1 301")) == 3
  assert !string.contains(string.lowercase(received), "connection: close")
  assert get(env.admin <> "/readyz", []).status == 200
  // ...until SIGTERM: until the grace period ends, it is closed after each
  // response
  let #(ready, received) =
    support.with_draining(fn() {
      #(get(env.admin <> "/readyz", []), raw_exchange(port, two_requests))
    })
  assert ready.status == 503
  let assert Ok(received) = bit_array.to_string(received)
  assert list.length(string.split(received, "HTTP/1.1 301")) == 2
  assert string.contains(string.lowercase(received), "connection: close")
}

/// `server.health_path` is answered before the rules, even by a catch-all
/// rule, and turns 503 while draining.
pub fn redirect_listener_health_path_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, health_path: "/_health"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/\", \"match\": \"prefix\", \"target\": \"https://elsewhere.test/\"}]",
    )
  let assert Ok(_) = reload_rules(env)
  assert get(env.redirect <> "/anything", []).status == 301
  let requests = metric(env, "redirect_proxy_requests_total")
  let resp = get(env.redirect <> "/_health", [])
  assert resp.status == 200
  assert resp.body == "ok"
  assert response.get_header(resp, "cache-control") == Ok("no-store")
  // probes are not counted as traffic
  assert metric(env, "redirect_proxy_requests_total") == requests
  let draining =
    support.with_draining(fn() { get(env.redirect <> "/_health", []) })
  assert draining.status == 503
}

/// `server.metrics_path`: a replica without an admin or API listener
/// serves its metrics on the redirect listener, before the rules, with the
/// metrics token.
pub fn redirect_listener_metrics_path_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(
          ..d.admin,
          metrics_token: "a-long-metrics-token",
        ),
        server: config.ServerConfig(..d.server, metrics_path: "/_metrics"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/\", \"match\": \"prefix\", \"target\": \"https://elsewhere.test/\"}]",
    )
  let assert Ok(_) = reload_rules(env)
  let denied = get(env.redirect <> "/_metrics", [])
  assert denied.status == 401
  assert !string.contains(denied.body, "redirect_proxy_")
  let resp =
    get(env.redirect <> "/_metrics", [
      #("authorization", "Bearer a-long-metrics-token"),
    ])
  assert resp.status == 200
  assert string.contains(resp.body, "redirect_proxy_requests_total")
  assert response.get_header(resp, "cache-control") == Ok("no-store")
  // other paths still go to the rules
  assert get(env.redirect <> "/_metrics/x", []).status == 301
}

/// Without a health path, the same path goes to the rules.
pub fn health_path_is_off_by_default_test() {
  let env = boot(config.default())
  assert get(env.redirect <> "/_health", []).status == 404
}

pub fn sighup_reloads_rules_test() {
  let env = boot(config.default())
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/hup\", \"target\": \"/after-sighup\"}]",
    )
  let _ =
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  wait_until(fn() { get(env.redirect <> "/hup", []).status == 301 }, 50)
  assert location(get(env.redirect <> "/hup", [])) == "/after-sighup"
}

pub fn sighup_with_an_invalid_file_keeps_the_rules_test() {
  let env = boot(config.default())
  let failures = metric(env, "redirect_proxy_reload_failures_total")
  let assert Ok(Nil) =
    simplifile.write(env.dir <> "/redirects.json", "{ not json")
  let _ =
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  wait_until(
    fn() { metric(env, "redirect_proxy_reload_failures_total") > failures },
    50,
  )
  assert location(get(env.redirect <> "/old", [])) == "https://example.com/new"
}

/// A reload callback that crashes is logged; later signals still reach it.
pub fn sighup_survives_a_crashing_callback_test() {
  let calls = process.new_subject()
  ffi.on_sighup(fn() {
    process.send(calls, Nil)
    panic as "reload exploded"
  })
  let hup = fn() {
    os_cmd(charlist.from_string("kill -HUP " <> charlist.to_string(os_pid())))
  }
  let _ = hup()
  let first = process.receive(calls, 2000)
  let _ = hup()
  let second = process.receive(calls, 2000)
  // the next boot installs the application's own callback again
  ffi.on_sighup(fn() { Nil })
  assert first == Ok(Nil)
  assert second == Ok(Nil)
}

/// Signals other than SIGTERM keep OTP's default handling, and the drain
/// handler stays installed.
pub fn other_signals_are_left_to_otp_test() {
  let _ = boot(config.default())
  notify_signal("sigusr2")
  notify_signal("sigchld")
  assert !ffi.draining()
  assert list.contains(signal_handlers(), "redirect_proxy_sigterm")
  assert !list.contains(signal_handlers(), "erl_signal_handler")
}

pub fn request_counters_test() {
  let env = boot(config.default())
  let before = fn(name) { metric(env, name) }
  let requests = before("redirect_proxy_requests_total")
  let redirects = before("redirect_proxy_redirects_total")
  let not_found = before("redirect_proxy_not_found_total")
  assert get(env.redirect <> "/old", []).status == 301
  assert get(env.redirect <> "/blog/7", []).status == 308
  assert get(env.redirect <> "/nothing", []).status == 404
  // other tests may run requests concurrently: at least ours are counted
  assert metric(env, "redirect_proxy_requests_total") >= requests + 3
  assert metric(env, "redirect_proxy_redirects_total") >= redirects + 2
  assert metric(env, "redirect_proxy_not_found_total") >= not_found + 1
}

pub fn latency_and_response_metrics_test() {
  let env = boot(config.default())
  let count = fn() {
    metric(
      env,
      "redirect_proxy_request_duration_seconds_count{listener=\"redirect\"}",
    )
  }
  let redirects = metric(env, "redirect_proxy_responses_total{class=\"3xx\"}")
  let before = count()
  assert get(env.redirect <> "/old", []).status == 301
  assert get(env.redirect <> "/nothing", []).status == 404
  assert count() >= before + 2
  assert metric(env, "redirect_proxy_responses_total{class=\"3xx\"}")
    >= redirects + 1
  let body = get(env.admin <> "/metrics", []).body
  // cumulative buckets end with +Inf, equal to the count
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"+Inf\"}",
  )
  // buckets of microseconds, for redirects, written as decimals
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"0.000005\"}",
  )
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"0.0025\"}",
  )
  assert string.contains(
    body,
    "redirect_proxy_request_duration_seconds_bucket{listener=\"redirect\",le=\"1\"}",
  )
  assert !string.contains(body, "0e-")
  assert string.contains(body, "redirect_proxy_rules_by_kind{kind=\"exact\"} 1")
  assert string.contains(
    body,
    "redirect_proxy_rules_by_kind{kind=\"prefix\"} 1",
  )
  assert string.contains(body, "redirect_proxy_rules_by_kind{kind=\"regex\"} 1")
  assert metric(env, "redirect_proxy_last_reload_timestamp_seconds") > 0
}

/// Failures that need an operator are counted: an unwritable data directory
/// and an identity provider that cannot be reached.
pub fn failure_metrics_test() {
  let d = config.default()
  // nothing listens on the free port: SSO discovery fails
  let issuer = "http://127.0.0.1:" <> int.to_string(support.free_port())
  let env =
    boot(
      config.Config(
        ..d,
        oidc: config.OidcConfig(
          ..d.oidc,
          enabled: True,
          issuer:,
          client_id: "redirect-proxy",
          client_secret: "secret",
        ),
      ),
    )
  let idp = metric(env, "redirect_proxy_idp_fetch_failures_total")
  assert get(env.admin <> "/auth/oidc/start", []).status == 303
  assert metric(env, "redirect_proxy_idp_fetch_failures_total") == idp + 1

  let #(cookie, csrf) = login(env)
  let writes = metric(env, "redirect_proxy_storage_write_failures_total")
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o500)
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/unsaved"),
      #("target", "/x"),
      #("priority", "100"),
      #("enabled", "on"),
    ])
  let assert Ok(Nil) = simplifile.set_permissions_octal(env.dir, 0o700)
  assert resp.status == 422
  assert metric(env, "redirect_proxy_storage_write_failures_total") > writes
}

/// A replica serving a read-only volume (a Kubernetes ConfigMap): with the
/// admin disabled it starts, serves the rules and picks up a replaced file,
/// without writing to the data directory.
pub fn replica_on_a_read_only_data_dir_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"id\":\"r1\",\"source\":\"/ro\",\"target\":\"/one\"}]}",
    )
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o500)
  let d = config.default()
  let cfg =
    config.Config(
      ..d,
      server: config.ServerConfig(..d.server, listen: "127.0.0.1", port: 0),
      admin: config.AdminConfig(..d.admin, enabled: False),
      api: config.ApiConfig(..d.api, enabled: False),
      storage: config.StorageConfig(
        ..config.default().storage,
        data_dir: dir,
        backups: 3,
        watch_interval: 0,
      ),
      access_log: config.AccessLogConfig(..d.access_log, enabled: False),
    )
  let started = app.start(cfg)
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o700)
  let assert Ok(running) = started
  let resp =
    get(
      "http://127.0.0.1:" <> int.to_string(running.redirect_port) <> "/ro",
      [],
    )
  assert resp.status == 301
  assert location(resp) == "/one"
  // nothing was written: no cookie secret, no lock left behind
  let assert Ok(files) = simplifile.read_directory(dir)
  assert files == ["redirects.json"]
}

/// With `admin.metrics_token`, /metrics needs the bearer token; health
/// probes stay public.
pub fn metrics_token_test() {
  let d = config.default()
  let token = "a-metrics-token-of-some-length"
  let env =
    boot(
      config.Config(
        ..d,
        admin: config.AdminConfig(..d.admin, metrics_token: token),
      ),
    )
  let scrape = fn(headers) { get(env.admin <> "/metrics", headers) }
  let resp = scrape([])
  assert resp.status == 401
  assert response.get_header(resp, "www-authenticate")
    == Ok("Bearer realm=\"metrics\"")
  assert scrape([#("authorization", "Bearer wrong")]).status == 401
  assert scrape([#("authorization", "Basic " <> token)]).status == 401
  let resp = scrape([#("authorization", "Bearer " <> token)])
  assert resp.status == 200
  assert string.contains(resp.body, "redirect_proxy_build_info")
  assert scrape([#("authorization", "bearer " <> token)]).status == 200
  assert get(env.admin <> "/healthz", []).status == 200
}
