# Monitoring

Health endpoints, Prometheus metrics and the alerts worth having. Access
logs have [their own page](access-logs).

## Health endpoints

The admin listener answers `/healthz` (the process is up) and `/readyz`
(ready for traffic: 503 while draining before a stop) without
authentication. An API on its own port serves them too.

## Metrics

`GET :8081/metrics` returns these series, in the
Prometheus text format:

| Metric | Type | What it counts |
| --- | --- | --- |
| `redirect_proxy_requests_total` | counter | Requests received on the redirect listener |
| `redirect_proxy_redirects_total` | counter | Requests answered with a matching rule |
| `redirect_proxy_not_found_total` | counter | Requests without a matching rule |
| `redirect_proxy_fallback_redirects_total` | counter | Unmatched requests redirected to `server.fallback_url` |
| `redirect_proxy_responses_total{class}` | counter | Redirect listener responses by status class (`2xx`...), forwarded ones included |
| `redirect_proxy_request_duration_seconds{listener}` | histogram | Time to serve a request (5 µs to 1 s buckets), for the redirect, admin and API listeners; forwarded requests are not in it |
| `redirect_proxy_upstream_requests_total` | counter | Requests forwarded to `server.upstream` |
| `redirect_proxy_upstream_errors_total{reason}` | counter | Forwarded requests that failed upstream: `unreachable` (502), `timeout` (504), `invalid_response` (502, or a truncated response) |
| `redirect_proxy_upstream_duration_seconds` | histogram | Time to forward a request and relay the whole response |
| `redirect_proxy_regex_limit_exceeded_total` | counter | Regex runs stopped by the backtracking budget (counted as no match) |
| `redirect_proxy_admin_requests_total` | counter | Requests received on the admin listener |
| `redirect_proxy_login_failures_total` | counter | Failed admin logins and wrong current passwords |
| `redirect_proxy_api_requests_total` | counter | Requests to the REST API and the token endpoint |
| `redirect_proxy_api_tokens_issued_total` | counter | Access tokens issued by the built-in token endpoint |
| `redirect_proxy_api_auth_failures_total` | counter | Rejected API tokens and client authentications |
| `redirect_proxy_idp_fetch_failures_total` | counter | Failed fetches of an identity provider's metadata or signing keys (SSO and external API tokens) |
| `redirect_proxy_rules` | gauge | Enabled rules currently loaded |
| `redirect_proxy_rules_by_kind{kind}` | gauge | Enabled rules by match kind |
| `redirect_proxy_reloads_total` | counter | Successful loads of the redirections file |
| `redirect_proxy_reload_failures_total` | counter | Rejected loads of the redirections file |
| `redirect_proxy_last_reload_timestamp_seconds` | gauge | When the redirections file was last loaded successfully |
| `redirect_proxy_reload_duration_seconds` | gauge | Duration of that load |
| `redirect_proxy_storage_write_failures_total` | counter | Changes not saved because the redirections file could not be written (disk full, permissions) |
| `redirect_proxy_memory_bytes` | gauge | Memory allocated by the Erlang VM |
| `redirect_proxy_processes` | gauge | Erlang processes |
| `redirect_proxy_build_info{version}` | gauge | Always 1, labelled with the running version |
| `process_start_time_seconds` | gauge | Start time of the process, in seconds since the epoch |

Alerts worth having: `redirect_proxy_reload_failures_total` or
`redirect_proxy_storage_write_failures_total` increasing, and a rise of
`redirect_proxy_regex_limit_exceeded_total` or
`redirect_proxy_login_failures_total`.

Per-rule hit counts are shown in the admin, not exported (one series per
rule would be too many).
Without `admin.metrics_token` the endpoint is not authenticated: like the
rest of the admin listener, keep it off the public network. The container image binds the admin to
`0.0.0.0` so that it can be published: publish it on `127.0.0.1` only, as
in the quick start.

## Health check on the traffic port

For load balancers that can only
probe the port they send traffic to, set `server.health_path` (for
example `/_health`, `RP_SERVER_HEALTH_PATH`). The redirect listener then
answers that path itself, before any rule: 200 `ok`, or 503 `draining`
during the shutdown grace. Probes are not counted in
`redirect_proxy_requests_total`. Off by default, so that every path stays
available to rules.

## Metrics on the traffic port

Replicas usually run without an admin or
API listener, so they have no `/metrics`. Set `server.metrics_path` (for
example `/_metrics`, `RP_SERVER_METRICS_PATH`) and the redirect listener
serves the metrics on that path, before any rule. The listener is public,
so this needs `admin.metrics_token`, sent as
`Authorization: Bearer <token>`; without the token the request gets a 401. Off by default.

## Container health check

The image probes the admin listener's
`/healthz` on `RP_ADMIN_PORT`. With `RP_ADMIN_ENABLED=false` it probes
`RP_SERVER_HEALTH_PATH` on `RP_SERVER_PORT` when that is set (so a
draining container reports unhealthy), and otherwise checks that the
redirect listener accepts connections. Settings made only in a config
file need a `HEALTHCHECK` override.
