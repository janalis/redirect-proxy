[← redirect-proxy](../README.md)

# Operations

- **Reload.** Edit `redirects.json`, then `kill -HUP <pid>` (or
  `systemctl reload redirect-proxy`). An invalid or missing file is rejected,
  the error is logged and the current rules stay active. `SIGHUP` only
  reloads the rules: the configuration (`config.toml`, environment) is read at
  start, so changing it needs a restart, which also ends every admin
  session.
  - With `storage.watch_interval = <seconds>` (`RP_STORAGE_WATCH_INTERVAL`),
    the server checks the file that often and reloads it when it changed,
    without a signal: for a Kubernetes ConfigMap, a GitOps sync or an
    editor. The server's own writes are not taken for changes, and an
    invalid file is reported once (`rules.reload_failed`), not at every
    check.
  - If the rule store restarts after a crash while the file is invalid, it
    keeps the rules it had (and logs an error) instead of failing again until
    the whole node stops. Changes are refused until the file is fixed.
  - Files are replaced atomically and durably (the directory is synced
    after the rename) and keep their permissions. Files holding secrets
    (`users.json`, `api_clients.json`, `secret_key_base`) are created
    `0600`, and backups get the permissions of `redirects.json`.
- **Concurrent writes.** The admin UI, the API and the CLI can change the
  rules, users and API clients at the same time:
  - Every write holds a lock file next to the file it changes
    (`redirects.json.lock`, `users.json.lock`, `api_clients.json.lock`),
    shared by every process: the server and CLI commands such as
    `rules import`, `user add` or `client add`. A lock older than 10 seconds
    is treated as left over by a crashed process.
  - If `redirects.json` was changed by another process or by hand since the
    server last read it, the server reloads it before applying a change, so
    outside edits are never overwritten. If the changed file is invalid, the
    change is refused and the file is left as it is.
  - Edits from the admin UI and the API (`If-Match`) carry the rule version.
    If someone else changed the rule meanwhile, nothing is saved and the
    editor is told.
  - An import previewed in the admin applies exactly what was shown: if the
    rules changed meanwhile, nothing is written and the updated preview is
    shown again. The API does the same with the `ETag` of a dry run.
- **Hit counts.** `<data_dir>/hits.json` keeps each rule's hit count and
  last hit time across restarts. It is written every minute, when a stop
  begins (`SIGTERM`) and right before the VM stops, so the requests served
  while draining are counted and a crash loses at most a minute of counts.
  Deleting it resets the counts.
- **Backups.** Each change keeps the previous file as
  `<data_dir>/backups/redirects-<ms>.json`, up to `storage.backups` copies.
- **Audit.** `<data_dir>/audit.jsonl` records who changed what, with the rule
  before and after, and sign-ins: logins, failed logins (with the client
  address) and logouts, for local, SSO and proxy-header sessions. SSO entries
  carry the provider `issuer` and `subject`, failed ones the reason. Names
  from SSO and proxy headers are recorded as `sso:<name>` and
  `proxy:<name>`, so that they cannot pass for a local user, `system` or an
  API client (`client:<id>`). Throttling (`auth.throttled`) is recorded
  once per client and window, and API tokens issued and refused
  (`api.token_issued`, `api.token_rejected`) are recorded too. A refused
  token request names its client as the actor only when that client
  exists; the client id sent is always the target. Failures
  need no credentials, so at most 60 failed sign-ins and token requests a
  minute are recorded, from all clients: past that, one
  `audit.failures_not_recorded` entry per minute says that some were left
  out (they are still logged and counted in the metrics), so that they
  cannot push real entries out of the rotated files. A failed login with a
  name no account can have keeps that name in its details, not as the
  actor. Imports and
  reloads record the file fingerprint before and after and the rules added,
  removed and changed (counts, and up to 100 ids each). Rejected reloads and
  imports are recorded with the reason (`rules.reload_failed`,
  `rules.import.merge_failed`...). The file is rotated to `audit.jsonl.1`
  (then `.2`...) once it reaches `storage.audit_max_bytes` (10 MB), keeping
  `storage.audit_files` (5) rotated files. The admin's audit page and
  `GET /api/audit` search all of them.
- **Metrics.** `GET :8081/metrics` returns these series, in the
  Prometheus text format:

  | Metric | Type | What it counts |
  | --- | --- | --- |
  | `redirect_proxy_requests_total` | counter | Requests received on the redirect listener |
  | `redirect_proxy_redirects_total` | counter | Requests answered with a matching rule |
  | `redirect_proxy_not_found_total` | counter | Requests without a matching rule |
  | `redirect_proxy_fallback_redirects_total` | counter | Unmatched requests redirected to `server.fallback_url` |
  | `redirect_proxy_responses_total{class}` | counter | Redirect listener responses by status class (`2xx`...) |
  | `redirect_proxy_request_duration_seconds{listener}` | histogram | Time to serve a request (5 µs to 1 s buckets), for the redirect, admin and API listeners |
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
- **Shutdown.** On `SIGTERM` the node drains for `server.shutdown_grace`
  seconds (default 5, `RP_SERVER_SHUTDOWN_GRACE`): `/readyz` answers 503 and
  the redirect listener closes connections after each response, so load
  balancers move traffic away. Then the VM stops. A second `SIGTERM` stops
  it at once. Keep the grace below the stop timeout of your supervisor
  (systemd `TimeoutStopSec=15`, Docker 10 s by default).
- **Health check on the traffic port.** For load balancers that can only
  probe the port they send traffic to, set `server.health_path` (for
  example `/_health`, `RP_SERVER_HEALTH_PATH`). The redirect listener then
  answers that path itself, before any rule: 200 `ok`, or 503 `draining`
  during the shutdown grace. Probes are not counted in
  `redirect_proxy_requests_total`. Off by default, so that every path stays
  available to rules.
- **Metrics on the traffic port.** Replicas usually run without an admin or
  API listener, so they have no `/metrics`. Set `server.metrics_path` (for
  example `/_metrics`, `RP_SERVER_METRICS_PATH`) and the redirect listener
  serves the metrics on that path, before any rule. The listener is public,
  so this needs `admin.metrics_token`, sent as `Authorization: Bearer
  <token>`; without the token the request gets a 401. Off by default.
- **HTTP to HTTPS.** With `server.https_redirect` (`RP_SERVER_HTTPS_REDIRECT`),
  plain HTTP requests are redirected to the same host, path and query over
  HTTPS before any rule: 301 for `GET` and `HEAD`, 308 for other methods so
  that they are repeated as they were. Requests that a TLS proxy forwards
  with `X-Forwarded-Proto: https` go to the rules as usual. A client sending
  that header itself only skips the upgrade. Rules cannot do this
  themselves: the server cannot tell the schemes apart, so a rule to the
  same host over HTTPS is refused as a redirect loop.
- **Long paths.** Requests whose path is longer than `server.max_path_bytes`
  (default 8192, `RP_SERVER_MAX_PATH_BYTES`) get a 414 without rule lookup.
- **Container health check.** The image probes the admin listener's
  `/healthz` on `RP_ADMIN_PORT`. With `RP_ADMIN_ENABLED=false` it checks
  that the redirect listener on `RP_SERVER_PORT` accepts connections
  instead. Ports set only in a config file need a `HEALTHCHECK` override.
- **Tuning.** Pass extra VM flags with `ERL_FLAGS`. For example, on a small
  host `ERL_FLAGS="+S 2:2 +SDio 2"` limits schedulers and lowers memory use.

## Several instances

Each instance keeps some state in memory: admin sessions, login and token
throttling, and the access tokens of the built-in token endpoint. Hit
counts and the audit log are kept in its own data directory. Instances do
not share any of it, so run one writer and any number of replicas:

- **The writer** runs the admin and the API, and owns a writable data
  directory. Run one: two admins writing the same file would overwrite
  each other's changes, and a session only works on the instance that
  created it.
- **Replicas** only redirect: `RP_ADMIN_ENABLED=false` and
  `RP_API_ENABLED=false`. They read `redirects.json` from a volume that
  can be read-only (a Kubernetes ConfigMap, a directory synced from git,
  the writer's volume mounted read-only), with `storage.watch_interval`
  (`RP_STORAGE_WATCH_INTERVAL`) to pick up changes. They write nothing
  there. Their hit counts are then not kept across restarts, and they log
  that once. Set `server.metrics_path` to scrape their metrics (see
  "Metrics on the traffic port"). Hit counts are per instance: the
  writer's admin shows only its own, so judge unused rules from the
  replicas that take the traffic.
- The file must carry rule ids, since a replica cannot write the ids it
  would assign. Use the writer's file or `GET /api/redirects/export`, or
  give a hand-written file its ids with `redirect-proxy rules import` into
  a data directory.
- Replace the file atomically (write a temporary file, then rename it, as
  ConfigMap updates and `git` checkouts do), so that a replica never reads
  half a file.

## Command line

```text
redirect-proxy [serve] [--config FILE]
redirect-proxy check-config [--config FILE]   # also warns about unknown keys
redirect-proxy user add <username> [--role ROLE] | user passwd|delete <username> | user role <username> <ROLE> | user list
redirect-proxy client add <name> [--scope SCOPE]... | client list | client rotate|delete <client_id>
redirect-proxy rules validate [FILE] | rules export | rules import <FILE> [--replace]
redirect-proxy version | help
```

`user add` and `user passwd` read the password from `$RP_PASSWORD` or prompt
for it. `rules import` writes the file; a running server applies it on
`SIGHUP` or "Reload from disk".

## Performance

`make bench` (or the *Benchmark* workflow) generates 10 000 exact, 1 000
prefix and 500 regex rules. It then load-tests four scenarios with
[oha](https://github.com/hatoo/oha), falling back to ApacheBench:

- An exact hit.
- A prefix hit.
- The last regex.
- A miss. Prefix and regex rules starting with a literal are indexed, so a
  miss does not try every rule; regex rules that do not start with `^` and
  a literal are all run.

It reports throughput, latency percentiles and memory. The access log is
written to a file during the run, as it is enabled by default
(`RP_ACCESS_LOG_ENABLED=false` measures without it).

Measured locally on a laptop with the self-contained bundle, using
ApacheBench (single-threaded, so the client is the bottleneck): redirects
ran at about 14 000 requests/s.

Rule lookup itself, measured in-process with the same 11 500 rules, takes
about 0.4 µs for an exact hit, 1.2 µs for a prefix hit, 1.9 µs for the last
regex rule and 0.7 µs for a miss.

`make bench-matcher` measures the work of one redirect in-process (lookup,
hit count and `Location`), in BEAM reductions, for more request shapes:
many prefix lengths, unindexed regexes, many hosts and wildcard hosts,
query conditions and trailing slash retries. Reductions do not depend on
the load of the machine, so CI compares them with
`scripts/matcher-bench-baseline.json` and fails a change that makes a
scenario more than 10 % more expensive (`scripts/matcher-bench.py
--update` writes a new baseline).

Memory:

- An idle node with no rules uses about 70 MB RSS in the container image.
- Loading 11 500 rules adds about 5 MB to the shared snapshot.

Run the benchmark on your own hardware before sizing.
