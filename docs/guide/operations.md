# Operations

Day-to-day running: reloading the rules, concurrent changes, the files kept
in the data directory, and stopping.

## Reload

Edit `redirects.json`, then `kill -HUP <pid>` (or
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

## Concurrent writes

The admin UI, the API and the CLI can change the
rules, users and API clients at the same time:

- Every write holds a lock file next to the file it changes
  (`redirects.json.lock`, `users.json.lock`, `api_clients.json.lock`),
  shared by every process: the server and CLI commands such as
  `rules import`, `user add` or `client add`. Its holder refreshes it every
  2 seconds; a lock not refreshed for 10 seconds is treated as left over
  by a crashed process. A process that is alive but stuck keeps its lock
  fresh, so the lock is never broken: stop that process to release it.

- While the rules lock is held, or other changes are queued, a change that
  cannot be made in time is not made. The API answers
  `503 store_busy`, the admin pages a 503 page (both with
  `Retry-After: 1`), and `rules import` exits with status 1 and
  "the rules are busy". Retry once the other change is done.

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

## Hit counts

`<data_dir>/hits.json` keeps each rule's hit count and
last hit time across restarts. It is written every minute, when a stop
begins (`SIGTERM`) and right before the VM stops, so the requests served
while draining are counted and a crash loses at most a minute of counts.
A change that deletes rules saves them at once. To reset the counts, stop
the server, then delete the file (deleted while it runs, it is written
again from the counts in memory). A file that cannot be read is moved
aside to `hits.json.corrupt-<ms>`, not overwritten.

## Backups

Each change keeps the previous file as
`<data_dir>/backups/redirects-<ms>.json`, up to `storage.backups` copies.

## Audit

`<data_dir>/audit.jsonl` records who changed what, with the rule
before and after, and sign-ins: logins, failed logins (with the client
address) and logouts, for local, SSO and proxy-header sessions, and wrong
current passwords given to change a password
(`auth.password_check_failed`). SSO entries
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

## Shutdown

On `SIGTERM` the node drains for `server.shutdown_grace`
seconds (default 5, `RP_SERVER_SHUTDOWN_GRACE`): `/readyz` answers 503 and
the redirect listener closes connections after each response, and idle
kept-alive connections at once, so load balancers move traffic away. Then the VM stops. A second `SIGTERM` stops
it at once. Keep the grace below the stop timeout of your supervisor
(systemd `TimeoutStopSec=15`, Docker 10 s by default).

## Long paths

Requests whose path is longer than `server.max_path_bytes`
(default 8192, `RP_SERVER_MAX_PATH_BYTES`) get a 414 without rule lookup.

## Connection limits

A request head must arrive whole within the idle timeout (10 seconds),
however slowly it trickles in; then 408 and the connection is closed. The
redirect listener closes new connections while the VM uses more than 90%
of its port limit (`+Q`, `ERL_MAX_PORTS`), keeping room for files and the
other listeners; each forwarded client connection, and each tunnel, uses a
second port to the upstream. The open files limit of the process (`ulimit -n`,
`LimitNOFILE`) may be lower: raise both together.

One client address may hold at most `server.max_connections_per_ip`
(default 256, `RP_SERVER_MAX_CONNECTIONS_PER_IP`; 0: no limit) open
connections to the redirect listener; more are closed at once, with a
warning in the log (at most one a second). IPv6 clients count by /64, as
one host usually holds a whole /64. A browser opens about six. Loopback
peers, `access_log.trusted_proxies` and `auth.header.trusted_proxies` are
not limited, since a proxy carries many clients' connections. Clients
behind one NAT address (a company, a carrier-grade NAT) share its quota:
raise the limit if many of them use the service at once.

::: warning Behind a load balancer or ingress
List the address it connects from (or its network: the pod CIDR, the
Compose subnet) in `access_log.trusted_proxies`, or all its clients count
as one address and get refused once it opens 256 connections. A
Kubernetes Service with `externalTrafficPolicy: Cluster` makes clients
arrive from node addresses: list those too, or use `Local`.
:::

## Tuning

Pass extra VM flags with `ERL_FLAGS`. For example, on a small
host `ERL_FLAGS="+S 2:2 +SDio 2"` limits schedulers and lowers memory use.
