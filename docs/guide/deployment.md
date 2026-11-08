# Deployment

Running behind a TLS proxy or a load balancer, and running several
instances.

[Web servers](web-servers) has tested configurations for nginx, HAProxy,
Apache httpd, Caddy and Traefik.

## HTTP to HTTPS

With `server.https_redirect` (`RP_SERVER_HTTPS_REDIRECT`),
plain HTTP requests are redirected to the same host, path and query over
HTTPS before any rule: 301 for `GET` and `HEAD`, 308 for other methods so
that they are repeated as they were. Requests that a TLS proxy forwards
with `X-Forwarded-Proto: https` go to the rules as usual. A client sending
that header itself only skips the upgrade. Rules cannot do this
themselves: the server cannot tell the schemes apart, so a rule to the
same host over HTTPS is refused as a redirect loop.

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
  [Metrics on the traffic port](monitoring#metrics-on-the-traffic-port)). Hit counts are per instance: the
  writer's admin shows only its own, so judge unused rules from the
  replicas that take the traffic.
- The file must carry rule ids, since a replica cannot write the ids it
  would assign. Use the writer's file or `GET /api/redirects/export`, or
  give a hand-written file its ids with `redirect-proxy rules import` into
  a data directory.
- Replace the file atomically (write a temporary file, then rename it, as
  ConfigMap updates and `git` checkouts do), so that a replica never reads
  half a file.
