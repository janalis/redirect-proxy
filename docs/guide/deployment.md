# Deployment

Running behind a TLS proxy or a load balancer, and running several
instances.

## HTTP to HTTPS

With `server.https_redirect` (`RP_SERVER_HTTPS_REDIRECT`),
plain HTTP requests are redirected to the same host, path and query over
HTTPS before any rule: 301 for `GET` and `HEAD`, 308 for other methods so
that they are repeated as they were. Requests that a TLS proxy forwards
with `X-Forwarded-Proto: https` (or `wss`, as Traefik marks WebSocket
upgrades) go to the rules as usual. With
`access_log.trusted_proxies` set, only the header of a trusted proxy
counts; without, any peer's does, and a client sending that header itself
only skips the upgrade. Rules cannot do this
themselves: the server cannot tell the schemes apart, so a rule to the
same host over HTTPS is refused as a redirect loop.

## In front of a website

With `server.upstream` (`RP_SERVER_UPSTREAM`, for example
`http://127.0.0.1:3000`), redirect-proxy sits in front of a website: TLS
terminator or load balancer, then redirect-proxy, then the site. It answers
the requests its rules match (and `server.health_path`,
`server.metrics_path`, `server.https_redirect`, 414s) itself, and forwards
every other request to the upstream, whatever its method, instead of
answering 404 (`server.fallback_url` cannot be set as well).

- The request goes as it came (method, path and query, `Host`, headers,
  body streamed), over HTTP/1.1, without the hop-by-hop headers
  (`Connection` and the headers it names, `Keep-Alive`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `Proxy-Connection`). `Expect:
  100-continue` is answered by redirect-proxy. `Content-Length` is sent
  once, normalised; chunked bodies are re-chunked. A request with both
  `Content-Length` and `Transfer-Encoding`, an invalid length, a transfer
  coding other than `chunked`, a `Transfer-Encoding` in an HTTP/1.0
  request, or malformed chunks gets 400 and its connection is closed.
  HTTP/1.0 requests do not upgrade.
- `X-Forwarded-For` gets the client address. From a peer in
  `access_log.trusted_proxies`, it is appended to the incoming list, and
  the incoming `X-Forwarded-Proto` and `X-Forwarded-Host` are kept, as
  are `Forwarded`, `X-Real-IP`, `X-Forwarded-Port`, `X-Forwarded-Prefix`,
  `X-Forwarded-Server` and `X-Forwarded-Ssl`. From any other peer the first
  three are replaced (`http` and the `Host`) and the others dropped.
- The response is relayed as it comes, streamed, without hop-by-hop
  headers (a `Connection` header cannot remove its framing). Transfer
  codings other than `chunked` are kept; an HTTP/1.0 client cannot get
  them (502). A response head with control characters gets 502. Each
  client connection opens one upstream connection when it first needs one
  and keeps it while both sides keep alive.
- The request body is streamed to the upstream before its response is
  read: an upstream that answers early (a 413, say) is relayed once the
  body is sent, or when it stops reading. Each read of the client's body
  may wait `server.upstream_timeout` (an idle timeout, like nginx's
  `client_body_timeout`, not a limit on the whole upload); then 408.
- WebSockets and other upgrades (`Connection: upgrade`) are tunnelled once
  the upstream answers 101, until either side closes or no byte flows for
  `server.upstream_timeout`: have the application ping more often than
  that. A tunnel counts as one upstream request; its lifetime is the
  duration of its access log line, but is not in
  `redirect_proxy_upstream_duration_seconds`.
- An upstream that cannot be reached gets the client a 502, one that does
  not send its response head within `server.upstream_timeout` (default 60
  seconds) a 504, one that closes the connection before a complete head a
  502. These are logged as warnings, at most one a second, and counted in
  `redirect_proxy_upstream_errors_total`.
- An `https://` upstream's certificate is checked against the system CAs;
  `server.upstream_tls_verify = false` accepts a self-signed one.
- Forwarded requests are logged with the upstream's status, the body bytes
  relayed and the full duration, without a rule id; 499 when the client
  went away before the whole response was sent. Their time is in
  `redirect_proxy_upstream_duration_seconds`, not in the redirect
  listener's `redirect_proxy_request_duration_seconds`.

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
