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
with `X-Forwarded-Proto: https` (or `wss`, as Traefik marks WebSocket
upgrades) go to the rules as usual. With
`access_log.trusted_proxies` set, only the header of a trusted proxy
counts; without, any peer's does, and a client sending that header itself
only skips the upgrade. Rules cannot do this
themselves: the server cannot tell the schemes apart, so a rule to the
same host over HTTPS is refused as a redirect loop.

::: warning Redirect loops behind a containerised proxy
List the address the TLS proxy connects from in
`access_log.trusted_proxies`. A proxy in another container or pod
connects from that container's address: with only `127.0.0.1/32` listed,
its `X-Forwarded-Proto: https` is ignored, HTTPS requests are redirected
to HTTPS again, and browsers loop. List the network's CIDR (the Compose
network's subnet, the cluster's pod CIDR) instead.
:::

## In front of a website

With `server.upstream` (`RP_SERVER_UPSTREAM`, for example
`http://127.0.0.1:3000`), redirect-proxy sits in front of a website: TLS
terminator or load balancer, then redirect-proxy, then the site. It answers
the requests its rules match (and `server.health_path`,
`server.metrics_path`, `server.https_redirect`, 414s) itself, and forwards
every other request to the upstream, whatever its method, instead of
answering 404 (`server.fallback_url` cannot be set as well).
[Web servers](web-servers) has the web server's side.

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
  three are replaced (`http` and the `Host`; no `X-Forwarded-Host` for an
  HTTP/1.0 request without `Host`) and the others dropped, with
  `X-Client-IP` and `True-Client-IP`, so that the upstream cannot be
  handed a forged address or host. When `auth.header` is enabled, its user, email
  and role headers are dropped too from peers in neither
  `access_log.trusted_proxies` nor `auth.header.trusted_proxies`, so that
  the upstream cannot be handed a forged identity (with `auth.header`
  disabled, they are passed on: an authenticating proxy may set them).
  A header spelled with `_` instead of `-` (`X_Forwarded_For`), which some
  applications read as the same one, is dropped whenever its `-` spelling
  is set or dropped.
- The response is relayed as it comes, streamed, without hop-by-hop
  headers (a `Connection` header cannot remove its framing). Transfer
  codings other than `chunked` are kept; an HTTP/1.0 client cannot get
  them (502). A response head with control characters gets 502. Each
  client connection opens one upstream connection when it first needs one
  and keeps it while both sides keep alive.
- The request body is streamed to the upstream before its response is
  read: an upstream that answers early (a 413, say) is relayed once the
  body is sent, or when it stops reading. Each read of the client's body
  may wait 10 seconds (an idle timeout, like nginx's
  `client_body_timeout`, not a limit on the whole upload); then 408.
  `server.max_request_body_bytes` limits the body's size (413).
- WebSockets and other upgrades (`Connection: upgrade`) are tunnelled once
  the upstream answers 101 with the protocol asked for (a 101 to another
  protocol gets 502), until either side closes or no byte flows for
  `server.upstream_timeout`: have the application ping more often than
  that. A tunnel counts as one upstream request; its lifetime is the
  duration of its access log line, but is not in
  `redirect_proxy_upstream_duration_seconds`.
- `Upgrade: h2c` is never forwarded: the request goes on as plain
  HTTP/1.1, so that HTTP/2 cannot bypass the forwarding headers.
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

## Header authentication

[Trusted proxy headers](authentication#trusted-proxy-headers) trust
`auth.header.trusted_proxies`, by default `127.0.0.1/32` and `::1/128`:
every process on the host, including a website behind `server.upstream`
and redirect-proxy's own forwarded requests if `server.upstream` points
at the admin port. Narrow it to the address the authenticating proxy
connects from (its container or pod address, or a dedicated network), and
keep the admin listener off every other network.

## Kubernetes

One writer and replicas, as in [Several instances](#several-instances).
The writer keeps its data directory on a volume and serves the admin and
the API inside the cluster; the replicas serve the traffic from a
ConfigMap, with a read-only root file system.

The writer, its volume and an internal service for the admin and the API
(port 8081). It also needs a `redirect-proxy` Secret with the bootstrap
password (`kubectl create secret generic redirect-proxy
--from-literal=admin-password=…`):

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redirect-proxy-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redirect-proxy-writer
spec:
  replicas: 1
  # never two writers on the volume, even during a rollout
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: redirect-proxy
      role: writer
  template:
    metadata:
      labels:
        app: redirect-proxy
        role: writer
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
        - name: redirect-proxy
          image: ghcr.io/janalis/redirect-proxy:latest
          env:
            - name: RP_ADMIN_PUBLIC_URL
              value: https://redirects-admin.example.com
            - name: RP_BOOTSTRAP_ADMIN_USERNAME
              value: admin
            - name: RP_BOOTSTRAP_ADMIN_PASSWORD_FILE
              value: /run/secrets/redirect-proxy/admin-password
          ports:
            - name: http
              containerPort: 8080
            - name: admin
              containerPort: 8081
          livenessProbe:
            httpGet:
              path: /healthz
              port: admin
          readinessProbe:
            httpGet:
              path: /readyz
              port: admin
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: data
              mountPath: /var/lib/redirect-proxy
            - name: secrets
              mountPath: /run/secrets/redirect-proxy
              readOnly: true
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: redirect-proxy-data
        - name: secrets
          secret:
            secretName: redirect-proxy
---
# The admin and the API: inside the cluster only (or behind an
# authenticating ingress)
apiVersion: v1
kind: Service
metadata:
  name: redirect-proxy-admin
spec:
  type: ClusterIP
  selector:
    app: redirect-proxy
    role: writer
  ports:
    - name: admin
      port: 8081
      targetPort: admin
```

- One replica and the `Recreate` strategy: two writers must never share
  the data directory, not even during a rollout.
- The image's environment sets the data directory
  (`RP_STORAGE_DATA_DIR=/var/lib/redirect-proxy`) and binds the admin to
  `0.0.0.0:8081` (`RP_ADMIN_LISTEN`, `RP_ADMIN_PORT`), so that the kubelet
  can probe `/healthz` (liveness) and `/readyz` (readiness, 503 while
  draining). Expose port 8081 only inside the cluster, or through an
  [authenticating](authentication) ingress.

The replicas take the traffic. They read `redirects.json` from the
`redirect-proxy-rules` ConfigMap, mounted as their data directory:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redirect-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: redirect-proxy
      role: replica
  template:
    metadata:
      labels:
        app: redirect-proxy
        role: replica
    spec:
      # above server.shutdown_grace, with room for the VM to stop
      terminationGracePeriodSeconds: 30
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
      containers:
        - name: redirect-proxy
          image: ghcr.io/janalis/redirect-proxy:latest
          env:
            - name: RP_ADMIN_ENABLED
              value: "false"
            - name: RP_API_ENABLED
              value: "false"
            - name: RP_STORAGE_DATA_DIR
              value: /var/lib/redirect-proxy
            - name: RP_STORAGE_WATCH_INTERVAL
              value: "10"
            - name: RP_SERVER_HEALTH_PATH
              value: /_health
            # longer than readiness periodSeconds x failureThreshold (5 x 2)
            - name: RP_SERVER_SHUTDOWN_GRACE
              value: "15"
            # the ingress controller's pods: their X-Forwarded-* count
            - name: RP_ACCESS_LOG_TRUSTED_PROXIES
              value: 10.0.0.0/8
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /_health
              port: http
            periodSeconds: 5
            failureThreshold: 2
          livenessProbe:
            tcpSocket:
              port: http
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          volumeMounts:
            # the whole ConfigMap as the data directory: no subPath, which
            # would never be updated
            - name: rules
              mountPath: /var/lib/redirect-proxy
              readOnly: true
      volumes:
        - name: rules
          configMap:
            name: redirect-proxy-rules
            items:
              - key: redirects.json
                path: redirects.json
---
apiVersion: v1
kind: Service
metadata:
  name: redirect-proxy
spec:
  selector:
    app: redirect-proxy
    role: replica
  ports:
    - name: http
      port: 80
      targetPort: http
```

- `RP_ADMIN_ENABLED=false` and `RP_API_ENABLED=false`: replicas only
  redirect and write nothing to their data directory, so the ConfigMap and
  the root file system can be read-only.
- Mount the ConfigMap as a directory, never with `subPath`: Kubernetes
  updates a mounted ConfigMap by swapping the whole directory, which
  `storage.watch_interval` (`RP_STORAGE_WATCH_INTERVAL`, seconds) picks
  up, while a `subPath` mount keeps the first version forever. The kubelet
  itself takes up to about a minute to update the files. A ConfigMap holds
  at most 1 MiB: for more rules, use a volume synced from git or the
  writer's volume mounted read-only.
- `server.health_path` (`RP_SERVER_HEALTH_PATH`) gives the readiness probe
  a path on the traffic port, which answers 503 while draining. The
  liveness probe only checks that the port accepts connections.
- `RP_ACCESS_LOG_TRUSTED_PROXIES` lists the addresses the ingress
  controller connects from (here a placeholder for the pod CIDR): see
  [HTTP to HTTPS](#http-to-https).

Publish the writer's rules to the replicas from its API (a client with
`redirects:read`), or from a file kept in git:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  http://redirect-proxy-admin:8081/api/redirects/export > redirects.json
kubectl create configmap redirect-proxy-rules --from-file=redirects.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Shutdown and probes

On `SIGTERM` a pod drains for `server.shutdown_grace` seconds
(`RP_SERVER_SHUTDOWN_GRACE`, default 5): its readiness answers 503 and it
closes connections after each response, then stops (see
[Shutdown](operations#shutdown)). Kubernetes removes a terminating pod
from its Services on its own, but that takes a moment to reach every node
and ingress controller, and load balancers that probe the pods themselves
only move away once readiness has failed `failureThreshold` times,
`periodSeconds` apart. Size the grace above
`periodSeconds × failureThreshold` (5 × 2 = 10 seconds above, hence 15),
and `terminationGracePeriodSeconds` (default 30) above the grace, or the
pod is killed while it drains.

## Docker Compose

nginx terminates TLS in front of redirect-proxy, which forwards what no
rule answers to the website. `docker-compose.yml`:

```yaml
services:
  nginx:
    image: nginx:1.30-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/ssl/site:ro
    depends_on:
      - redirect-proxy
    networks: [web]

  redirect-proxy:
    image: ghcr.io/janalis/redirect-proxy:latest
    read_only: true
    environment:
      RP_SERVER_UPSTREAM: http://website:80
      RP_SERVER_HTTPS_REDIRECT: "true"
      # nginx connects from the web network, not from 127.0.0.1
      RP_ACCESS_LOG_TRUSTED_PROXIES: 172.30.0.0/24
      RP_ADMIN_PUBLIC_URL: http://localhost:8081
      RP_BOOTSTRAP_ADMIN_USERNAME: admin
      RP_BOOTSTRAP_ADMIN_PASSWORD_FILE: /run/secrets/admin_password
    secrets: [admin_password]
    ports:
      # the admin and the API, on this host only
      - "127.0.0.1:8081:8081"
    volumes:
      - data:/var/lib/redirect-proxy
    stop_grace_period: 15s
    networks: [web]

  website:
    image: traefik/whoami  # your website
    networks: [web]

networks:
  web:
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  data:

secrets:
  admin_password:
    file: ./admin_password.txt
```

`nginx.conf`, as in [Web servers](web-servers#nginx), with the service
name as the upstream server:

```nginx
upstream redirect_proxy {
    server redirect-proxy:8080;
    keepalive 32;
}

map $http_upgrade $websocket_upgrade {
    ~*^websocket$ $http_upgrade;
    default       "";
}
map $http_upgrade $connection_upgrade {
    ~*^websocket$ upgrade;
    default       "";
}

server {
    listen 80;
    listen 443 ssl;
    server_name _;
    ssl_certificate     /etc/ssl/site/site.crt;
    ssl_certificate_key /etc/ssl/site/site.key;

    location / {
        proxy_pass http://redirect_proxy;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $websocket_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

- The `web` network has a fixed subnet so that
  `RP_ACCESS_LOG_TRUSTED_PROXIES` can list it: nginx does not connect from
  `127.0.0.1` (see [HTTP to HTTPS](#http-to-https)).
- `admin_password.txt` holds the first administrator's password, readable
  by the container's user (uid 10001). The admin is published on the
  host's loopback only.
- The image's health check probes the admin's `/healthz`. The container's
  root file system is read-only; the data directory is the `data` volume.
- `stop_grace_period` (Docker's default is 10 seconds) stays above
  `server.shutdown_grace` (5).
