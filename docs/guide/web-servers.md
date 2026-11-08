# Web servers

redirect-proxy usually sits in front of a website, behind the web server
or load balancer that terminates TLS:

```text
client → web server (TLS) → redirect-proxy → website
```

The web server passes all of the site's traffic to redirect-proxy, which
answers the requests its rules match and forwards every other one to the
website (`server.upstream`, see
[In front of a website](deployment#in-front-of-a-website)). The redirects
then live in one place, whatever the site is built with. This page shows
that setup for nginx, HAProxy, Apache httpd, Caddy and Traefik, then:

- [Domains that only redirect](#domains-that-only-redirect) (an old brand,
  a retired site).
- [The web server stays in charge](#alternative-the-web-server-stays-in-charge),
  when redirect-proxy cannot be in the request path, or the web server
  should serve the site's files itself: it sends redirect-proxy only what
  the site does not have.

Every example below was run against the official images (nginx 1.30,
HAProxy 3.4, httpd 2.4, Caddy 2.11, Traefik 3.7) with redirect-proxy on
`127.0.0.1:8080` and the website on `127.0.0.1:3000`, using these rules:

```json
{
  "version": 1,
  "rules": [
    {
      "host": "old.example.com",
      "match": "prefix",
      "source": "/",
      "target": "https://new.example.com/$1",
      "preserve_query": true
    },
    {
      "host": "www.example.com",
      "source": "/old-page",
      "target": "https://www.example.com/new-page"
    }
  ]
}
```

## redirect-proxy's side

```sh
RP_SERVER_LISTEN=127.0.0.1
# the website: what no rule answers is forwarded to it
RP_SERVER_UPSTREAM=http://127.0.0.1:3000
RP_SERVER_HTTPS_REDIRECT=true
RP_SERVER_HEALTH_PATH=/healthz
# the web server: its X-Forwarded-* headers are kept
RP_ACCESS_LOG_TRUSTED_PROXIES=127.0.0.1/32
```

::: warning Trust the address the web server connects from
`access_log.trusted_proxies` decides whose `X-Forwarded-Proto` counts for
`server.https_redirect`. When the web server and redirect-proxy run in
different containers (Docker, Compose, Kubernetes), the web server
connects from its container's address, not from `127.0.0.1`: with
`127.0.0.1/32` its `X-Forwarded-Proto: https` is ignored, every request is
redirected to HTTPS again, and browsers end in a redirect loop. List the
network's CIDR instead (for example the Compose network's subnet,
`docker network inspect <network>`, or the cluster's pod CIDR), and keep
that network private to the web server.
:::

What it needs from the web server:

- **The `Host` header the client sent.** Rules match on it, and the
  website gets it too. nginx and Apache replace it by default
  (`proxy_set_header Host $host`, `ProxyPreserveHost On`); HAProxy, Caddy
  and Traefik pass it on.
- **`X-Forwarded-Proto`**, with `server.https_redirect`: requests marked
  `https` go to the rules and the website, the others are redirected to
  HTTPS first (see [Deployment](deployment#http-to-https)). Without it,
  let the web server redirect HTTP to HTTPS itself.
- **`X-Forwarded-For` or `X-Real-IP`**, for the client address. With the
  web server in `access_log.trusted_proxies`, redirect-proxy logs the
  client's address (see
  [Access logs](access-logs#client-address-behind-a-proxy)) and passes the
  web server's `X-Forwarded-*` headers on to the website, adding its own
  hop to `X-Forwarded-For`. Without, the website gets `X-Forwarded-For`
  with the web server's address and `X-Forwarded-Proto: http`.
- **Keep-alive connections** to redirect-proxy, where the web server makes
  it a choice (nginx): redirect-proxy keeps one connection to the website
  per client connection.
- **WebSocket upgrades** passed on, where the web server needs to be told
  (nginx, Apache): redirect-proxy tunnels them to the website.
- Only the traffic port. Keep the admin and API ports (8081) off the
  public web server, or behind an [authenticating one](authentication).

`server.health_path` gives the load balancer a path to probe (`/healthz`),
answered by redirect-proxy itself. Tell the website its proxy is now
redirect-proxy, if it checks where `X-Forwarded-*` headers come from.

## nginx

`/etc/nginx/conf.d/redirect-proxy.conf`:

```nginx
upstream redirect_proxy {
    server 127.0.0.1:8080;
    keepalive 32;
}

# Upgrade and "Connection: upgrade" for WebSockets only; nothing otherwise
# (the connection is kept open, and no other protocol upgrade is passed on)
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
    server_name www.example.com old.example.com;
    ssl_certificate     /etc/ssl/example.com.crt;
    ssl_certificate_key /etc/ssl/example.com.key;
    # the largest request body the website accepts
    client_max_body_size 20m;

    location / {
        proxy_pass http://redirect_proxy;
        proxy_http_version 1.1;
        # an empty value is not sent
        proxy_set_header Upgrade $websocket_upgrade;
        proxy_set_header Connection $connection_upgrade;
        # rules match on the host the client asked for
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## HAProxy

HAProxy passes the `Host` header on, keeps connections to the server open
and passes WebSocket upgrades on (`timeout tunnel` is how long an idle one
stays open).

```haproxy
global
    log stdout format raw local0

defaults
    mode http
    log global
    timeout connect 5s
    timeout client 30s
    timeout server 60s
    timeout tunnel 1h

frontend web
    bind :80
    bind :443 ssl crt /etc/ssl/example.com.pem
    # X-Forwarded-For with the client address (the previous value is kept)
    option forwardfor
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    http-request set-header X-Real-IP %[src]
    default_backend redirect_proxy

backend redirect_proxy
    option httpchk
    http-check send meth GET uri /healthz
    server rp1 127.0.0.1:8080 check
```

## Apache httpd

The modules, with `mod_ssl` for TLS (and `mod_rewrite` for the
[alternative](#apache-httpd-1) below). `mod_proxy_http` adds
`X-Forwarded-For` itself, keeps connections to redirect-proxy open, and
passes WebSocket upgrades on with `upgrade=websocket` (httpd 2.4.47 and
later).

```apache
LoadModule headers_module modules/mod_headers.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule ssl_module modules/mod_ssl.so
```

```apache
<VirtualHost *:80>
    ServerName www.example.com
    ServerAlias old.example.com
    # rules match on the host the client asked for
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "http"
    ProxyPass / http://127.0.0.1:8080/
</VirtualHost>
<VirtualHost *:443>
    ServerName www.example.com
    ServerAlias old.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/example.com.crt
    SSLCertificateKeyFile /etc/ssl/example.com.key
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass / http://127.0.0.1:8080/ upgrade=websocket
</VirtualHost>
```

## Caddy

Caddy passes the `Host` header and WebSocket upgrades on, sets
`X-Forwarded-For` and `X-Forwarded-Proto`, and redirects HTTP to HTTPS
itself (308): `RP_SERVER_HTTPS_REDIRECT` can be left out.

```caddy
www.example.com, old.example.com {
    tls /etc/ssl/example.com.crt /etc/ssl/example.com.key
    reverse_proxy 127.0.0.1:8080 {
        health_uri /healthz
    }
}
```

With certificates from Let's Encrypt, leave the `tls` lines out.

## Traefik

Traefik passes the `Host` header and WebSocket upgrades on, and sets
`X-Forwarded-For` and `X-Forwarded-Proto`. The entry points, with HTTP
redirected to HTTPS:

```sh
traefik \
  --entryPoints.web.address=:80 \
  --entryPoints.websecure.address=:443 \
  --entryPoints.web.http.redirections.entryPoint.to=websecure \
  --entryPoints.web.http.redirections.entryPoint.scheme=https \
  --providers.file.filename=/etc/traefik/dynamic.yml
```

The router and service (`/etc/traefik/dynamic.yml`):

```yaml
http:
  routers:
    site:
      rule: Host(`www.example.com`) || Host(`old.example.com`)
      entryPoints: [websecure]
      service: redirect-proxy
      tls: {}

  services:
    redirect-proxy:
      loadBalancer:
        healthCheck:
          path: /healthz
          interval: 10s
        servers:
          - url: http://127.0.0.1:8080

tls:
  certificates:
    - certFile: /etc/ssl/example.com.crt
      keyFile: /etc/ssl/example.com.key
```

With Docker labels or Kubernetes, the same applies: the site's router
points at redirect-proxy instead of the website.

## Domains that only redirect

A domain that only redirects goes to redirect-proxy like the site, as
`old.example.com` does above. Give it a rule for the whole domain (a
prefix rule on `/`, as above) so that none of its requests reaches the
website.

Without a website at all, the configurations above stay the same and
`RP_SERVER_UPSTREAM` is left out: requests no rule matches get a 404, or
go to `server.fallback_url`.

## Alternative: the web server stays in charge

When redirect-proxy cannot be in the site's request path, or the web
server should keep serving the site's files itself, the web server sends
redirect-proxy only what the site does not have, and redirect-proxy runs
without `server.upstream`. Some servers can send it whatever the site
does not have (its 404s); the others route the paths that moved.

| Server | Site from files: what is not a file | Application: its 404s | Application: paths that moved |
| --- | --- | --- | --- |
| [nginx](#nginx-1) | yes | yes | yes |
| [HAProxy](#haproxy-1) | | no | yes |
| [Apache httpd](#apache-httpd-1) | yes | no | yes |
| [Caddy](#caddy-1) | yes | yes | yes |
| [Traefik](#traefik-1) | | no | yes |

HAProxy cannot send a request again to another backend once the first one
answered. Traefik's `errors` middleware and Apache's `ProxyErrorOverride`
with an `ErrorDocument` were tried and still answered 404 for a page that
moved. With these servers, list the paths that moved.

The settings are the same as above, without `RP_SERVER_UPSTREAM`; the
site's application is on `127.0.0.1:3000`, and its files in
`/var/www/site`. Each example also sends the domains that only redirect
to redirect-proxy.

### nginx

The headers, shared by every location that passes requests on
(`/etc/nginx/redirect_proxy_params`):

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
# rules match on the host the client asked for
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

Domains that only redirect, and a site whose application's 404s go to
redirect-proxy (`/etc/nginx/conf.d/redirect-proxy.conf`):

```nginx
upstream redirect_proxy {
    server 127.0.0.1:8080;
    keepalive 32;
}

# Domains that only redirect: every request goes to redirect-proxy.
server {
    listen 80;
    listen 443 ssl;
    server_name old.example.com;
    ssl_certificate     /etc/ssl/example.com.crt;
    ssl_certificate_key /etc/ssl/example.com.key;

    location / {
        include /etc/nginx/redirect_proxy_params;
        proxy_pass http://redirect_proxy;
    }
}

# A site: what the application answers with 404 goes to redirect-proxy.
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/ssl/example.com.crt;
    ssl_certificate_key /etc/ssl/example.com.key;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_intercept_errors on;
        error_page 404 = @redirects;
    }

    location @redirects {
        include /etc/nginx/redirect_proxy_params;
        # no URI after the address: the original request URI is passed on
        proxy_pass http://redirect_proxy;
    }
}
```

A site served from files: what is not a file goes to redirect-proxy.

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/ssl/example.com.crt;
    ssl_certificate_key /etc/ssl/example.com.key;
    root /var/www/site;

    location / {
        try_files $uri $uri/ @redirects;
    }

    location @redirects {
        include /etc/nginx/redirect_proxy_params;
        proxy_pass http://redirect_proxy;
    }
}
```

### HAProxy

The paths that moved on a site are listed in a file, one prefix per line
(`/usr/local/etc/haproxy/moved-paths.lst`):

```text
/old-page
/blog/
```

```haproxy
global
    log stdout format raw local0

defaults
    mode http
    log global
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend web
    bind :80
    bind :443 ssl crt /etc/ssl/example.com.pem
    # X-Forwarded-For with the client address (the previous value is kept)
    option forwardfor
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    http-request set-header X-Real-IP %[src]

    # domains that only redirect
    acl redirect_only req.hdr(host),field(1,:),lower -m str old.example.com legacy.example.org
    use_backend redirect_proxy if redirect_only
    # on a site, the paths that moved (one prefix per line in the file)
    acl moved path_beg -f /usr/local/etc/haproxy/moved-paths.lst
    use_backend redirect_proxy if { req.hdr(host),field(1,:),lower -m str www.example.com } moved
    default_backend app

backend redirect_proxy
    # Host is passed on unchanged: rules match on it
    option httpchk
    http-check send meth GET uri /healthz
    server rp1 127.0.0.1:8080 check

backend app
    server app1 127.0.0.1:3000
```

### Apache httpd

With the modules above. Domains that only redirect:

```apache
<VirtualHost *:80>
    ServerName old.example.com
    # rules match on the host the client asked for
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "http"
    ProxyPass        / http://127.0.0.1:8080/
</VirtualHost>
<VirtualHost *:443>
    ServerName old.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/example.com.crt
    SSLCertificateKeyFile /etc/ssl/example.com.key
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass        / http://127.0.0.1:8080/
</VirtualHost>
```

A site served from files: what is not a file or a directory goes to
redirect-proxy.

```apache
<VirtualHost *:443>
    ServerName www.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/example.com.crt
    SSLCertificateKeyFile /etc/ssl/example.com.key
    DocumentRoot "/var/www/site"
    <Directory "/var/www/site">
        Require all granted
    </Directory>
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RewriteEngine On
    RewriteCond "%{DOCUMENT_ROOT}%{REQUEST_URI}" !-f
    RewriteCond "%{DOCUMENT_ROOT}%{REQUEST_URI}" !-d
    RewriteRule "^" "http://127.0.0.1:8080%{REQUEST_URI}" [P]
</VirtualHost>
```

A site proxied to an application: the paths that moved go to
redirect-proxy.

```apache
<VirtualHost *:443>
    ServerName www.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/example.com.crt
    SSLCertificateKeyFile /etc/ssl/example.com.key
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    # before the application's ProxyPass: the first match wins
    ProxyPass      /old-page http://127.0.0.1:8080/old-page
    ProxyPass      /blog/    http://127.0.0.1:8080/blog/
    ProxyPass      /         http://127.0.0.1:3000/
</VirtualHost>
```

### Caddy

```caddy
# Domains that only redirect: every request goes to redirect-proxy.
old.example.com {
    tls /etc/ssl/example.com.crt /etc/ssl/example.com.key
    reverse_proxy 127.0.0.1:8080
}

# A site: what the application answers with 404 goes to redirect-proxy.
www.example.com {
    tls /etc/ssl/example.com.crt /etc/ssl/example.com.key
    reverse_proxy 127.0.0.1:3000 {
        @not_found status 404
        handle_response @not_found {
            reverse_proxy 127.0.0.1:8080
        }
    }
}
```

A site served from files: what is not a file goes to redirect-proxy.

```caddy
www.example.com {
    tls /etc/ssl/example.com.crt /etc/ssl/example.com.key
    root * /var/www/site
    @moved not file {path} {path}/index.html
    reverse_proxy @moved 127.0.0.1:8080
    file_server
}
```

### Traefik

The same entry points as above. The paths that moved on a site get a
router with a higher priority than the site's (`/etc/traefik/dynamic.yml`):

```yaml
http:
  routers:
    # domains that only redirect
    redirects:
      rule: Host(`old.example.com`) || Host(`legacy.example.org`)
      entryPoints: [websecure]
      service: redirect-proxy
      tls: {}
    # on a site, the paths that moved (a higher priority than the site's)
    moved:
      rule: Host(`www.example.com`) && (Path(`/old-page`) || PathPrefix(`/blog/`))
      priority: 100
      entryPoints: [websecure]
      service: redirect-proxy
      tls: {}
    site:
      rule: Host(`www.example.com`)
      priority: 10
      entryPoints: [websecure]
      service: app
      tls: {}

  services:
    redirect-proxy:
      loadBalancer:
        # the Host header is passed on unchanged (passHostHeader)
        healthCheck:
          path: /healthz
          interval: 10s
        servers:
          - url: http://127.0.0.1:8080
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:3000

tls:
  certificates:
    - certFile: /etc/ssl/example.com.crt
      keyFile: /etc/ssl/example.com.key
```

With Docker labels or Kubernetes, the same routers apply: a `Host` rule
for the domains that only redirect, and a higher priority router for the
paths that moved.
