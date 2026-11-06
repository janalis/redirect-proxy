# redirect-proxy

[![CI](https://github.com/janalis/redirect-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/janalis/redirect-proxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/janalis/redirect-proxy/graph/badge.svg)](https://codecov.io/gh/janalis/redirect-proxy)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast HTTP redirect server written in [Gleam](https://gleam.run) for the
Erlang VM, with a web administration backend.

It answers requests with `301`/`302`/`303`/`307`/`308` redirections based on
rules. It never proxies traffic to an upstream.

- **Fast and highly concurrent.** The compiled rule set lives in
  `persistent_term`, so every request process reads it without locks, copies
  or message passing. Exact rules are O(1) dictionary lookups. The BEAM
  schedules hundreds of thousands of concurrent connections.
- **Small footprint.** One OS process with no database. It typically uses
  tens of megabytes plus a few megabytes per 10 000 rules.
- **Hard to break.**
  - An invalid rules file is never loaded: the previous rules stay live.
  - Every write is atomic (temp file, `fsync`, `rename`) and backed up.
  - Regular expressions are checked for catastrophic backtracking and run
    with a PCRE budget.
  - Processes are supervised by OTP.
- **Administration backend** (Bootstrap 6):
  - Create, read, update and delete rules, with search, filters (host, match
    type, state) and sorting (source, host, hits, last update).
  - Enable, disable or delete a selection of rules, or every rule matching
    the filters, in one change.
  - A "test a URL" tool that explains the result: every rule that matches,
    which one applies, which are shadowed or disabled, and the redirect chain.
  - JSON import and export. An import can be previewed (rules added, changed
    and removed); a replace is always previewed first.
  - Users, and an audit log with filters and a field by field diff.
- **REST API** with OAuth 2.0:
  - A built-in client credentials token endpoint, with API clients managed in
    the admin or the CLI.
  - JWT access tokens from your own authorization server are also accepted.
  - An OpenAPI 3.1 document is served at `/api/openapi.json`.
- **Authentication:**
  - Local accounts (PBKDF2-SHA256).
  - Optional OpenID Connect single sign-on.
  - Optional trusted reverse-proxy headers.
- **Access logs** for the redirect, admin and API listeners, enabled by
  default:
  - Combined, Common and JSON formats, or your own nginx-style template.
  - Written to stdout, stderr or files (shared or one per listener), with
    rotation.
  - GDPR-minded defaults: truncated IP addresses and no query strings.
- **Plain files.**
  - `redirects.json` can be versioned, generated and edited by hand.
  - Reload it with `SIGHUP` or a button in the admin.

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Redirection rules](#redirection-rules)
- [Configuration](#configuration)
- [Administration and authentication](#administration-and-authentication)
- [REST API](#rest-api)
- [Command line](#command-line)
- [Operations](#operations)
- [Access logs](#access-logs)
- [Performance](#performance)
- [Development](#development)
- [Releasing](#releasing)
- [License](#license)

## Quick start

```sh
docker run -d --name redirect-proxy \
  -p 8080:8080 -p 127.0.0.1:8081:8081 \
  -v redirect-proxy:/var/lib/redirect-proxy \
  -e RP_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e RP_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password' \
  ghcr.io/janalis/redirect-proxy:latest
```

Open the administration at <http://localhost:8081> and create a redirection,
then try it:

```sh
curl -sI http://localhost:8080/old-page
# HTTP/1.1 301 Moved Permanently
# location: https://example.com/new-page
```

The redirect listener (`8080`) is meant to be public. The admin listener
(`8081`) should only be reachable from a trusted network or through an
authenticating reverse proxy.

The bootstrap password stays readable in the container configuration: once
the administrator exists, recreate the container without
`RP_BOOTSTRAP_ADMIN_PASSWORD` (the server warns while it is still set), or
pass it as a secret file with `RP_BOOTSTRAP_ADMIN_PASSWORD_FILE`.

## Installation

| Platform | Install with |
| --- | --- |
| Any (container) | `docker pull ghcr.io/janalis/redirect-proxy` (linux/amd64, linux/arm64) |
| Debian 12+ / Ubuntu 22.04+ | `.deb` from the [releases](https://github.com/janalis/redirect-proxy/releases) |
| macOS | `brew install janalis/tap/redirect-proxy` |
| Linux (other) | `redirect-proxy-<version>-linux-<arch>.tar.gz`, which includes the Erlang runtime |
| Anywhere with Erlang/OTP 27+ | `redirect-proxy-<version>-erlang.tar.gz` |

### Debian / Ubuntu

```sh
sudo apt install ./redirect-proxy_<version>_amd64.deb
sudo -u redirect-proxy RP_CONFIG=/etc/redirect-proxy/config.toml redirect-proxy user add admin
sudo systemctl start redirect-proxy
```

The package installs these files:

- The application, in `/usr/lib/redirect-proxy`. It bundles the Erlang
  runtime, so there is no system Erlang dependency.
- A hardened systemd unit.
- `/etc/redirect-proxy/config.toml`.
- The data directory, `/var/lib/redirect-proxy`.

The unit can bind ports 80 and 443 without root. `systemctl reload
redirect-proxy` re-reads the redirections file.

### Homebrew

```sh
brew install janalis/tap/redirect-proxy
RP_CONFIG=$(brew --prefix)/etc/redirect-proxy/config.toml \
RP_STORAGE_DATA_DIR=$(brew --prefix)/var/lib/redirect-proxy \
  redirect-proxy user add admin
brew services start redirect-proxy
```

### Verifying a download

Every release asset comes with a `SHA256SUMS` file and a build provenance
attestation signed by the release workflow, so you can check that a file was
built by this repository's CI from the tagged commit:

```sh
# the files are intact
sha256sum -c --ignore-missing SHA256SUMS
# they were built by janalis/redirect-proxy's release workflow (GitHub CLI)
gh attestation verify redirect-proxy-<version>-linux-amd64.tar.gz \
  --repo janalis/redirect-proxy
# the same for the container image
gh attestation verify oci://ghcr.io/janalis/redirect-proxy:<version> \
  --repo janalis/redirect-proxy
```

On macOS, use `shasum -a 256 -c --ignore-missing SHA256SUMS`.

### From source

You need Gleam 1.19+ and Erlang/OTP 27+.

```sh
git clone https://github.com/janalis/redirect-proxy && cd redirect-proxy
make dev          # admin / change-me-please, data in ./data
make bundle       # self-contained bundle in dist/
```

## Redirection rules

Rules are stored in `<data_dir>/redirects.json`:

```json
{
  "version": 1,
  "rules": [
    { "source": "/old", "target": "https://example.com/new" },
    {
      "host": "docs.example.com",
      "match": "prefix",
      "source": "/v1/",
      "target": "https://docs.example.com/v2/$1",
      "status": 302,
      "preserve_query": true
    },
    {
      "match": "regex",
      "source": "^/blog/(\\d+)(?:/[a-z0-9-]*)?$",
      "target": "/articles/$1",
      "status": 308,
      "note": "Legacy blog URLs"
    }
  ]
}
```

Only `source` and `target` are required, and a bare array of rules is also
accepted. Ids and timestamps are added automatically.

| Field | Default | Description |
| --- | --- | --- |
| `host` | `*` | Host name to match, case-insensitively and without a port (requests match whatever their port). `*` matches every host; `*.example.com` matches every subdomain of `example.com` (not `example.com` itself). International names are written in punycode (`xn--caf-dma.example`). |
| `match` | `exact` | `exact`, `prefix` or `regex`. |
| `source` | (required) | The request path without its query string. Regexes are PCRE and are not anchored automatically. |
| `target` | (required) | An absolute `http(s)://` URL, a protocol-relative `//host/path` or a path `/path`. |
| `status` | `301` | `301`, `302`, `303`, `307` or `308`. |
| `preserve_query` | `false` | Append the request query string to the target. |
| `case_insensitive` | `false` | Match the source without regard to case. |
| `priority` | `100` | Lower runs first, among regex rules and among prefix rules of the same length. |
| `enabled` | `true` | Disabled rules are kept but ignored. |
| `note` | `""` | Free text shown in the admin. |

**Target substitutions:**

| Syntax | Meaning |
| --- | --- |
| `$1` … `$9`, `${10}` | Regex capture groups. |
| `$0` | The whole match. |
| `$1` in a prefix rule | The rest of the path after the prefix. |
| `$$` | A literal `$`. |

Substitutions apply to prefix and regex rules. The target of an exact rule
is used as written, `$` included.

**Resolution order.** Rules for the request's `Host` are tried first, then
those of wildcard hosts from the closest one (for `a.b.example.com`:
`*.b.example.com`, then `*.example.com`), then the `*` rules. Within each
host, the first match wins in this order:

1. Exact rules, which are O(1) lookups.
2. Prefix rules, longest prefix first.
3. Regex rules, by priority, then file order.

Prefix rules, and regex rules that start with `^` and a literal (such as
`^/blog/(\d+)$`), are indexed by that literal. A lookup costs one dictionary
access per distinct literal length instead of one test per rule. Only regex
rules without a leading literal (unanchored, using `|`, or case-insensitive)
are tried one by one on every request that reaches them. Put a literal
prefix in your patterns when you can.

**Equivalent paths.** Paths are compared in one form, so a rule written
`/café` matches the `/caf%C3%A9` browsers send, and `%7e` matches `~`.
Escapes of unreserved characters and of valid UTF-8 are decoded; the
others, such as `%2F` (which is not a path separator), are kept and
compared in upper case. Regex rules see the path in this form too. In the
`Location` header, non-ASCII characters are percent-encoded.

**Trailing slashes.** By default `/docs` and `/docs/` are different paths.
With `server.trailing_slash = "ignore"` (`RP_SERVER_TRAILING_SLASH`), a
request that matches no rule is retried with the trailing slash added or
removed. A rule for the exact form always wins.

**When nothing matches.** The server answers `404`, or redirects (302) to
`server.fallback_url` if it is set.

**Caching.** `301` and `308` responses carry
`Cache-Control: public, max-age=<server.cache_max_age>`. Temporary redirects
are sent with `no-store`.

**Safety checks.** A rule is rejected if any of these hold:

- It duplicates the source of another enabled exact rule on the same host.
- It redirects to itself.
- When created or edited, a request to it would be redirected back to it,
  directly or through other rules (for example `/a/` → `/a/b/$1`). Up to 10
  redirects are followed, as a browser would. When the rules file is
  loaded, loops are logged as warnings instead, so a file that loaded before
  keeps loading.
- When created or edited, it can never apply as written: an exact or prefix
  source with a query string (`?`) or a fragment (`#`), or starting with
  `//` (the server reads a request for `//a/b` as the path `/b`), or a host
  with a port. These are also logged as warnings when the file is loaded or rules
  are imported. Loop checks follow `server.trailing_slash`.
- It contains control characters (header injection).
- Its regex backtracks catastrophically.

At request time, each regex match also has a fixed backtracking budget.

**Substitutions cannot leave the target's host.** Captures come from the
request path, so they are checked after `$1`... are replaced (open redirect
guard):

- A target starting with `/` stays a path on the same host: leading `/` and
  `\` are collapsed, so `/old/(.*)` → `/$1` sends `/old//evil.com` to
  `/evil.com`, not to `//evil.com`.
- An absolute target keeps its host: with `https://example.com$1`,
  `/go/page` redirects but `/go.evil.com` and `/go@evil.com` do not.
- A host starting with placeholders, as in `https://$1.example.com/`, must
  stay a subdomain of `example.com`. Placeholders elsewhere in the host
  (`https://example$1.com/`, `https://$1.com/`) never redirect.

A rule whose result fails the check does not match, so the next rule or
the 404 applies.

## Configuration

Configuration is read from the TOML file given with `--config` or
`$RP_CONFIG`. [`config.example.toml`](config.example.toml) documents every
option. Each option can be overridden with an environment variable named
`RP_<SECTION>_<KEY>`; lists are comma separated. A number, a boolean
(`true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`) or a log level that does
not parse stops the start with an error naming the variable.

Secrets can be read from a file instead, so that they do not show in the
process environment (`docker inspect`, `/proc/<pid>/environ`): set
`RP_ADMIN_SECRET_KEY_BASE_FILE`, `RP_AUTH_OIDC_CLIENT_SECRET_FILE` or
`RP_BOOTSTRAP_ADMIN_PASSWORD_FILE` to the path of a file holding the value
(Docker and Kubernetes secrets). A trailing line break is ignored.

| Variable | Default |
| --- | --- |
| `RP_SERVER_LISTEN` / `RP_SERVER_PORT` | `0.0.0.0` / `8080` |
| `RP_SERVER_CACHE_MAX_AGE` | `3600` |
| `RP_SERVER_SHUTDOWN_GRACE` | `5` (seconds) |
| `RP_SERVER_TRAILING_SLASH` | `strict` (`ignore`: retry a miss with/without the trailing slash) |
| `RP_SERVER_FALLBACK_URL` | (none) |
| `RP_SERVER_NOT_FOUND_BODY` | `Not Found` (body of the 404 when no fallback is set) |
| `RP_SERVER_HEALTH_PATH` | (none: off) |
| `RP_SERVER_MAX_PATH_BYTES` | `8192` (longer paths get a 414) |
| `RP_ADMIN_ENABLED` | `true` |
| `RP_ADMIN_LISTEN` / `RP_ADMIN_PORT` | `127.0.0.1` / `8081` |
| `RP_ADMIN_PUBLIC_URL` | `http://localhost:8081` |
| `RP_ADMIN_SECRET_KEY_BASE` | generated into `<data_dir>/secret_key_base` |
| `RP_ADMIN_SESSION_TTL` | `28800` (8 hours) |
| `RP_ADMIN_SESSION_IDLE_TIMEOUT` | `3600` (1 hour, `0`: never) |
| `RP_STORAGE_DATA_DIR` / `RP_STORAGE_BACKUPS` | `./data` / `10` |
| `RP_STORAGE_WATCH_INTERVAL` | `0` (seconds between checks of the rules file, `0`: off) |
| `RP_AUTH_LOCAL_ENABLED` | `true` |
| `RP_AUTH_OIDC_ENABLED`, `_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_SCOPES`, `_ALLOWED_EMAILS`, `_ALLOWED_DOMAINS`, `_ALLOWED_GROUPS` | disabled |
| `RP_AUTH_OIDC_GROUPS_CLAIM`, `_BUTTON_LABEL` | `groups`, `Sign in with SSO` |
| `RP_AUTH_HEADER_ENABLED`, `_TRUSTED_PROXIES` | disabled |
| `RP_AUTH_HEADER_USER_HEADER`, `_EMAIL_HEADER` | `X-Forwarded-User`, `X-Forwarded-Email` (empty user header: identify by email) |
| `RP_API_ENABLED`, `RP_API_TOKEN_TTL`, `RP_API_MAX_BODY_BYTES` | `true`, `3600`, `10485760` |
| `RP_API_LISTEN` / `RP_API_PORT`, `RP_API_PUBLIC_URL` | `admin.listen` / `admin.port`, (none) |
| `RP_API_OAUTH_ENABLED`, `_ISSUER`, `_AUDIENCE`, `_SCOPE_CLAIM`, `_READ_SCOPE`, `_WRITE_SCOPE`, `_OPS_SCOPE` | disabled |
| `RP_ACCESS_LOG_ENABLED`, `_FORMAT`, `_ESCAPE`, `_OUTPUT` | `true`, `combined`, `default`, `stdout` |
| `RP_ACCESS_LOG_ANONYMIZE_IP`, `_LOG_QUERY`, `_TRUSTED_PROXIES` | `truncate`, `false`, (none) |
| `RP_ACCESS_LOG_MAX_BYTES`, `_MAX_FILES`, `_COMPRESS` | `0` (no rotation), `7`, `true` |
| `RP_ACCESS_LOG_{REDIRECT,ADMIN,API}_ENABLED`, `_FORMAT`, `_OUTPUT` | `true`, inherited, inherited |
| `RP_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | creates the first local administrator when none exists |
| `RP_LOG_LEVEL` | `info` (`debug`, `warning`, `error`); does not affect the access log |
| `RP_LOG_FORMAT` | `text` (`json`: one `{time, level, msg, domain}` object per line) |
| `NO_COLOR` | plain log lines (automatic when output is not a terminal) |

## Administration and authentication

The admin listener serves these pages:

- Redirections: search, filter, create, edit, enable/disable, delete.
- A URL tester.
- JSON import (merge or replace) and export.
- Local users.
- The audit log.
- "Reload from disk".

Unauthenticated endpoints: `/healthz` (the process is up), `/readyz` (ready
for traffic: 503 while draining before a stop) and `/metrics` (Prometheus).

- **Local accounts.**
  - Passwords are hashed with PBKDF2-HMAC-SHA256 (600 000 iterations) and
    must be at least 12 characters.
  - Accounts live in `users.json`.
  - Manage them in the admin or with `redirect-proxy user …`.
- **OpenID Connect.**
  - Uses the authorization code flow with PKCE, `state` and `nonce`.
  - The ID token signature is verified against the provider JWKS, and `iss`,
    `aud`, `exp`, `nbf` and (when present) `azp` are checked.
  - To allow users, set `allowed_emails`, `allowed_domains` (checked against
    verified emails) and/or `allowed_groups` (from `groups_claim`). With all
    three lists empty, every account of the provider is accepted, and the
    server logs a warning at startup (and `check-config` reports it).
  - An email counts as verified only when the ID token says
    `email_verified: true`. Providers that never send that claim, such as
    Entra ID, can only be restricted with `allowed_groups`.
  - Register `<admin.public_url>/auth/oidc/callback` as the redirect URI at the
    provider.
- **Trusted proxy headers.** With `auth.header` enabled, the user named in
  `user_header` (`X-Forwarded-User`) is signed in. Set `user_header = ""` to
  use `email_header` (`X-Forwarded-Email`) instead. The two are never
  combined. The header is only accepted when the TCP peer is in
  `trusted_proxies`, and a request carrying several values in it is refused.
  Configure the proxy to set (not append to) that header, and never expose the
  admin port directly in this mode. The session ends on the first request
  that arrives without the header (signed out at the proxy, or a replayed
  cookie).

Security measures:

- **Sessions.** Server-side and revocable, using signed `HttpOnly`,
  `SameSite=Lax` cookies.
  - A session ends after `session_ttl`, or after `session_idle_timeout`
    without a request.
  - A local account's sessions end when the user is deleted or their
    password changes, including from the CLI. Changing your own password
    keeps you signed in, in a new session.
  - SSO logins are bound to the browser that started them.
- **Passwords.** Changing a local password, yours or another user's, needs
  your current password and a local session: administrators signed in with
  SSO or proxy headers cannot change local passwords. Deleting a user or an
  API client, and rotating a secret, ask for a confirmation.
- **CSRF.** Every form carries a token, and `Origin`/`Referer` are checked.
- **Login throttling.** Over 15 minutes, a client may fail 10 times for
  one account and 20 times in all; an account accepts 100 failures from all
  clients. A correct password from another client still works, so failures
  cannot lock a user out. The API token endpoint works the same way with
  client ids. A client may start 30 SSO logins and fail 20 SSO callbacks,
  and the API accepts 100 invalid access tokens from one client before
  answering 429 without checking more. A throttled request gets a 429 with
  `Retry-After`. Behind a proxy, list it in `access_log.trusted_proxies` so
  that the client address is the forwarded one.
- **Input limits.** Admin forms are limited to 64 KB (imports: like the API,
  `api.max_body_bytes`) and usernames to 64 bytes.
- **HTTP headers.** A strict Content-Security-Policy (no inline scripts),
  `X-Frame-Options: DENY` and `nosniff`. When `admin.public_url` is
  `https://`, responses carry `Strict-Transport-Security` and the session
  and SSO state cookies are named `__Host-rp_session` and
  `__Host-rp_oidc_state`, which a sibling subdomain cannot set or shadow.

> **Behind a reverse proxy.** Keep the `Host` header unchanged so that the
> origin check passes. Serve the admin over HTTPS so that cookies get the
> `Secure` flag, and send `X-Forwarded-Proto`.

## REST API

The API lives under `/api`, next to the OAuth 2.0 token endpoint
`/oauth/token`. Its OpenAPI 3.1 description is at
[`/api/openapi.json`](http://localhost:8081/api/openapi.json).

The port decides which listener serves the API:

- **Same port as the admin UI** (the default; `api.port = 0` means
  `admin.port`): one listener serves both.
- **Another port:** the API gets its own listener, on `api.listen` (default
  `admin.listen`) and `api.port`, with a `/healthz` endpoint. The admin
  listener then no longer answers `/api`, so each can be exposed to different
  networks.
- **Admin UI disabled:** the API keeps running on its own listener.

```sh
# 1. Create an API client in the admin ("API clients"), or with the CLI.
#    The secret is shown only once.
redirect-proxy client add deploy --scope redirects:write

# 2. Get an access token (client credentials grant).
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  http://localhost:8081/oauth/token | jq -r .access_token)

# 3. Call the API.
curl -s -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"source": "/old", "target": "https://example.com/new", "status": 301}' \
  http://localhost:8081/api/redirects
```

| Endpoint | Scope | |
| --- | --- | --- |
| `GET /api/redirects` | `redirects:read` | Filters `q`, `host`, `match`, `enabled`; `sort` by `source`, `host`, `hits` or `updated` (`-` for descending); pages via `page` and `per_page` (max 500), with a `Link` header. Invalid values answer `400`. Rules include their `hits` since the server started. The `ETag` is the version of the whole rule set. |
| `POST /api/redirects` | `redirects:write` | Create. Returns `201`, `Location` and `ETag`. |
| `GET` / `PUT` / `PATCH` / `DELETE /api/redirects/{id}` | read / write | `PATCH` is a JSON merge patch. All writes honour `If-Match` (`412` on mismatch); `GET` honours `If-None-Match` (`304`). |
| `GET /api/redirects/export` | `redirects:read` | Same format as `redirects.json`. Takes the list filters (`q`, `host`, `match`, `enabled`). `ETag` and `If-None-Match` as for the list. |
| `POST /api/redirects/import?mode=merge\|replace` | `redirects:write` | All or nothing, as `application/json`. `dry_run=true` returns what would be added, changed and removed without writing, with an `ETag`: send it in `If-Match` to apply exactly that change (`412` if the rules changed meanwhile). |
| `POST /api/redirects/bulk` | `redirects:write` | `{"ids": [...], "action": "enable\|disable\|delete"}`, all or nothing. Honours `If-Match` with the version of the rule set. |
| `POST /api/reload` | `redirects:ops` | Re-read `redirects.json` from disk. |
| `GET /api/test?url=` | `redirects:read` | Which rule matches a URL and where it redirects, every matching rule with its verdict (applied, shadowed, disabled), and the redirect chain. |

**Tokens.**

- Tokens from `/oauth/token` are opaque and expire after `api.token_ttl`.
- Rotating a client's secret or deleting the client revokes its tokens
  immediately, including when you do it from the CLI.
- A token request can ask for fewer scopes than the client has with
  `scope=…`.
- `redirects:write` implies `redirects:read`.

**External authorization server.** With `[api.oauth]` enabled, JWT access
tokens from your own authorization server are accepted too:

- The server is found through OIDC or RFC 8414 discovery on `issuer`.
- The signature is checked against its JWKS.
- `iss`, `aud`, `exp` and `nbf` are verified.
- Scopes are read from `scope` or `scp` and mapped through `read_scope`,
  `write_scope` and `ops_scope`.

**Errors** use [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
`application/problem+json`. Validation errors carry an `errors` array of
`{field, message}`. Authentication failures follow
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) (`WWW-Authenticate:
Bearer error="invalid_token"` or `"insufficient_scope"`). The API never uses
cookies, so it isn't exposed to CSRF.

**Compatibility.** There is no version prefix. The API only changes
additively, so clients must ignore fields they don't know. Retiring a field
or endpoint works like this:

1. It is first deprecated. It still works, and responses that use it carry a
   [`Deprecation`](https://www.rfc-editor.org/rfc/rfc9745) header, plus a
   [`Sunset`](https://www.rfc-editor.org/rfc/rfc8594) header once a removal
   date is set.
2. It is flagged `deprecated: true` in the OpenAPI document and announced in
   the changelog.
3. It is removed only in a major release.

## Command line

```text
redirect-proxy [serve] [--config FILE]
redirect-proxy check-config [--config FILE]   # also warns about unknown keys
redirect-proxy user add|passwd|delete <username> | user list
redirect-proxy client add <name> [--scope SCOPE]... | client list | client rotate|delete <client_id>
redirect-proxy rules validate [FILE] | rules export | rules import <FILE> [--replace]
redirect-proxy version | help
```

`user add` and `user passwd` read the password from `$RP_PASSWORD` or prompt
for it. `rules import` writes the file; a running server applies it on
`SIGHUP` or "Reload from disk".

## Operations

- **Reload.** Edit `redirects.json`, then `kill -HUP <pid>` (or
  `systemctl reload redirect-proxy`). An invalid or missing file is rejected,
  the error is logged and the current rules stay active.
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
    after the rename) and keep their permissions.
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
  (`api.token_issued`, `api.token_rejected`) are recorded too. Imports and
  reloads record the file fingerprint before and after and the rules added,
  removed and changed (counts, and up to 100 ids each). Rejected reloads and
  imports are recorded with the reason (`rules.reload_failed`,
  `rules.import.merge_failed`...).
- **Metrics.** `GET :8081/metrics` returns requests, redirects, misses,
  fallbacks, login failures, reloads, API requests, issued tokens, API
  authentication failures, regex runs stopped by the backtracking budget,
  loaded rules, VM memory and process count, plus
  `redirect_proxy_build_info{version}` and `process_start_time_seconds`.
  Also:
  - `redirect_proxy_request_duration_seconds{listener}`: a histogram of the
    time to serve a request (0.5 ms to 1 s buckets) for the redirect, admin
    and API listeners;
  - `redirect_proxy_responses_total{class}`: redirect listener responses by
    status class;
  - `redirect_proxy_rules_by_kind{kind}`: enabled rules by match kind;
  - `redirect_proxy_last_reload_timestamp_seconds` and
    `redirect_proxy_reload_duration_seconds` for the last successful load of
    the redirections file.

  Per-rule hit counts are shown in the admin, not exported (one series per
  rule would be too many).
  The endpoint is not authenticated: like the rest of the admin listener,
  keep it off the public network. The container image binds the admin to
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
- **Long paths.** Requests whose path is longer than `server.max_path_bytes`
  (default 8192, `RP_SERVER_MAX_PATH_BYTES`) get a 414 without rule lookup.
- **Container health check.** The image probes the admin listener's
  `/healthz` on `RP_ADMIN_PORT`. With `RP_ADMIN_ENABLED=false` it checks
  that the redirect listener on `RP_SERVER_PORT` accepts connections
  instead. Ports set only in a config file need a `HEALTHCHECK` override.
- **Tuning.** Pass extra VM flags with `ERL_FLAGS`. For example, on a small
  host `ERL_FLAGS="+S 2:2 +SDio 2"` limits schedulers and lowers memory use.

## Access logs

The redirect, admin and API listeners write one line per request. Logging
is configured in the `[access_log]` section of the configuration file. By
default every listener uses the Combined Log Format on stdout, so
`docker logs`, `journalctl -u redirect-proxy` and Kubernetes log collectors
pick it up:

```text
203.0.113.0 - - [06/Nov/2026:10:00:00 +0000] "GET /old-page HTTP/1.1" 301 0 "https://www.example.org/" "Mozilla/5.0 ..."
```

| `format` | Use with |
| --- | --- |
| `combined` (default) | GoAccess (`--log-format=COMBINED`), AWStats, Logstash (`%{COMBINEDAPACHELOG}`), Fluent Bit (`apache2` parser), Datadog and Loki nginx pipelines |
| `common` | Tools expecting the NCSA Common Log Format |
| `json` | Elasticsearch/OpenSearch, Loki (`json` stage), Vector, Splunk, Datadog |
| a template | Anything else, e.g. `'$time_iso8601 $remote_addr $status $request_time $rule_id'` |

Templates use nginx variable names (`$var` or `${var}`):

- `remote_addr`, `remote_user`
- `time_local`, `time_iso8601`, `msec`
- `request`, `request_method`, `request_uri`, `uri`, `args`,
  `server_protocol`, `host`
- `status`, `body_bytes_sent`, `request_time`
- `http_referer`, `http_user_agent`, `http_<header>`
- `location` (the redirect target), `rule_id` (the matched rule),
  `listener` (`redirect`, `admin` or `api`)

`$http_authorization`, `$http_proxy_authorization` and `$http_cookie` are
refused, so session cookies and bearer tokens cannot end up in a log.

Values are escaped like nginx `escape=default` (`"` becomes `\x22`); set
`escape = "json"` to build your own JSON lines.

**Per listener.** `[access_log.redirect]`, `[access_log.admin]` and
`[access_log.api]` override `enabled`, `format` and `output`. For example,
you can keep redirect traffic in its own file for GoAccess and send admin
and API requests elsewhere:

```toml
[access_log]
output = "/var/log/redirect-proxy/access.log"

[access_log.admin]
output = "/var/log/redirect-proxy/admin.log"

[access_log.api]
output = "/var/log/redirect-proxy/admin.log"
format = "json"
```

When the API shares the admin port, `/api` and `/oauth` requests still use
the API settings. Listeners writing to the same output share one handler.
Admin requests include health checks (`/healthz`) and Prometheus scrapes
(`/metrics`); disable `[access_log.admin]` if they are only noise for you.

**Files.** Set `output` to any path, for example
`/var/log/redirect-proxy/access.log` (the Debian package creates that
directory and ships a logrotate policy). Missing directories are created. A
renamed file is reopened within a second, so logrotate needs no
`copytruncate` or signal. You can also use the built-in rotation:
`max_bytes`, `max_files` and `compress`.

**Performance.** Each request process formats its own line, and one
dedicated OTP logger handler per output batches the writes, so the three
listeners log concurrently without coordinating. The handlers never block
or throttle requests. Under extreme overload they drop lines and report how
many were dropped in the application log. `RP_LOG_LEVEL` only controls the application
log, so access logging stays on with `RP_LOG_LEVEL=warning`. Set
`enabled = false` to turn it off entirely.

**Client address behind a proxy.** List your load balancers in
`trusted_proxies` (CIDRs). The address is then taken from `X-Forwarded-For`
(the rightmost hop that is not trusted) or `X-Real-IP`. Headers sent by any
other peer are ignored.

### GDPR

Access logs contain personal data, IP addresses in particular. The defaults
follow data minimisation (GDPR art. 5(1)(c)):

- **IP addresses are truncated** (`anonymize_ip = "truncate"`): IPv4 to /24
  (`203.0.113.0`) and IPv6 to /48. This is done before the line is written,
  so full addresses never reach the disk.
- **Query strings are not logged** (`log_query = false`). They are left out
  of the request line, the referer and the redirect location, because they
  often carry e-mail addresses, tokens or tracking identifiers.
- No cookies, credentials or request bodies are ever logged.
- The `User-Agent` and the referer (without its query) are kept, as in the
  standard formats. Use the `common` preset or a template to drop them.

You remain the data controller:

- **Retention.** Set a retention period: `max_files`, a logrotate `rotate`
  count, or your log platform's retention.
- **Records.** Document access logging (security, abuse prevention,
  statistics) in your record of processing activities.
- **Full data.** Only set `anonymize_ip = "none"` or `log_query = true` when
  you have a lawful basis for keeping that data.

## Performance

`make bench` (or the *Benchmark* workflow) generates 10 000 exact, 1 000
prefix and 500 regex rules. It then load-tests four scenarios with
[oha](https://github.com/hatoo/oha), falling back to ApacheBench:

- An exact hit.
- A prefix hit.
- The last regex.
- A miss, where every rule is tried.

It reports throughput, latency percentiles and memory. The access log is
written to a file during the run, as it is enabled by default
(`RP_ACCESS_LOG_ENABLED=false` measures without it).

Measured locally on a laptop with the self-contained bundle, using
ApacheBench (single-threaded, so the client is the bottleneck): redirects
ran at about 14 000 requests/s.

Rule lookup itself, measured in-process with the same 11 500 rules, takes
about 0.4 µs for an exact hit, 1.2 µs for a prefix hit, 1.9 µs for the last
regex rule and 0.7 µs for a miss.

Memory:

- An idle node with no rules uses about 70 MB RSS in the container image.
- Loading 11 500 rules adds about 5 MB to the shared snapshot.

Run the benchmark on your own hardware before sizing.

## Development

```sh
make help         # every target
make dev          # run with a throwaway admin
make check        # format check, warnings-as-errors build, linters, tests
make coverage     # tests under Erlang `cover`, LCOV in coverage/lcov.info
lefthook install  # optional git hooks (format, build, conventional commits)
```

The test suite has several layers:

- Unit tests.
- Property-based tests ([qcheck](https://hexdocs.pm/qcheck)), including the
  matcher against a reference implementation.
- Store tests on real files.
- End-to-end tests that start the application on ephemeral ports. These
  drive it over HTTP: redirects, login, CSRF, CRUD, import/export, `SIGHUP`
  reload, header auth, and OIDC against an in-process fake identity provider.

Coverage is measured with Erlang's `cover` on the Erlang code that Gleam
generates. It is reported per Gleam module, but line numbers refer to the
generated `.erl` files, so treat it as an approximation of source coverage.

Project layout:

```text
src/redirect_proxy/
  rule.gleam, matcher.gleam   rule model, validation, compiled matcher
  store.gleam                 single writer actor: persistence, backups, audit, reload
  proxy/server.gleam          redirect listener (mist, hot path)
  admin/                      router, auth (local, OIDC, header, sessions), views
  api/                        REST API, token endpoint, clients, OpenAPI, deprecations
  app.gleam                   supervision tree
src/redirect_proxy_ffi.erl    persistent_term, PCRE limits, atomic writes, crypto, JWT
packaging/                    launcher, systemd unit, Debian scripts, Homebrew formula
scripts/                      bundle, .deb packaging, coverage, benchmark
```

## Releasing

Releases are automated with
[release-please](https://github.com/googleapis/release-please) and
[Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` bumps the minor version.
- `fix:`, `perf:`, `security:` and `deps:` bump the patch version. Dependabot
  writes base image updates as `deps:`, so that an OS-level fix is released.
- `feat!:` or a `BREAKING CHANGE:` footer bumps the minor version while the
  version is below 1.0 (`bump-minor-pre-major`), then the major version.

Every push to `main` updates a release PR with the next version and changelog.
Merging that PR tags `vX.Y.Z` and publishes these artifacts:

- Linux amd64 and arm64 bundles that include the Erlang runtime.
- `.deb` packages, install-tested on the runner.
- A portable Erlang bundle, smoke-tested on macOS.
- `SHA256SUMS`, an SPDX SBOM and build provenance attestations.
- Multi-arch images `ghcr.io/janalis/redirect-proxy:{X.Y.Z,X.Y,X,latest}`,
  pushed only once every other artifact passed its tests, and scanned with
  Trivy on both platforms before they are pushed. `latest` only moves to the
  newest release: rebuilding an older tag leaves it alone. The published
  `latest` image is rescanned every week, and an issue is opened when a
  fixable vulnerability turns up.
- An updated Homebrew formula in `janalis/homebrew-tap`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the required repository settings.

## License

[MIT](LICENSE). The bundled [Bootstrap](https://getbootstrap.com)
6.0.0-alpha.1 is also MIT licensed (`priv/static/bootstrap/LICENSE`).
