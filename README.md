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
  - Create, read, update and delete rules, with search and filters.
  - Enable and disable rules.
  - A "test a URL" tool.
  - JSON import and export.
  - Users and an audit log.
- **Authentication:**
  - Local accounts (PBKDF2-SHA256).
  - Optional OpenID Connect single sign-on.
  - Optional trusted reverse-proxy headers.
- **Plain files.**
  - `redirects.json` can be versioned, generated and edited by hand.
  - Reload it with `SIGHUP` or a button in the admin.

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Redirection rules](#redirection-rules)
- [Configuration](#configuration)
- [Administration and authentication](#administration-and-authentication)
- [Command line](#command-line)
- [Operations](#operations)
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
| `host` | `*` | Host name to match, case-insensitively and ignoring the port. `*` matches every host. |
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

**Resolution order.** Rules for the request's `Host` are tried before the
`*` rules. Within each host, the first match wins in this order:

1. Exact rules, which are O(1) lookups.
2. Prefix rules, longest prefix first.
3. Regex rules, by priority, then file order.

**When nothing matches.** The server answers `404`, or redirects (302) to
`server.fallback_url` if it is set.

**Caching.** `301` and `308` responses carry
`Cache-Control: public, max-age=<server.cache_max_age>`. Temporary redirects
are sent with `no-store`.

**Safety checks.** A rule is rejected if any of these hold:

- It duplicates the source of another enabled exact rule on the same host.
- It redirects to itself.
- It contains control characters (header injection).
- Its regex backtracks catastrophically.

At request time, each regex match also has a fixed backtracking budget.

## Configuration

Configuration is read from the TOML file given with `--config` or
`$RP_CONFIG`. [`config.example.toml`](config.example.toml) documents every
option. Each option can be overridden with an environment variable named
`RP_<SECTION>_<KEY>`; lists are comma separated.

| Variable | Default |
| --- | --- |
| `RP_SERVER_LISTEN` / `RP_SERVER_PORT` | `0.0.0.0` / `8080` |
| `RP_SERVER_CACHE_MAX_AGE` | `3600` |
| `RP_SERVER_FALLBACK_URL` | (none) |
| `RP_ADMIN_ENABLED` | `true` |
| `RP_ADMIN_LISTEN` / `RP_ADMIN_PORT` | `127.0.0.1` / `8081` |
| `RP_ADMIN_PUBLIC_URL` | `http://localhost:8081` |
| `RP_ADMIN_SECRET_KEY_BASE` | generated into `<data_dir>/secret_key_base` |
| `RP_ADMIN_SESSION_TTL` | `28800` (8 hours) |
| `RP_STORAGE_DATA_DIR` / `RP_STORAGE_BACKUPS` | `./data` / `10` |
| `RP_AUTH_LOCAL_ENABLED` | `true` |
| `RP_AUTH_OIDC_ENABLED`, `_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_SCOPES`, `_ALLOWED_EMAILS`, `_ALLOWED_DOMAINS`, `_ALLOWED_GROUPS` | disabled |
| `RP_AUTH_HEADER_ENABLED`, `_TRUSTED_PROXIES` | disabled |
| `RP_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | creates the first local administrator when none exists |
| `RP_LOG_LEVEL` | `info` (`debug`, `warning`, `error`) |
| `NO_COLOR` | plain log lines (automatic when output is not a terminal) |

## Administration and authentication

The admin listener serves these pages:

- Redirections: search, filter, create, edit, enable/disable, delete.
- A URL tester.
- JSON import (merge or replace) and export.
- Local users.
- The audit log.
- "Reload from disk".

Unauthenticated endpoints: `/healthz`, `/readyz` and `/metrics` (Prometheus).

- **Local accounts.**
  - Passwords are hashed with PBKDF2-HMAC-SHA256 (600 000 iterations) and
    must be at least 12 characters.
  - Accounts live in `users.json`.
  - Manage them in the admin or with `redirect-proxy user …`.
- **OpenID Connect.**
  - Uses the authorization code flow with PKCE, `state` and `nonce`.
  - The ID token signature is verified against the provider JWKS, and `iss`,
    `aud` and `exp` are checked.
  - To allow users, set `allowed_emails`, `allowed_domains` (checked against
    verified emails) and/or `allowed_groups` (from `groups_claim`). With all
    three lists empty, every account of the provider is accepted.
  - Register `<admin.public_url>/auth/oidc/callback` as the redirect URI at the
    provider.
- **Trusted proxy headers.** With `auth.header` enabled, the user named in
  `X-Forwarded-User` (or `X-Forwarded-Email`) is signed in. The header is only
  accepted when the TCP peer is in `trusted_proxies`. Never expose the admin
  port directly in this mode.

Security measures:

- **Sessions.** Server-side and revocable, using signed `HttpOnly`,
  `SameSite=Lax` cookies.
- **CSRF.** Every form carries a token, and `Origin`/`Referer` are checked.
- **Login throttling.** Limits apply per IP and per account.
- **HTTP headers.** A strict Content-Security-Policy (no inline scripts),
  `X-Frame-Options: DENY` and `nosniff`.

> **Behind a reverse proxy.** Keep the `Host` header unchanged so that the
> origin check passes. Serve the admin over HTTPS so that cookies get the
> `Secure` flag.

## Command line

```text
redirect-proxy [serve] [--config FILE]
redirect-proxy check-config [--config FILE]
redirect-proxy user add|passwd|delete <username> | user list
redirect-proxy rules validate [FILE] | rules export | rules import <FILE> [--replace]
redirect-proxy version | help
```

`user add` and `user passwd` read the password from `$RP_PASSWORD` or prompt
for it. `rules import` writes the file; a running server applies it on
`SIGHUP` or "Reload from disk".

## Operations

- **Reload.** Edit `redirects.json`, then `kill -HUP <pid>` (or
  `systemctl reload redirect-proxy`). An invalid file is rejected, the error
  is logged and the current rules stay active.
- **Backups.** Each change keeps the previous file as
  `<data_dir>/backups/redirects-<ms>.json`, up to `storage.backups` copies.
- **Audit.** `<data_dir>/audit.jsonl` records who changed what, with the rule
  before and after.
- **Metrics.** `GET :8081/metrics` returns requests, redirects, misses,
  fallbacks, login failures, reloads, loaded rules, VM memory and process
  count.
- **Shutdown.** `SIGTERM` stops the VM gracefully, which suits containers and
  systemd.
- **Tuning.** Pass extra VM flags with `ERL_FLAGS`. For example, on a small
  host `ERL_FLAGS="+S 2:2 +SDio 2"` limits schedulers and lowers memory use.

## Performance

`make bench` (or the *Benchmark* workflow) generates 10 000 exact, 1 000
prefix and 500 regex rules. It then load-tests four scenarios with
[oha](https://github.com/hatoo/oha), falling back to ApacheBench:

- An exact hit.
- A prefix hit.
- The last regex.
- A miss, where every rule is tried.

It reports throughput, latency percentiles and memory.

Measured locally on a laptop with the self-contained bundle, using
ApacheBench (single-threaded, so the client is the bottleneck): exact-rule
redirects ran at about 14 000 requests/s. Regex-heavy misses ran at about
7 500 requests/s with 500 regexes evaluated on each request.

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
- `fix:`, `perf:` and `security:` bump the patch version.
- `feat!:` or a `BREAKING CHANGE:` footer bumps the major version.

Every push to `main` updates a release PR with the next version and changelog.
Merging that PR tags `vX.Y.Z` and publishes these artifacts:

- Linux amd64 and arm64 bundles that include the Erlang runtime.
- `.deb` packages, install-tested on the runner.
- A portable Erlang bundle, smoke-tested on macOS.
- `SHA256SUMS`, an SPDX SBOM and build provenance attestations.
- Multi-arch images `ghcr.io/janalis/redirect-proxy:{X.Y.Z,X.Y,X,latest}`,
  scanned with Trivy.
- An updated Homebrew formula in `janalis/homebrew-tap`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the required repository settings.

## License

[MIT](LICENSE). The bundled [Bootstrap](https://getbootstrap.com)
6.0.0-alpha.1 is also MIT licensed (`priv/static/bootstrap/LICENSE`).
