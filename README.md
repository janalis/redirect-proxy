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
- **Administration backend** (Bootstrap 6, a pre-release):
  - Create, read, update and delete rules, with search, filters (host, match
    type, state, tag) and sorting (source, host, hits, last hit, last update).
    Hit counts and the time of the last hit are kept across restarts, so
    rules nobody uses any more are easy to find.
  - Enable, disable or delete a selection of rules, or every rule matching
    the filters, in one change.
  - A "test a URL" tool that explains the result: every rule that matches,
    which one applies, which are shadowed or disabled, and the redirect chain.
  - JSON and CSV import and export. An import can be previewed (rules added, changed
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

## Documentation

- [Redirection rules](docs/rules.md): matching, substitutions, scheduled
  rules, tags, CSV.
- [Configuration](docs/configuration.md): the configuration file and every
  environment variable.
- [Administration and authentication](docs/administration.md): the admin
  pages, local accounts, OpenID Connect, proxy headers, roles, security.
- [REST API](docs/api.md): endpoints, OAuth 2.0 tokens, errors,
  compatibility.
- [Operations](docs/operations.md): command line, reloads, backups, hit
  counts, audit, metrics, shutdown, several instances, performance.
- [Access logs](docs/access-logs.md): formats, outputs, rotation, GDPR.
- [Development](docs/development.md): building, testing, releasing.

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
redirect-proxy` re-reads the redirections file only: changes to
`config.toml` need `systemctl restart redirect-proxy`.

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

## License

[MIT](LICENSE). The bundled [Bootstrap](https://getbootstrap.com)
6.0.0-alpha.1 is also MIT licensed (`priv/static/bootstrap/LICENSE`).
