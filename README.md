<p align="center">
  <img src="docs/public/logo.png" alt="redirect-proxy" width="160">
</p>

<h1 align="center">redirect-proxy</h1>

<p align="center">
  <strong>Fast HTTP redirect server.</strong><br>
  Rules in a plain file · web administration · REST API · Docker, .deb and Homebrew
</p>

<p align="center">
  <a href="https://github.com/janalis/redirect-proxy/actions/workflows/ci.yml"><img src="https://github.com/janalis/redirect-proxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://janalis.github.io/redirect-proxy/"><img src="https://github.com/janalis/redirect-proxy/actions/workflows/docs.yml/badge.svg" alt="Docs"></a>
  <a href="https://github.com/janalis/redirect-proxy/actions/workflows/ci.yml"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fjanalis.github.io%2Fredirect-proxy%2Fbadges%2Fcoverage.json" alt="Coverage"></a>
  <a href="https://github.com/janalis/redirect-proxy/releases"><img src="https://img.shields.io/github/v/release/janalis/redirect-proxy?sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/janalis/redirect-proxy" alt="MIT license"></a>
</p>

<p align="center">
  <a href="https://janalis.github.io/redirect-proxy/"><strong>Documentation</strong></a> ·
  <a href="https://janalis.github.io/redirect-proxy/guide/getting-started">Getting started</a> ·
  <a href="https://janalis.github.io/redirect-proxy/guide/rules">Rules</a> ·
  <a href="https://janalis.github.io/redirect-proxy/guide/administration">Administration</a> ·
  <a href="https://janalis.github.io/redirect-proxy/guide/api">REST API</a>
</p>

---

redirect-proxy answers HTTP requests with `301`/`302`/`303`/`307`/`308`
redirections based on rules, and never proxies traffic to an upstream. It is
written in [Gleam](https://gleam.run) for the Erlang VM: the compiled rule
set is read by every request without locks, exact rules are O(1) lookups,
and one OS process with no database serves hundreds of thousands of
concurrent connections.

It is hard to break: an invalid rules file is never loaded, every write is
atomic and backed up, regular expressions run with a backtracking budget,
and OTP supervises it all. Rules live in `redirects.json`, which you can
version, generate or edit by hand, and are managed from a web
administration, a REST API with OAuth 2.0, or the command line, with local
accounts, OpenID Connect or proxy-header sign-in, an audit log, Prometheus
metrics and access logs.

<p align="center">
  <a href="https://janalis.github.io/redirect-proxy/guide/administration"><img src="https://janalis.github.io/redirect-proxy/screenshots/rules.png" alt="The list of redirections in the administration" width="800"></a>
</p>

## Performance

<!-- benchmark:start -->
Requests per second on a GitHub Actions Linux runner (4 vCPUs, 2 for the server) with 10,000 exact, 1,000 prefix and 500 regex rules, measured on 2026-11-07:

| Server | Version | Exact | Prefix | Regex | Miss | Memory |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| redirect-proxy | 0.6.1 | 104.6 k | 87.8 k | 81.1 k | 108.4 k | 82 MiB |
| nginx | 1.30.6 | 162.6 k | 159.9 k | 44.2 k | 50.5 k | 24 MiB |
| HAProxy | 3.4.7 | 164.1 k | 157.5 k | 62.7 k | 65.9 k | 24 MiB |
| Caddy | 2.11.9 | 10.5 k | 3.8 k | 9.1 k | 3.6 k | 133 MiB |
| Traefik | 3.7.17 | 8.4 k | 18.6 k | 27.8 k | 2.9 k | 191 MiB |
| Apache httpd | 2.4.69 | 71.7 k | 15.4 k | 12.6 k | 11.9 k | 27 MiB |

Updated every week from the *Benchmark* workflow. See [Performance](https://janalis.github.io/redirect-proxy/guide/performance#compared-with-other-servers) for the method, latencies and configurations.
<!-- benchmark:end -->

## Install

```sh
docker pull ghcr.io/janalis/redirect-proxy   # linux/amd64, linux/arm64
brew install janalis/tap/redirect-proxy      # macOS
```

`.deb` packages for Debian 12+ and Ubuntu 22.04+, self-contained Linux
bundles and a portable Erlang bundle are on the
[releases page](https://github.com/janalis/redirect-proxy/releases). See
[Installation](https://janalis.github.io/redirect-proxy/guide/installation)
for each platform, verifying downloads and building from source.

## Quick start

```sh
docker run -d --name redirect-proxy \
  -p 8080:8080 -p 127.0.0.1:8081:8081 \
  -v redirect-proxy:/var/lib/redirect-proxy \
  -e RP_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e RP_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password' \
  ghcr.io/janalis/redirect-proxy:latest
```

Open the administration at <http://localhost:8081>, create a redirection,
then try it:

```sh
curl -sI http://localhost:8080/old-page
# HTTP/1.1 301 Moved Permanently
# location: https://example.com/new-page
```

The redirect listener (`8080`) is meant to be public; keep the admin
listener (`8081`) on a trusted network. The
[getting started guide](https://janalis.github.io/redirect-proxy/guide/getting-started)
walks through it, including what to do with the bootstrap password.

## Configuration

An optional TOML file (`RP_CONFIG`, or `/etc/redirect-proxy/config.toml`)
sets listeners, storage, sign-in, the API and access logs, and every option
can be overridden with an `RP_<SECTION>_<KEY>` environment variable. See
[Configuration](https://janalis.github.io/redirect-proxy/guide/configuration)
and [`config.example.toml`](config.example.toml).

## Contributing

Bug reports and pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[development guide](https://janalis.github.io/redirect-proxy/contributing/).

```sh
make dev            # http://localhost:8081, admin / change-me-please
make check          # format check, strict build, linters, tests
make docs-dev       # preview the documentation site
```

## License

[MIT](LICENSE). The bundled [Bootstrap](https://getbootstrap.com)
6.0.0-alpha.1 is also MIT licensed (`priv/static/bootstrap/LICENSE`).
