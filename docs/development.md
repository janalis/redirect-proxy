[← redirect-proxy](../README.md)

# Development

```sh
make help         # every target
make dev          # run with a throwaway admin
make check        # format check, warnings-as-errors build, linters, tests
make coverage     # tests under Erlang `cover`, LCOV in coverage/lcov.info
make bench-matcher  # matcher work per request vs the baseline (reductions)
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
- `SHA256SUMS`, build provenance attestations and an SPDX SBOM of the Hex
  packages and the Erlang/OTP runtime they ship (`scripts/sbom.py`, from
  `manifest.toml`).
- Multi-arch images `ghcr.io/janalis/redirect-proxy:{X.Y.Z,X.Y,X,latest}`,
  pushed only once every other artifact passed its tests, and scanned with
  Trivy on both platforms before they are pushed. `latest` only moves to the
  newest release: rebuilding an older tag leaves it alone. The published
  `latest` image is rescanned every week, and an issue is opened when a
  fixable vulnerability turns up. Another weekly job opens an issue when
  newer versions of the locked Hex packages are available (Dependabot does
  not support Gleam).
- An updated Homebrew formula in `janalis/homebrew-tap`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the required repository settings.
