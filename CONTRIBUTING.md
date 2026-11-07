# Contributing

Thanks for helping improve redirect-proxy!

## Development setup

You need [Gleam](https://gleam.run/getting-started/installing/) 1.19+ and
Erlang/OTP 27+ (see `.tool-versions`).

Optional tools, which `make lint` skips when they are missing (`make check
STRICT=1` fails instead, so that a local pass means CI will pass):

- shellcheck
- actionlint
- hadolint
- markdownlint-cli2
- [lefthook](https://lefthook.dev) for git hooks
- Docker, for `make docker` and for building `.deb` packages without nfpm

```sh
make deps
make dev      # http://localhost:8081, admin / change-me-please
make check    # what CI runs: format check, strict build, linters, tests
```

`make coverage` fails under `COVERAGE_MIN` percent of covered lines (see
the `Makefile`), counting application code only (test helpers and
benchmarks are left out). Tests in `test/redirect_proxy/docs_test.gleam`
fail when an `RP_…` variable read in `config/env.gleam` is missing from the
configuration table of `docs/guide/configuration.md`, or a metric `/metrics`
exports is missing from `docs/guide/monitoring.md`.

## Pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages and PR titles. They drive versioning and the changelog:
  - `feat:` new behaviour (minor bump)
  - `fix:`, `perf:`, `security:` (patch bump)
  - `feat!:` or a `BREAKING CHANGE:` footer (major bump)
  - `docs:`, `test:`, `refactor:`, `ci:`, `build:`, `chore:` (no release)
- Add tests for every behaviour change. Hot-path changes (`matcher.gleam`,
  `proxy/server.gleam`) should come with `make bench` numbers before and
  after.
- Keep the Erlang FFI minimal and compiled with warnings as errors
  (`make lint-erlang`).
- Update the documentation (`README.md`, `docs/`, previewed with
  `make docs-dev`) and `config.example.toml` when configuration or
  behaviour changes.

## Releases

Releases are fully automated by `.github/workflows/release.yml`, so do not
edit `CHANGELOG.md` or version numbers by hand. See
[Releasing](https://janalis.github.io/redirect-proxy/contributing/releasing)
for the versioning rules and the one-time repository setup.
