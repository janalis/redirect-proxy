# Contributing

Thanks for helping improve redirect-proxy!

## Development setup

You need [Gleam](https://gleam.run/getting-started/installing/) 1.19+ and
Erlang/OTP 27+ (see `.tool-versions`).

Optional tools, which `make lint` skips when they are missing:

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
- Update `README.md` and `config.example.toml` when configuration or
  behaviour changes.

## Releases

Releases are fully automated by `.github/workflows/release.yml`, so do not
edit `CHANGELOG.md` or version numbers by hand.

One-time repository setup:

1. **Workflow permissions.** In *Settings → Actions → General*, allow GitHub
   Actions to create and approve pull requests. release-please needs this.
2. **Packages.** The container image is pushed to GHCR with `GITHUB_TOKEN`.
   Make the package public after the first release.
3. **Homebrew tap.** Add a `HOMEBREW_TAP_TOKEN` secret: a fine-grained token
   with *Contents: read and write* on `janalis/homebrew-tap`. Without it the
   tap update is skipped with a warning.
4. **Coverage.** Optionally add a `CODECOV_TOKEN` secret.
5. **Package maintainer.** Optionally set a `PACKAGE_MAINTAINER` repository
   variable (`Name <email>`) for the `.deb` metadata.
6. **First release.** `0.1.0` is the initial version recorded in
   `.release-please-manifest.json`. Tag the initial commit `v0.1.0`, create
   the GitHub release, then run the *Release* workflow manually with
   `tag: v0.1.0` to build and attach its artifacts. After that, release-please
   handles every later version.

To rebuild the artifacts of an existing release, run the *Release* workflow
manually with its tag.
