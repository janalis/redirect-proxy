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

`make coverage` fails under `COVERAGE_MIN` percent of covered lines (see
the `Makefile`). A test in `test/redirect_proxy/docs_test.gleam` fails when
an `RP_…` variable read in `config/env.gleam` is missing from the
configuration table of `README.md`.

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
4. **Checks on the release PR.** A PR opened with `GITHUB_TOKEN` does not
   trigger the CI workflow, so the release PR has no checks by default. Add
   a `RELEASE_PLEASE_TOKEN` secret, a fine-grained token on this repository
   with *Contents* and *Pull requests: read and write*, so that release-please
   opens it with that token instead.
5. **Coverage.** Optionally add a `CODECOV_TOKEN` secret.
6. **Package maintainer.** Optionally set a `PACKAGE_MAINTAINER` repository
   variable (`Name <email>`) for the `.deb` metadata.
7. **First release (new forks only).** release-please starts from the
   version in `.release-please-manifest.json` and needs a matching tag and
   GitHub release to compute the next one. On a fresh fork, tag the commit
   that holds that version `v<version>`, create its GitHub release, then run
   the *Release* workflow manually with that tag to build and attach its
   artifacts. After that, release-please handles every later version.

Keep `main`'s history: release-please finds the last release from the
release commit it merged. If `main` is rewound past a release commit while
its tag stays, the next release PR proposes that version again, and
publishing it fails because the tag exists. Restore the release commit on
`main` (or delete the tag and its GitHub release, if nothing was published)
before merging more work.

To rebuild the artifacts of an existing release, run the *Release* workflow
manually with its tag.
