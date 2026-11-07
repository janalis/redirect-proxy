# Releasing

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

## Repository setup

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
5. **Documentation site.** In *Settings → Pages*, set the source to
   *GitHub Actions*. The *Docs* workflow then publishes the site, its
   screenshots and the coverage badge on every push to `main`.
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
