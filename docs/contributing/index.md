# Development

The contribution rules (commits, tests, pull requests) are in
[CONTRIBUTING.md](https://github.com/janalis/redirect-proxy/blob/main/CONTRIBUTING.md).

```sh
make help         # every target
make dev          # run with a throwaway admin
make check        # format check, warnings-as-errors build, linters, tests
make coverage     # tests under Erlang `cover`, LCOV in coverage/lcov.info
make bench-matcher  # matcher work per request vs the baseline (reductions)
make bench-store    # time to load 50 000 rules and to change one
lefthook install  # optional git hooks (format, build, conventional commits)
```

The documentation site is built with [VitePress](https://vitepress.dev)
from `docs/` (Node 20+):

```sh
make docs-deps    # npm ci, and Chromium for the screenshots
make screenshots  # run the server on demo rules and capture the admin
make docs-dev     # live preview at http://localhost:5173/redirect-proxy/
make docs         # the whole site, as published
```

The screenshots are not committed. `docs/scripts/screenshots.mjs` starts the
server on free ports with the rules of `docs/screenshots/redirects.json`,
makes a few changes so that the audit log and the users and API clients
pages have content, then captures each page. The *Docs* workflow does the
same on every push to `main`, so the pictures always show the current admin.
To show a new page, add it to the script and reference
`/screenshots/<name>.png` from the page.

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
`make coverage` also writes `coverage/badge.json`, which the *Docs* workflow
publishes with the site for the README badge.

Project layout:

```text
src/redirect_proxy/
  rule.gleam, matcher.gleam   rule model, validation, compiled matcher
  rule/template.gleam         target templates and their host guard
  store.gleam                 single writer actor: persistence, backups, audit, reload
  proxy/server.gleam          redirect listener (mist, hot path)
  admin/                      router, auth (local, OIDC, header, sessions), views
  api/                        REST API: router, handlers, token endpoint, clients, OpenAPI
  app.gleam                   supervision tree
src/redirect_proxy_ffi.erl    persistent_term, PCRE limits, atomic writes, crypto, JWT
packaging/                    launcher, systemd unit, Debian scripts, Homebrew formula
scripts/                      bundle, .deb packaging, coverage, benchmark
```

See [Releasing](releasing) for versions and published artifacts.
