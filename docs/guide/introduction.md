# What is redirect-proxy?

A fast HTTP redirect server written in [Gleam](https://gleam.run) for the
Erlang VM, with a web administration backend.

It sits in front of your website, behind the web server or load balancer
that terminates TLS: it answers the requests its rules match with
`301`/`302`/`303`/`307`/`308` redirections, and passes every other request
on to the website (`server.upstream`), as a reverse proxy. The redirects
live in one place, whatever the site is built with. Domains that only
redirect need no website behind it. [Web servers](web-servers) shows the
setup with nginx, HAProxy, Apache httpd, Caddy and Traefik.

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

![The list of redirections in the administration](/screenshots/rules.png)

Next: [install it](installation) or go straight to the [quick start](getting-started).
