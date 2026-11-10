# Administration

The admin listener (port `8081` by default) serves a web administration.
Keep it on a trusted network or behind an authenticating reverse proxy: see
[Authentication](authentication). What each person can do depends on their
[role](authentication#roles).

## Redirections

Create, read, update and delete rules, with search, filters (host, match
type, state, tag) and sorting (source, host, hits, last hit, last update).
Hit counts and the time of the last hit are kept across restarts, so rules
nobody uses any more are easy to find. Enable, disable or delete a selection
of rules, or every rule matching the filters, in one change.

![The list of redirections, sorted by hits](/screenshots/rules.png)

The form explains each field. Scheduled rules show as *scheduled* or
*expired* in the list. See [Redirection rules](rules) for what every field
does.

![Editing a regular expression rule](/screenshots/rule-form.png)

## Test a URL

The tester explains the result for a URL: every rule that matches, which one
applies, which are shadowed or disabled, and the redirect chain.

![Testing a URL against the rules](/screenshots/tester.png)

## Import and export

JSON and CSV import and export. An import can be previewed (rules added,
changed and removed); a replace is always previewed first, and the preview
is applied exactly as shown.

![The preview of a CSV import](/screenshots/import-preview.png)

"Reload from disk" re-reads `redirects.json` after an edit by hand, like
`SIGHUP` (see [Operations](operations#reload)).

## Users and API clients

Local users and their roles, and the API clients of the
[REST API](api) with their scopes.

![Local users and their roles](/screenshots/users.png)

## Audit log

Who changed what, with filters and a field by field diff, and sign-ins. See
[Operations](operations#audit) for what is recorded and how the file
rotates.

![The audit log, with a rule change opened](/screenshots/audit.png)

## Health and metrics endpoints

Unauthenticated endpoints: `/healthz` (the process is up), `/readyz` (ready
for traffic: 503 while draining before a stop) and `/metrics` (Prometheus).
An API on its own port serves `/healthz` and `/readyz` too, and `/metrics`
when the admin is disabled. With `admin.metrics_token`
(`RP_ADMIN_METRICS_TOKEN`, at least 16 characters), `/metrics` answers 401
unless the request has `Authorization: Bearer <token>`: in Prometheus, set
`authorization: { credentials_file: ... }` on the scrape job. Without a
token, `/metrics` is only served by a listener on the loopback interface
(404 elsewhere, as in the container image).

The series are listed in [Monitoring](monitoring#metrics).
