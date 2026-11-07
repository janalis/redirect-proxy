[← redirect-proxy](../README.md)

# Administration and authentication

The admin listener serves these pages:

- Redirections: search, filter, create, edit, enable/disable, delete.
- A URL tester.
- JSON import (merge or replace) and export.
- Local users, with their roles.
- The audit log.
- "Reload from disk".

Unauthenticated endpoints: `/healthz` (the process is up), `/readyz` (ready
for traffic: 503 while draining before a stop) and `/metrics` (Prometheus).
An API on its own port serves `/healthz` and `/readyz` too, and `/metrics`
when the admin is disabled. With `admin.metrics_token`
(`RP_ADMIN_METRICS_TOKEN`, at least 16 characters), `/metrics` answers 401
unless the request has `Authorization: Bearer <token>`: in Prometheus, set
`authorization: { credentials_file: ... }` on the scrape job.

- **Local accounts.**
  - Passwords are hashed with PBKDF2-HMAC-SHA256 (600 000 iterations) and
    must be at least 12 characters.
  - Accounts live in `users.json`.
  - Manage them in the admin or with `redirect-proxy user …`.
- **OpenID Connect.**
  - Uses the authorization code flow with PKCE, `state` and `nonce`.
  - The ID token signature is verified against the provider JWKS, and `iss`,
    `aud`, `exp`, `nbf` and (when present) `azp` are checked.
  - The provider metadata and JWKS are cached for an hour, and the last
    good ones are used for up to a day more while the provider cannot be
    reached. A plain `http://` issuer on another host gets a startup
    warning.
  - To allow users, set `allowed_emails`, `allowed_domains` (checked against
    verified emails) and/or `allowed_groups` (from `groups_claim`). With all
    three lists empty, every account of the provider is accepted, and the
    server logs a warning at startup (and `check-config` reports it).
  - An email counts as verified only when the ID token says
    `email_verified: true`. Providers that never send that claim, such as
    Entra ID, can only be restricted with `allowed_groups`.
  - Register `<admin.public_url>/auth/oidc/callback` as the redirect URI at the
    provider.
  - After signing in, you land on the page that asked for it, as with a
    password.
  - With `logout_at_provider = true`, signing out also ends the session at
    the provider (its `end_session_endpoint`), which sends you back to the
    login page: register `<admin.public_url>/login` as a post-logout
    redirect URI there.
- **Trusted proxy headers.** With `auth.header` enabled, the user named in
  `user_header` (`X-Forwarded-User`) is signed in. Set `user_header = ""` to
  use `email_header` (`X-Forwarded-Email`) instead. The two are never
  combined. The header is only accepted when the TCP peer is in
  `trusted_proxies`, and a request carrying several values in it is refused.
  Configure the proxy to set (not append to) that header, and never expose the
  admin port directly in this mode. The session ends on the first request
  that arrives without the header (signed out at the proxy, or a replayed
  cookie). A user and role have one session: a client that does not keep
  cookies (a script, a monitoring check) reuses it rather than starting a
  session, and an `auth.login` audit entry, on every request.

## Roles

Every session has a role, and each includes the one before:

| Role | May |
| --- | --- |
| `viewer` | See the rules (with their details), test URLs, export, change their own password. |
| `editor` | Also create, change, delete, enable and disable rules, import, and reload. |
| `admin` | Also manage local users and API clients, and read the audit log (which records sign-ins with client addresses). |

Pages and buttons a role cannot use are not shown, and the server answers
403 to their requests. Roles come from:

- **Local accounts:** the role stored with the user, chosen when the user
  is created (`redirect-proxy user add <name> --role editor`, or the admin's
  users page) and changed there or with `redirect-proxy user role <name>
  <role>`. A change applies to the user's sessions at once. Accounts created
  before roles are administrators, and the last administrator cannot be
  demoted or deleted. Every role can change its own password on the
  account page.
- **OpenID Connect:** `admin_groups`, `editor_groups` and `viewer_groups`
  name groups of `groups_claim`. A user gets the highest role their groups
  give, and `default_role` (`viewer`) when they are in none of them. Set
  `admin_groups`, or `default_role = "admin"`, for someone to manage users
  and API clients: the server warns at startup when no one can get the
  admin role. The role is set
  at sign-in: a change of groups at the provider applies at the next
  sign-in, at the latest after `admin.session_ttl`.
- **Trusted proxy headers:** with `role_header` (for example
  `X-Forwarded-Role`), the proxy sets the role of each request; a missing,
  repeated or unknown value gives `viewer`, and the session follows changes
  of the header. Without it, every proxy user gets `default_role`
  (`viewer`).

API clients are not affected: they have scopes (see [REST API](api.md)).

## Security measures

- **Sessions.** Server-side and revocable, using signed `HttpOnly`,
  `SameSite=Lax` cookies.
  - A session ends after `session_ttl`, or after `session_idle_timeout`
    without a request.
  - A local account's sessions end when the user is deleted or their
    password changes, including from the CLI. Changing your own password
    keeps you signed in, in a new session.
  - SSO logins are bound to the browser that started them.
- **Passwords.** Changing a local password, yours or another user's, needs
  your current password and a local session: administrators signed in with
  SSO or proxy headers cannot change local passwords. Deleting a user or an
  API client, and rotating a secret, ask for a confirmation.
- **CSRF.** Every form carries a token, and `Origin`/`Referer` are checked.
- **Login throttling.** Over 15 minutes, a client may fail 10 times for
  one account and 20 times in all; an account accepts 100 failures from all
  clients. IPv6 clients are counted by /64, since one host usually holds a
  whole /64. A browser where the account signed in with its password before
  (a signed `rp_device` cookie, kept 90 days) is not held back by the
  account's limit, so failures from elsewhere cannot lock its owner out.
  The API token endpoint allows 10 failures for one client id and 30 in
  all per client address. There is no limit per client id alone: secrets
  are too long to guess, so such a limit would only let anyone lock a
  pipeline out. Token requests are limited to 64 KB. A client may start 30
  SSO logins and fail 20 SSO callbacks, and the API accepts 100 invalid
  access tokens from one client before answering 429 without checking more.
  A throttled request gets a 429 with `Retry-After`. An attempt is counted
  before the password is checked, so parallel guesses get no more than
  the limits. Password checks also run at most a few at once (half the CPU
  cores, at least 2): past that, a login gets a 503 with `Retry-After: 1`,
  so that a burst of logins leaves CPU for the redirect listener. Behind a
  proxy, list it in `access_log.trusted_proxies` so that the client address
  is the forwarded one.
- **Input limits.** Admin forms are limited to 64 KB (imports: like the API,
  `api.max_body_bytes`) and usernames to 64 bytes.
- **HTTP headers.** A strict Content-Security-Policy (no inline scripts),
  `X-Frame-Options: DENY` and `nosniff`. When `admin.public_url` is
  `https://`, responses carry `Strict-Transport-Security` and the session
  and SSO state cookies are named `__Host-rp_session` and
  `__Host-rp_oidc_state`, which a sibling subdomain cannot set or shadow.

> **Behind a reverse proxy.** Keep the `Host` header unchanged so that the
> origin check passes. Serve the admin over HTTPS so that cookies get the
> `Secure` flag, and send `X-Forwarded-Proto`.
