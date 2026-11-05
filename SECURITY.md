# Security policy

## Supported versions

Security fixes are released for the latest minor version.

## Reporting a vulnerability

Please **do not open a public issue**. Report vulnerabilities privately
through
[GitHub private vulnerability reporting](https://github.com/janalis/redirect-proxy/security/advisories/new).

Include the affected version, your configuration (with secrets redacted), and
steps to reproduce. You will get an acknowledgement within a few working days
and a fix or mitigation plan once the issue is confirmed. We will credit you in
the advisory unless you prefer otherwise.

## Hardening recommendations

- Expose only the redirect listener publicly. Bind the admin to a private
  interface, or put it behind an authenticating reverse proxy served over
  HTTPS.
- When `auth.header` is enabled, restrict `trusted_proxies` to the exact
  addresses of your proxies.
- Keep `<data_dir>` readable only by the service account. It contains
  password hashes and the cookie signing secret.
