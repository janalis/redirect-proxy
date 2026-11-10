# Configuration

Configuration is read from the TOML file given with `--config` or the
`RP_CONFIG` environment variable, else from `/etc/redirect-proxy/config.toml`
when it exists (where the packages install it: `sudo` drops `RP_CONFIG`),
else defaults are used. Commands that change users, API clients or rules
print the data directory they change. [`config.example.toml`](#example-file) documents every
option. Each option can be overridden with an environment variable named
`RP_<SECTION>_<KEY>`; lists are comma separated. A number, a boolean
(`true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`) or a log level that does
not parse stops the start with an error naming the variable.

Secrets can be read from a file instead, so that they do not show in the
process environment (`docker inspect`, `/proc/<pid>/environ`): set
`RP_ADMIN_SECRET_KEY_BASE_FILE`, `RP_ADMIN_METRICS_TOKEN_FILE`,
`RP_AUTH_OIDC_CLIENT_SECRET_FILE` or
`RP_BOOTSTRAP_ADMIN_PASSWORD_FILE` to the path of a file holding the value
(Docker and Kubernetes secrets). A trailing line break is ignored.

| Variable | Default |
| --- | --- |
| `RP_SERVER_LISTEN` / `RP_SERVER_PORT` | `0.0.0.0` / `8080` |
| `RP_SERVER_CACHE_MAX_AGE` | `3600` |
| `RP_SERVER_SHUTDOWN_GRACE` | `5` (seconds) |
| `RP_SERVER_TRAILING_SLASH` | `strict` (`ignore`: retry a miss with/without the trailing slash) |
| `RP_SERVER_FALLBACK_URL` | (none) |
| `RP_SERVER_NOT_FOUND_BODY` | `Not Found` (body of the 404 when no fallback is set) |
| `RP_SERVER_HEALTH_PATH` | (none: off) |
| `RP_SERVER_METRICS_PATH` | (none: off; needs `RP_ADMIN_METRICS_TOKEN`) |
| `RP_SERVER_MAX_PATH_BYTES` | `8192` (longer paths get a 414) |
| `RP_SERVER_MAX_REQUEST_BODY_BYTES` | `0` (forwarded requests with a longer body get a 413; 0: no limit) |
| `RP_SERVER_HTTPS_REDIRECT` | `false` (redirect plain HTTP requests to HTTPS before any rule) |
| `RP_SERVER_UPSTREAM` | (none: off; an `http://` or `https://` origin that requests no rule answers are forwarded to, see [In front of a website](deployment#in-front-of-a-website)) |
| `RP_SERVER_UPSTREAM_TIMEOUT` | `60` (seconds to wait for the upstream's response head; idle timeout of upstream reads and writes) |
| `RP_SERVER_UPSTREAM_TLS_VERIFY` | `true` (check an https upstream's certificate against the system CAs) |
| `RP_ADMIN_ENABLED` | `true` |
| `RP_ADMIN_LISTEN` / `RP_ADMIN_PORT` | `127.0.0.1` / `8081` |
| `RP_ADMIN_PUBLIC_URL` | `http://localhost:8081` |
| `RP_ADMIN_SECRET_KEY_BASE` | generated into `<data_dir>/secret_key_base` |
| `RP_ADMIN_SESSION_TTL` | `28800` (8 hours) |
| `RP_ADMIN_SESSION_IDLE_TIMEOUT` | `3600` (1 hour, `0`: never) |
| `RP_ADMIN_METRICS_TOKEN` | (none: `/metrics` is public on a loopback listener, 404 on any other) |
| `RP_STORAGE_DATA_DIR` / `RP_STORAGE_BACKUPS` | `./data` / `10` |
| `RP_STORAGE_WATCH_INTERVAL` | `0` (seconds between checks of the rules file, `0`: off) |
| `RP_STORAGE_AUDIT_MAX_BYTES` / `RP_STORAGE_AUDIT_FILES` | `10485760` (10 MB, `0`: never rotate) / `5` rotated files kept |
| `RP_AUTH_LOCAL_ENABLED` | `true` |
| `RP_AUTH_OIDC_ENABLED`, `_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_SCOPES`, `_ALLOWED_EMAILS`, `_ALLOWED_DOMAINS`, `_ALLOWED_GROUPS`, `_ALLOW_ANY_ACCOUNT` | disabled |
| `RP_AUTH_OIDC_GROUPS_CLAIM`, `_BUTTON_LABEL`, `_LOGOUT_AT_PROVIDER` | `groups`, `Sign in with SSO`, `false` |
| `RP_AUTH_OIDC_ADMIN_GROUPS`, `RP_AUTH_OIDC_EDITOR_GROUPS`, `RP_AUTH_OIDC_VIEWER_GROUPS`, `RP_AUTH_OIDC_DEFAULT_ROLE` | (none), `viewer` (see [Roles](authentication#roles)) |
| `RP_AUTH_HEADER_ENABLED`, `_TRUSTED_PROXIES` | disabled |
| `RP_AUTH_HEADER_USER_HEADER`, `_EMAIL_HEADER` | `X-Forwarded-User`, `X-Forwarded-Email` (empty user header: identify by email) |
| `RP_AUTH_HEADER_ROLE_HEADER`, `RP_AUTH_HEADER_DEFAULT_ROLE` | (none), `viewer` (see [Roles](authentication#roles)) |
| `RP_API_ENABLED`, `RP_API_TOKEN_TTL`, `RP_API_MAX_BODY_BYTES`, `RP_API_REQUIRE_IF_MATCH` | `true`, `3600`, `10485760`, `false` |
| `RP_API_LISTEN` / `RP_API_PORT`, `RP_API_PUBLIC_URL` | `admin.listen` / `admin.port`, (none) |
| `RP_API_OAUTH_ENABLED`, `_ISSUER`, `_AUDIENCE`, `_SCOPE_CLAIM`, `_REQUIRE_AT_JWT`, `_READ_SCOPE`, `_WRITE_SCOPE`, `_OPS_SCOPE`, `_AUDIT_SCOPE` | disabled |
| `RP_ACCESS_LOG_ENABLED`, `_FORMAT`, `_ESCAPE`, `_OUTPUT` | `true`, `combined`, `default`, `stdout` |
| `RP_ACCESS_LOG_ANONYMIZE_IP`, `_LOG_QUERY`, `_TRUSTED_PROXIES` | `truncate`, `false`, (none) |
| `RP_ACCESS_LOG_MAX_BYTES`, `_MAX_FILES`, `_COMPRESS` | `0` (no rotation), `7`, `true` |
| `RP_ACCESS_LOG_{REDIRECT,ADMIN,API}_ENABLED`, `_FORMAT`, `_OUTPUT` | `true`, inherited, inherited |
| `RP_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | creates the first local administrator when none exists |
| `RP_LOG_LEVEL` | `info` (`debug`, `warning`, `error`); does not affect the access log |
| `RP_LOG_FORMAT` | `text` (`json`: one `{time, level, msg, domain}` object per line) |
| `NO_COLOR` | plain log lines (automatic when output is not a terminal) |

## Example file

`config.example.toml` documents every option, with its default:

<<< @/../config.example.toml
