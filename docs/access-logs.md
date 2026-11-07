[← redirect-proxy](../README.md)

# Access logs

The redirect, admin and API listeners write one line per request. Logging
is configured in the `[access_log]` section of the configuration file. By
default every listener uses the Combined Log Format on stdout, so
`docker logs`, `journalctl -u redirect-proxy` and Kubernetes log collectors
pick it up:

```text
203.0.113.0 - - [06/Nov/2026:10:00:00 +0000] "GET /old-page HTTP/1.1" 301 0 "https://www.example.org/" "Mozilla/5.0 ..."
```

| `format` | Use with |
| --- | --- |
| `combined` (default) | GoAccess (`--log-format=COMBINED`), AWStats, Logstash (`%{COMBINEDAPACHELOG}`), Fluent Bit (`apache2` parser), Datadog and Loki nginx pipelines |
| `common` | Tools expecting the NCSA Common Log Format |
| `json` | Elasticsearch/OpenSearch, Loki (`json` stage), Vector, Splunk, Datadog |
| a template | Anything else, e.g. `'$time_iso8601 $remote_addr $status $request_time $rule_id'` |

Templates use nginx variable names (`$var` or `${var}`):

- `remote_addr`, `remote_user`
- `time_local`, `time_iso8601`, `msec`
- `request`, `request_method`, `request_uri`, `uri`, `args`,
  `server_protocol`, `host`
- `status`, `body_bytes_sent`, `request_time`
- `http_referer`, `http_user_agent`, `http_<header>`
- `location` (the redirect target), `rule_id` (the matched rule),
  `listener` (`redirect`, `admin` or `api`)

`$http_authorization`, `$http_proxy_authorization` and `$http_cookie` are
refused, so session cookies and bearer tokens cannot end up in a log.

Values are escaped like nginx `escape=default` (`"` becomes `\x22`); set
`escape = "json"` to build your own JSON lines.

**Per listener.** `[access_log.redirect]`, `[access_log.admin]` and
`[access_log.api]` override `enabled`, `format` and `output`. For example,
you can keep redirect traffic in its own file for GoAccess and send admin
and API requests elsewhere:

```toml
[access_log]
output = "/var/log/redirect-proxy/access.log"

[access_log.admin]
output = "/var/log/redirect-proxy/admin.log"

[access_log.api]
output = "/var/log/redirect-proxy/admin.log"
format = "json"
```

When the API shares the admin port, `/api` and `/oauth` requests still use
the API settings. Listeners writing to the same output share one handler.
Admin requests include health checks (`/healthz`) and Prometheus scrapes
(`/metrics`); disable `[access_log.admin]` if they are only noise for you.

**Files.** Set `output` to any path, for example
`/var/log/redirect-proxy/access.log` (the Debian package creates that
directory and ships a logrotate policy). Missing directories are created. A
renamed file is reopened within a second, so logrotate needs no
`copytruncate` or signal. You can also use the built-in rotation:
`max_bytes` (0, or at least 65536), `max_files` (1 to 100) and `compress`.
Use one or the other, not both: they name rotated files the same way
(`access.log.1`...) and would overwrite each other's. With the Debian
package's logrotate policy, leave `max_bytes = 0`.

**Performance.** Each request process formats its own line, and one
dedicated OTP logger handler per output batches the writes, so the three
listeners log concurrently without coordinating. The handlers never block
or throttle requests. Under extreme overload they drop lines and report how
many were dropped in the application log. `RP_LOG_LEVEL` only controls the application
log, so access logging stays on with `RP_LOG_LEVEL=warning`. Set
`enabled = false` to turn it off entirely.

**Client address behind a proxy.** List your load balancers in
`trusted_proxies` (CIDRs). The address is then taken from `X-Forwarded-For`
(the rightmost hop that is not trusted) or `X-Real-IP`, if it is an IP
address (otherwise the proxy's own address is used). Headers sent by any
other peer are ignored. Make sure your proxy sets `X-Real-IP` itself rather
than passing on the client's: the client address keys every throttle.

## GDPR

Access logs contain personal data, IP addresses in particular. The defaults
follow data minimisation (GDPR art. 5(1)(c)):

- **IP addresses are truncated** (`anonymize_ip = "truncate"`): IPv4 to /24
  (`203.0.113.0`) and IPv6 to /48 (6to4 addresses, which embed an IPv4
  address, to its /24). Headers that carry client addresses, when a custom
  format logs them (`$http_x_forwarded_for`, `$http_x_real_ip`,
  `$http_forwarded`, `$http_cf_connecting_ip`...), are truncated hop by hop
  too. This is done before the line is written, so full addresses never
  reach the disk.
- **Query strings are not logged** (`log_query = false`). They are left out
  of the request line, the referer and the redirect location, because they
  often carry e-mail addresses, tokens or tracking identifiers.
- No cookies, credentials or request bodies are ever logged.
- The `User-Agent` and the referer (without its query) are kept, as in the
  standard formats. Use the `common` preset or a template to drop them.

You remain the data controller:

- **Retention.** Set a retention period: `max_files`, a logrotate `rotate`
  count, or your log platform's retention.
- **Records.** Document access logging (security, abuse prevention,
  statistics) in your record of processing activities.
- **Full data.** Only set `anonymize_ip = "none"` or `log_query = true` when
  you have a lawful basis for keeping that data.
