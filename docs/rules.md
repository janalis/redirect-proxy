[← redirect-proxy](../README.md)

# Redirection rules

Rules are stored in `<data_dir>/redirects.json`:

```json
{
  "version": 1,
  "rules": [
    { "source": "/old", "target": "https://example.com/new" },
    {
      "host": "docs.example.com",
      "match": "prefix",
      "source": "/v1/",
      "target": "https://docs.example.com/v2/$1",
      "status": 302,
      "preserve_query": true
    },
    {
      "match": "regex",
      "source": "^/blog/(\\d+)(?:/[a-z0-9-]*)?$",
      "target": "/articles/$1",
      "status": 308,
      "note": "Legacy blog URLs"
    }
  ]
}
```

Only `source` and `target` are required, and a bare array of rules is also
accepted. Ids and timestamps are added automatically.

| Field | Default | Description |
| --- | --- | --- |
| `host` | `*` | Host name to match, case-insensitively and without a port (requests match whatever their port). `*` matches every host; `*.example.com` matches every subdomain of `example.com` (not `example.com` itself). International names are written in punycode (`xn--caf-dma.example`). |
| `match` | `exact` | `exact`, `prefix` or `regex`. |
| `source` | (required) | The request path without its query string. Regexes are PCRE and are not anchored automatically. |
| `target` | (required) | An absolute `http(s)://` URL, a protocol-relative `//host/path` or a path `/path`. |
| `status` | `301` | `301`, `302`, `303`, `307` or `308`. |
| `preserve_query` | `false` | Append the request query string to the target. Parameters the target sets itself win: a request parameter of the same name is dropped (`/new?lang=fr` with `?lang=en&utm=x` gives `/new?lang=fr&utm=x`). |
| `case_insensitive` | `false` | Match the source without regard to case. |
| `query` | `""` | Exact rules only: query parameters the request must have, with these values (`id=42&lang=fr`; other parameters are allowed). For the same path, a rule with query parameters wins over one without, and more parameters win. Written to the file only when set. |
| `whole_segments` | `false` | Prefix rules only: match whole path segments, so that `/blog` matches `/blog` and `/blog/…` but not `/blogger`. `$1` is then empty or starts with `/`. Written to the file only when `true`. |
| `priority` | `100` | Lower runs first, among regex rules and among prefix rules of the same length. |
| `enabled` | `true` | Disabled rules are kept but ignored. |
| `starts_at` | `""` | RFC 3339 date-time with a time zone (`2026-12-01T00:00:00Z`) from which the rule applies. Empty: always. |
| `expires_at` | `""` | RFC 3339 date-time from which the rule no longer applies. Empty: never. |
| `note` | `""` | Free text shown in the admin. |
| `tags` | `[]` | Labels to group and filter rules (`["campaign", "legacy"]`): stored lower case, sorted and without duplicates; at most 20, each at most 40 characters, without commas. Written to the file only when set. |

**CSV.** Imports (admin, API, `rules import`, `rules validate`) also take
CSV: a header row naming the columns, then one rule per line. The columns
are those of the CSV export: `id`, `host`, `match`, `source`, `target`,
`status`, `preserve_query`, `case_insensitive`, `whole_segments`, `query`,
`priority`, `enabled`, `starts_at`, `expires_at`, `tags` and `note`, in any
order. Only `source` and `target` are required; empty cells take the
default, booleans are `true`/`false` (or `yes`/`no`, `1`/`0`), and tags are
separated by commas inside a quoted cell (`"campaign, legacy"`). Unknown
columns are refused, so that a typo does not drop a field. In an export,
cells that a spreadsheet would run as a formula (starting with `=`, `+`,
`-`, `@`) start with `'`, which an import removes.

**Scheduled rules.** A rule with `starts_at` or `expires_at` only applies
within that window: the server republishes the rules within a second of a
boundary, without touching the file, and the admin list marks rules as
"scheduled" or "expired". Two exact rules for one path may take turns (a
campaign target, then the usual one) as long as their windows do not
overlap. Both fields are written to the file only when set.

**Target substitutions:**

| Syntax | Meaning |
| --- | --- |
| `$1` … `$9`, `${10}` | Regex capture groups. |
| `$0` | The whole match. |
| `$1` in a prefix rule | The rest of the path after the prefix. |
| `${host}` | The request host, lower case, without its port. Only as the whole host of the target (`https://${host}/$1`): the result must keep that host. |
| `${sub}` | For a wildcard rule host (`*.old.example`), what `*` stands for in the request (`a.b` for `a.b.old.example`): `https://${sub}.new.example/$1`. |
| `$$` | A literal `$`. |

Substitutions apply to prefix and regex rules. The target of an exact rule
is used as written, `$` included.

**Resolution order.** Rules for the request's `Host` are tried first, then
those of wildcard hosts from the closest one (for `a.b.example.com`:
`*.b.example.com`, then `*.example.com`), then the `*` rules. Within each
host, the first match wins in this order:

1. Exact rules, which are O(1) lookups.
2. Prefix rules, longest prefix first.
3. Regex rules, by priority, then file order.

Prefix rules, and regex rules that start with `^` and a literal (such as
`^/blog/(\d+)$`), are indexed by that literal. A lookup costs one dictionary
access per distinct literal length instead of one test per rule. Only regex
rules without a leading literal (unanchored, using `|`, or case-insensitive)
are tried one by one on every request that reaches them. Put a literal
prefix in your patterns when you can.

**Equivalent paths.** Paths are compared in one form, so a rule written
`/café` matches the `/caf%C3%A9` browsers send, and `%7e` matches `~`.
Escapes of unreserved characters and of valid UTF-8 are decoded; the
others, such as `%2F` (which is not a path separator), are kept and
compared in upper case. Regex rules see the path in this form too. In the
`Location` header, non-ASCII characters are percent-encoded.

**Trailing slashes.** By default `/docs` and `/docs/` are different paths.
With `server.trailing_slash = "ignore"` (`RP_SERVER_TRAILING_SLASH`), a
request that matches no rule is retried with the trailing slash added or
removed. A rule for the exact form always wins.

**When nothing matches.** The server answers `404`, or redirects (302) to
`server.fallback_url` if it is set.

**Caching.** `301` and `308` responses carry
`Cache-Control: public, max-age=<server.cache_max_age>`. Temporary redirects
are sent with `no-store`.

**Safety checks.** A rule is rejected if any of these hold:

- It duplicates the source of another enabled exact rule on the same host.
- It redirects to itself.
- When created or edited, a request to it would be redirected back to it,
  directly or through other rules (for example `/a/` → `/a/b/$1`). Up to 10
  redirects are followed, as a browser would. When the rules file is
  loaded, loops are logged as warnings instead, so a file that loaded before
  keeps loading.
- When created or edited, it can never apply as written: an exact or prefix
  source with a query string (`?`: use `query` instead) or a fragment
  (`#`), or starting with `//` (the server reads a request for `//a/b` as
  the path `/b`), or a host with a port. These are also logged as warnings
  when the file is loaded or rules
  are imported. Loop checks follow `server.trailing_slash`.
- It contains control characters (header injection).
- Its regex backtracks catastrophically.

At request time, each regex match also has a fixed backtracking budget.

**Substitutions cannot leave the target's host.** Captures come from the
request path, so they are checked after `$1`... are replaced (open redirect
guard):

- A target starting with `/` stays a path on the same host: leading `/` and
  `\` are collapsed, so `/old/(.*)` → `/$1` sends `/old//evil.com` to
  `/evil.com`, not to `//evil.com`.
- An absolute target keeps its host: with `https://example.com$1`,
  `/go/page` redirects but `/go.evil.com` and `/go@evil.com` do not.
- A host starting with placeholders, as in `https://$1.example.com/`, must
  stay a subdomain of `example.com`. Placeholders elsewhere in the host
  (`https://example$1.com/`, `https://$1.com/`) never redirect, and such
  targets are refused when a rule is created or edited.
- `https://${host}...` must keep the request's host, and `${host}` is only
  filled with a host name (letters, digits, `-` and `.`).

A rule whose result fails the check does not match, so the next rule or
the 404 applies.

The server cannot tell `http` from `https` requests, so a rule redirecting
a host to itself over another scheme (`https://${host}/$1` on that host) is
refused as a redirect loop.
