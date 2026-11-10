# Migrating from nginx or Apache

Redirects kept in web server configuration map onto the three rule kinds
of redirect-proxy: `exact`, `prefix` and `regex` (see
[Redirection rules](rules)). This page lists the usual forms, the
differences that change behaviour, and one-liners that turn simple
configurations into the [CSV import format](rules#csv).

## Mapping

| Web server | Rule |
| --- | --- |
| nginx `location = /old { return 301 /new; }` | `match: exact`, `source: /old`, `target: /new`, `status: 301`. |
| nginx `location /old/ { return 301 /new/; }` | `match: prefix`, `source: /old/`, `target: /new/` (no `$1`: `return` does not append the rest of the path). |
| nginx `location ~ ^/old/(.*)$ { return 301 /new/$1; }` | `match: regex`, same pattern, `target: /new/$1`. `~*` is `case_insensitive: true`. |
| nginx `rewrite ^/old/(.*)$ /new/$1 permanent;` | `match: regex`, `target: /new/$1`, `status: 301` (`redirect`: `302`), `preserve_query: true`. |
| nginx `return 301 https://new.example$request_uri;` in a `server` block | `host: old.example`, `match: prefix`, `source: /`, `target: https://new.example/$1`, `preserve_query: true`. |
| nginx `map $uri $target { /old /new; }` with `return 301 $target;` | One `exact` rule per entry; `~` entries are `regex` rules. |
| Apache `Redirect 301 /old /new` | `match: prefix`, `whole_segments: true`, `source: /old`, `target: /new$1`, `preserve_query: true`. |
| Apache `RedirectMatch 301 ^/old/(.*)$ /new/$1` | `match: regex`, `target: /new/$1`, `preserve_query: true`. |
| Apache `RewriteRule ^old/(.*)$ /new/$1 [R=301,L]` | `match: regex`, `source: ^/old/(.*)$`, `target: /new/$1`, `preserve_query: true`. `[NC]` is `case_insensitive: true`. |
| Apache `RewriteCond %{HTTP_HOST} ^old\.example$ [NC]` | `host: old.example` on the rules that follow it. |
| Apache `RewriteCond %{QUERY_STRING} ^id=42$` | `query: id=42` on an `exact` rule. |
| nginx `server_name`, Apache `ServerName`/`ServerAlias` | `host`, one rule per name, or `*.example.com` for every subdomain. |

Status codes: `permanent` is 301, `redirect` (nginx) and `temp` (Apache)
are 302, `seeother` is 303; 307 and 308 are written as numbers. `gone`
(410) and other non-redirect statuses have no equivalent: leave them in
the web server, or let the [upstream](deployment#in-front-of-a-website)
answer them.

Capture groups are written the same way: `$1` to `$9`, then `${10}`. In a
prefix rule, `$1` is the rest of the path after the prefix. See
[Target substitutions](rules#target-substitutions).

## Traps

- **Query strings.** nginx `return` drops the query string unless the
  target carries `$args` or `$request_uri`. `rewrite` keeps it, unless the
  replacement ends with `?`. Apache `Redirect`, `RedirectMatch` and
  `RewriteRule` keep it, unless the target has a query of its own (or
  `RewriteRule` has `[QSD]`; `[QSA]` merges both). In redirect-proxy the
  query is dropped by default: set `preserve_query: true` to keep it.
  Parameters the target sets win over request parameters of the same
  name.
- **Prefix matching.** nginx `location /old` matches `/older` too, as a
  plain `prefix` rule does. Apache `Redirect /old` matches whole path
  segments only (`/old` and `/old/…`, not `/older`) and appends the rest
  of the path to the target: that is `whole_segments: true` and `$1` at
  the end of the target. A source ending with `/` (`Redirect /old/ /new/`)
  only matches below it: a plain `prefix` rule.
- **Leading slash in `.htaccess`.** In `.htaccess` and `<Directory>`
  blocks, `RewriteRule` patterns see the path without its leading `/`
  (`^old/`). Rules always see it: write `^/old/`.
- **Anchors.** Regex sources are not anchored automatically, as in nginx
  and Apache: `/old` as a regex also matches `/x/old/y`. Keep the `^` and
  `$` of the original pattern.
- **Hosts.** A rule without `host` applies to every host (`*`). Rules for
  one `server_name` or `RewriteCond %{HTTP_HOST}` need that `host`;
  hosts match case-insensitively and without the port.
- **`map $request_uri`** includes the query string, which `source` never
  does: convert those entries to a `source` and a `query`.
- **Order.** nginx and Apache try rules in configuration order; here exact
  rules win, then the longest prefix, then regex rules by `priority` (see
  [Resolution order](rules#resolution-order)). Give overlapping regex
  rules priorities if their order matters.
- **Exact duplicates.** Two enabled exact rules for the same host and path
  are refused, where a web server would silently use the first.

## Converting to CSV

The one-liners below handle the simple forms, one directive per line, as
written above. They give each rule an `id` derived from its source, so
that importing the file again updates the rules instead of adding them.
Check the result with `redirect-proxy rules validate FILE` before you
import it, and convert what they skip (`if` blocks, `RewriteCond`, multi
line `location` blocks) by hand. Sources and targets containing `"` need
the quote doubled.

nginx, `location = /path { return CODE target; }`:

```sh
awk 'BEGIN { print "id,match,source,target,status" }
$1 == "location" && $2 == "=" && $4 == "{" && $5 == "return" {
  target = $7; sub(/;.*/, "", target)
  id = "nginx" $3; gsub(/[^A-Za-z0-9_~-]+/, "-", id); sub(/-$/, "", id)
  printf "%s,exact,\"%s\",\"%s\",%s\n", id, $3, target, $6
}' site.conf > exact.csv
```

nginx, `rewrite regex replacement permanent|redirect;`:

```sh
awk 'BEGIN { print "id,match,source,target,status,preserve_query" }
$1 == "rewrite" && ($4 == "permanent;" || $4 == "redirect;") {
  status = ($4 == "permanent;") ? 301 : 302
  target = $3; keep = "true"
  if (target ~ /\?$/) { sub(/\?$/, "", target); keep = "false" }
  id = "nginx" $2; gsub(/[^A-Za-z0-9_~-]+/, "-", id); sub(/-$/, "", id)
  printf "%s,regex,\"%s\",\"%s\",%s,%s\n", id, $2, target, status, keep
}' site.conf > rewrite.csv
```

nginx, the entries of a `map $uri` block (one `/source target;` per line,
here with the 301 of its `return`):

```sh
awk 'BEGIN { print "id,match,source,target,status" }
NF == 2 && $1 ~ /^\// {
  target = $2; sub(/;$/, "", target)
  id = "map" $1; gsub(/[^A-Za-z0-9_~-]+/, "-", id); sub(/-$/, "", id)
  printf "%s,exact,\"%s\",\"%s\",301\n", id, $1, target
}' redirects.map > map.csv
```

Apache, `Redirect` and `RedirectMatch`:

```sh
awk 'BEGIN { print "id,match,whole_segments,source,target,status,preserve_query" }
$1 == "Redirect" || $1 == "RedirectMatch" {
  if (NF == 3) { status = "temp"; src = $2; target = $3 }
  else { status = $2; src = $3; target = $4 }
  if (status == "permanent") status = 301
  else if (status == "temp") status = 302
  else if (status == "seeother") status = 303
  else if (status !~ /^30[12378]$/) next
  keep = (target ~ /\?/) ? "false" : "true"
  kind = "regex"; whole = ""
  if ($1 == "Redirect") {
    # /old matches /old and /old/...; /old/ matches /old/... only
    kind = "prefix"; whole = (src ~ /\/$/) ? "false" : "true"
    if (keep == "true") target = target "$1"
  }
  id = "apache" src; gsub(/[^A-Za-z0-9_~-]+/, "-", id); sub(/-$/, "", id)
  printf "%s,%s,%s,\"%s\",\"%s\",%s,%s\n", id, kind, whole, src, target, status, keep
}' .htaccess > apache.csv
```

Apache, `RewriteRule ^pattern target [R…]` without `RewriteCond`:

```sh
awk 'BEGIN { print "id,match,source,target,status,preserve_query,case_insensitive" }
$1 == "RewriteRule" && $2 ~ /^\^/ && $4 ~ /^\[(.*,)?R[],=]/ {
  src = $2; sub(/^\^\/?/, "^/", src)
  status = 302
  if (match($4, /R=[0-9]+/)) status = substr($4, RSTART + 2, RLENGTH - 2)
  target = $3
  keep = (target ~ /\?/ && $4 !~ /QSA/ || $4 ~ /QSD/) ? "false" : "true"
  sub(/\?$/, "", target)
  ci = ($4 ~ /NC/) ? "true" : "false"
  id = "rewrite" src; gsub(/[^A-Za-z0-9_~-]+/, "-", id); sub(/-$/, "", id)
  printf "%s,regex,\"%s\",\"%s\",%s,%s,%s\n", id, src, target, status, keep, ci
}' .htaccess > rewriterule.csv
```

The rules of one `server_name` or virtual host need its `host`: add the
column with `sed`.

```sh
sed '1s/^/host,/; 2,$s/^/www.example.com,/' exact.csv > exact-www.csv
```

Then check and import each file:

```sh
redirect-proxy rules validate exact-www.csv
redirect-proxy rules import exact-www.csv
```

## Importing more than once

An import merges by `id`: a rule whose `id` exists replaces it, the others
are added. Ids follow the same rules as in the [API](api): up to 128
letters, digits, `.`, `_`, `~` or `-`. Without ids, every import adds the rules again: exact rules
then collide with their earlier copies and the import is refused, and
prefix and regex rules are duplicated. While the web server configuration
is still the source of truth and you convert it again and again, either
keep the `id` column, or import with `--replace` (`mode=replace` in the
[API](api)), which makes the file the whole rule set: rules created in the
admin since are removed.

`redirect-proxy rules import` writes `redirects.json`; a running server
applies it on `SIGHUP`, *Reload from disk*, or within
`storage.watch_interval` (see [Command line](cli#rules-import)). The
admin's import and `POST /api/redirects/import` apply at once.
