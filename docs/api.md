[← redirect-proxy](../README.md)

# REST API

The API lives under `/api`, next to the OAuth 2.0 token endpoint
`/oauth/token`. Its OpenAPI 3.1 description is at
[`/api/openapi.json`](http://localhost:8081/api/openapi.json).

The port decides which listener serves the API:

- **Same port as the admin UI** (the default; `api.port = 0` means
  `admin.port`): one listener serves both.
- **Another port:** the API gets its own listener, on `api.listen` (default
  `admin.listen`) and `api.port`, with a `/healthz` endpoint. The admin
  listener then no longer answers `/api`, so each can be exposed to different
  networks.
- **Admin UI disabled:** the API keeps running on its own listener.

```sh
# 1. Create an API client in the admin ("API clients"), or with the CLI.
#    The secret is shown only once.
redirect-proxy client add deploy --scope redirects:write

# 2. Get an access token (client credentials grant).
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  http://localhost:8081/oauth/token | jq -r .access_token)

# 3. Call the API.
curl -s -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"source": "/old", "target": "https://example.com/new", "status": 301}' \
  http://localhost:8081/api/redirects
```

| Endpoint | Scope | |
| --- | --- | --- |
| `GET /api/redirects` | `redirects:read` | Filters `q`, `host`, `match`, `enabled`, `tag`; `sort` by `source`, `host`, `hits`, `last_hit` or `updated` (`-` for descending); pages via `page` and `per_page` (positive integers; `per_page` above 500 gets 500), with a `Link` header. Invalid values answer `400`. Rules include their `hits` and `last_hit_at`. The `ETag` is the version of the whole rule set. |
| `POST /api/redirects` | `redirects:write` | Create. Returns `201`, `Location` and `ETag`. An optional `id` (up to 128 letters, digits, `.`, `_`, `~` or `-`) makes a retry safe: the same `id` again answers `409` with `Location` pointing to the rule, instead of creating a second one. |
| `GET` / `PUT` / `PATCH` / `DELETE /api/redirects/{id}` | read / write | `PATCH` is a JSON merge patch. All writes honour `If-Match` (`412` on mismatch) with the rule's `ETag`. `GET` always answers `200`: its body has the live `hits` and `last_hit_at`, which the `ETag` (the version of the rule's settings) does not cover. |
| `GET /api/redirects/export` | `redirects:read` | Same format as `redirects.json`, or CSV with `format=csv`. Takes the list filters (`q`, `host`, `match`, `enabled`, `tag`). The `ETag` is the version of the whole rule set and `If-None-Match` answers `304` (the export has no hit counts; the list, which has them, does not answer `304`). |
| `POST /api/redirects/import?mode=merge\|replace` | `redirects:write` | All or nothing, as `application/json` or `text/csv`. `dry_run=true` returns what would be added, changed and removed without writing, with an `ETag`: send it in `If-Match` to apply exactly that change (`412` if the rules changed meanwhile). |
| `POST /api/redirects/bulk` | `redirects:write` | `{"ids": [...], "action": "enable\|disable\|delete"}`, all or nothing. Honours `If-Match` with the version of the rule set. |
| `POST /api/reload` | `redirects:ops` | Re-read `redirects.json` from disk. |
| `GET /api/test?url=` | `redirects:read` | Which rule matches a URL and where it redirects, every matching rule with its verdict (applied, shadowed, disabled), and the redirect chain. |
| `GET /api/audit` | `audit:read` | Audit entries as recorded, newest first, from the current and rotated files. Filters `actor` (exact), `action` (prefix: `rule.`), `target` (contains), `since` and `until` (RFC 3339); pages via `page` and `per_page` (max 500), with `meta.has_more` and a `Link` header for the next page. |

**Tokens.**

- Tokens from `/oauth/token` are opaque and expire after `api.token_ttl`.
- Rotating a client's secret or deleting the client revokes its tokens
  immediately, including when you do it from the CLI.
- A token request can ask for fewer scopes than the client has with
  `scope=…`.
- `redirects:write` implies `redirects:read`.

**External authorization server.** With `[api.oauth]` enabled, JWT access
tokens from your own authorization server are accepted too:

- The server is found through OIDC or RFC 8414 discovery on `issuer`.
- The signature is checked against its JWKS. The discovery document and
  the JWKS are cached for an hour. While the server cannot be reached, the
  last good ones are used for up to a day more (each failed fetch is
  counted in `redirect_proxy_idp_fetch_failures_total`). A JWKS without a
  `keys` list is refused. A plain `http://` issuer on another host gets a
  startup warning, since its keys could be changed in transit.
- `iss`, `aud`, `exp` and `nbf` are verified.
- ID tokens (they carry a `nonce`) are refused: give the API an `audience`
  of its own rather than the `[auth.oidc]` `client_id` (a startup warning
  says so). ID tokens without a nonce cannot be told apart by their
  claims: if your server types its access tokens (`typ: at+jwt`, RFC 9068),
  set `require_at_jwt = true` to accept only those.
- The caller is `sub`, else `client_id`, else `azp`, recorded as
  `oauth:<subject>` in the audit log. A token with none of them is
  refused.
- Scopes are read from `scope` or `scp` and mapped through `read_scope`,
  `write_scope`, `ops_scope` and `audit_scope`.

**Errors** use [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
`application/problem+json`. Validation errors carry an `errors` array of
`{field, message}`. Authentication failures follow
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) (`WWW-Authenticate:
Bearer error="invalid_token"` or `"insufficient_scope"`). The API never uses
cookies, so it isn't exposed to CSRF.

**Compatibility.** There is no version prefix. The API only changes
additively, so clients must ignore fields they don't know. Retiring a field
or endpoint works like this:

1. It is first deprecated. It still works, and responses that use it carry a
   [`Deprecation`](https://www.rfc-editor.org/rfc/rfc9745) header, plus a
   [`Sunset`](https://www.rfc-editor.org/rfc/rfc8594) header once a removal
   date is set.
2. It is flagged `deprecated: true` in the OpenAPI document and announced in
   the changelog.
3. It is removed only in a major release.
