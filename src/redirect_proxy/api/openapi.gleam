//// OpenAPI 3.1 description of the REST API, generated at runtime so that
//// deprecations from the registry are always reflected.

import gleam/int
import gleam/json.{type Json}
import gleam/list
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/rule
import redirect_proxy/store/rules as store_rules

pub fn document(registry: List(Deprecation)) -> String {
  json.object([
    #("openapi", json.string("3.1.0")),
    #(
      "info",
      json.object([
        #("title", json.string("redirect-proxy API")),
        #(
          "description",
          json.string(
            "Manage HTTP redirections. The API has no version prefix: it evolves additively and retires fields and operations through deprecation (`deprecated: true`, `Deprecation` and `Sunset` response headers) before removing them in a major release. Clients must ignore unknown response fields.",
          ),
        ),
        #("version", json.string("1")),
        #(
          "license",
          json.object([
            #("name", json.string("MIT")),
            #("identifier", json.string("MIT")),
          ]),
        ),
      ]),
    ),
    #(
      "security",
      json.array([oauth_security(), bearer_security()], fn(j) { j }),
    ),
    #("paths", paths(registry)),
    #("components", components(registry)),
  ])
  |> json.to_string
}

fn oauth_security() -> Json {
  json.object([#("oauth2", json.preprocessed_array([]))])
}

fn bearer_security() -> Json {
  json.object([#("bearer", json.preprocessed_array([]))])
}

fn ref(name: String) -> Json {
  json.object([#("$ref", json.string("#/components/schemas/" <> name))])
}

fn response(description: String, schema: Json) -> Json {
  json.object([
    #("description", json.string(description)),
    #(
      "content",
      json.object([
        #("application/json", json.object([#("schema", schema)])),
      ]),
    ),
  ])
}

fn problem_response(description: String) -> Json {
  json.object([
    #("description", json.string(description)),
    #(
      "content",
      json.object([
        #(
          "application/problem+json",
          json.object([#("schema", ref("Problem"))]),
        ),
      ]),
    ),
  ])
}

fn errors(codes: List(#(String, String))) -> List(#(String, Json)) {
  [
    #("401", problem_response("Missing, invalid or expired access token.")),
    #("403", problem_response("The token lacks the required scope.")),
    #(
      "429",
      problem_response(
        "Too many invalid access tokens from this client address. Retry-After gives the seconds to wait.",
      ),
    ),
    ..list.map(codes, fn(c) { #(c.0, problem_response(c.1)) })
  ]
}

/// Responses of operations that read a request body.
fn body_errors() -> List(#(String, Json)) {
  [
    #("413", problem_response("The body is larger than api.max_body_bytes.")),
    #("415", problem_response("The body is not of the documented media type.")),
  ]
}

fn header(description: String) -> Json {
  json.object([
    #("description", json.string(description)),
    #("schema", string_schema()),
  ])
}

fn typed(t: String, doc: String) -> Json {
  json.object([#("type", json.string(t)), #("description", json.string(doc))])
}

fn string_array() -> Json {
  json.object([#("type", json.string("array")), #("items", string_schema())])
}

fn enum_schema(values: List(String)) -> Json {
  json.object([
    #("type", json.string("string")),
    #("enum", json.array(values, json.string)),
  ])
}

fn param(name: String, location: String, schema: Json, doc: String) -> Json {
  json.object([
    #("name", json.string(name)),
    #("in", json.string(location)),
    #("required", json.bool(location == "path")),
    #("description", json.string(doc)),
    #("schema", schema),
  ])
}

fn string_schema() -> Json {
  json.object([#("type", json.string("string"))])
}

fn int_schema() -> Json {
  json.object([#("type", json.string("integer"))])
}

fn id_param() -> Json {
  param("id", "path", string_schema(), "Redirection id.")
}

fn if_match_param() -> Json {
  param(
    "If-Match",
    "header",
    string_schema(),
    "Version (ETag) the change is based on. 412 when it no longer matches.",
  )
}

/// `If-Match` on changes to the whole rule set (import, bulk).
fn set_if_match_param() -> Json {
  param(
    "If-Match",
    "header",
    string_schema(),
    "Version of the rule set (ETag of the list, the export or an import dry run) the change is based on. 412 when the rules changed since.",
  )
}

fn if_none_match_param() -> Json {
  param(
    "If-None-Match",
    "header",
    string_schema(),
    "ETag of a copy already held: 304 while it is current.",
  )
}

fn not_modified() -> #(String, Json) {
  #(
    "304",
    json.object([
      #(
        "description",
        json.string("Not modified: the copy held (If-None-Match) is current."),
      ),
    ]),
  )
}

fn set_version_header() -> #(String, Json) {
  #(
    "ETag",
    header(
      "Version of the whole rule set, for If-Match on import and bulk changes.",
    ),
  )
}

fn operation(
  registry: List(Deprecation),
  method: String,
  path: String,
  summary: String,
  scope: String,
  fields: List(#(String, Json)),
) -> #(String, Json) {
  let security = case scope {
    "" -> [#("security", json.preprocessed_array([]))]
    _ -> [
      #(
        "security",
        json.preprocessed_array([
          json.object([#("oauth2", json.array([scope], json.string))]),
          json.object([#("bearer", json.preprocessed_array([]))]),
        ]),
      ),
      #("description", json.string("Requires the `" <> scope <> "` scope.")),
    ]
  }
  #(
    method,
    json.object(
      list.flatten([
        [
          #("summary", json.string(summary)),
          #(
            "deprecated",
            json.bool(deprecation.is_route_deprecated(registry, method, path)),
          ),
        ],
        security,
        fields,
      ]),
    ),
  )
}

fn body(schema: Json, content_type: String) -> #(String, Json) {
  #(
    "requestBody",
    json.object([
      #("required", json.bool(True)),
      #(
        "content",
        json.object([#(content_type, json.object([#("schema", schema)]))]),
      ),
    ]),
  )
}

fn paths(registry: List(Deprecation)) -> Json {
  let op = fn(method, path, summary, scope, fields) {
    operation(registry, method, path, summary, scope, fields)
  }
  json.object([
    #(
      "/oauth/token",
      json.object([
        op(
          "post",
          "/oauth/token",
          "Issue an access token (OAuth 2.0 client credentials grant)",
          "",
          [
            #(
              "description",
              json.string(
                "Clients authenticate with HTTP Basic (client id and secret) or with client_id and client_secret in the form. `scope` is an optional space separated subset of the client's scopes; the token gets all of them when it is omitted. Failed attempts are throttled (429).",
              ),
            ),
            body(
              json.object([
                #("type", json.string("object")),
                #("required", json.array(["grant_type"], json.string)),
                #(
                  "properties",
                  json.object([
                    #(
                      "grant_type",
                      json.object([
                        #("type", json.string("string")),
                        #("const", json.string("client_credentials")),
                      ]),
                    ),
                    #("scope", string_schema()),
                    #("client_id", string_schema()),
                    #("client_secret", string_schema()),
                  ]),
                ),
              ]),
              "application/x-www-form-urlencoded",
            ),
            #(
              "responses",
              json.object([
                #("200", response("Access token.", ref("TokenResponse"))),
                #("400", response("OAuth error.", ref("OAuthError"))),
                #(
                  "401",
                  response("Client authentication failed.", ref("OAuthError")),
                ),
                #(
                  "429",
                  response(
                    "Too many failed attempts (error slow_down). Retry-After gives the seconds to wait.",
                    ref("OAuthError"),
                  ),
                ),
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/redirects",
      json.object([
        op("get", "/api/redirects", "List redirections", "redirects:read", [
          #(
            "parameters",
            json.preprocessed_array([
              param("q", "query", string_schema(), "Text search."),
              param("host", "query", string_schema(), "Exact host (or *)."),
              param("tag", "query", string_schema(), "Rules with this tag."),
              param(
                "match",
                "query",
                enum_schema(rule.kind_names()),
                "exact, prefix or regex.",
              ),
              param(
                "enabled",
                "query",
                enum_schema(["true", "false"]),
                "true or false.",
              ),
              param(
                "sort",
                "query",
                // the fields the list really sorts by, each also descending
                enum_schema(
                  list.flat_map(store_rules.sort_fields, fn(field) {
                    [field, "-" <> field]
                  }),
                ),
                "Sort field; - for descending. File order by default.",
              ),
              param("page", "query", int_schema(), "Page number (from 1)."),
              param("per_page", "query", int_schema(), "Page size (max 500)."),
            ]),
          ),
          #(
            "responses",
            json.object([
              #(
                "200",
                json.object([
                  #("description", json.string("A page of redirections.")),
                  #(
                    "headers",
                    json.object([
                      #(
                        "Link",
                        header("rel=\"next\" and rel=\"prev\" page URLs."),
                      ),
                      set_version_header(),
                    ]),
                  ),
                  #(
                    "content",
                    json.object([
                      #(
                        "application/json",
                        json.object([#("schema", ref("RuleList"))]),
                      ),
                    ]),
                  ),
                ]),
              ),
              ..errors([#("400", "Invalid match, enabled or sort value.")])
            ]),
          ),
        ]),
        op("post", "/api/redirects", "Create a redirection", "redirects:write", [
          body(ref("RuleInput"), "application/json"),
          #(
            "responses",
            json.object([
              #(
                "201",
                json.object([
                  #("description", json.string("Created.")),
                  #(
                    "headers",
                    json.object([
                      #("Location", header("URL of the new redirection.")),
                      #("ETag", header("Version of the new redirection.")),
                    ]),
                  ),
                  #(
                    "content",
                    json.object([
                      #(
                        "application/json",
                        json.object([#("schema", ref("Rule"))]),
                      ),
                    ]),
                  ),
                ]),
              ),
              ..list.append(
                body_errors(),
                errors([#("422", "Validation failed.")]),
              )
            ]),
          ),
        ]),
      ]),
    ),
    #(
      "/api/redirects/{id}",
      json.object([
        op("get", "/api/redirects/{id}", "Get a redirection", "redirects:read", [
          #("parameters", json.preprocessed_array([id_param()])),
          #(
            "responses",
            json.object([
              #(
                "200",
                response(
                  "The redirection, with its current hit counts. The ETag is the version of the rule (for If-Match), not of its hit counts.",
                  ref("Rule"),
                ),
              ),
              ..errors([#("404", "Not found.")])
            ]),
          ),
        ]),
        op(
          "put",
          "/api/redirects/{id}",
          "Replace a redirection",
          "redirects:write",
          [
            #(
              "parameters",
              json.preprocessed_array([id_param(), if_match_param()]),
            ),
            body(ref("RuleInput"), "application/json"),
            #(
              "responses",
              json.object([
                #("200", response("Updated.", ref("Rule"))),
                ..list.append(
                  body_errors(),
                  errors([
                    #("404", "Not found."),
                    #("412", "Version mismatch."),
                    #("422", "Validation failed."),
                  ]),
                )
              ]),
            ),
          ],
        ),
        op(
          "patch",
          "/api/redirects/{id}",
          "Update fields of a redirection (JSON merge patch)",
          "redirects:write",
          [
            #(
              "parameters",
              json.preprocessed_array([id_param(), if_match_param()]),
            ),
            body(ref("RulePatch"), "application/merge-patch+json"),
            #(
              "responses",
              json.object([
                #("200", response("Updated.", ref("Rule"))),
                ..list.append(
                  body_errors(),
                  errors([
                    #("404", "Not found."),
                    #("412", "Version mismatch."),
                    #("422", "Validation failed."),
                  ]),
                )
              ]),
            ),
          ],
        ),
        op(
          "delete",
          "/api/redirects/{id}",
          "Delete a redirection",
          "redirects:write",
          [
            #(
              "parameters",
              json.preprocessed_array([id_param(), if_match_param()]),
            ),
            #(
              "responses",
              json.object([
                #(
                  "204",
                  json.object([#("description", json.string("Deleted."))]),
                ),
                ..errors([#("404", "Not found."), #("412", "Version mismatch.")])
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/redirects/export",
      json.object([
        op(
          "get",
          "/api/redirects/export",
          "Export the redirections (all, or those matching the filters)",
          "redirects:read",
          [
            #(
              "parameters",
              json.preprocessed_array([
                param("q", "query", string_schema(), "Text search."),
                param("host", "query", string_schema(), "Exact host (or *)."),
                param("tag", "query", string_schema(), "Rules with this tag."),
                param(
                  "match",
                  "query",
                  enum_schema(rule.kind_names()),
                  "exact, prefix or regex.",
                ),
                param(
                  "enabled",
                  "query",
                  enum_schema(["true", "false"]),
                  "true or false.",
                ),
                param(
                  "format",
                  "query",
                  enum_schema(["json", "csv"]),
                  "json (default): a redirections file. csv: a header row of every column, then one rule per line (cells that a spreadsheet would run as a formula start with ').",
                ),
                if_none_match_param(),
              ]),
            ),
            #(
              "responses",
              json.object([
                #(
                  "200",
                  json.object([
                    #("description", json.string("Redirections file.")),
                    #("headers", json.object([set_version_header()])),
                    #(
                      "content",
                      json.object([
                        #(
                          "application/json",
                          json.object([#("schema", ref("RulesFile"))]),
                        ),
                        #(
                          "text/csv",
                          json.object([#("schema", string_schema())]),
                        ),
                      ]),
                    ),
                  ]),
                ),
                not_modified(),
                ..errors([#("400", "Invalid match, enabled or format value.")])
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/redirects/import",
      json.object([
        op(
          "post",
          "/api/redirects/import",
          "Import redirections (all or nothing)",
          "redirects:write",
          [
            #(
              "parameters",
              json.preprocessed_array([
                param(
                  "mode",
                  "query",
                  enum_schema(["merge", "replace"]),
                  "merge (default) or replace.",
                ),
                param(
                  "dry_run",
                  "query",
                  enum_schema(["true", "false"]),
                  "true: return what would change (added, removed, changed) without writing, with the version it was computed against as ETag: send it back in If-Match to apply exactly that change.",
                ),
                set_if_match_param(),
              ]),
            ),
            #(
              "requestBody",
              json.object([
                #("required", json.bool(True)),
                #(
                  "content",
                  json.object([
                    #(
                      "application/json",
                      json.object([#("schema", ref("RulesFile"))]),
                    ),
                    #(
                      "text/csv",
                      json.object([
                        #("schema", string_schema()),
                        #(
                          "description",
                          json.string(
                            "A header row naming the columns (those of the CSV export; source and target are required), then one rule per line.",
                          ),
                        ),
                      ]),
                    ),
                  ]),
                ),
              ]),
            ),
            #(
              "responses",
              json.object([
                #(
                  "200",
                  response(
                    "Imported.",
                    json.object([
                      #("type", json.string("object")),
                      #(
                        "properties",
                        json.object([
                          #("imported", int_schema()),
                          #("total", int_schema()),
                          #("dry_run", typed("boolean", "With dry_run=true.")),
                          #("added", int_schema()),
                          #("removed", int_schema()),
                          #("changed", int_schema()),
                          #("added_ids", string_array()),
                          #("removed_ids", string_array()),
                          #("changed_ids", string_array()),
                        ]),
                      ),
                    ]),
                  ),
                ),
                ..list.append(
                  body_errors(),
                  errors([
                    #("400", "mode is not merge or replace."),
                    #("412", "The rules changed since the If-Match version."),
                    #("422", "Validation failed."),
                  ]),
                )
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/redirects/bulk",
      json.object([
        op(
          "post",
          "/api/redirects/bulk",
          "Enable, disable or delete several redirections (all or nothing)",
          "redirects:write",
          [
            #("parameters", json.preprocessed_array([set_if_match_param()])),
            body(
              json.object([
                #("type", json.string("object")),
                #("required", json.array(["ids", "action"], json.string)),
                #(
                  "properties",
                  json.object([
                    #(
                      "ids",
                      json.object([
                        #("type", json.string("array")),
                        #("items", string_schema()),
                      ]),
                    ),
                    #("action", enum_schema(["enable", "disable", "delete"])),
                  ]),
                ),
              ]),
              "application/json",
            ),
            #(
              "responses",
              json.object([
                #(
                  "200",
                  response(
                    "Changed (rules already in the requested state are not counted).",
                    json.object([
                      #("type", json.string("object")),
                      #("properties", json.object([#("changed", int_schema())])),
                    ]),
                  ),
                ),
                ..list.append(
                  body_errors(),
                  errors([
                    #("412", "The rules changed since the If-Match version."),
                    #("422", "Unknown id, invalid action or conflict."),
                  ]),
                )
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/reload",
      json.object([
        op(
          "post",
          "/api/reload",
          "Reload the redirections file from disk",
          "redirects:ops",
          [
            #(
              "responses",
              json.object([
                #(
                  "200",
                  response(
                    "Reloaded.",
                    json.object([
                      #("type", json.string("object")),
                      #("properties", json.object([#("rules", int_schema())])),
                    ]),
                  ),
                ),
                ..errors([#("422", "The file is invalid; rules unchanged.")])
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/test",
      json.object([
        op(
          "get",
          "/api/test",
          "Resolve a URL against the current rules",
          "redirects:read",
          [
            #(
              "parameters",
              json.preprocessed_array([
                param("url", "query", string_schema(), "Absolute URL."),
              ]),
            ),
            #(
              "responses",
              json.object([
                #("200", response("Resolution.", ref("TestResult"))),
                ..errors([#("400", "Invalid URL.")])
              ]),
            ),
          ],
        ),
      ]),
    ),
    #(
      "/api/audit",
      json.object([
        op(
          "get",
          "/api/audit",
          "Audit log entries, newest first (current and rotated files)",
          "audit:read",
          [
            #(
              "parameters",
              json.preprocessed_array([
                param("actor", "query", string_schema(), "Exactly this actor."),
                param(
                  "action",
                  "query",
                  string_schema(),
                  "Actions starting with this (rule. for every rule change).",
                ),
                param(
                  "target",
                  "query",
                  string_schema(),
                  "Targets containing this.",
                ),
                param(
                  "since",
                  "query",
                  string_schema(),
                  "RFC 3339 date-time: entries at or after it.",
                ),
                param(
                  "until",
                  "query",
                  string_schema(),
                  "RFC 3339 date-time: entries before it.",
                ),
                param("page", "query", int_schema(), "Page number (from 1)."),
                param("per_page", "query", int_schema(), "Page size (max 500)."),
              ]),
            ),
            #(
              "responses",
              json.object([
                #(
                  "200",
                  response(
                    "Entries as recorded; meta.has_more (and a Link rel=next header) when older ones match.",
                    ref("AuditPage"),
                  ),
                ),
                ..errors([#("400", "Invalid date or paging value.")])
              ]),
            ),
          ],
        ),
      ]),
    ),
  ])
}

fn components(registry: List(Deprecation)) -> Json {
  json.object([
    #(
      "securitySchemes",
      json.object([
        #(
          "oauth2",
          json.object([
            #("type", json.string("oauth2")),
            #(
              "flows",
              json.object([
                #(
                  "clientCredentials",
                  json.object([
                    #("tokenUrl", json.string("/oauth/token")),
                    #(
                      "scopes",
                      json.object([
                        #(
                          "redirects:read",
                          json.string("Read, export and test redirections."),
                        ),
                        #(
                          "redirects:write",
                          json.string(
                            "Create, update, delete and import redirections (implies read).",
                          ),
                        ),
                        #(
                          "redirects:ops",
                          json.string("Reload the redirections file."),
                        ),
                        #(
                          "audit:read",
                          json.string(
                            "Read the audit log (sign-ins with client addresses, user and API client changes). Not implied by any other scope.",
                          ),
                        ),
                      ]),
                    ),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
        #(
          "bearer",
          json.object([
            #("type", json.string("http")),
            #("scheme", json.string("bearer")),
            #(
              "description",
              json.string(
                "JWT access token issued by the configured external authorization server (api.oauth).",
              ),
            ),
          ]),
        ),
      ]),
    ),
    #(
      "schemas",
      json.object([
        #("Rule", object_schema(registry, "Rule", rule_properties(True), [])),
        #(
          "RuleInput",
          object_schema(registry, "RuleInput", rule_properties(False), [
            "source", "target",
          ]),
        ),
        #(
          "RulePatch",
          object_schema(registry, "RulePatch", rule_properties(False), []),
        ),
        #(
          "RuleList",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #(
                  "data",
                  json.object([
                    #("type", json.string("array")),
                    #("items", ref("Rule")),
                  ]),
                ),
                #(
                  "meta",
                  json.object([
                    #("type", json.string("object")),
                    #(
                      "properties",
                      json.object([
                        #("total", int_schema()),
                        #("page", int_schema()),
                        #("per_page", int_schema()),
                        #("total_pages", int_schema()),
                      ]),
                    ),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
        #(
          "RulesFile",
          json.object([
            #(
              "oneOf",
              json.preprocessed_array([
                json.object([
                  #("type", json.string("object")),
                  #(
                    "properties",
                    json.object([
                      #("version", int_schema()),
                      #(
                        "rules",
                        json.object([
                          #("type", json.string("array")),
                          #("items", ref("RuleInput")),
                        ]),
                      ),
                    ]),
                  ),
                ]),
                json.object([
                  #("type", json.string("array")),
                  #("items", ref("RuleInput")),
                ]),
              ]),
            ),
          ]),
        ),
        #(
          "AuditPage",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #(
                  "data",
                  json.object([
                    #("type", json.string("array")),
                    #("items", ref("AuditEntry")),
                  ]),
                ),
                #(
                  "meta",
                  json.object([
                    #("type", json.string("object")),
                    #(
                      "properties",
                      json.object([
                        #("page", int_schema()),
                        #("per_page", int_schema()),
                        #("has_more", typed("boolean", "Older entries match.")),
                      ]),
                    ),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
        #(
          "AuditEntry",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #("at", typed("string", "RFC 3339 time.")),
                #(
                  "actor",
                  typed(
                    "string",
                    "Who: a local user, sso:<name>, proxy:<name>, client:<id>, oauth:<subject>, system, cli...",
                  ),
                ),
                #(
                  "action",
                  typed("string", "rule.create, rules.reload, auth.login..."),
                ),
                #("target", typed("string", "What it applies to.")),
                #(
                  "before",
                  typed("object", "The state before (null for none)."),
                ),
                #("after", typed("object", "The state after (null for none).")),
              ]),
            ),
          ]),
        ),
        #(
          "TestResult",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #("matched", json.object([#("type", json.string("boolean"))])),
                #("status", int_schema()),
                #("location", string_schema()),
                #("rule", ref("Rule")),
                #(
                  "candidates",
                  json.object([
                    #("type", json.string("array")),
                    #(
                      "description",
                      json.string(
                        "Every rule of the candidate hosts matching the path, in resolution order.",
                      ),
                    ),
                    #(
                      "items",
                      json.object([
                        #("type", json.string("object")),
                        #(
                          "properties",
                          json.object([
                            #(
                              "verdict",
                              enum_schema([
                                "applied", "shadowed", "disabled",
                                "out_of_schedule",
                              ]),
                            ),
                            #("rule", ref("Rule")),
                          ]),
                        ),
                      ]),
                    ),
                  ]),
                ),
                #(
                  "chain",
                  json.object([
                    #("type", json.string("array")),
                    #(
                      "description",
                      json.string(
                        "The redirects a browser follows (10 at most).",
                      ),
                    ),
                    #(
                      "items",
                      json.object([
                        #("type", json.string("object")),
                        #(
                          "properties",
                          json.object([
                            #("location", string_schema()),
                            #("status", int_schema()),
                            #("rule_id", string_schema()),
                          ]),
                        ),
                      ]),
                    ),
                  ]),
                ),
                #("loop", typed("boolean", "The chain comes back to a URL.")),
              ]),
            ),
          ]),
        ),
        #(
          "TokenResponse",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #("access_token", string_schema()),
                #("token_type", string_schema()),
                #("expires_in", int_schema()),
                #("scope", string_schema()),
              ]),
            ),
          ]),
        ),
        #(
          "OAuthError",
          json.object([
            #("type", json.string("object")),
            #(
              "properties",
              json.object([
                #("error", string_schema()),
                #("error_description", string_schema()),
              ]),
            ),
          ]),
        ),
        #(
          "Problem",
          json.object([
            #("type", json.string("object")),
            #("description", json.string("RFC 9457 problem details.")),
            #(
              "properties",
              json.object([
                #("type", string_schema()),
                #("title", string_schema()),
                #("status", int_schema()),
                #("detail", string_schema()),
                #(
                  "errors",
                  json.object([
                    #("type", json.string("array")),
                    #(
                      "items",
                      json.object([
                        #("type", json.string("object")),
                        #(
                          "properties",
                          json.object([
                            #("field", string_schema()),
                            #("message", string_schema()),
                          ]),
                        ),
                      ]),
                    ),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
      ]),
    ),
  ])
}

fn rule_properties(read_only: Bool) -> List(#(String, Json)) {
  let writable = [
    #("host", typed("string", "Host name or * (default *).")),
    #(
      "match",
      json.object([
        #("type", json.string("string")),
        #("enum", json.array(rule.kind_names(), json.string)),
      ]),
    ),
    #("source", typed("string", "Request path, prefix or PCRE regex.")),
    #(
      "target",
      typed("string", "Absolute URL or path; $1..$9 / ${n} captures."),
    ),
    #(
      "status",
      json.object([
        #("type", json.string("integer")),
        #("enum", json.array(rule.allowed_statuses, json.int)),
      ]),
    ),
    #(
      "preserve_query",
      typed(
        "boolean",
        "Append the request query string. Parameters the target sets itself win over the request's of the same name.",
      ),
    ),
    #("case_insensitive", typed("boolean", "Match regardless of case.")),
    #(
      "query",
      typed(
        "string",
        "Exact rules: query parameters the request must have, with these values (id=42&lang=fr). Other parameters are allowed; rules with more parameters win.",
      ),
    ),
    #(
      "whole_segments",
      typed(
        "boolean",
        "Prefix rules: match whole path segments only (/blog matches /blog and /blog/..., not /blogger).",
      ),
    ),
    #("priority", typed("integer", "Lower runs first (default 100).")),
    #("enabled", typed("boolean", "Disabled rules are ignored.")),
    #(
      "starts_at",
      typed(
        "string",
        "RFC 3339 date-time from which the rule applies (empty: always).",
      ),
    ),
    #(
      "expires_at",
      typed(
        "string",
        "RFC 3339 date-time from which the rule no longer applies (empty: never).",
      ),
    ),
    #("note", typed("string", "Free text.")),
    #(
      "tags",
      json.object([
        #("type", json.string("array")),
        #("items", string_schema()),
        #(
          "description",
          json.string(
            "Labels to group and filter rules: stored lower case, sorted, without duplicates; at most "
            <> int.to_string(rule.max_tags)
            <> " of at most "
            <> int.to_string(rule.max_tag_length)
            <> " characters, without commas.",
          ),
        ),
      ]),
    ),
  ]
  case read_only {
    False -> writable
    True ->
      list.flatten([
        [#("id", typed("string", "Identifier."))],
        writable,
        [
          #("created_at", typed("string", "RFC 3339 creation time.")),
          #("updated_at", typed("string", "RFC 3339 last update time.")),
          #("updated_by", typed("string", "Actor of the last change.")),
          #("version", typed("string", "Content version, also sent as ETag.")),
          #(
            "hits",
            typed(
              "integer",
              "Requests redirected (kept across restarts, saved every minute).",
            ),
          ),
          #(
            "last_hit_at",
            typed(
              "string",
              "RFC 3339 time of the last request redirected (empty: never).",
            ),
          ),
        ],
      ])
  }
}

fn object_schema(
  registry: List(Deprecation),
  schema: String,
  properties: List(#(String, Json)),
  required: List(String),
) -> Json {
  let properties =
    list.map(properties, fn(p) {
      case deprecation.is_field_deprecated(registry, schema, p.0) {
        False -> p
        True -> #(
          p.0,
          json.object([
            #("allOf", json.preprocessed_array([p.1])),
            #("deprecated", json.bool(True)),
          ]),
        )
      }
    })
  json.object([
    #("type", json.string("object")),
    #("required", json.array(required, json.string)),
    #("properties", json.object(properties)),
  ])
}
