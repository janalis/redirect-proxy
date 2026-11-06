//// Login, URL tester, import/export, users and audit pages.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session} as auth_session
import redirect_proxy/admin/views/layout.{type Flash}
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/audit
import redirect_proxy/matcher/explain
import redirect_proxy/rule.{type Rule}
import redirect_proxy/users.{type User}

// --- login ------------------------------------------------------------------

pub fn login(
  error: Option(String),
  local_enabled: Bool,
  sso_label: Option(String),
  username: String,
  next: String,
) -> String {
  layout.page(
    title: "Sign in",
    session: None,
    nav: layout.NavNone,
    flash: option.map(error, layout.Failure),
    features: layout.no_features,
    content: [
      h.div([a.class("row")], [
        h.div([a.class("col-12 md:col-6 lg:col-4 mx-auto")], [
          h.div([a.class("card shadow-sm")], [
            h.div([a.class("card-body p-4")], [
              h.h1([a.class("h4 mb-4")], [h.text("Sign in")]),
              case local_enabled {
                False -> element.none()
                True ->
                  // No action: post back to the current URL so that the
                  // `next` query parameter survives.
                  h.form([a.method("post")], [
                    h.div([a.class("mb-3")], [
                      h.label([a.for("username"), a.class("form-label")], [
                        h.text("Username"),
                      ]),
                      h.input([
                        a.id("username"),
                        a.name("username"),
                        a.class("form-control"),
                        a.autocomplete("username"),
                        a.value(username),
                        a.required(True),
                        a.autofocus(True),
                      ]),
                    ]),
                    h.div([a.class("mb-3")], [
                      h.label([a.for("password"), a.class("form-label")], [
                        h.text("Password"),
                      ]),
                      h.input([
                        a.id("password"),
                        a.name("password"),
                        a.type_("password"),
                        a.class("form-control"),
                        a.autocomplete("current-password"),
                        a.required(True),
                      ]),
                    ]),
                    h.button(
                      [
                        a.type_("submit"),
                        a.class("btn btn-solid theme-primary w-100"),
                      ],
                      [h.text("Sign in")],
                    ),
                  ])
              },
              case sso_label {
                None -> element.none()
                Some(label) ->
                  h.div(
                    [
                      a.class(case local_enabled {
                        True -> "mt-3 pt-3 border-top"
                        False -> ""
                      }),
                    ],
                    [
                      h.a(
                        [
                          a.class("btn btn-outline theme-primary w-100"),
                          // SSO comes back to the same page as a password
                          a.href(case next {
                            "" -> "/auth/oidc/start"
                            next ->
                              "/auth/oidc/start?"
                              <> uri.query_to_string([#("next", next)])
                          }),
                        ],
                        [h.text(label)],
                      ),
                    ],
                  )
              },
            ]),
          ]),
        ]),
      ]),
    ],
  )
}

// --- test a URL -------------------------------------------------------------

pub type TestResult {
  NotTested
  Matched(rule: Rule, location: String)
  NoMatch
  InvalidUrl
}

pub fn test_url(
  session: Session,
  features: layout.Features,
  url: String,
  result: TestResult,
  explanation: Option(explain.Explanation),
) -> String {
  layout.page(
    title: "Test a URL",
    session: Some(session),
    nav: layout.NavTest,
    flash: None,
    features:,
    content: [
      layout.heading("Test a URL", []),
      h.form([a.method("get"), a.action("/test"), a.class("row g-2 mb-4")], [
        h.div([a.class("col-12 md:col")], [
          h.label([a.for("url"), a.class("visually-hidden")], [h.text("URL")]),
          h.input([
            a.id("url"),
            a.name("url"),
            a.class("form-control font-monospace"),
            a.value(url),
            a.placeholder("https://old.example.com/blog/42?utm_source=x"),
            a.required(True),
          ]),
        ]),
        h.div([a.class("col-12 md:col-auto")], [
          h.button(
            [a.type_("submit"), a.class("btn btn-solid theme-primary w-100")],
            [
              h.text("Test"),
            ],
          ),
        ]),
      ]),
      case result {
        NotTested -> element.none()
        InvalidUrl ->
          layout.alert(
            "theme-warning",
            "Enter an absolute URL such as https://example.com/path.",
          )
        NoMatch ->
          layout.alert(
            "theme-secondary",
            "No redirection matches this URL (the fallback applies).",
          )
        Matched(r, location) ->
          h.div([a.class("card")], [
            h.div([a.class("card-body")], [
              h.p([a.class("mb-2")], [
                h.span([a.class("badge theme-success me-2")], [
                  h.text(int.to_string(r.status)),
                ]),
                h.code([a.class("text-break")], [h.text(location)]),
              ]),
              h.p([a.class("mb-0 small fg-secondary")], [
                h.text("Matched by " <> rule.kind_to_string(r.kind) <> " rule "),
                h.code([], [h.text(r.host <> " " <> r.source)]),
                h.text(" · "),
                h.a([a.href(edit_href(r))], [h.text("edit")]),
              ]),
            ]),
          ])
      },
      case explanation {
        Some(e) -> explanation_view(e)
        None -> element.none()
      },
    ],
  )
}

fn edit_href(r: Rule) -> String {
  "/rules/" <> uri.percent_encode(r.id) <> "/edit"
}

/// Why this rule: every matching rule of the candidate hosts, and the
/// redirect chain.
fn explanation_view(e: explain.Explanation) -> Element(Nil) {
  element.fragment([
    h.h2([a.class("h5 mt-4")], [h.text("Rules matching this URL")]),
    h.p([a.class("small fg-secondary")], [
      h.text("Host "),
      h.code([], [h.text(e.host)]),
      h.text(", path compared as "),
      h.code([], [h.text(e.path)]),
      h.text(
        ". Host rules come first, then wildcard hosts, then *; within a host: exact, longest prefix, then regex by priority.",
      ),
    ]),
    case e.candidates {
      [] ->
        h.p([a.class("small")], [h.text("No rule matches, enabled or not.")])
      _ ->
        h.div([a.class("table-responsive")], [
          h.table([a.class("table table-sm align-middle")], [
            h.thead([], [
              h.tr([], [
                h.th([a.scope("col")], [h.text("Rule")]),
                h.th([a.scope("col")], [h.text("Verdict")]),
              ]),
            ]),
            h.tbody(
              [],
              list.map(e.candidates, fn(c) {
                h.tr([], [
                  h.td([], [
                    h.a([a.href(edit_href(c.rule))], [
                      h.code([], [
                        h.text(
                          c.rule.host
                          <> " "
                          <> rule.kind_to_string(c.rule.kind)
                          <> " "
                          <> c.rule.source,
                        ),
                      ]),
                    ]),
                  ]),
                  h.td([], [
                    case c.verdict {
                      explain.Applied ->
                        h.span([a.class("badge theme-success")], [
                          h.text("applies"),
                        ])
                      explain.Shadowed ->
                        h.span([a.class("badge theme-secondary")], [
                          h.text("shadowed by the rule that applies"),
                        ])
                      explain.Disabled ->
                        h.span([a.class("badge theme-warning")], [
                          h.text("disabled"),
                        ])
                    },
                  ]),
                ])
              }),
            ),
          ]),
        ])
    },
    case e.chain {
      [] | [_] -> element.none()
      chain ->
        element.fragment([
          h.h2([a.class("h5 mt-4")], [h.text("Redirect chain")]),
          h.ol(
            [],
            list.map(chain, fn(hop) {
              h.li([], [
                h.text(int.to_string(hop.status) <> " → "),
                h.code([a.class("text-break")], [h.text(hop.location)]),
              ])
            }),
          ),
          case e.loops {
            True ->
              layout.alert(
                "theme-danger",
                "This chain loops: a browser would stop with too many redirects.",
              )
            False -> element.none()
          },
        ])
    },
  ])
}

// --- import / export --------------------------------------------------------

pub fn import_export(
  session: Session,
  features: layout.Features,
  flash: Option(Flash),
  errors: List(String),
) -> String {
  layout.page(
    title: "Import / export",
    session: Some(session),
    nav: layout.NavImport,
    flash:,
    features:,
    content: [
      layout.heading("Import / export", [
        layout.button_link(
          "/export",
          "Download JSON export",
          "btn-outline theme-primary",
        ),
      ]),
      layout.errors_view(errors),
      h.form(
        [
          a.method("post"),
          a.action("/import"),
          a.enctype("multipart/form-data"),
          a.class("card"),
        ],
        [
          h.div([a.class("card-body")], [
            layout.csrf_field(session),
            h.div([a.class("mb-3")], [
              h.label([a.for("file"), a.class("form-label")], [
                h.text("JSON file"),
              ]),
              h.input([
                a.id("file"),
                a.name("file"),
                a.type_("file"),
                a.accept(["application/json", ".json"]),
                a.class("form-control"),
              ]),
              h.div([a.class("form-text")], [
                h.text(
                  "Either {\"version\": 1, \"rules\": [...]} (as exported) or a bare array of rules. Only source and target are required.",
                ),
              ]),
            ]),
            h.div([a.class("mb-3")], [
              h.label([a.for("content"), a.class("form-label")], [
                h.text("…or paste JSON"),
              ]),
              h.textarea(
                [
                  a.id("content"),
                  a.name("content"),
                  a.rows(8),
                  a.class("form-control font-monospace"),
                  a.placeholder(
                    "[{\"host\": \"*\", \"source\": \"/old\", \"target\": \"/new\", \"status\": 301}]",
                  ),
                ],
                "",
              ),
            ]),
            h.div([a.class("d-flex flex-wrap gap-3 mb-3")], [
              radio(
                "mode",
                "merge",
                "Merge (update rules with the same id, add others)",
                True,
              ),
              radio(
                "mode",
                "replace",
                "Replace every existing redirection",
                False,
              ),
            ]),
            h.div([a.class("d-flex flex-wrap gap-2")], [
              h.button(
                [
                  a.type_("submit"),
                  a.name("step"),
                  a.value("preview"),
                  a.class("btn btn-outline theme-primary"),
                ],
                [h.text("Preview changes")],
              ),
              h.button(
                [a.type_("submit"), a.class("btn btn-solid theme-primary")],
                [h.text("Import")],
              ),
            ]),
            h.div([a.class("form-text")], [
              h.text("A replace is always previewed before it is applied."),
            ]),
          ]),
        ],
      ),
    ],
  )
}

/// What an import would change, and a form to apply it.
pub fn import_preview(
  session: Session,
  features: layout.Features,
  added: List(String),
  removed: List(String),
  changed: List(String),
  content: String,
  mode: String,
  version: String,
  stale: Bool,
) -> String {
  let group = fn(title, ids, theme) {
    h.div([a.class("col-12 md:col-4")], [
      h.div([a.class("card h-100")], [
        h.div([a.class("card-body")], [
          h.h2([a.class("h6")], [
            h.span([a.class("badge " <> theme <> " me-2")], [
              h.text(int.to_string(list.length(ids))),
            ]),
            h.text(title),
          ]),
          h.ul(
            [a.class("small mb-0")],
            ids
              |> list.take(50)
              |> list.map(fn(id) { h.li([], [h.code([], [h.text(id)])]) }),
          ),
        ]),
      ]),
    ])
  }
  layout.page(
    title: "Import preview",
    session: Some(session),
    nav: layout.NavImport,
    flash: None,
    features:,
    content: [
      layout.heading("Import preview", []),
      case stale {
        True ->
          layout.alert(
            "theme-warning",
            "The redirections were changed while you were reviewing: this preview was updated. Nothing has been written yet.",
          )
        False -> h.text("")
      },
      h.p([], [
        h.text(case mode {
          "replace" ->
            "Replace every existing redirection. Nothing has been written yet."
          _ ->
            "Merge into the existing redirections. Nothing has been written yet."
        }),
      ]),
      h.div([a.class("row g-3 mb-3")], [
        group("added", added, "theme-success"),
        group("changed", changed, "theme-info"),
        group("removed", removed, "theme-danger"),
      ]),
      h.form([a.method("post"), a.action("/import"), a.class("d-flex gap-2")], [
        layout.csrf_field(session),
        h.input([a.type_("hidden"), a.name("mode"), a.value(mode)]),
        h.input([a.type_("hidden"), a.name("step"), a.value("apply")]),
        // applies exactly what is shown, or nothing if the rules changed
        h.input([a.type_("hidden"), a.name("version"), a.value(version)]),
        h.textarea([a.name("content"), a.hidden(True)], content),
        h.button([a.type_("submit"), a.class("btn btn-solid theme-primary")], [
          h.text("Apply"),
        ]),
        layout.button_link("/import", "Cancel", "btn-outline theme-secondary"),
      ]),
    ],
  )
}

fn radio(
  name: String,
  value: String,
  label: String,
  checked: Bool,
) -> Element(Nil) {
  h.label([a.class("d-flex align-items-center gap-2")], [
    h.input([
      a.type_("radio"),
      a.class("radio"),
      a.name(name),
      a.value(value),
      a.checked(checked),
    ]),
    h.text(label),
  ])
}

// --- users ------------------------------------------------------------------

pub fn users(
  session: Session,
  features: layout.Features,
  flash: Option(Flash),
  all: List(User),
  errors: List(String),
) -> String {
  layout.page(
    title: "Users",
    session: Some(session),
    nav: layout.NavUsers,
    flash:,
    features:,
    content: [
      layout.heading("Local users", []),
      layout.errors_view(errors),
      h.div([a.class("row g-4")], [
        h.div([a.class("col-12 lg:col-7")], [
          h.div([a.class("table-responsive")], [
            h.table([a.class("table align-middle")], [
              h.thead([], [
                h.tr([], [
                  h.th([], [h.text("Username")]),
                  h.th([], [h.text("Created")]),
                  h.th([], [h.text("Password changed")]),
                  h.th([a.class("text-end")], [h.text("Actions")]),
                ]),
              ]),
              h.tbody(
                [],
                list.map(all, fn(u) {
                  h.tr([], [
                    h.td([], [h.text(u.username)]),
                    h.td([a.class("small")], [h.text(u.created_at)]),
                    h.td([a.class("small")], [h.text(u.updated_at)]),
                    h.td([a.class("text-end")], [
                      case u.username == session.username {
                        True ->
                          h.span([a.class("small fg-secondary")], [
                            h.text("you"),
                          ])
                        False ->
                          h.a(
                            [
                              a.href(
                                "/users/"
                                <> uri.percent_encode(u.username)
                                <> "/delete",
                              ),
                              a.class("btn btn-sm btn-outline theme-danger"),
                              a.aria_label("Delete user " <> u.username),
                            ],
                            [h.text("Delete")],
                          )
                      },
                    ]),
                  ])
                }),
              ),
            ]),
          ]),
        ]),
        h.div([a.class("col-12 lg:col-5")], [
          user_form(session, "/users", "Add a user", True, False, "Create user"),
          h.div([a.class("mt-4")], [
            case session.method {
              auth_session.Local ->
                user_form(
                  session,
                  "/account/password",
                  "Change a password",
                  True,
                  True,
                  "Change password",
                )
              _ ->
                layout.alert(
                  "theme-secondary",
                  "You signed in with single sign-on or a proxy: only local administrators can change local passwords.",
                )
            },
          ]),
        ]),
      ]),
    ],
  )
}

fn user_form(
  session: Session,
  action: String,
  title: String,
  with_username: Bool,
  with_current: Bool,
  submit: String,
) -> Element(Nil) {
  h.form([a.method("post"), a.action(action), a.class("card")], [
    h.div([a.class("card-body")], [
      h.h2([a.class("h5 mb-3")], [h.text(title)]),
      layout.csrf_field(session),
      case with_username {
        False -> element.none()
        True ->
          h.div([a.class("mb-3")], [
            h.label([a.class("form-label"), a.for(action <> "-username")], [
              h.text("Username"),
            ]),
            h.input([
              a.id(action <> "-username"),
              a.name("username"),
              a.class("form-control"),
              a.required(True),
              a.autocomplete("off"),
            ]),
          ])
      },
      h.div([a.class("mb-3")], [
        h.label([a.class("form-label"), a.for(action <> "-password")], [
          h.text("New password"),
        ]),
        h.input([
          a.id(action <> "-password"),
          a.name("password"),
          a.type_("password"),
          a.class("form-control"),
          a.required(True),
          a.autocomplete("new-password"),
          a.attribute("minlength", "12"),
        ]),
        h.div([a.class("form-text")], [h.text("At least 12 characters.")]),
      ]),
      case with_current {
        False -> element.none()
        True ->
          h.div([a.class("mb-3")], [
            h.label([a.class("form-label"), a.for(action <> "-current")], [
              h.text("Your current password"),
            ]),
            h.input([
              a.id(action <> "-current"),
              a.name("current_password"),
              a.type_("password"),
              a.class("form-control"),
              a.required(True),
              a.autocomplete("current-password"),
            ]),
            h.div([a.class("form-text")], [
              h.text(
                "Required for any password change, yours or another user's.",
              ),
            ]),
          ])
      },
      h.button([a.type_("submit"), a.class("btn btn-solid theme-primary")], [
        h.text(submit),
      ]),
    ]),
  ])
}

/// Confirmation of a destructive action: what will happen, a form to
/// confirm it, and a way back.
pub fn confirm(
  session: Session,
  features: layout.Features,
  nav: layout.Nav,
  title: String,
  message: String,
  action: String,
  button: String,
  back: String,
) -> String {
  layout.page(
    title:,
    session: Some(session),
    nav:,
    flash: None,
    features:,
    content: [
      layout.heading(title, []),
      h.div([a.class("card")], [
        h.div([a.class("card-body")], [
          h.p([], [h.text(message)]),
          h.form([a.method("post"), a.action(action), a.class("d-flex gap-2")], [
            layout.csrf_field(session),
            h.button(
              [a.type_("submit"), a.class("btn btn-solid theme-danger")],
              [
                h.text(button),
              ],
            ),
            layout.button_link(back, "Cancel", "btn-outline theme-secondary"),
          ]),
        ]),
      ]),
    ],
  )
}

// --- audit ------------------------------------------------------------------

pub type AuditFilters {
  AuditFilters(actor: String, action: String, target: String)
}

pub fn audit_log(
  session: Session,
  features: layout.Features,
  entries: List(audit.Entry),
  filters: AuditFilters,
  page: Int,
  pages: Int,
) -> String {
  let query = fn(page) {
    [
      #("actor", filters.actor),
      #("action", filters.action),
      #("target", filters.target),
    ]
    |> list.filter(fn(kv) { kv.1 != "" })
    |> list.append([#("page", int.to_string(page))])
    |> uri.query_to_string
  }
  layout.page(
    title: "Audit log",
    session: Some(session),
    nav: layout.NavAudit,
    flash: None,
    features:,
    content: [
      layout.heading("Audit log", []),
      h.form([a.method("get"), a.action("/audit"), a.class("row g-2 mb-3")], [
        audit_filter("actor", "Who", filters.actor, "alice, oauth:client..."),
        audit_filter("action", "Action", filters.action, "rule., auth.login..."),
        audit_filter("target", "Subject", filters.target, "rule id, user..."),
        h.div([a.class("col-12 md:col-auto")], [
          h.button(
            [a.type_("submit"), a.class("btn btn-outline theme-primary w-100")],
            [h.text("Filter")],
          ),
        ]),
      ]),
      h.p([a.class("small fg-secondary")], [
        h.text(
          "Among the 1000 most recent entries, newest first. Page "
          <> int.to_string(page)
          <> " of "
          <> int.to_string(pages)
          <> ".",
        ),
      ]),
      case entries {
        [] ->
          h.div([a.class("card")], [
            h.div([a.class("card-body text-center fg-secondary")], [
              h.text("No audit entry matches."),
            ]),
          ])
        _ ->
          h.div([a.class("table-responsive")], [
            h.table([a.class("table table-sm align-middle")], [
              h.thead([], [
                h.tr([], [
                  h.th([a.scope("col")], [h.text("When")]),
                  h.th([a.scope("col")], [h.text("Who")]),
                  h.th([a.scope("col")], [h.text("Action")]),
                  h.th([a.scope("col")], [h.text("Subject")]),
                ]),
              ]),
              h.tbody([], list.map(entries, audit_row)),
            ]),
          ])
      },
      h.nav([a.aria_label("Pagination"), a.class("d-flex gap-2")], [
        case page > 1 {
          True ->
            layout.button_link(
              "/audit?" <> query(page - 1),
              "Newer",
              "btn-outline theme-secondary",
            )
          False -> element.none()
        },
        case page < pages {
          True ->
            layout.button_link(
              "/audit?" <> query(page + 1),
              "Older",
              "btn-outline theme-secondary",
            )
          False -> element.none()
        },
      ]),
    ],
  )
}

fn audit_filter(
  name: String,
  label: String,
  value: String,
  placeholder: String,
) -> Element(Nil) {
  h.div([a.class("col-12 md:col")], [
    h.label([a.for("audit-" <> name), a.class("visually-hidden")], [
      h.text(label),
    ]),
    h.input([
      a.id("audit-" <> name),
      a.name(name),
      a.value(value),
      a.class("form-control"),
      a.placeholder(label <> ": " <> placeholder),
    ]),
  ])
}

fn audit_row(e: audit.Entry) -> Element(Nil) {
  let changes = audit.changes(e)
  h.tr([], [
    h.td([a.class("small text-nowrap")], [h.text(e.at)]),
    h.td([], [h.text(e.actor)]),
    h.td([], [h.code([], [h.text(e.action)])]),
    h.td([a.class("small text-break")], [
      h.details([], [
        h.summary([], [h.text(e.target)]),
        case changes {
          [] -> element.none()
          _ ->
            h.table([a.class("table table-sm mb-2")], [
              h.thead([], [
                h.tr([], [
                  h.th([a.scope("col")], [h.text("Field")]),
                  h.th([a.scope("col")], [h.text("Before")]),
                  h.th([a.scope("col")], [h.text("After")]),
                ]),
              ]),
              h.tbody(
                [],
                list.map(changes, fn(c) {
                  h.tr([], [
                    h.td([], [h.code([], [h.text(c.0)])]),
                    h.td([], [h.text(c.1)]),
                    h.td([], [h.text(c.2)]),
                  ])
                }),
              ),
            ])
        },
        h.pre([a.class("small mb-0")], [h.text(e.details)]),
      ]),
    ]),
  ])
}

// --- errors -----------------------------------------------------------------

pub fn error(
  session: Option(Session),
  features: layout.Features,
  title: String,
  message: String,
) -> String {
  layout.page(
    title:,
    session:,
    nav: layout.NavNone,
    flash: None,
    features:,
    content: [
      layout.heading(title, []),
      layout.alert("theme-danger", message),
      layout.button_link("/rules", "Back", "btn-outline theme-secondary"),
    ],
  )
}

// --- API clients ------------------------------------------------------------

pub type IssuedSecret {
  IssuedSecret(client_id: String, secret: String)
}

pub fn api_clients(
  session: Session,
  features: layout.Features,
  flash: Option(Flash),
  all: List(clients.Client),
  issued: Option(IssuedSecret),
  errors: List(String),
  public_url: String,
) -> String {
  layout.page(
    title: "API clients",
    session: Some(session),
    nav: layout.NavClients,
    flash:,
    features:,
    content: [
      layout.heading("API clients", [
        h.a(
          [
            a.class("btn btn-outline theme-secondary"),
            a.href("/api/openapi.json"),
          ],
          [h.text("OpenAPI document")],
        ),
      ]),
      layout.errors_view(errors),
      case issued {
        None -> element.none()
        Some(IssuedSecret(client_id, secret)) ->
          h.div([a.class("alert mb-3 theme-warning"), a.role("alert")], [
            h.div([], [
              h.p([a.class("mb-2")], [
                h.strong([], [h.text("Copy the client secret now: ")]),
                h.text("it will not be shown again."),
              ]),
              h.dl([a.class("mb-0")], [
                h.dt([], [h.text("client_id")]),
                h.dd([], [
                  h.code([a.class("user-select-all")], [h.text(client_id)]),
                ]),
                h.dt([], [h.text("client_secret")]),
                h.dd([a.class("mb-0")], [
                  h.code([a.class("user-select-all text-break")], [
                    h.text(secret),
                  ]),
                ]),
              ]),
            ]),
          ])
      },
      h.div([a.class("row g-4")], [
        h.div([a.class("col-12 lg:col-7")], [
          case all {
            [] ->
              h.div([a.class("card")], [
                h.div([a.class("card-body fg-secondary")], [
                  h.text("No API client yet."),
                ]),
              ])
            _ ->
              h.div([a.class("table-responsive")], [
                h.table([a.class("table align-middle")], [
                  h.thead([], [
                    h.tr([], [
                      h.th([], [h.text("Client")]),
                      h.th([], [h.text("Scopes")]),
                      h.th([], [h.text("Last used")]),
                      h.th([a.class("text-end")], [h.text("Actions")]),
                    ]),
                  ]),
                  h.tbody([], list.map(all, client_row)),
                ]),
              ])
          },
        ]),
        h.div([a.class("col-12 lg:col-5")], [
          new_client_form(session),
          h.div([a.class("card mt-4")], [
            h.div([a.class("card-body")], [
              h.h2([a.class("h5 mb-3")], [h.text("Usage")]),
              h.pre([a.class("small mb-0 text-wrap")], [
                h.text(
                  "curl -u CLIENT_ID:CLIENT_SECRET \\\n  -d grant_type=client_credentials \\\n  "
                  <> public_url
                  <> "/oauth/token\n\ncurl -H \"Authorization: Bearer $TOKEN\" \\\n  "
                  <> public_url
                  <> "/api/redirects",
                ),
              ]),
            ]),
          ]),
        ]),
      ]),
    ],
  )
}

fn client_row(c: clients.Client) -> Element(Nil) {
  h.tr([], [
    h.td([], [
      h.div([], [h.text(c.name)]),
      h.code([a.class("small")], [h.text(c.client_id)]),
    ]),
    h.td(
      [],
      list.map(c.scopes, fn(s) {
        h.span([a.class("badge badge-subtle theme-primary me-1")], [
          h.text(scope.to_string(s)),
        ])
      }),
    ),
    h.td([a.class("small")], [
      h.text(case c.last_used_at {
        "" -> "never"
        at -> at
      }),
    ]),
    h.td([a.class("text-end text-nowrap")], [
      // both go through a confirmation page
      h.a(
        [
          a.href(
            "/api-clients/" <> uri.percent_encode(c.client_id) <> "/rotate",
          ),
          a.class("btn btn-sm btn-outline theme-secondary me-1"),
          a.aria_label("Rotate the secret of " <> c.client_id),
        ],
        [h.text("Rotate secret")],
      ),
      h.a(
        [
          a.href(
            "/api-clients/" <> uri.percent_encode(c.client_id) <> "/delete",
          ),
          a.class("btn btn-sm btn-outline theme-danger"),
          a.aria_label("Delete " <> c.client_id),
        ],
        [h.text("Delete")],
      ),
    ]),
  ])
}

fn new_client_form(session: Session) -> Element(Nil) {
  let scope_box = fn(s: scope.Scope, checked: Bool, help: String) {
    h.label([a.class("d-flex align-items-center gap-2 mb-2")], [
      h.input([
        a.type_("checkbox"),
        a.class("check"),
        a.name("scope"),
        a.value(scope.to_string(s)),
        a.checked(checked),
      ]),
      h.span([], [
        h.code([a.class("text-nowrap")], [h.text(scope.to_string(s))]),
        h.span([a.class("d-block small fg-secondary")], [h.text(help)]),
      ]),
    ])
  }
  h.form([a.method("post"), a.action("/api-clients"), a.class("card")], [
    h.div([a.class("card-body")], [
      h.h2([a.class("h5 mb-3")], [h.text("New API client")]),
      layout.csrf_field(session),
      h.div([a.class("mb-3")], [
        h.label([a.class("form-label"), a.for("client-name")], [h.text("Name")]),
        h.input([
          a.id("client-name"),
          a.name("name"),
          a.class("form-control"),
          a.required(True),
          a.placeholder("ci-pipeline"),
        ]),
      ]),
      h.div([a.class("mb-3")], [
        scope_box(scope.Read, False, "read, export, test"),
        scope_box(scope.Write, True, "create, update, delete, import"),
        scope_box(scope.Ops, False, "reload from disk"),
      ]),
      h.button([a.type_("submit"), a.class("btn btn-solid theme-primary")], [
        h.text("Create client"),
      ]),
    ]),
  ])
}
