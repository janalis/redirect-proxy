//// Login, URL tester, import/export, users and audit pages.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout.{type Flash}
import redirect_proxy/audit
import redirect_proxy/rule.{type Rule}
import redirect_proxy/users.{type User}

// --- login ------------------------------------------------------------------

pub fn login(
  error: Option(String),
  local_enabled: Bool,
  sso_label: Option(String),
  username: String,
) -> String {
  layout.page(
    title: "Sign in",
    session: None,
    nav: layout.NavNone,
    flash: option.map(error, layout.Failure),
    show_users: False,
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
                          a.href("/auth/oidc/start"),
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
  show_users: Bool,
  url: String,
  result: TestResult,
) -> String {
  layout.page(
    title: "Test a URL",
    session: Some(session),
    nav: layout.NavTest,
    flash: None,
    show_users:,
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
                h.a([a.href("/rules/" <> r.id <> "/edit")], [h.text("edit")]),
              ]),
            ]),
          ])
      },
    ],
  )
}

// --- import / export --------------------------------------------------------

pub fn import_export(
  session: Session,
  show_users: Bool,
  flash: Option(Flash),
  errors: List(String),
) -> String {
  layout.page(
    title: "Import / export",
    session: Some(session),
    nav: layout.NavImport,
    flash:,
    show_users:,
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
            h.button(
              [a.type_("submit"), a.class("btn btn-solid theme-primary")],
              [
                h.text("Import"),
              ],
            ),
          ]),
        ],
      ),
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
  flash: Option(Flash),
  all: List(User),
  errors: List(String),
) -> String {
  layout.page(
    title: "Users",
    session: Some(session),
    nav: layout.NavUsers,
    flash:,
    show_users: True,
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
                          h.form(
                            [
                              a.method("post"),
                              a.action("/users/" <> u.username <> "/delete"),
                            ],
                            [
                              layout.csrf_field(session),
                              h.button(
                                [
                                  a.type_("submit"),
                                  a.class("btn btn-sm btn-outline theme-danger"),
                                ],
                                [h.text("Delete")],
                              ),
                            ],
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
          user_form(session, "/users", "Add a user", True, "Create user"),
          h.div([a.class("mt-4")], [
            user_form(
              session,
              "/account/password",
              "Change a password",
              True,
              "Change password",
            ),
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
          a.min("12"),
        ]),
        h.div([a.class("form-text")], [h.text("At least 12 characters.")]),
      ]),
      h.button([a.type_("submit"), a.class("btn btn-solid theme-primary")], [
        h.text(submit),
      ]),
    ]),
  ])
}

// --- audit ------------------------------------------------------------------

pub fn audit_log(
  session: Session,
  show_users: Bool,
  entries: List(audit.Entry),
) -> String {
  layout.page(
    title: "Audit log",
    session: Some(session),
    nav: layout.NavAudit,
    flash: None,
    show_users:,
    content: [
      layout.heading("Audit log", []),
      h.p([a.class("small fg-secondary")], [
        h.text("Most recent 200 entries, newest first."),
      ]),
      h.div([a.class("table-responsive")], [
        h.table([a.class("table table-sm align-middle")], [
          h.thead([], [
            h.tr([], [
              h.th([], [h.text("When")]),
              h.th([], [h.text("Who")]),
              h.th([], [h.text("Action")]),
              h.th([], [h.text("Subject")]),
            ]),
          ]),
          h.tbody(
            [],
            list.map(entries, fn(e) {
              h.tr([], [
                h.td([a.class("small text-nowrap")], [h.text(e.at)]),
                h.td([], [h.text(e.actor)]),
                h.td([], [h.code([], [h.text(e.action)])]),
                h.td([a.class("small text-break")], [
                  h.details([], [
                    h.summary([], [h.text(e.target)]),
                    h.pre([a.class("small mb-0")], [h.text(e.details)]),
                  ]),
                ]),
              ])
            }),
          ),
        ]),
      ]),
    ],
  )
}

// --- errors -----------------------------------------------------------------

pub fn error(
  session: Option(Session),
  show_users: Bool,
  title: String,
  message: String,
) -> String {
  layout.page(
    title:,
    session:,
    nav: layout.NavNone,
    flash: None,
    show_users:,
    content: [
      layout.heading(title, []),
      layout.alert("theme-danger", message),
      layout.button_link("/rules", "Back", "btn-outline theme-secondary"),
    ],
  )
}
