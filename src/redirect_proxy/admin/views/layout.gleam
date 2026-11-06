//// Page chrome shared by every admin page (Bootstrap 6).

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/role

pub const app_name = "Redirect Proxy"

pub type Flash {
  Success(String)
  Failure(String)
  Info(String)
}

/// Optional sections shown in the navigation bar.
/// Whether the session may change rules (editor or admin).
pub fn can_edit(s: Session) -> Bool {
  role.allows(s.role, role.Editor)
}

pub fn is_admin(s: Session) -> Bool {
  role.allows(s.role, role.Admin)
}

pub type Features {
  Features(users: Bool, api: Bool)
}

pub const no_features = Features(users: False, api: False)

pub type Nav {
  NavRules
  NavTest
  NavImport
  NavUsers
  NavAudit
  NavClients
  NavAccount
  NavNone
}

pub fn page(
  title title: String,
  session session: Option(Session),
  nav nav: Nav,
  flash flash: Option(Flash),
  features features: Features,
  content content: List(Element(Nil)),
) -> String {
  h.html([a.lang("en")], [
    h.head([], [
      h.meta([a.charset("utf-8")]),
      h.meta([
        a.name("viewport"),
        a.content("width=device-width, initial-scale=1"),
      ]),
      h.meta([a.name("robots"), a.content("noindex, nofollow")]),
      h.title([], title <> " · " <> app_name),
      h.link([
        a.rel("stylesheet"),
        a.href("/static/bootstrap/css/bootstrap.min.css"),
      ]),
      h.link([a.rel("stylesheet"), a.href("/static/admin.css")]),
      h.link([a.rel("icon"), a.href("/static/favicon.svg")]),
    ]),
    h.body([], [
      h.a(
        [
          a.href("#main"),
          a.class("visually-hidden-focusable btn btn-solid theme-primary m-2"),
        ],
        [h.text("Skip to content")],
      ),
      navbar(session, nav, features),
      h.main([a.id("main"), a.class("container py-4")], [
        flash_view(flash),
        ..content
      ]),
      h.footer([a.class("container pb-4 small fg-secondary")], [
        h.text(app_name),
      ]),
    ]),
  ])
  |> element.to_document_string
}

fn navbar(
  session: Option(Session),
  nav: Nav,
  features: Features,
) -> Element(Nil) {
  let link = fn(target: Nav, href: String, label: String) {
    h.li([a.class("nav-item")], [
      h.a(
        [
          a.class(case target == nav {
            True -> "nav-link active"
            False -> "nav-link"
          }),
          a.href(href),
          case target == nav {
            True -> a.aria_current("page")
            False -> a.none()
          },
        ],
        [h.text(label)],
      ),
    ])
  }
  h.nav([a.class("navbar navbar-expand border-bottom bg-body")], [
    h.div([a.class("container")], [
      h.a([a.class("navbar-brand fw-semibold"), a.href("/rules")], [
        h.text(app_name),
      ]),
      case session {
        None -> element.none()
        Some(s) ->
          element.fragment([
            h.ul(
              [a.class("navbar-nav me-auto")],
              // only what the session's role may open
              list.flatten([
                [
                  link(NavRules, "/rules", "Redirections"),
                  link(NavTest, "/test", "Test a URL"),
                ],
                case can_edit(s) {
                  True -> [link(NavImport, "/import", "Import / export")]
                  False -> []
                },
                case features.users && is_admin(s) {
                  True -> [link(NavUsers, "/users", "Users")]
                  False -> []
                },
                case features.api && is_admin(s) {
                  True -> [link(NavClients, "/api-clients", "API clients")]
                  False -> []
                },
                case is_admin(s) {
                  True -> [link(NavAudit, "/audit", "Audit log")]
                  False -> []
                },
              ]),
            ),
            h.div([a.class("d-flex align-items-center gap-2")], [
              h.a([a.class("navbar-text small"), a.href("/account")], [
                h.text(
                  session.display_name(s)
                  <> " ("
                  <> session.method_to_string(s.method)
                  <> ", "
                  <> role.to_string(s.role)
                  <> ")",
                ),
              ]),
              case s.method {
                session.Header -> element.none()
                _ ->
                  h.form([a.method("post"), a.action("/logout")], [
                    csrf_field(s),
                    h.button(
                      [
                        a.type_("submit"),
                        a.class("btn btn-sm btn-outline theme-secondary"),
                      ],
                      [h.text("Sign out")],
                    ),
                  ])
              },
            ]),
          ])
      },
    ]),
  ])
}

pub fn flash_view(flash: Option(Flash)) -> Element(Nil) {
  case flash {
    None -> element.none()
    Some(Success(message)) -> alert("theme-success", message)
    Some(Failure(message)) -> alert("theme-danger", message)
    Some(Info(message)) -> alert("theme-info", message)
  }
}

pub fn alert(theme: String, message: String) -> Element(Nil) {
  h.div([a.class("alert mb-3 " <> theme), a.role("alert")], [h.text(message)])
}

/// The errors of a form. A message prefixed with a field name (`source:
/// ...`) links to that field, where it is repeated (see `field_errors`).
pub fn errors_view(errors: List(String)) -> Element(Nil) {
  case errors {
    [] -> element.none()
    _ ->
      h.div(
        [
          a.id("errors"),
          a.class("alert mb-3 theme-danger"),
          a.role("alert"),
          a.tabindex(-1),
        ],
        [
          h.strong([], [h.text("Please fix the following:")]),
          h.ul(
            [a.class("mb-0")],
            list.map(errors, fn(e) {
              case string.split_once(e, ":") {
                Ok(#(field, _)) if field != "" ->
                  case string.contains(field, " ") {
                    True -> h.li([], [h.text(e)])
                    False ->
                      h.li([], [h.a([a.href("#" <> field)], [h.text(e)])])
                  }
                _ -> h.li([], [h.text(e)])
              }
            }),
          ),
        ],
      )
  }
}

/// The messages of `errors` about `field`, without the field prefix.
pub fn field_errors(errors: List(String), field: String) -> List(String) {
  errors
  |> list.filter_map(fn(e) {
    case string.split_once(e, ":") {
      Ok(#(f, message)) if f == field -> Ok(string.trim(message))
      _ -> Error(Nil)
    }
  })
}

/// Attributes of an input with errors: invalid, described by its messages.
pub fn invalid_attributes(
  errors: List(String),
  field: String,
) -> List(a.Attribute(Nil)) {
  case field_errors(errors, field) {
    [] -> []
    _ -> [
      a.aria_invalid("true"),
      a.aria_describedby(field <> "-errors"),
    ]
  }
}

/// The messages about a field, under it.
pub fn field_feedback(errors: List(String), field: String) -> Element(Nil) {
  case field_errors(errors, field) {
    [] -> element.none()
    messages ->
      h.div([a.id(field <> "-errors"), a.class("invalid-feedback")], [
        h.text(string.join(messages, " ")),
      ])
  }
}

pub fn csrf_field(s: Session) -> Element(Nil) {
  h.input([a.type_("hidden"), a.name("csrf_token"), a.value(s.csrf_token)])
}

/// The version of the rule a form was rendered from, so that a change made
/// meanwhile by someone else is detected instead of overwritten.
pub fn version_field(version: String) -> Element(Nil) {
  h.input([a.type_("hidden"), a.name("version"), a.value(version)])
}

pub fn heading(title: String, actions: List(Element(Nil))) -> Element(Nil) {
  h.div(
    [
      a.class(
        "d-flex flex-wrap justify-content-between align-items-center gap-2 mb-4",
      ),
    ],
    [
      h.h1([a.class("h3 mb-0")], [h.text(title)]),
      h.div([a.class("d-flex gap-2")], actions),
    ],
  )
}

pub fn button_link(href: String, label: String, theme: String) -> Element(Nil) {
  h.a([a.class("btn " <> theme), a.href(href)], [h.text(label)])
}
