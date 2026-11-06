//// Admin users and their passwords.

import gleam/list
import gleam/option.{type Option, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session} as auth_session
import redirect_proxy/admin/views/layout.{type Flash}
import redirect_proxy/users.{type User}

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
