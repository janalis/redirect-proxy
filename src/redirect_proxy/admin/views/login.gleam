//// The login page.

import gleam/option.{type Option, None, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element
import lustre/element/html as h
import redirect_proxy/admin/views/layout

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
