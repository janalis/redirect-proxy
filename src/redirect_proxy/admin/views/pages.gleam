//// Pages shared by every section: confirmations and errors.

import gleam/option.{type Option, None, Some}
import lustre/attribute as a
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout

// --- confirmations ---------------------------------------------------------

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
