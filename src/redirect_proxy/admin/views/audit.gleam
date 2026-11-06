//// The audit log.

import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/audit

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
