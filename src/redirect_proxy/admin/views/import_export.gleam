//// JSON and CSV import and export, and the import preview.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout.{type Flash}

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
        layout.button_link(
          "/export?format=csv",
          "Download CSV export",
          "btn-outline theme-secondary",
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
                h.text("JSON or CSV file"),
              ]),
              h.input([
                a.id("file"),
                a.name("file"),
                a.type_("file"),
                a.accept(["application/json", ".json", "text/csv", ".csv"]),
                a.class("form-control"),
              ]),
              h.div([a.class("form-text")], [
                h.text(
                  "JSON: {\"version\": 1, \"rules\": [...]} (as exported) or a bare array of rules. CSV: a header row naming the columns (as in the CSV export), then one rule per line. Only source and target are required.",
                ),
              ]),
            ]),
            h.div([a.class("mb-3")], [
              h.label([a.for("content"), a.class("form-label")], [
                h.text("…or paste JSON or CSV"),
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
        // base64: a form turns the line breaks of a textarea into CRLF (and
        // drops a leading one), which would change multi-line cells
        h.input([
          a.type_("hidden"),
          a.name("content_base64"),
          a.value(bit_array.base64_encode(bit_array.from_string(content), True)),
        ]),
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
