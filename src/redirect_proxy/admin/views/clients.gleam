//// API clients and their secrets.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout.{type Flash}
import redirect_proxy/api/clients
import redirect_proxy/api/scope

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
