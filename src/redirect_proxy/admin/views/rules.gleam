//// Redirection list, form and delete confirmation pages.

import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/string
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout.{type Flash}
import redirect_proxy/rule.{type Rule}

pub type Filters {
  Filters(query: String, kind: String, status: String, page: Int)
}

pub type Row {
  Row(rule: Rule, hits: Int)
}

pub const page_size = 50

pub fn index(
  session: Session,
  show_users: Bool,
  flash: Option(Flash),
  rows: List(Row),
  total: Int,
  filters: Filters,
) -> String {
  let pages = int.max(1, { list.length(rows) + page_size - 1 } / page_size)
  let page = int.clamp(filters.page, 1, pages)
  let visible =
    rows |> list.drop({ page - 1 } * page_size) |> list.take(page_size)
  layout.page(
    title: "Redirections",
    session: option.Some(session),
    nav: layout.NavRules,
    flash:,
    show_users:,
    content: [
      layout.heading("Redirections", [
        h.form([a.method("post"), a.action("/reload")], [
          layout.csrf_field(session),
          h.button(
            [
              a.type_("submit"),
              a.class("btn btn-outline theme-secondary"),
              a.title("Re-read the redirections file from disk"),
            ],
            [h.text("Reload from disk")],
          ),
        ]),
        layout.button_link(
          "/rules/new",
          "New redirection",
          "btn-solid theme-primary",
        ),
      ]),
      filters_form(filters),
      h.p([a.class("small fg-secondary")], [
        h.text(
          int.to_string(list.length(rows))
          <> " matching of "
          <> int.to_string(total)
          <> " redirection(s)",
        ),
      ]),
      case visible {
        [] ->
          h.div([a.class("card")], [
            h.div([a.class("card-body text-center fg-secondary")], [
              h.text("No redirection found."),
            ]),
          ])
        _ -> table(session, visible)
      },
      pagination(filters, page, pages),
    ],
  )
}

fn filters_form(filters: Filters) -> Element(Nil) {
  h.form([a.method("get"), a.action("/rules"), a.class("row g-2 mb-3")], [
    h.div([a.class("col-12 md:col")], [
      h.label([a.for("q"), a.class("visually-hidden")], [h.text("Search")]),
      h.input([
        a.type_("search"),
        a.id("q"),
        a.name("q"),
        a.value(filters.query),
        a.class("form-control"),
        a.placeholder("Search host, source, target or note"),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("kind"), a.class("visually-hidden")], [h.text("Match")]),
      h.select([a.id("kind"), a.name("kind"), a.class("form-control")], [
        option("", "All match types", filters.kind),
        option("exact", "Exact", filters.kind),
        option("prefix", "Prefix", filters.kind),
        option("regex", "Regex", filters.kind),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("status"), a.class("visually-hidden")], [h.text("State")]),
      h.select([a.id("status"), a.name("status"), a.class("form-control")], [
        option("", "Enabled and disabled", filters.status),
        option("enabled", "Enabled only", filters.status),
        option("disabled", "Disabled only", filters.status),
      ]),
    ]),
    h.div([a.class("col-12 md:col-auto")], [
      h.button(
        [a.type_("submit"), a.class("btn btn-outline theme-primary w-100")],
        [
          h.text("Filter"),
        ],
      ),
    ]),
  ])
}

fn option(value: String, label: String, current: String) -> Element(Nil) {
  h.option([a.value(value), a.selected(value == current)], label)
}

fn table(session: Session, rows: List(Row)) -> Element(Nil) {
  h.div([a.class("table-responsive")], [
    h.table([a.class("table table-hover align-middle")], [
      h.thead([], [
        h.tr([], [
          h.th([], [h.text("Host")]),
          h.th([], [h.text("Source")]),
          h.th([], [h.text("Target")]),
          h.th([], [h.text("Status")]),
          h.th([a.class("text-end")], [h.text("Hits")]),
          h.th([], [h.text("State")]),
          h.th([a.class("text-end")], [h.text("Actions")]),
        ]),
      ]),
      h.tbody([], list.map(rows, row(session, _))),
    ]),
  ])
}

fn row(session: Session, row: Row) -> Element(Nil) {
  let r = row.rule
  h.tr([], [
    h.td([a.class("text-nowrap")], [h.text(r.host)]),
    h.td([], [
      kind_badge(r.kind),
      h.text(" "),
      h.code([a.class("text-break")], [h.text(r.source)]),
      case r.note {
        "" -> element.none()
        note -> h.div([a.class("small fg-secondary")], [h.text(note)])
      },
    ]),
    h.td([a.class("text-break")], [h.code([], [h.text(r.target)])]),
    h.td([], [h.text(int.to_string(r.status))]),
    h.td([a.class("text-end")], [h.text(int.to_string(row.hits))]),
    h.td([], [
      h.form(
        [
          a.method("post"),
          a.action("/rules/" <> uri.percent_encode(r.id) <> "/toggle"),
        ],
        [
          layout.csrf_field(session),
          h.button(
            [
              a.type_("submit"),
              a.class(case r.enabled {
                True -> "badge theme-success border-0"
                False -> "badge theme-secondary border-0"
              }),
              a.title("Click to toggle"),
            ],
            [
              h.text(case r.enabled {
                True -> "enabled"
                False -> "disabled"
              }),
            ],
          ),
        ],
      ),
    ]),
    h.td([a.class("text-end text-nowrap")], [
      h.a(
        [
          a.class("btn btn-sm btn-outline theme-primary me-1"),
          a.href("/rules/" <> uri.percent_encode(r.id) <> "/edit"),
        ],
        [h.text("Edit")],
      ),
      h.a(
        [
          a.class("btn btn-sm btn-outline theme-danger"),
          a.href("/rules/" <> uri.percent_encode(r.id) <> "/delete"),
        ],
        [h.text("Delete")],
      ),
    ]),
  ])
}

fn kind_badge(kind: rule.MatchKind) -> Element(Nil) {
  let theme = case kind {
    rule.Exact -> "theme-primary"
    rule.Prefix -> "theme-info"
    rule.Regex -> "theme-warning"
  }
  h.span([a.class("badge badge-subtle " <> theme)], [
    h.text(rule.kind_to_string(kind)),
  ])
}

fn pagination(filters: Filters, page: Int, pages: Int) -> Element(Nil) {
  case pages {
    1 -> element.none()
    _ -> {
      let href = fn(p) {
        "/rules?"
        <> uri.query_to_string([
          #("q", filters.query),
          #("kind", filters.kind),
          #("status", filters.status),
          #("page", int.to_string(p)),
        ])
      }
      let item = fn(p: Int, label: String, enabled: Bool, active: Bool) {
        h.li(
          [
            a.class(
              "page-item"
              <> case active {
                True -> " active"
                False -> ""
              }
              <> case enabled {
                True -> ""
                False -> " disabled"
              },
            ),
          ],
          [h.a([a.class("page-link"), a.href(href(p))], [h.text(label)])],
        )
      }
      h.nav([a.aria_label("Pagination")], [
        h.ul(
          [a.class("pagination")],
          list.flatten([
            [item(page - 1, "Previous", page > 1, False)],
            int.range(from: pages, to: 0, with: [], run: fn(acc, p) {
              [p, ..acc]
            })
              |> list.filter(fn(p) {
                p == 1 || p == pages || int.absolute_value(p - page) <= 2
              })
              |> list.map(fn(p) { item(p, int.to_string(p), True, p == page) }),
            [item(page + 1, "Next", page < pages, False)],
          ]),
        ),
      ])
    }
  }
}

// --- form -------------------------------------------------------------------

pub fn form(
  session: Session,
  show_users: Bool,
  r: Rule,
  errors: List(String),
  is_new: Bool,
) -> String {
  let title = case is_new {
    True -> "New redirection"
    False -> "Edit redirection"
  }
  let action = case is_new {
    True -> "/rules"
    False -> "/rules/" <> uri.percent_encode(r.id)
  }
  layout.page(
    title:,
    session: option.Some(session),
    nav: layout.NavRules,
    flash: option.None,
    show_users:,
    content: [
      layout.heading(title, []),
      layout.errors_view(errors),
      h.form([a.method("post"), a.action(action), a.class("card")], [
        h.div([a.class("card-body")], [
          layout.csrf_field(session),
          h.div([a.class("row g-3")], [
            field_col("md:col-4", [
              label("host", "Host"),
              h.input([
                a.id("host"),
                a.name("host"),
                a.class(input_class(errors, "host")),
                a.value(r.host),
                a.required(True),
                a.placeholder("*"),
              ]),
              help("Host name to match (port ignored), or * for any host."),
            ]),
            field_col("md:col-4", [
              label("match", "Match type"),
              h.select(
                [a.id("match"), a.name("match"), a.class("form-control")],
                [
                  option("exact", "Exact path", rule.kind_to_string(r.kind)),
                  option("prefix", "Path prefix", rule.kind_to_string(r.kind)),
                  option(
                    "regex",
                    "Regular expression",
                    rule.kind_to_string(r.kind),
                  ),
                ],
              ),
              help("Exact > prefix (longest first) > regex (by priority)."),
            ]),
            field_col("md:col-4", [
              label("status", "HTTP status"),
              h.select(
                [a.id("status"), a.name("status"), a.class("form-control")],
                list.map(
                  [
                    #(301, "301 Moved Permanently"),
                    #(302, "302 Found"),
                    #(303, "303 See Other"),
                    #(307, "307 Temporary Redirect"),
                    #(308, "308 Permanent Redirect"),
                  ],
                  fn(s) {
                    option(int.to_string(s.0), s.1, int.to_string(r.status))
                  },
                ),
              ),
            ]),
            field_col("col-12", [
              label("source", "Source"),
              h.input([
                a.id("source"),
                a.name("source"),
                a.class(input_class(errors, "source") <> " font-monospace"),
                a.value(r.source),
                a.required(True),
                a.placeholder("/old-path or ^/blog/(\\d+)$"),
              ]),
              help(
                "Path (without query string). Regexes are not anchored automatically; use ^ and $.",
              ),
            ]),
            field_col("col-12", [
              label("target", "Target"),
              h.input([
                a.id("target"),
                a.name("target"),
                a.class(input_class(errors, "target") <> " font-monospace"),
                a.value(r.target),
                a.required(True),
                a.placeholder("https://example.com/new-path/$1"),
              ]),
              help(
                "Absolute URL or path. $1..$9 / ${n} insert regex captures; for prefix rules $1 is the rest of the path. $$ is a literal $.",
              ),
            ]),
            field_col("md:col-4", [
              label("priority", "Priority"),
              h.input([
                a.id("priority"),
                a.name("priority"),
                a.type_("number"),
                a.min("0"),
                a.max("1000000"),
                a.class(input_class(errors, "priority")),
                a.value(int.to_string(r.priority)),
              ]),
              help("Lower runs first among regex and same-length prefix rules."),
            ]),
            field_col("md:col-8", [
              label("note", "Note"),
              h.input([
                a.id("note"),
                a.name("note"),
                a.class(input_class(errors, "note")),
                a.value(r.note),
                a.placeholder("Optional description"),
              ]),
            ]),
            field_col("col-12", [
              h.div([a.class("d-flex flex-wrap gap-3")], [
                checkbox("enabled", "Enabled", r.enabled),
                checkbox(
                  "preserve_query",
                  "Preserve query string",
                  r.preserve_query,
                ),
                checkbox(
                  "case_insensitive",
                  "Case insensitive",
                  r.case_insensitive,
                ),
              ]),
            ]),
          ]),
        ]),
        h.div([a.class("card-body border-top")], [
          h.div([a.class("d-flex gap-2")], [
            h.button(
              [a.type_("submit"), a.class("btn btn-solid theme-primary")],
              [
                h.text("Save"),
              ],
            ),
            layout.button_link(
              "/rules",
              "Cancel",
              "btn-outline theme-secondary",
            ),
          ]),
        ]),
      ]),
    ],
  )
}

fn field_col(class: String, children: List(Element(Nil))) -> Element(Nil) {
  h.div([a.class(class)], children)
}

fn label(for: String, text: String) -> Element(Nil) {
  h.label([a.for(for), a.class("form-label")], [h.text(text)])
}

fn help(text: String) -> Element(Nil) {
  h.div([a.class("form-text")], [h.text(text)])
}

fn checkbox(name: String, text: String, checked: Bool) -> Element(Nil) {
  h.label([a.class("d-flex align-items-center gap-2")], [
    h.input([
      a.type_("checkbox"),
      a.class("check"),
      a.name(name),
      a.value("on"),
      a.checked(checked),
    ]),
    h.text(text),
  ])
}

fn input_class(errors: List(String), field: String) -> String {
  case list.any(errors, string.starts_with(_, field <> ":")) {
    True -> "form-control is-invalid"
    False -> "form-control"
  }
}

// --- delete -----------------------------------------------------------------

pub fn confirm_delete(session: Session, show_users: Bool, r: Rule) -> String {
  layout.page(
    title: "Delete redirection",
    session: option.Some(session),
    nav: layout.NavRules,
    flash: option.None,
    show_users:,
    content: [
      layout.heading("Delete redirection", []),
      h.div([a.class("card")], [
        h.div([a.class("card-body")], [
          h.p([], [h.text("This redirection will be removed permanently:")]),
          h.p([], [
            h.code([], [h.text(r.host <> " " <> r.source)]),
            h.text(" → "),
            h.code([], [h.text(r.target)]),
          ]),
          h.form(
            [
              a.method("post"),
              a.action("/rules/" <> uri.percent_encode(r.id) <> "/delete"),
              a.class("d-flex gap-2"),
            ],
            [
              layout.csrf_field(session),
              h.button(
                [a.type_("submit"), a.class("btn btn-solid theme-danger")],
                [
                  h.text("Delete"),
                ],
              ),
              layout.button_link(
                "/rules",
                "Cancel",
                "btn-outline theme-secondary",
              ),
            ],
          ),
        ]),
      ]),
    ],
  )
}
