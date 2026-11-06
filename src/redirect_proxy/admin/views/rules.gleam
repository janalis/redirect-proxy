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
import redirect_proxy/ffi
import redirect_proxy/rule.{type Rule}

pub type Filters {
  Filters(
    query: String,
    host: String,
    /// `match` in the URL, as in the API: exact, prefix, regex or "".
    kind: String,
    /// `enabled` in the URL, as in the API: true, false or "".
    status: String,
    sort: String,
    page: Int,
    /// Rules with this tag ("" for any).
    tag: String,
  )
}

pub type Row {
  Row(rule: Rule, hits: Int, last_hit: Int)
}

pub const page_size = 50

/// The list query of filters (without the page).
pub fn filters_query(filters: Filters) -> List(#(String, String)) {
  [
    #("q", filters.query),
    #("host", filters.host),
    #("match", filters.kind),
    #("enabled", filters.status),
    #("tag", filters.tag),
    #("sort", filters.sort),
  ]
  |> list.filter(fn(kv) { kv.1 != "" })
}

/// `rows` are the rules of the current page; `matching` counts the rules
/// matching the filters, `total` every rule. `here` is the URL of this page,
/// where actions return.
pub fn index(
  session: Session,
  features: layout.Features,
  flash: Option(Flash),
  rows: List(Row),
  total: Int,
  matching: Int,
  filters: Filters,
  pages: Int,
  here: String,
  version: String,
) -> String {
  layout.page(
    title: "Redirections",
    session: option.Some(session),
    nav: layout.NavRules,
    flash:,
    features:,
    content: [
      layout.heading("Redirections", case layout.can_edit(session) {
        False -> []
        True -> [
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
        ]
      }),
      filters_form(filters),
      h.p([a.class("small fg-secondary d-flex gap-2")], [
        h.text(
          int.to_string(matching)
          <> " matching of "
          <> int.to_string(total)
          <> " redirection(s)",
        ),
        case filters_query(Filters(..filters, sort: "")) {
          [] -> element.none()
          query ->
            h.a([a.href("/export?" <> uri.query_to_string(query))], [
              h.text("Export these"),
            ])
        },
      ]),
      case rows {
        [] -> empty_state(total)
        _ ->
          element.fragment([
            case layout.can_edit(session) {
              True -> bulk_form(session, filters, matching, here, version)
              False -> element.none()
            },
            table(session, rows, filters, here),
          ])
      },
      pagination(filters, filters.page, pages),
    ],
  )
}

fn empty_state(total: Int) -> Element(Nil) {
  h.div([a.class("card")], [
    h.div([a.class("card-body text-center fg-secondary")], case total {
      // a fresh install, not a filter without results
      0 -> [
        h.p([], [h.text("No redirection yet.")]),
        h.div([a.class("d-flex gap-2 justify-content-center")], [
          layout.button_link(
            "/rules/new",
            "Create a redirection",
            "btn-solid theme-primary",
          ),
          layout.button_link(
            "/import",
            "Import a file",
            "btn-outline theme-secondary",
          ),
        ]),
      ]
      _ -> [h.text("No redirection matches these filters.")]
    }),
  ])
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
        a.placeholder("Search host, source, target, note or tags"),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("host"), a.class("visually-hidden")], [h.text("Host")]),
      h.input([
        a.id("host"),
        a.name("host"),
        a.value(filters.host),
        a.class("form-control"),
        a.placeholder("Host (exact, or *)"),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("tag"), a.class("visually-hidden")], [h.text("Tag")]),
      h.input([
        a.id("tag"),
        a.name("tag"),
        a.value(filters.tag),
        a.class("form-control"),
        a.placeholder("Tag"),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("match"), a.class("visually-hidden")], [h.text("Match")]),
      h.select([a.id("match"), a.name("match"), a.class("form-control")], [
        option("", "All match types", filters.kind),
        option("exact", "Exact", filters.kind),
        option("prefix", "Prefix", filters.kind),
        option("regex", "Regex", filters.kind),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("enabled"), a.class("visually-hidden")], [h.text("State")]),
      h.select([a.id("enabled"), a.name("enabled"), a.class("form-control")], [
        option("", "Enabled and disabled", filters.status),
        option("true", "Enabled only", filters.status),
        option("false", "Disabled only", filters.status),
      ]),
    ]),
    h.div([a.class("col-6 md:col-auto")], [
      h.label([a.for("sort"), a.class("visually-hidden")], [h.text("Sort")]),
      h.select([a.id("sort"), a.name("sort"), a.class("form-control")], [
        option("", "File order", filters.sort),
        option("source", "Source", filters.sort),
        option("host", "Host", filters.sort),
        option("-hits", "Most hits", filters.sort),
        option("hits", "Fewest hits", filters.sort),
        option("last_hit", "Least recently hit", filters.sort),
        option("-updated", "Recently updated", filters.sort),
      ]),
    ]),
    h.div([a.class("col-12 md:col-auto")], [
      h.button(
        [a.type_("submit"), a.class("btn btn-outline theme-primary w-100")],
        [h.text("Filter")],
      ),
    ]),
  ])
}

fn option(value: String, label: String, current: String) -> Element(Nil) {
  h.option([a.value(value), a.selected(value == current)], label)
}

/// The bulk action bar. Row checkboxes belong to this form through their
/// `form` attribute (each row also has its own toggle form, and forms cannot
/// be nested).
fn bulk_form(
  session: Session,
  filters: Filters,
  matching: Int,
  here: String,
  version: String,
) -> Element(Nil) {
  h.form(
    [
      a.id("bulk"),
      a.method("post"),
      a.action("/rules/bulk"),
      a.class("d-flex flex-wrap align-items-center gap-2 mb-2"),
    ],
    list.flatten([
      [layout.csrf_field(session)],
      [h.input([a.type_("hidden"), a.name("return_to"), a.value(here)])],
      // the rules the page shows: a change since refuses the action
      [h.input([a.type_("hidden"), a.name("version"), a.value(version)])],
      // the filters, for "every matching rule"
      list.map(filters_query(filters), fn(kv) {
        h.input([a.type_("hidden"), a.name("filter_" <> kv.0), a.value(kv.1)])
      }),
      [
        h.label([a.for("bulk-action"), a.class("visually-hidden")], [
          h.text("Action on the selected redirections"),
        ]),
        h.select(
          [
            a.id("bulk-action"),
            a.name("action"),
            a.class("form-control w-auto"),
          ],
          [
            h.option([a.value("enable")], "Enable"),
            h.option([a.value("disable")], "Disable"),
            h.option([a.value("delete")], "Delete"),
          ],
        ),
        h.label([a.class("d-flex align-items-center gap-2 small")], [
          h.input([
            a.type_("checkbox"),
            a.class("check"),
            a.name("all_matching"),
            a.value("on"),
          ]),
          h.text(
            "every matching redirection (" <> int.to_string(matching) <> ")",
          ),
        ]),
        h.button(
          [a.type_("submit"), a.class("btn btn-outline theme-secondary")],
          [h.text("Apply to selection")],
        ),
      ],
    ]),
  )
}

fn table(
  session: Session,
  rows: List(Row),
  filters: Filters,
  here: String,
) -> Element(Nil) {
  h.div([a.class("table-responsive")], [
    h.table([a.class("table table-hover align-middle")], [
      h.thead([], [
        h.tr([], [
          h.th([a.scope("col")], [
            h.span([a.class("visually-hidden")], [h.text("Select")]),
          ]),
          h.th([a.scope("col")], [sort_link("Host", "host", filters)]),
          h.th([a.scope("col")], [sort_link("Source", "source", filters)]),
          h.th([a.scope("col")], [h.text("Target")]),
          h.th([a.scope("col")], [h.text("Status")]),
          h.th([a.scope("col"), a.class("text-end")], [
            sort_link("Hits", "-hits", filters),
          ]),
          h.th([a.scope("col")], [h.text("State")]),
          h.th([a.scope("col"), a.class("text-end")], [h.text("Actions")]),
        ]),
      ]),
      h.tbody([], list.map(rows, row(session, _, here))),
    ]),
  ])
}

fn sort_link(label: String, sort: String, filters: Filters) -> Element(Nil) {
  let current = filters.sort == sort
  h.a(
    [
      a.href(
        "/rules?"
        <> uri.query_to_string(filters_query(Filters(..filters, sort:, page: 1))),
      ),
      a.class("text-reset"),
      case current {
        True -> a.attribute("aria-sort", "ascending")
        False -> a.none()
      },
    ],
    [h.text(label)],
  )
}

fn row(session: Session, row: Row, here: String) -> Element(Nil) {
  let r = row.rule
  let name = r.host <> " " <> r.source
  h.tr([], [
    h.td([], case layout.can_edit(session) {
      True -> [
        h.input([
          a.type_("checkbox"),
          a.class("check"),
          a.name("ids"),
          a.value(r.id),
          a.form("bulk"),
          a.aria_label("Select " <> name),
        ]),
      ]
      False -> []
    }),
    h.td([a.class("text-nowrap")], [h.text(r.host)]),
    h.td([], [
      kind_badge(r.kind),
      h.text(" "),
      h.code([a.class("text-break")], [h.text(r.source)]),
      tag_badges(r.tags),
      case r.note {
        "" -> element.none()
        note -> h.div([a.class("small fg-secondary")], [h.text(note)])
      },
    ]),
    h.td([a.class("text-break")], [h.code([], [h.text(r.target)])]),
    h.td([], [h.text(int.to_string(r.status))]),
    h.td(
      [
        a.class("text-end"),
        a.title(case row.last_hit {
          0 -> "Never hit"
          at -> "Last hit " <> ffi.rfc3339(at)
        }),
      ],
      [h.text(int.to_string(row.hits))],
    ),
    h.td([], [
      case layout.can_edit(session) {
        False ->
          h.span(
            [
              a.class(case r.enabled {
                True -> "badge theme-success"
                False -> "badge theme-secondary"
              }),
            ],
            [
              h.text(case r.enabled {
                True -> "enabled"
                False -> "disabled"
              }),
            ],
          )
        True ->
          h.form(
            [
              a.method("post"),
              a.action("/rules/" <> uri.percent_encode(r.id) <> "/toggle"),
            ],
            [
              layout.csrf_field(session),
              layout.version_field(rule.version(r)),
              h.input([a.type_("hidden"), a.name("return_to"), a.value(here)]),
              h.button(
                [
                  a.type_("submit"),
                  a.class(case r.enabled {
                    True -> "badge theme-success border-0"
                    False -> "badge theme-secondary border-0"
                  }),
                  a.aria_label(
                    case r.enabled {
                      True -> "Enabled. Disable "
                      False -> "Disabled. Enable "
                    }
                    <> name,
                  ),
                  a.title("Click to toggle"),
                ],
                [
                  h.text(case r.enabled {
                    True -> "enabled"
                    False -> "disabled"
                  }),
                ],
              ),
              schedule_badge(r),
            ],
          )
      },
    ]),
    h.td([a.class("text-end text-nowrap")], [
      h.a(
        [
          a.class("btn btn-sm btn-outline theme-primary me-1"),
          a.href("/rules/" <> uri.percent_encode(r.id) <> "/edit"),
          a.aria_label(case layout.can_edit(session) {
            True -> "Edit " <> name
            False -> "View " <> name
          }),
        ],
        [
          h.text(case layout.can_edit(session) {
            True -> "Edit"
            False -> "View"
          }),
        ],
      ),
      case layout.can_edit(session) {
        False -> element.none()
        True ->
          h.a(
            [
              a.class("btn btn-sm btn-outline theme-danger"),
              a.href(
                "/rules/"
                <> uri.percent_encode(r.id)
                <> "/delete?"
                <> uri.query_to_string([#("return_to", here)]),
              ),
              a.aria_label("Delete " <> name),
            ],
            [h.text("Delete")],
          )
      },
    ]),
  ])
}

/// A rule's tags, each a link to the rules with that tag.
fn tag_badges(tags: List(String)) -> Element(Nil) {
  case tags {
    [] -> element.none()
    tags ->
      h.div(
        [a.class("d-flex flex-wrap gap-1 mt-1")],
        list.map(tags, fn(tag) {
          h.a(
            [
              a.class("badge badge-subtle theme-secondary"),
              a.href("/rules?" <> uri.query_to_string([#("tag", tag)])),
            ],
            [h.text(tag)],
          )
        }),
      )
  }
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
        <> uri.query_to_string(
          list.append(filters_query(filters), [#("page", int.to_string(p))]),
        )
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
          [
            case enabled {
              // a disabled link is not focusable
              False ->
                h.span([a.class("page-link"), a.aria_disabled(True)], [
                  h.text(label),
                ])
              True ->
                h.a(
                  [
                    a.class("page-link"),
                    a.href(href(p)),
                    case active {
                      True -> a.aria_current("page")
                      False -> a.none()
                    },
                  ],
                  [h.text(label)],
                )
            },
          ],
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

/// Confirmation of a bulk delete: lists the redirections and repeats the
/// selection.
pub fn confirm_bulk_delete(
  session: Session,
  features: layout.Features,
  rules: List(Rule),
  return_to: String,
  version: String,
) -> String {
  let shown = list.take(rules, 20)
  layout.page(
    title: "Delete redirections",
    session: option.Some(session),
    nav: layout.NavRules,
    flash: option.None,
    features:,
    content: [
      layout.heading("Delete redirections", []),
      h.div([a.class("card")], [
        h.div([a.class("card-body")], [
          h.p([], [
            h.text(
              int.to_string(list.length(rules))
              <> " redirection(s) will be removed permanently:",
            ),
          ]),
          h.ul(
            [],
            list.map(shown, fn(r) {
              h.li([], [h.code([], [h.text(r.host <> " " <> r.source)])])
            }),
          ),
          case list.length(rules) - list.length(shown) {
            0 -> element.none()
            more ->
              h.p([a.class("small fg-secondary")], [
                h.text("and " <> int.to_string(more) <> " more."),
              ])
          },
          h.form(
            [a.method("post"), a.action("/rules/bulk"), a.class("d-flex gap-2")],
            list.flatten([
              [layout.csrf_field(session)],
              [
                h.input([a.type_("hidden"), a.name("action"), a.value("delete")]),
                h.input([a.type_("hidden"), a.name("confirm"), a.value("yes")]),
                h.input([a.type_("hidden"), a.name("version"), a.value(version)]),
                h.input([
                  a.type_("hidden"),
                  a.name("return_to"),
                  a.value(return_to),
                ]),
              ],
              list.map(rules, fn(r) {
                h.input([a.type_("hidden"), a.name("ids"), a.value(r.id)])
              }),
              [
                h.button(
                  [a.type_("submit"), a.class("btn btn-solid theme-danger")],
                  [h.text("Delete")],
                ),
                layout.button_link(
                  return_to,
                  "Cancel",
                  "btn-outline theme-secondary",
                ),
              ],
            ]),
          ),
        ]),
      ]),
    ],
  )
}

// --- form -------------------------------------------------------------------

/// `version` is the version of the stored rule the form edits ("" for a new
/// rule).
pub fn form(
  session: Session,
  features: layout.Features,
  r: Rule,
  errors: List(String),
  is_new: Bool,
  version: String,
  hits: Int,
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
    features:,
    content: [
      layout.heading(title, []),
      layout.errors_view(errors),
      case is_new {
        True -> element.none()
        False -> details(r, hits)
      },
      h.form([a.method("post"), a.action(action), a.class("card")], [
        h.div([a.class("card-body")], [
          layout.csrf_field(session),
          layout.version_field(version),
          h.div([a.class("row g-3")], [
            field_col("md:col-4", [
              label("host", "Host"),
              h.input(list.append(
                [
                  a.id("host"),
                  a.name("host"),
                  a.class(input_class(errors, "host")),
                  a.value(r.host),
                  a.required(True),
                  a.placeholder("*"),
                ],
                layout.invalid_attributes(errors, "host"),
              )),
              layout.field_feedback(errors, "host"),
              help("Host name to match (port ignored), or * for any host."),
            ]),
            field_col("md:col-4", [
              label("match", "Match type"),
              h.select(
                list.append(
                  [
                    a.id("match"),
                    a.name("match"),
                    a.class(input_class(errors, "match")),
                  ],
                  layout.invalid_attributes(errors, "match"),
                ),
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
              layout.field_feedback(errors, "match"),
              help("Exact > prefix (longest first) > regex (by priority)."),
            ]),
            field_col("md:col-4", [
              label("status", "HTTP status"),
              h.select(
                list.append(
                  [
                    a.id("status"),
                    a.name("status"),
                    a.class(input_class(errors, "status")),
                  ],
                  layout.invalid_attributes(errors, "status"),
                ),
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
              layout.field_feedback(errors, "status"),
            ]),
            field_col("col-12", [
              label("source", "Source"),
              h.input(list.append(
                [
                  a.id("source"),
                  a.name("source"),
                  a.class(input_class(errors, "source") <> " font-monospace"),
                  a.value(r.source),
                  a.required(True),
                  a.placeholder("/old-path or ^/blog/(\\d+)$"),
                ],
                layout.invalid_attributes(errors, "source"),
              )),
              layout.field_feedback(errors, "source"),
              help(
                "Path (without query string). Regexes are not anchored automatically; use ^ and $.",
              ),
            ]),
            field_col("col-12", [
              label("target", "Target"),
              h.input(list.append(
                [
                  a.id("target"),
                  a.name("target"),
                  a.class(input_class(errors, "target") <> " font-monospace"),
                  a.value(r.target),
                  a.required(True),
                  a.placeholder("https://example.com/new-path/$1"),
                ],
                layout.invalid_attributes(errors, "target"),
              )),
              layout.field_feedback(errors, "target"),
              help(
                "Absolute URL or path. $1..$9 / ${n} insert regex captures; for prefix rules $1 is the rest of the path. $$ is a literal $.",
              ),
            ]),
            field_col("md:col-4", [
              label("priority", "Priority"),
              h.input(list.append(
                [
                  a.id("priority"),
                  a.name("priority"),
                  a.type_("number"),
                  a.min("0"),
                  a.max("1000000"),
                  a.class(input_class(errors, "priority")),
                  a.value(int.to_string(r.priority)),
                ],
                layout.invalid_attributes(errors, "priority"),
              )),
              layout.field_feedback(errors, "priority"),
              help("Lower runs first among regex and same-length prefix rules."),
            ]),
            field_col("md:col-8", [
              label("note", "Note"),
              h.input(list.append(
                [
                  a.id("note"),
                  a.name("note"),
                  a.class(input_class(errors, "note")),
                  a.value(r.note),
                  a.placeholder("Optional description"),
                ],
                layout.invalid_attributes(errors, "note"),
              )),
              layout.field_feedback(errors, "note"),
            ]),
            field_col("col-12", [
              label("tags", "Tags"),
              h.input(list.append(
                [
                  a.id("tags"),
                  a.name("tags"),
                  a.class(input_class(errors, "tags")),
                  a.value(rule.tags_to_string(r.tags)),
                  a.placeholder("campaign, legacy"),
                ],
                layout.invalid_attributes(errors, "tags"),
              )),
              layout.field_feedback(errors, "tags"),
              help("Comma separated, to group and filter redirections."),
            ]),
            field_col("col-12", [
              label("query", "Query parameters (exact rules)"),
              h.input(list.append(
                [
                  a.id("query"),
                  a.name("query"),
                  a.class(input_class(errors, "query")),
                  a.value(r.query),
                  a.placeholder("id=42&lang=fr (optional)"),
                ],
                layout.invalid_attributes(errors, "query"),
              )),
              layout.field_feedback(errors, "query"),
              help(
                "The request must have these parameters with these values; others are allowed.",
              ),
            ]),
            time_field(errors, "starts_at", "Starts at", r.starts_at),
            time_field(errors, "expires_at", "Expires at", r.expires_at),
            field_col("col-12", [
              h.div([a.class("d-flex flex-wrap gap-3")], [
                checkbox("enabled", "Enabled", r.enabled),
                checkbox(
                  "preserve_query",
                  "Preserve query string (the target's own parameters win)",
                  r.preserve_query,
                ),
                checkbox(
                  "case_insensitive",
                  "Case insensitive",
                  r.case_insensitive,
                ),
                checkbox(
                  "whole_segments",
                  "Whole path segments (prefix: /blog matches /blog/…, not /blogger)",
                  r.whole_segments,
                ),
              ]),
            ]),
          ]),
        ]),
        h.div([a.class("card-body border-top")], [
          case layout.can_edit(session) {
            False ->
              h.div([a.class("d-flex gap-2 align-items-center")], [
                h.p([a.class("small fg-secondary mb-0 me-auto")], [
                  h.text("Read only: your role cannot change redirections."),
                ]),
                layout.button_link(
                  "/rules",
                  "Back",
                  "btn-outline theme-secondary",
                ),
              ])
            True ->
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
                case is_new {
                  True -> element.none()
                  False ->
                    element.fragment([
                      layout.button_link(
                        "/rules/new?" <> uri.query_to_string([#("from", r.id)]),
                        "Duplicate",
                        "btn-outline theme-secondary ms-auto",
                      ),
                      layout.button_link(
                        "/rules/" <> uri.percent_encode(r.id) <> "/delete",
                        "Delete",
                        "btn-outline theme-danger",
                      ),
                    ])
                },
              ])
          },
        ]),
      ]),
    ],
  )
}

/// When and by whom the rule was changed, its hits, and its history.
fn details(r: Rule, hits: Int) -> Element(Nil) {
  h.p([a.class("small fg-secondary")], [
    h.text(
      "Created "
      <> r.created_at
      <> ", updated "
      <> r.updated_at
      <> " by "
      <> r.updated_by
      <> " · "
      <> int.to_string(hits)
      <> " hit(s) · ",
    ),
    h.a([a.href("/audit?" <> uri.query_to_string([#("target", r.id)]))], [
      h.text("History"),
    ]),
  ])
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

pub fn confirm_delete(
  session: Session,
  features: layout.Features,
  r: Rule,
  return_to: String,
) -> String {
  layout.page(
    title: "Delete redirection",
    session: option.Some(session),
    nav: layout.NavRules,
    flash: option.None,
    features:,
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
              layout.version_field(rule.version(r)),
              h.input([
                a.type_("hidden"),
                a.name("return_to"),
                a.value(return_to),
              ]),
              h.button(
                [a.type_("submit"), a.class("btn btn-solid theme-danger")],
                [
                  h.text("Delete"),
                ],
              ),
              layout.button_link(
                return_to,
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

/// An optional RFC 3339 date-time (`starts_at`, `expires_at`). A text field:
/// `datetime-local` has no time zone.
fn time_field(
  errors: List(String),
  name: String,
  text: String,
  value: String,
) -> Element(Nil) {
  field_col("md:col-6", [
    label(name, text),
    h.input(list.append(
      [
        a.id(name),
        a.name(name),
        a.class(input_class(errors, name)),
        a.value(value),
        a.placeholder("2026-12-01T00:00:00Z (optional)"),
      ],
      layout.invalid_attributes(errors, name),
    )),
    layout.field_feedback(errors, name),
    help("RFC 3339 with a time zone. Empty: no limit."),
  ])
}

/// "scheduled" before `starts_at`, "expired" from `expires_at`.
fn schedule_badge(r: rule.Rule) -> Element(Nil) {
  let now = ffi.now_seconds()
  let #(from, until) = rule.window(r)
  let badge = fn(text, title) {
    h.span([a.class("badge theme-warning ms-1"), a.title(title)], [h.text(text)])
  }
  case now < from, now >= until {
    True, _ -> badge("scheduled", "Applies from " <> r.starts_at)
    _, True -> badge("expired", "Expired at " <> r.expires_at)
    _, _ -> element.none()
  }
}
