//// The redirection form (create and edit) and the delete confirmation of a
//// rule. The list pages are in `rules`.

import gleam/int
import gleam/list
import gleam/option
import gleam/string
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/rule.{type Rule}

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
                  layout.select_option(
                    "exact",
                    "Exact path",
                    rule.kind_to_string(r.kind),
                  ),
                  layout.select_option(
                    "prefix",
                    "Path prefix",
                    rule.kind_to_string(r.kind),
                  ),
                  layout.select_option(
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
                    layout.select_option(
                      int.to_string(s.0),
                      s.1,
                      int.to_string(r.status),
                    )
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
