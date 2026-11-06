//// The "test a URL" page and its explanation of the result.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/uri
import lustre/attribute as a
import lustre/element.{type Element}
import lustre/element/html as h
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/matcher/explain
import redirect_proxy/rule.{type Rule}

// --- test a URL -------------------------------------------------------------

pub type TestResult {
  NotTested
  Matched(rule: Rule, location: String)
  NoMatch
  InvalidUrl
}

pub fn test_url(
  session: Session,
  features: layout.Features,
  url: String,
  result: TestResult,
  explanation: Option(explain.Explanation),
) -> String {
  layout.page(
    title: "Test a URL",
    session: Some(session),
    nav: layout.NavTest,
    flash: None,
    features:,
    content: [
      layout.heading("Test a URL", []),
      h.form([a.method("get"), a.action("/test"), a.class("row g-2 mb-4")], [
        h.div([a.class("col-12 md:col")], [
          h.label([a.for("url"), a.class("visually-hidden")], [h.text("URL")]),
          h.input([
            a.id("url"),
            a.name("url"),
            a.class("form-control font-monospace"),
            a.value(url),
            a.placeholder("https://old.example.com/blog/42?utm_source=x"),
            a.required(True),
          ]),
        ]),
        h.div([a.class("col-12 md:col-auto")], [
          h.button(
            [a.type_("submit"), a.class("btn btn-solid theme-primary w-100")],
            [
              h.text("Test"),
            ],
          ),
        ]),
      ]),
      case result {
        NotTested -> element.none()
        InvalidUrl ->
          layout.alert(
            "theme-warning",
            "Enter an absolute URL such as https://example.com/path.",
          )
        NoMatch ->
          layout.alert(
            "theme-secondary",
            "No redirection matches this URL (the fallback applies).",
          )
        Matched(r, location) ->
          h.div([a.class("card")], [
            h.div([a.class("card-body")], [
              h.p([a.class("mb-2")], [
                h.span([a.class("badge theme-success me-2")], [
                  h.text(int.to_string(r.status)),
                ]),
                h.code([a.class("text-break")], [h.text(location)]),
              ]),
              h.p([a.class("mb-0 small fg-secondary")], [
                h.text("Matched by " <> rule.kind_to_string(r.kind) <> " rule "),
                h.code([], [h.text(r.host <> " " <> r.source)]),
                h.text(" · "),
                h.a([a.href(edit_href(r))], [h.text("edit")]),
              ]),
            ]),
          ])
      },
      case explanation {
        Some(e) -> explanation_view(e)
        None -> element.none()
      },
    ],
  )
}

fn edit_href(r: Rule) -> String {
  "/rules/" <> uri.percent_encode(r.id) <> "/edit"
}

/// Why this rule: every matching rule of the candidate hosts, and the
/// redirect chain.
fn explanation_view(e: explain.Explanation) -> Element(Nil) {
  element.fragment([
    h.h2([a.class("h5 mt-4")], [h.text("Rules matching this URL")]),
    h.p([a.class("small fg-secondary")], [
      h.text("Host "),
      h.code([], [h.text(e.host)]),
      h.text(", path compared as "),
      h.code([], [h.text(e.path)]),
      h.text(
        ". Host rules come first, then wildcard hosts, then *; within a host: exact, longest prefix, then regex by priority.",
      ),
    ]),
    case e.candidates {
      [] ->
        h.p([a.class("small")], [h.text("No rule matches, enabled or not.")])
      _ ->
        h.div([a.class("table-responsive")], [
          h.table([a.class("table table-sm align-middle")], [
            h.thead([], [
              h.tr([], [
                h.th([a.scope("col")], [h.text("Rule")]),
                h.th([a.scope("col")], [h.text("Verdict")]),
              ]),
            ]),
            h.tbody(
              [],
              list.map(e.candidates, fn(c) {
                h.tr([], [
                  h.td([], [
                    h.a([a.href(edit_href(c.rule))], [
                      h.code([], [
                        h.text(
                          c.rule.host
                          <> " "
                          <> rule.kind_to_string(c.rule.kind)
                          <> " "
                          <> c.rule.source,
                        ),
                      ]),
                    ]),
                  ]),
                  h.td([], [
                    case c.verdict {
                      explain.Applied ->
                        h.span([a.class("badge theme-success")], [
                          h.text("applies"),
                        ])
                      explain.Shadowed ->
                        h.span([a.class("badge theme-secondary")], [
                          h.text("shadowed by the rule that applies"),
                        ])
                      explain.Disabled ->
                        h.span([a.class("badge theme-warning")], [
                          h.text("disabled"),
                        ])
                      explain.OutOfSchedule ->
                        h.span([a.class("badge theme-warning")], [
                          h.text("not in its starts_at / expires_at window"),
                        ])
                    },
                  ]),
                ])
              }),
            ),
          ]),
        ])
    },
    case e.chain {
      [] | [_] -> element.none()
      chain ->
        element.fragment([
          h.h2([a.class("h5 mt-4")], [h.text("Redirect chain")]),
          h.ol(
            [],
            list.map(chain, fn(hop) {
              h.li([], [
                h.text(int.to_string(hop.status) <> " → "),
                h.code([a.class("text-break")], [h.text(hop.location)]),
              ])
            }),
          ),
          case e.loops {
            True ->
              layout.alert(
                "theme-danger",
                "This chain loops: a browser would stop with too many redirects.",
              )
            False -> element.none()
          },
        ])
    },
  ])
}
