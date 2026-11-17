//// The audit log page of the admin.

import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/audit as audit_view
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/web.{type Context, features, html} as _

import redirect_proxy/audit
import redirect_proxy/config
import wisp.{type Request, type Response}

/// The most recent matching audit entries the audit page pages through,
/// in the current file and the rotated ones.
const audit_window = 10_000

const audit_page_size = 50

pub fn audit_page(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) {
    list.key_find(query, key) |> result.unwrap("") |> string.trim
  }
  // a date that cannot be read is ignored, and the page says so
  let bound = fn(name) {
    case get(name) {
      "" -> #(0, [])
      value ->
        case audit.parse_bound(value) {
          Ok(at) -> #(at, [])
          Error(Nil) -> #(0, [
            name <> " \"" <> value <> "\" (" <> audit.bound_hint <> ")",
          ])
        }
    }
  }
  let #(since, ignored_since) = bound("since")
  let #(until, ignored_until) = bound("until")
  let filters =
    audit_view.AuditFilters(
      actor: get("actor"),
      action: get("action"),
      target: get("target"),
      since: get("since"),
      until: get("until"),
    )
  let matching =
    audit.search(
      config.audit_path(ctx.config),
      audit.Filter(
        actor: filters.actor,
        action: filters.action,
        target: filters.target,
        since:,
        until:,
      ),
      audit_window,
    )
  let flash = case list.append(ignored_since, ignored_until) {
    [] -> None
    ignored ->
      Some(layout.Failure(
        "Ignored invalid filters: " <> string.join(ignored, ", ") <> ".",
      ))
  }
  let pages_count =
    int.max(
      1,
      { list.length(matching) + audit_page_size - 1 } / audit_page_size,
    )
  let page =
    int.parse(get("page")) |> result.unwrap(1) |> int.clamp(1, pages_count)
  let entries =
    matching
    |> list.drop({ page - 1 } * audit_page_size)
    |> list.take(audit_page_size)
  html(
    200,
    audit_view.audit_log(
      s,
      features(ctx),
      flash,
      entries,
      filters,
      page,
      pages_count,
      audit_window,
    ),
  )
}
