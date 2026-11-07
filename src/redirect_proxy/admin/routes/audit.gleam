//// The audit log page of the admin.

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/audit as audit_view
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
  let filters =
    audit_view.AuditFilters(
      actor: get("actor"),
      action: get("action"),
      target: get("target"),
    )
  let matching =
    audit.search(
      config.audit_path(ctx.config),
      audit.Filter(
        ..audit.any,
        actor: filters.actor,
        action: filters.action,
        target: filters.target,
      ),
      audit_window,
    )
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
    audit_view.audit_log(s, features(ctx), entries, filters, page, pages_count),
  )
}
