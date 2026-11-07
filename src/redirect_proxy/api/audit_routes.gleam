//// `GET /api/audit`, the audit log of the REST API.

import gleam/bool
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/api/problem
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import wisp.{type Request, type Response}

import redirect_proxy/api/params

const max_audit_entries = 100_000

/// `GET /api/audit`: the audit entries as recorded (newest first), filtered,
/// in pages. `has_more` (and a `Link: rel="next"`) tells whether older
/// entries match, without counting them all.
pub fn audit_log(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) {
    list.key_find(query, key) |> result.unwrap("") |> string.trim
  }
  let time = fn(name) {
    case get(name) {
      "" -> Ok(0)
      value ->
        // `+01:00` sent unencoded arrives as ` 01:00`
        ffi.parse_rfc3339(string.replace(value, " ", "+"))
        |> result.replace_error(problem.bad_request(
          name <> " must be an RFC 3339 date-time (2026-11-06T12:00:00Z).",
        ))
    }
  }
  use page <- params.result_or_response(params.positive_param(get, "page", 1))
  use per_page <- params.result_or_response(params.positive_param(
    get,
    "per_page",
    params.default_per_page,
  ))
  let per_page = int.min(per_page, params.max_per_page)
  // each page reads the files up to it: older entries are for `until`
  use <- bool.guard(
    page * per_page > max_audit_entries,
    problem.bad_request(
      "page: at most the "
      <> int.to_string(max_audit_entries)
      <> " most recent matching entries are paged through; use until for older ones.",
    ),
  )
  use since <- params.result_or_response(time("since"))
  use until <- params.result_or_response(time("until"))
  let filter =
    audit.Filter(
      actor: get("actor"),
      action: get("action"),
      target: get("target"),
      since:,
      until:,
    )
  let found =
    audit.search(config.audit_path(ctx.config), filter, page * per_page + 1)
  let has_more = list.length(found) > page * per_page
  let lines =
    found
    |> list.drop({ page - 1 } * per_page)
    |> list.take(per_page)
    |> list.map(fn(e) { e.details })
  let meta =
    json.object([
      #("page", json.int(page)),
      #("per_page", json.int(per_page)),
      #("has_more", json.bool(has_more)),
    ])
  // entries are sent as recorded: each line is a JSON object
  let body =
    "{\"data\":["
    <> string.join(lines, ",")
    <> "],\"meta\":"
    <> json.to_string(meta)
    <> "}"
  let resp =
    wisp.response(200)
    |> wisp.set_header("content-type", "application/json; charset=utf-8")
    |> wisp.set_header("cache-control", "no-store")
    |> wisp.string_body(body)
  case has_more {
    False -> resp
    True ->
      wisp.set_header(
        resp,
        "link",
        "</api/audit?"
          <> uri.query_to_string(
          query
          |> list.filter(fn(kv) { kv.0 != "page" })
          |> list.append([#("page", int.to_string(page + 1))]),
        )
          <> ">; rel=\"next\"",
      )
  }
}
