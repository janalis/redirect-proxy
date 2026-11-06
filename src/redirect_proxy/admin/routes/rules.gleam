//// Redirection rules: list, create, edit, delete, toggle, reload, URL
//// tester, import and export, audit log.

import gleam/bytes_tree
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/layout
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/views/rules as rules_view
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, form_value, html,
  not_found, require_csrf_form, return_to,
} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules
import simplifile
import wisp.{type Request, type Response}

fn filters_from(get: fn(String) -> String) -> rules_view.Filters {
  rules_view.Filters(
    query: string.trim(get("q")),
    host: string.trim(get("host")),
    kind: get("kind"),
    status: get("status"),
    sort: get("sort"),
    page: int.parse(get("page")) |> result.unwrap(1),
  )
}

pub fn list_rules(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let filters =
    filters_from(fn(key) { list.key_find(query, key) |> result.unwrap("") })
  let all = store.all(ctx.store)
  let found = matching(all, filters)
  let sorted =
    store_rules.sort(found, filters.sort, metrics.hits, metrics.last_hit)
    |> result.unwrap(found)
  let count = list.length(sorted)
  let pages =
    int.max(1, { count + rules_view.page_size - 1 } / rules_view.page_size)
  let page = int.clamp(filters.page, 1, pages)
  // hit counts are read for the displayed page only
  let rows =
    sorted
    |> list.drop({ page - 1 } * rules_view.page_size)
    |> list.take(rules_view.page_size)
    |> list.map(fn(r) {
      rules_view.Row(
        rule: r,
        hits: metrics.hits(r.id),
        last_hit: metrics.last_hit(r.id),
      )
    })
  let filters = rules_view.Filters(..filters, page:)
  let here =
    "/rules?"
    <> uri.query_to_string(
      list.append(rules_view.filters_query(filters), [
        #("page", int.to_string(page)),
      ]),
    )
  // after enabling or disabling, name the rule (looked up by id, never
  // taken as text from the link)
  let flash = case
    list.key_find(query, "flash"),
    list.key_find(query, "id") |> result.try(store.get(ctx.store, _))
  {
    Ok("enabled"), Ok(r) ->
      Some(layout.Success(
        "Redirection " <> r.host <> " " <> r.source <> " enabled.",
      ))
    Ok("disabled"), Ok(r) ->
      Some(layout.Success(
        "Redirection " <> r.host <> " " <> r.source <> " disabled.",
      ))
    _, _ -> flash_from_query(req)
  }
  html(
    200,
    rules_view.index(
      s,
      features(ctx),
      flash,
      rows,
      list.length(all),
      count,
      filters,
      pages,
      here,
    ),
  )
}

fn matching(rules: List(Rule), f: rules_view.Filters) -> List(Rule) {
  store_rules.filter(
    rules,
    store_rules.Filter(
      text: f.query,
      host: f.host,
      kind: f.kind,
      enabled: case f.status {
        "enabled" -> Some(True)
        "disabled" -> Some(False)
        _ -> None
      },
    ),
  )
}

/// Enable, disable or delete the selected rules, or every rule matching the
/// list filters. Deleting asks for a confirmation first.
pub fn bulk(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  let back = form_value(form, "return_to")
  let selected = case form_value(form, "all_matching") {
    "on" -> {
      let filters = filters_from(fn(key) { form_value(form, "filter_" <> key) })
      matching(store.all(ctx.store), filters)
      |> list.map(fn(r) { r.id })
    }
    _ ->
      form.values
      |> list.filter(fn(kv) { kv.0 == "ids" })
      |> list.map(fn(kv) { kv.1 })
  }
  case store.bulk_action_from_string(form_value(form, "action")), selected {
    Error(Nil), _ -> wisp.redirect(return_to(back, []))
    Ok(_), [] -> wisp.redirect(return_to(back, []))
    Ok(store.Remove), ids ->
      case form_value(form, "confirm") {
        "yes" -> apply_bulk(ctx, s, ids, store.Remove, back)
        _ -> {
          let wanted = set.from_list(ids)
          let rules =
            store.all(ctx.store)
            |> list.filter(fn(r) { set.contains(wanted, r.id) })
          html(
            200,
            rules_view.confirm_bulk_delete(
              s,
              features(ctx),
              rules,
              return_to(back, []),
            ),
          )
        }
      }
    Ok(action), ids -> apply_bulk(ctx, s, ids, action, back)
  }
}

fn apply_bulk(
  ctx: Context,
  s: Session,
  ids: List(String),
  action: store.BulkAction,
  back: String,
) -> Response {
  case store.bulk(ctx.store, ids, action, s.username) {
    Ok(count) ->
      wisp.redirect(
        return_to(back, [#("flash", "bulk"), #("count", int.to_string(count))]),
      )
    Error(errors) ->
      error_page(ctx, s, 422, "Not changed", string.join(errors, " "))
  }
}

/// The form of a new rule, or of a copy of `?from=<id>` (Duplicate).
pub fn new_rule(req: Request, ctx: Context, s: Session) -> Response {
  let start = case list.key_find(wisp.get_query(req), "from") {
    Ok(id) ->
      case store.get(ctx.store, id) {
        Ok(r) ->
          rule.Rule(..r, id: "", note: case r.note {
            "" -> "Copy"
            note -> note <> " (copy)"
          })
        Error(Nil) -> rule.blank()
      }
    Error(Nil) -> rule.blank()
  }
  html(200, rules_view.form(s, features(ctx), start, [], True, "", 0))
}

pub fn create_rule(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  case rule_from_form(form.values, rule.blank()) {
    Error(#(r, errors)) ->
      html(422, rules_view.form(s, features(ctx), r, errors, True, "", 0))
    Ok(r) ->
      case store.create(ctx.store, rule.Rule(..r, id: ""), s.username) {
        Ok(_) -> wisp.redirect("/rules?flash=created")
        Error(errors) ->
          html(422, rules_view.form(s, features(ctx), r, errors, True, "", 0))
      }
  }
}

pub fn edit_rule(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) ->
      html(
        200,
        rules_view.form(
          s,
          features(ctx),
          r,
          [],
          False,
          rule.version(r),
          metrics.hits(r.id),
        ),
      )
    Error(Nil) -> not_found(ctx, s)
  }
}

pub fn update_rule(
  req: Request,
  ctx: Context,
  s: Session,
  id: String,
) -> Response {
  use form <- require_csrf_form(req, s)
  let version = form_version(form.values)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(existing) -> {
      let render = fn(status, r, errors, version) {
        html(
          status,
          rules_view.form(
            s,
            features(ctx),
            r,
            errors,
            False,
            version,
            metrics.hits(r.id),
          ),
        )
      }
      let submitted_version = option.unwrap(version, rule.version(existing))
      case rule_from_form(form.values, existing) {
        Error(#(r, errors)) -> render(422, r, errors, submitted_version)
        Ok(r) ->
          case store.update_versioned(ctx.store, r, version, s.username) {
            Ok(_) -> wisp.redirect("/rules?flash=updated")
            Error(store.NotFound) -> not_found(ctx, s)
            // Keep the submitted values; saving again overwrites knowingly.
            Error(store.Conflict(current)) ->
              render(
                409,
                r,
                [
                  conflict_message(current)
                  <> " Your changes are shown below; saving again replaces theirs.",
                ],
                rule.version(current),
              )
            Error(store.Invalid(errors)) ->
              render(422, r, errors, submitted_version)
          }
      }
    }
  }
}

pub fn confirm_delete(
  req: Request,
  ctx: Context,
  s: Session,
  id: String,
) -> Response {
  let back =
    list.key_find(wisp.get_query(req), "return_to") |> result.unwrap("")
  case store.get(ctx.store, id) {
    Ok(r) ->
      html(
        200,
        rules_view.confirm_delete(s, features(ctx), r, return_to(back, [])),
      )
    Error(Nil) -> not_found(ctx, s)
  }
}

pub fn delete_rule(
  req: Request,
  ctx: Context,
  s: Session,
  id: String,
) -> Response {
  use form <- require_csrf_form(req, s)
  let version = form_version(form.values)
  case store.delete_versioned(ctx.store, id, version, s.username) {
    Ok(_) ->
      wisp.redirect(
        return_to(form_value(form, "return_to"), [#("flash", "deleted")]),
      )
    Error(store.Conflict(current)) ->
      error_page(
        ctx,
        s,
        409,
        "Not deleted",
        conflict_message(current) <> " Review it, then delete it again.",
      )
    Error(error) ->
      error_page(
        ctx,
        s,
        404,
        "Cannot delete",
        string.join(store.describe_change_error(error), " "),
      )
  }
}

pub fn toggle_rule(
  req: Request,
  ctx: Context,
  s: Session,
  id: String,
) -> Response {
  use form <- require_csrf_form(req, s)
  case store.get(ctx.store, id) {
    Error(Nil) -> not_found(ctx, s)
    Ok(r) ->
      case
        store.update_versioned(
          ctx.store,
          rule.Rule(..r, enabled: !r.enabled),
          form_version(form.values),
          s.username,
        )
      {
        Ok(_) ->
          wisp.redirect(
            return_to(form_value(form, "return_to"), [
              #("flash", case r.enabled {
                True -> "disabled"
                False -> "enabled"
              }),
              #("id", r.id),
            ]),
          )
        Error(store.Conflict(current)) ->
          error_page(
            ctx,
            s,
            409,
            "Not changed",
            conflict_message(current) <> " Review it, then try again.",
          )
        Error(error) ->
          error_page(
            ctx,
            s,
            422,
            "Cannot update",
            string.join(store.describe_change_error(error), " "),
          )
      }
  }
}

/// The rule version a form was rendered from (`None` for old forms).
fn form_version(values: List(#(String, String))) -> Option(String) {
  case list.key_find(values, "version") |> result.map(string.trim) {
    Ok("") | Error(Nil) -> None
    Ok(version) -> Some(version)
  }
}

fn conflict_message(current: Rule) -> String {
  "This redirection was changed by "
  <> current.updated_by
  <> " at "
  <> current.updated_at
  <> " while you were working on it, so nothing was saved."
}

pub fn reload(req: Request, ctx: Context, s: Session) -> Response {
  use _form <- require_csrf_form(req, s)
  case store.reload(ctx.store, s.username) {
    Ok(count) ->
      wisp.redirect("/rules?flash=reloaded&count=" <> int.to_string(count))
    Error(reason) ->
      error_page(
        ctx,
        s,
        422,
        "Reload rejected",
        "The file on disk is invalid; the current redirections are kept. "
          <> reason,
      )
  }
}

/// Builds a rule from submitted form values on top of `base`.
pub fn rule_from_form(
  values: List(#(String, String)),
  base: Rule,
) -> Result(Rule, #(Rule, List(String))) {
  let get = fn(key) { list.key_find(values, key) |> result.unwrap("") }
  let checked = fn(key) { get(key) == "on" || get(key) == "true" }
  let kind = rule.kind_from_string(get("match"))
  let status = int.parse(string.trim(get("status")))
  let priority = case string.trim(get("priority")) {
    "" -> Ok(rule.default_priority)
    p -> int.parse(p)
  }
  let r =
    rule.Rule(
      ..base,
      host: get("host"),
      source: get("source"),
      kind: result.unwrap(kind, rule.Exact),
      target: get("target"),
      status: result.unwrap(status, 301),
      preserve_query: checked("preserve_query"),
      case_insensitive: checked("case_insensitive"),
      // only meaningful for prefix rules: ignored for the others
        whole_segments: checked("whole_segments") && kind == Ok(rule.Prefix),
      priority: result.unwrap(priority, rule.default_priority),
      enabled: checked("enabled"),
      note: get("note"),
      starts_at: get("starts_at"),
      expires_at: get("expires_at"),
    )
  let errors =
    list.flatten([
      case kind {
        Ok(_) -> []
        Error(_) -> ["match: must be exact, prefix or regex"]
      },
      case status {
        Ok(_) -> []
        Error(_) -> ["status: must be a number"]
      },
      case priority {
        Ok(_) -> []
        Error(_) -> ["priority: must be a number"]
      },
    ])
  case errors {
    [] ->
      case rule.validate(r) {
        Ok(valid) -> Ok(valid)
        Error(errors) -> Error(#(r, errors))
      }
    _ -> Error(#(r, errors))
  }
}

pub fn test_url(req: Request, ctx: Context, s: Session) -> Response {
  let url = list.key_find(wisp.get_query(req), "url") |> result.unwrap("")
  let result = case string.trim(url) {
    "" -> pages.NotTested
    url ->
      case
        matcher.resolve_url(
          snapshot.current(),
          url,
          config.ignore_trailing_slash(ctx.config),
        )
      {
        matcher.Redirected(m, location) -> pages.Matched(m.rule, location)
        matcher.NotMatched -> pages.NoMatch
        matcher.BadUrl -> pages.InvalidUrl
      }
  }
  let explanation = case result {
    pages.Matched(..) | pages.NoMatch ->
      explain.explain(
        snapshot.current(),
        store.all(ctx.store),
        url,
        config.ignore_trailing_slash(ctx.config),
      )
      |> option.from_result
    _ -> None
  }
  html(200, pages.test_url(s, features(ctx), url, result, explanation))
}

/// Exports the rules matching the list filters of the query (all of them
/// without filters).
pub fn export(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let filters =
    filters_from(fn(key) { list.key_find(query, key) |> result.unwrap("") })
  let body =
    matching(store.all(ctx.store), filters)
    |> store_rules.export
  wisp.ok()
  |> wisp.set_header("content-type", "application/json")
  |> wisp.file_download_from_memory(
    named: "redirects.json",
    containing: bytes_tree.from_string(body),
  )
}

pub fn import_page(req: Request, ctx: Context, s: Session) -> Response {
  html(200, pages.import_export(s, features(ctx), flash_from_query(req), []))
}

pub fn import_rules(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  let pasted = form_value(form, "content")
  let uploaded = case list.key_find(form.files, "file") {
    Ok(file) ->
      simplifile.read(file.path)
      |> result.unwrap("")
    Error(Nil) -> ""
  }
  let content = case string.trim(uploaded) {
    "" -> pasted
    _ -> uploaded
  }
  let mode =
    form_value(form, "mode")
    |> store.import_mode_from_string
    |> result.unwrap(store.Merge)
  let fail = fn(errors) {
    html(422, pages.import_export(s, features(ctx), None, errors))
  }
  let imported = fn(count) {
    wisp.redirect("/rules?flash=imported&count=" <> int.to_string(count))
  }
  let preview = fn(incoming, stale) {
    case store.preview_import(ctx.store, incoming, mode, s.username) {
      Ok(#(d, version)) ->
        html(
          200,
          pages.import_preview(
            s,
            features(ctx),
            d.added,
            d.removed,
            d.changed,
            content,
            form_value(form, "mode"),
            version,
            stale,
          ),
        )
      Error(errors) -> fail(errors)
    }
  }
  case string.trim(content) {
    "" -> fail(["Provide a JSON file or paste JSON content."])
    _ ->
      case rule.file_from_string(content) {
        Error(reason) -> fail([reason])
        Ok(incoming) ->
          // a replace is always previewed before it is applied
          case form_value(form, "step"), mode {
            "apply", _ -> {
              // the version the preview was computed against
              let expected = case form_value(form, "version") {
                "" -> None
                version -> Some(version)
              }
              case
                store.import_rules_versioned(
                  ctx.store,
                  incoming,
                  mode,
                  expected,
                  s.username,
                )
              {
                Ok(count) -> imported(count)
                Error(store.Stale(_)) -> preview(incoming, True)
                Error(store.Rejected(errors)) -> fail(errors)
              }
            }
            "preview", _ | _, store.Replace -> preview(incoming, False)
            _, store.Merge ->
              case store.import_rules(ctx.store, incoming, mode, s.username) {
                Ok(count) -> imported(count)
                Error(errors) -> fail(errors)
              }
          }
      }
  }
}

/// The most recent audit entries considered by the audit page filters.
const audit_window = 1000

const audit_page_size = 50

pub fn audit_page(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) {
    list.key_find(query, key) |> result.unwrap("") |> string.trim
  }
  let filters =
    pages.AuditFilters(
      actor: get("actor"),
      action: get("action"),
      target: get("target"),
    )
  let matching =
    audit.tail(config.audit_path(ctx.config), audit_window)
    |> list.filter(fn(e) {
      { filters.actor == "" || e.actor == filters.actor }
      && {
        filters.action == "" || string.starts_with(e.action, filters.action)
      }
      && { filters.target == "" || string.contains(e.target, filters.target) }
    })
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
    pages.audit_log(s, features(ctx), entries, filters, page, pages_count),
  )
}
