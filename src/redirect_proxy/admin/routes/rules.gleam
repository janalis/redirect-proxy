//// Redirection rules: the list and its bulk actions, create, edit,
//// delete, toggle, reload, the URL tester and the export. The import is
//// in `import_export`, the audit log in `audit`.

import gleam/bool
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
import redirect_proxy/admin/views/rule_form as rule_form_view
import redirect_proxy/admin/views/rules as rules_view
import redirect_proxy/admin/views/tester as tester_view
import redirect_proxy/admin/web.{
  type Context, busy_page, error_page, features, flash_from_query, form_value,
  html, not_found, require_csrf_form, return_to, storage_page,
} as _
import redirect_proxy/config
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/matcher
import redirect_proxy/matcher/explain
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/rule_csv
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/rules/listing
import wisp.{type Request, type Response}

/// The list filters, named as in the API (`match`, `enabled=true|false`,
/// `sort=last_hit_at`). The names of earlier versions (`kind`,
/// `status=enabled|disabled`, `sort=last_hit`) are still read, so that
/// saved links keep working. An invalid value is replaced by the default
/// and returned with the others ignored, so that the page can say so.
fn filters_from(
  get: fn(String) -> String,
) -> #(rules_view.Filters, List(Ignored)) {
  let either = fn(name, old) {
    case get(name) {
      "" -> get(old)
      value -> value
    }
  }
  let match = either("match", "kind")
  let #(match, ignored_match) = case
    match == "" || list.contains(rule.kind_names(), match)
  {
    True -> #(match, [])
    False -> #("", [
      Ignored("match", match, string.join(rule.kind_names(), ", ")),
    ])
  }
  let #(enabled, ignored_enabled) = case either("enabled", "status") {
    "" -> #("", [])
    "true" | "enabled" -> #("true", [])
    "false" | "disabled" -> #("false", [])
    value -> #("", [Ignored("enabled", value, "true, false")])
  }
  // `last_hit` and `updated`: the earlier names of `last_hit_at` and
  // `updated_at`
  let sort = listing.current_sort(get("sort"))
  let #(sort, ignored_sort) = case
    listing.sort([], sort, fn(_) { 0 }, fn(_) { 0 })
  {
    Ok(_) -> #(sort, [])
    Error(Nil) -> #("", [
      Ignored("sort", sort, string.join(listing.sort_fields, ", ")),
    ])
  }
  let #(page, ignored_page) = case get("page") {
    "" -> #(1, [])
    value ->
      case int.parse(value) {
        Ok(page) if page >= 1 -> #(page, [])
        _ -> #(1, [Ignored("page", value, "a positive integer")])
      }
  }
  #(
    rules_view.Filters(
      query: string.trim(get("q")),
      host: string.trim(get("host")),
      match:,
      enabled:,
      sort:,
      tag: string.trim(get("tag")),
      page:,
    ),
    list.flatten([ignored_match, ignored_enabled, ignored_sort, ignored_page]),
  )
}

/// A query value the list ignored as invalid, with the values it accepts.
type Ignored {
  Ignored(name: String, value: String, accepted: String)
}

/// `Ignored invalid filters: sort "bogus" (source, host, …).`
fn describe_ignored(ignored: List(Ignored)) -> String {
  "Ignored invalid filters: "
  <> list.map(ignored, fn(i) {
    i.name <> " \"" <> shorten(i.value) <> "\" (" <> i.accepted <> ")"
  })
  |> string.join(", ")
  <> "."
}

/// A value from a link, cut short: it is shown, not trusted.
fn shorten(value: String) -> String {
  case string.length(value) > 40 {
    True -> string.slice(value, 0, 40) <> "…"
    False -> value
  }
}

pub fn list_rules(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let #(filters, ignored) =
    filters_from(fn(key) { list.key_find(query, key) |> result.unwrap("") })
  let #(all, version) = store.versioned(ctx.store)
  let found = matching(all, filters)
  let sorted =
    listing.sort(found, filters.sort, metrics.hits, metrics.last_hit)
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
      case ignored {
        [] -> None
        _ -> Some(describe_ignored(ignored))
      },
      rows,
      list.length(all),
      count,
      filters,
      pages,
      here,
      version,
    ),
  )
}

fn matching(rules: List(Rule), f: rules_view.Filters) -> List(Rule) {
  listing.filter(
    rules,
    listing.Filter(
      text: f.query,
      host: f.host,
      kind: f.match,
      enabled: case f.enabled {
        "true" -> Some(True)
        "false" -> Some(False)
        _ -> None
      },
      tag: f.tag,
    ),
  )
}

/// Enable, disable or delete the selected rules, or every rule matching the
/// list filters. Deleting asks for a confirmation first.
///
/// The form carries the version of the rules the page showed: when they
/// changed since (another admin, an import, a reload), nothing is changed,
/// so that "every matching rule" never takes in rules nobody saw.
pub fn bulk(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  let back = form_value(form, "return_to")
  let version = form_version(form.values)
  let #(rules, current) = store.versioned(ctx.store)
  let all_matching = form_value(form, "all_matching") == "on"
  // the filters select the rules the page showed only under its version,
  // which the list and the confirmation always carry
  use <- bool.lazy_guard(
    case version {
      Some(v) -> v != current
      None -> all_matching
    },
    fn() {
      change_error_page(
        ctx,
        s,
        store.Stale(current),
        "Not changed",
        "apply the action again",
      )
    },
  )
  let selected = case all_matching {
    True -> {
      // the filters of the page, which it only writes valid
      let #(filters, _) =
        filters_from(fn(key) { form_value(form, "filter_" <> key) })
      matching(rules, filters)
      |> list.map(fn(r) { r.id })
    }
    False ->
      form.values
      |> list.filter(fn(kv) { kv.0 == "ids" })
      |> list.map(fn(kv) { kv.1 })
  }
  case store.bulk_action_from_string(form_value(form, "action")), selected {
    Error(Nil), _ ->
      wisp.redirect(
        return_to(back, [
          #("flash", "unknown_action"),
          #("action", form_value(form, "action")),
        ]),
      )
    Ok(_), [] -> wisp.redirect(return_to(back, []))
    Ok(store.Remove), ids ->
      case form_value(form, "confirm") {
        "yes" -> apply_bulk(ctx, s, ids, store.Remove, current, back)
        _ -> {
          let wanted = set.from_list(ids)
          let rules = list.filter(rules, fn(r) { set.contains(wanted, r.id) })
          // every matching rule is confirmed with the filters (under the
          // version, they select the same rules), not one field per rule:
          // thousands of ids would go past the form size limit
          let selection = case all_matching {
            True -> [
              #("all_matching", "on"),
              ..list.filter(form.values, fn(kv) {
                string.starts_with(kv.0, "filter_")
              })
            ]
            False -> list.map(ids, fn(id) { #("ids", id) })
          }
          html(
            200,
            rules_view.confirm_bulk_delete(
              s,
              features(ctx),
              rules,
              selection,
              return_to(back, []),
              current,
            ),
          )
        }
      }
    Ok(action), ids -> apply_bulk(ctx, s, ids, action, current, back)
  }
}

fn apply_bulk(
  ctx: Context,
  s: Session,
  ids: List(String),
  action: store.BulkAction,
  version: String,
  back: String,
) -> Response {
  case store.bulk_versioned(ctx.store, ids, action, Some(version), s.username) {
    Ok(count) ->
      wisp.redirect(
        return_to(back, [#("flash", "bulk"), #("count", int.to_string(count))]),
      )
    Error(error) ->
      change_error_page(ctx, s, error, "Not changed", "apply the action again")
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
  html(200, rule_form_view.form(s, features(ctx), start, [], True, "", 0))
}

pub fn create_rule(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  case rule_from_form(form.values, rule.blank()) {
    Error(#(r, errors)) ->
      html(422, rule_form_view.form(s, features(ctx), r, errors, True, "", 0))
    Ok(r) ->
      case store.create(ctx.store, rule.Rule(..r, id: ""), s.username) {
        Ok(_) -> wisp.redirect("/rules?flash=created")
        Error(store.Invalid(errors)) ->
          html(
            422,
            rule_form_view.form(s, features(ctx), r, errors, True, "", 0),
          )
        Error(error) ->
          change_error_page(ctx, s, error, "Not created", "try again")
      }
  }
}

pub fn edit_rule(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) ->
      html(
        200,
        rule_form_view.form(
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
          rule_form_view.form(
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
                  field_error.general(
                    conflict_message(current)
                    <> " Your changes are shown below; saving again replaces theirs.",
                  ),
                ],
                rule.version(current),
              )
            Error(store.Invalid(errors)) ->
              render(422, r, errors, submitted_version)
            Error(error) ->
              change_error_page(ctx, s, error, "Not saved", "try again")
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
        rule_form_view.confirm_delete(s, features(ctx), r, return_to(back, [])),
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
    Error(error) ->
      change_error_page(ctx, s, error, "Not deleted", "delete it again")
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
        Error(error) ->
          change_error_page(ctx, s, error, "Not changed", "try again")
      }
  }
}

/// The page of a change the store refused, the same for every change,
/// with the statuses of the API: 404 when the rule is gone, 409 when it
/// (or the rule set) changed meanwhile (`retry` says what to do then), 422
/// when the change is invalid, 503 when another process holds the file
/// lock, 500 when the file could not be read or written.
fn change_error_page(
  ctx: Context,
  s: Session,
  error: store.ChangeError,
  title: String,
  retry: String,
) -> Response {
  case error {
    store.NotFound -> not_found(ctx, s)
    store.Conflict(current) ->
      error_page(
        ctx,
        s,
        409,
        title,
        conflict_message(current) <> " Review it, then " <> retry <> ".",
      )
    store.AlreadyExists ->
      error_page(
        ctx,
        s,
        409,
        title,
        "A redirection with this id already exists.",
      )
    store.Stale(_) ->
      error_page(
        ctx,
        s,
        409,
        title,
        "The redirections were changed since this page was shown, so nothing was changed. Review the list and "
          <> retry
          <> ".",
      )
    store.Invalid(errors) ->
      error_page(
        ctx,
        s,
        422,
        title,
        string.join(field_error.to_strings(errors), " "),
      )
    store.Busy(_) -> busy_page(ctx, s, title)
    store.Storage(reason) -> storage_page(ctx, s, title, reason)
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
    Error(store.ReloadBusy(_)) -> busy_page(ctx, s, "Not reloaded")
    Error(store.ReloadRejected(reason)) ->
      error_page(
        ctx,
        s,
        422,
        "Reload rejected",
        store.reload_rejected <> " " <> reason,
      )
  }
}

/// Builds a rule from submitted form values on top of `base`.
pub fn rule_from_form(
  values: List(#(String, String)),
  base: Rule,
) -> Result(Rule, #(Rule, List(FieldError))) {
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
      tags: rule.tags_from_string(get("tags")),
      // only meaningful for exact rules: ignored for the others
      query: case kind {
        Ok(rule.Exact) -> get("query")
        _ -> ""
      },
      starts_at: get("starts_at"),
      expires_at: get("expires_at"),
    )
  let errors =
    list.flatten([
      case kind {
        Ok(_) -> []
        Error(_) -> [FieldError("match", "must be exact, prefix or regex")]
      },
      case status {
        Ok(_) -> []
        Error(_) -> [FieldError("status", "must be a number")]
      },
      case priority {
        Ok(_) -> []
        Error(_) -> [FieldError("priority", "must be a number")]
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
  // one read of the published rules: the result and its explanation come
  // from the same rule set, even if a change is published in between
  let current = snapshot.current()
  let result = case string.trim(url) {
    "" -> tester_view.NotTested
    url ->
      case
        matcher.resolve_url(
          current,
          url,
          config.ignore_trailing_slash(ctx.config),
        )
      {
        matcher.Redirected(m, location) -> tester_view.Matched(m.rule, location)
        matcher.NotMatched -> tester_view.NoMatch
        matcher.BadUrl -> tester_view.InvalidUrl
      }
  }
  let explanation = case result {
    tester_view.Matched(..) | tester_view.NoMatch ->
      explain.explain(
        current,
        store.all(ctx.store),
        url,
        config.ignore_trailing_slash(ctx.config),
      )
      |> option.from_result
    _ -> None
  }
  html(200, tester_view.test_url(s, features(ctx), url, result, explanation))
}

/// Exports the rules matching the list filters of the query (all of them
/// without filters). Invalid filters or format are a 400, as in the API:
/// ignoring them would export another set than the one asked for.
pub fn export(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let #(filters, ignored) =
    filters_from(fn(key) { list.key_find(query, key) |> result.unwrap("") })
  // the export is in file order, of every page
  let ignored =
    list.filter(ignored, fn(i) { i.name != "sort" && i.name != "page" })
  let format = case list.key_find(query, "format") {
    Error(Nil) | Ok("") | Ok("json") -> Ok(False)
    Ok("csv") -> Ok(True)
    Ok(_) -> Error(Nil)
  }
  case ignored, format {
    [_, ..], _ ->
      error_page(ctx, s, 400, "Not exported", describe_ignored(ignored))
    _, Error(Nil) ->
      error_page(ctx, s, 400, "Not exported", "format must be json or csv.")
    [], Ok(csv) -> {
      let rules = matching(store.all(ctx.store), filters)
      let #(content_type, name, body) = case csv {
        True -> #(
          "text/csv; charset=utf-8",
          "redirects.csv",
          rule_csv.to_spreadsheet_string(rules),
        )
        False -> #("application/json", "redirects.json", listing.export(rules))
      }
      wisp.ok()
      |> wisp.set_header("content-type", content_type)
      |> wisp.file_download_from_memory(
        named: name,
        containing: bytes_tree.from_string(body),
      )
    }
  }
}
