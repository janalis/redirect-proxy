//// Redirection rules: list, create, edit, delete, toggle, reload, URL
//// tester, import and export, audit log.

import gleam/bytes_tree
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/pages
import redirect_proxy/admin/views/rules as rules_view
import redirect_proxy/admin/web.{
  type Context, error_page, features, flash_from_query, html, not_found,
  require_csrf_form,
} as _
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store
import simplifile
import wisp.{type Request, type Response}

pub fn list_rules(req: Request, ctx: Context, s: Session) -> Response {
  let query = wisp.get_query(req)
  let get = fn(key) { list.key_find(query, key) |> result.unwrap("") }
  let filters =
    rules_view.Filters(
      query: string.trim(get("q")),
      kind: get("kind"),
      status: get("status"),
      page: int.parse(get("page")) |> result.unwrap(1),
    )
  let all = store.all(ctx.store)
  let rows =
    all
    |> list.filter(matches_filters(_, filters))
    |> list.map(fn(r) { rules_view.Row(rule: r, hits: metrics.hits(r.id)) })
  html(
    200,
    rules_view.index(
      s,
      features(ctx),
      flash_from_query(req),
      rows,
      list.length(all),
      filters,
    ),
  )
}

fn matches_filters(r: Rule, f: rules_view.Filters) -> Bool {
  let needle = string.lowercase(f.query)
  let text_ok =
    needle == ""
    || list.any([r.host, r.source, r.target, r.note, r.id], fn(field) {
      string.contains(string.lowercase(field), needle)
    })
  let kind_ok = f.kind == "" || rule.kind_to_string(r.kind) == f.kind
  let status_ok = case f.status {
    "enabled" -> r.enabled
    "disabled" -> !r.enabled
    _ -> True
  }
  text_ok && kind_ok && status_ok
}

pub fn new_rule(_req: Request, ctx: Context, s: Session) -> Response {
  html(200, rules_view.form(s, features(ctx), rule.blank(), [], True, ""))
}

pub fn create_rule(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  case rule_from_form(form.values, rule.blank()) {
    Error(#(r, errors)) ->
      html(422, rules_view.form(s, features(ctx), r, errors, True, ""))
    Ok(r) ->
      case store.create(ctx.store, rule.Rule(..r, id: ""), s.username) {
        Ok(_) -> wisp.redirect("/rules?flash=created")
        Error(errors) ->
          html(422, rules_view.form(s, features(ctx), r, errors, True, ""))
      }
  }
}

pub fn edit_rule(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) ->
      html(
        200,
        rules_view.form(s, features(ctx), r, [], False, rule.version(r)),
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
          rules_view.form(s, features(ctx), r, errors, False, version),
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

pub fn confirm_delete(ctx: Context, s: Session, id: String) -> Response {
  case store.get(ctx.store, id) {
    Ok(r) -> html(200, rules_view.confirm_delete(s, features(ctx), r))
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
    Ok(_) -> wisp.redirect("/rules?flash=deleted")
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
        Ok(_) -> wisp.redirect("/rules?flash=toggled")
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
      priority: result.unwrap(priority, rule.default_priority),
      enabled: checked("enabled"),
      note: get("note"),
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
      case matcher.resolve_url(snapshot.current(), url) {
        matcher.Redirected(m, location) -> pages.Matched(m.rule, location)
        matcher.NotMatched -> pages.NoMatch
        matcher.BadUrl -> pages.InvalidUrl
      }
  }
  html(200, pages.test_url(s, features(ctx), url, result))
}

pub fn export(ctx: Context) -> Response {
  let body = store.export(store.all(ctx.store))
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
  let pasted = list.key_find(form.values, "content") |> result.unwrap("")
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
  let mode = case list.key_find(form.values, "mode") {
    Ok("replace") -> store.Replace
    _ -> store.Merge
  }
  let fail = fn(errors) {
    html(422, pages.import_export(s, features(ctx), None, errors))
  }
  case string.trim(content) {
    "" -> fail(["Provide a JSON file or paste JSON content."])
    _ ->
      case rule.file_from_string(content) {
        Error(reason) -> fail([reason])
        Ok(incoming) ->
          case store.import_rules(ctx.store, incoming, mode, s.username) {
            Ok(count) ->
              wisp.redirect(
                "/rules?flash=imported&count=" <> int.to_string(count),
              )
            Error(errors) -> fail(errors)
          }
      }
  }
}

pub fn audit_page(ctx: Context, s: Session) -> Response {
  let entries = audit.tail(config.audit_path(ctx.config), 200)
  html(200, pages.audit_log(s, features(ctx), entries))
}
