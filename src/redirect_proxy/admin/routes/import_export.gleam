//// The import page of the admin, with its preview. The export is a
//// download of the rules list (`rules.export`).

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/import_export as import_export_view
import redirect_proxy/admin/web.{
  type Context, busy_page, features, flash_from_query, form_value, html,
  require_csrf_form, storage_page,
} as _
import redirect_proxy/field_error
import redirect_proxy/rule_csv
import redirect_proxy/store
import redirect_proxy/store/rule_change
import simplifile
import wisp.{type Request, type Response}

pub fn import_page(req: Request, ctx: Context, s: Session) -> Response {
  html(
    200,
    import_export_view.import_export(
      s,
      features(ctx),
      flash_from_query(req),
      [],
    ),
  )
}

pub fn import_rules(req: Request, ctx: Context, s: Session) -> Response {
  use form <- require_csrf_form(req, s)
  // a previewed import comes back exactly as previewed (see the view)
  let pasted = case form_value(form, "content_base64") {
    "" -> form_value(form, "content")
    encoded ->
      bit_array.base64_decode(encoded)
      |> result.try(bit_array.to_string)
      |> result.unwrap("")
  }
  let uploaded = case list.key_find(form.files, "file") {
    Ok(file) -> simplifile.read(file.path) |> result.replace_error(Nil)
    Error(Nil) -> Ok("")
  }
  let fail = fn(errors) {
    html(422, import_export_view.import_export(s, features(ctx), None, errors))
  }
  // errors of the request or the document, not of a field
  let fail_with = fn(messages) { fail(list.map(messages, field_error.general)) }
  // a merge unless the form says otherwise; any other mode is an error,
  // not a merge the user did not ask for
  use mode <- result_or(
    case form_value(form, "mode") {
      "" -> Ok(rule_change.Merge)
      mode -> rule_change.import_mode_from_string(mode)
    },
    fn() { fail_with(["Mode must be merge or replace."]) },
  )
  // a file that is not UTF-8 (Excel's plain "CSV" is Windows-1252) is an
  // error, not an empty upload that would import the pasted text instead
  use uploaded <- result_or(uploaded, fn() {
    fail_with([
      "The file is not UTF-8 text. In a spreadsheet, save it as \"CSV UTF-8\".",
    ])
  })
  let content = case string.trim(uploaded) {
    "" -> pasted
    _ -> uploaded
  }
  let imported = fn(count) {
    wisp.redirect("/rules?flash=imported&count=" <> int.to_string(count))
  }
  let refused = fn(error) {
    case error {
      rule_change.Invalid(errors) -> fail(errors)
      rule_change.Busy(_) -> busy_page(ctx, s, "Not imported")
      rule_change.Storage(reason) ->
        storage_page(ctx, s, "Not imported", reason)
      // an import names no one rule, and is made whatever the version of
      // the rule set without one (`import_rules`)
      rule_change.NotFound
      | rule_change.AlreadyExists
      | rule_change.Conflict(_)
      | rule_change.Stale(_) ->
        fail_with(["The redirections were changed meanwhile: retry."])
    }
  }
  let preview = fn(incoming, stale) {
    case store.preview_import(ctx.store, incoming, mode, s.username) {
      Ok(#(d, version)) ->
        html(
          200,
          import_export_view.import_preview(
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
    "" -> fail_with(["Provide a JSON or CSV file, or paste its content."])
    _ ->
      case rule_csv.parse_import(content) {
        Error(errors) -> fail_with(errors)
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
                Error(rule_change.Stale(_)) -> preview(incoming, True)
                Error(error) -> refused(error)
              }
            }
            "preview", _ | _, rule_change.Replace -> preview(incoming, False)
            _, rule_change.Merge ->
              case store.import_rules(ctx.store, incoming, mode, s.username) {
                Ok(count) -> imported(count)
                Error(error) -> refused(error)
              }
          }
      }
  }
}

fn result_or(
  result: Result(a, Nil),
  otherwise: fn() -> Response,
  next: fn(a) -> Response,
) -> Response {
  case result {
    Ok(value) -> next(value)
    Error(Nil) -> otherwise()
  }
}
