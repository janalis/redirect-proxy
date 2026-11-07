//// The import page of the admin, with its preview.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import redirect_proxy/admin/auth/session.{type Session}
import redirect_proxy/admin/views/import_export as import_export_view
import redirect_proxy/admin/web.{
  type Context, features, flash_from_query, form_value, html, require_csrf_form,
} as _
import redirect_proxy/rule_csv
import redirect_proxy/store
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
  let mode =
    form_value(form, "mode")
    |> store.import_mode_from_string
    |> result.unwrap(store.Merge)
  let fail = fn(errors) {
    html(422, import_export_view.import_export(s, features(ctx), None, errors))
  }
  // a file that is not UTF-8 (Excel's plain "CSV" is Windows-1252) is an
  // error, not an empty upload that would import the pasted text instead
  use uploaded <- result_or(uploaded, fn() {
    fail([
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
    "" -> fail(["Provide a JSON or CSV file, or paste its content."])
    _ ->
      case rule_csv.parse_import(content) {
        Error(errors) -> fail(errors)
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
