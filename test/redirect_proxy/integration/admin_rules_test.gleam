//// End-to-end tests of managing rules in the admin: forms, bulk actions,
//// imports, the audit page.

import gleam/bit_array
import gleam/http
import gleam/http/response
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import integration_support.{
  between, boot, find_id, get, hidden_value, location, login, login_with_role,
  post_form, send,
}
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import simplifile

pub fn admin_bulk_actions_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let ids =
    get(env.admin <> "/rules", [#("cookie", cookie)]).body
    |> string.split("name=\"ids\" type=\"checkbox\" value=\"")
    |> list.drop(1)
    |> list.filter_map(fn(chunk) {
      string.split_once(chunk, "\"") |> result.map(fn(p) { p.0 })
    })
  assert list.length(ids) == 3
  // disable two of them, coming back to a filtered list
  let back = "/rules?kind=exact&page=1"
  let resp =
    post_form(
      env,
      "/rules/bulk",
      cookie,
      list.flatten([
        [#("csrf_token", csrf), #("action", "disable"), #("return_to", back)],
        list.map(list.take(ids, 2), fn(id) { #("ids", id) }),
      ]),
    )
  assert resp.status == 303
  assert string.starts_with(
    location(resp),
    "/rules?kind=exact&page=1&flash=bulk",
  )
  let after = get(env.admin <> location(resp), [#("cookie", cookie)])
  assert string.contains(after.body, "Changed 2 redirection(s).")
  // every rule matching a filter, deleted after a confirmation
  let confirm =
    post_form(env, "/rules/bulk", cookie, [
      #("csrf_token", csrf),
      #("action", "delete"),
      #("all_matching", "on"),
      #("filter_kind", "regex"),
      #("return_to", "/rules"),
    ])
  assert confirm.status == 200
  assert string.contains(confirm.body, "1 redirection(s) will be removed")
  assert get(env.redirect <> "/blog/1", []).status == 308
  let resp = post_form(env, "/rules/bulk", cookie, confirm_fields(confirm.body))
  assert resp.status == 303
  assert get(env.redirect <> "/blog/1", []).status == 404
}

/// A bulk action applies to the rules the page showed: when they changed
/// since, nothing is changed ("every matching rule" would otherwise take
/// in a rule nobody saw).
pub fn bulk_actions_refuse_a_changed_rule_set_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let bulk_version = fn() {
    let page = get(env.admin <> "/rules", [#("cookie", cookie)]).body
    let assert Ok(#(_, form)) = string.split_once(page, "id=\"bulk\"")
    hidden_value(form, "version")
  }
  let shown = bulk_version()
  // another admin adds a rule meanwhile
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/added-meanwhile"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let disable_all = fn(version) {
    post_form(env, "/rules/bulk", cookie, [
      #("csrf_token", csrf),
      #("action", "disable"),
      #("all_matching", "on"),
      #("version", version),
      #("return_to", "/rules"),
    ])
  }
  let resp = disable_all(shown)
  assert resp.status == 409
  assert string.contains(resp.body, "changed since this page was shown")
  assert get(env.redirect <> "/added-meanwhile", []).status == 301
  // from the current list, it applies
  assert disable_all(bulk_version()).status == 303
  assert get(env.redirect <> "/added-meanwhile", []).status == 404
}

pub fn toggle_keeps_the_list_filters_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = get(env.admin <> "/rules?q=old&sort=source", [#("cookie", cookie)])
  let assert Ok(#(_, rest)) = string.split_once(page.body, "/toggle\"")
  let assert Ok(#(before, _)) = string.split_once(page.body, "/toggle\"")
  let id = case string.split(before, "/rules/") |> list.last {
    Ok(id) -> id
    Error(Nil) -> ""
  }
  let assert Ok(#(_, version_rest)) =
    string.split_once(rest, "name=\"version\" type=\"hidden\" value=\"")
  let assert Ok(#(version, _)) = string.split_once(version_rest, "\"")
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("version", version),
      #("return_to", "/rules?q=old&sort=source&page=1"),
    ])
  assert resp.status == 303
  assert location(resp)
    == "/rules?q=old&sort=source&page=1&flash=disabled&id="
    <> uri.percent_encode(id)
  // the flash names the rule (looked up by id)
  let back = get(env.admin <> location(resp), [#("cookie", cookie)])
  assert string.contains(back.body, "Redirection * /old disabled.")
  // anything else than the rules list goes back to /rules
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("return_to", "https://evil.test/rules"),
    ])
  assert string.starts_with(location(resp), "/rules?")
}

pub fn audit_page_filters_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/audited"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let page = fn(query) {
    get(env.admin <> "/audit?" <> query, [#("cookie", cookie)]).body
  }
  // the action column renders <code>action</code>
  assert string.contains(page("action=rule."), "<code>rule.create</code>")
  assert !string.contains(page("action=rule."), "<code>auth.login</code>")
  assert string.contains(page("action=auth."), "<code>auth.login</code>")
  assert string.contains(page("actor=nobody"), "No audit entry matches.")
}

pub fn destructive_actions_are_confirmed_test() {
  let env = boot(config.default())
  let #(cookie, _) = login(env)
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]) }
  let users = page("/users")
  // a link to a confirmation page, not a form posting at once
  assert !string.contains(users.body, "action=\"/users/admin/delete\"")
  let assert Ok(_) =
    users.create(
      users.Settings(
        path: env.dir <> "/users.json",
        audit_path: env.dir <> "/audit.jsonl",
      ),
      "bob",
      password.hash_with("bob-password-123", 1000),
      by: "test",
    )
  let confirm = page("/users/bob/delete")
  assert confirm.status == 200
  assert string.contains(confirm.body, "will be removed and signed out")
  assert string.contains(confirm.body, "action=\"/users/bob/delete\"")
}

pub fn admin_forms_and_exports_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]) }
  // every page starts with a skip link to the content
  assert string.contains(page("/rules").body, "href=\"#main\"")
  // field errors are next to the field, announced as such
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "no-slash"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "aria-invalid=\"true\"")
  assert string.contains(resp.body, "id=\"source-errors\"")
  assert string.contains(resp.body, "href=\"#source\"")
  // Duplicate opens the form filled from another rule
  // the id of the regex rule, from its edit link
  let list = page("/rules?kind=regex").body
  let assert Ok(#(before, _)) = string.split_once(list, "/edit\"")
  let assert Ok(id) = string.split(before, "/rules/") |> list.last
  let copy = page("/rules/new?from=" <> id)
  assert string.contains(copy.body, "^/blog/")
  assert string.contains(copy.body, "(copy)")
    || string.contains(copy.body, "Copy")
  // exports follow the filters, in the admin and the API
  let export = page("/export?kind=regex").body
  assert string.contains(export, "/blog/")
  assert !string.contains(export, "/old")
  // the filters are named as in the API (the old names above still work)
  let export = page("/export?match=regex&enabled=true").body
  assert string.contains(export, "/blog/")
  assert !string.contains(export, "/old")
  assert !string.contains(
    page("/export?match=regex&enabled=false").body,
    "/blog/",
  )
  let list = page("/rules?status=enabled").body
  assert string.contains(list, "<option selected value=\"true\">Enabled only")
    || string.contains(list, "value=\"true\" selected")
  // the list links and the bulk form carry the API names
  let list = page("/rules?kind=exact&status=enabled").body
  assert string.contains(
    list,
    "name=\"filter_match\" type=\"hidden\" value=\"exact\"",
  )
  assert string.contains(
    list,
    "name=\"filter_enabled\" type=\"hidden\" value=\"true\"",
  )
}

pub fn rule_crud_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)

  // create
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "307"),
      #("source", "/promo"),
      #("target", "https://shop.test/sale"),
      #("priority", "100"),
      #("enabled", "on"),
    ])
  assert resp.status == 303
  let redirect = get(env.redirect <> "/promo", [])
  assert redirect.status == 307
  assert location(redirect) == "https://shop.test/sale"

  // validation errors are shown
  let resp =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("match", "regex"),
      #("status", "301"),
      #("source", "^/(a+)+$"),
      #("target", "/x"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "catastrophic backtracking")

  // the list shows it
  let list_page = get(env.admin <> "/rules?q=promo", [#("cookie", cookie)])
  assert string.contains(list_page.body, "https://shop.test/sale")

  // find its id in the persisted file
  let assert Ok(content) = simplifile.read(env.dir <> "/redirects.json")
  let assert Ok(#(_, after)) =
    string.split_once(content, "\"source\":\"/promo\"")
  let _ = after
  let id = find_id(content, "/promo")

  // update
  let resp =
    post_form(env, "/rules/" <> id, cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/promo"),
      #("target", "https://shop.test/summer"),
      #("enabled", "on"),
    ])
  assert resp.status == 303
  assert location(get(env.redirect <> "/promo", []))
    == "https://shop.test/summer"

  // toggle off
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.redirect <> "/promo", []).status == 404

  // delete
  let resp =
    post_form(env, "/rules/" <> id <> "/delete", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.admin <> "/rules/" <> id <> "/edit", [#("cookie", cookie)]).status
    == 404

  // audit trail
  let audit = get(env.admin <> "/audit", [#("cookie", cookie)])
  assert string.contains(audit.body, "rule.delete")
}

/// Two admins edit the same redirection: the second save is refused instead
/// of silently overwriting the first.
pub fn concurrent_admin_edits_are_detected_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert Ok(content) = simplifile.read(env.dir <> "/redirects.json")
  let id = find_id(content, "/old")
  let fields = fn(target, version) {
    [
      #("csrf_token", csrf),
      #("version", version),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/old"),
      #("target", target),
      #("enabled", "on"),
    ]
  }
  // both open the edit page
  let page = get(env.admin <> "/rules/" <> id <> "/edit", [#("cookie", cookie)])
  let version = hidden_value(page.body, "version")
  assert version != ""

  // the first one saves
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://first.test/", version),
    )
  assert resp.status == 303

  // the second one, based on the same version, is told and nothing changes
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://second.test/", version),
    )
  assert resp.status == 409
  assert string.contains(resp.body, "while you were working on it")
  assert string.contains(resp.body, "https://second.test/")
  assert location(get(env.redirect <> "/old", [])) == "https://first.test/"

  // saving the conflict form again (it carries the new version) overwrites
  let resp =
    post_form(
      env,
      "/rules/" <> id,
      cookie,
      fields("https://second.test/", hidden_value(resp.body, "version")),
    )
  assert resp.status == 303
  assert location(get(env.redirect <> "/old", [])) == "https://second.test/"

  // toggling and deleting from a stale page are refused too
  let resp =
    post_form(env, "/rules/" <> id <> "/toggle", cookie, [
      #("csrf_token", csrf),
      #("version", version),
    ])
  assert resp.status == 409
  let resp =
    post_form(env, "/rules/" <> id <> "/delete", cookie, [
      #("csrf_token", csrf),
      #("version", version),
    ])
  assert resp.status == 409
  assert get(env.redirect <> "/old", []).status == 301
}

pub fn import_export_and_tester_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let content =
    "[{\"source\": \"/imported\", \"target\": \"/landing\", \"status\": 302}]"
  // a replace is previewed first: nothing is written yet
  let preview =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("content", content),
    ])
  assert preview.status == 200
  assert string.contains(preview.body, "Import preview")
  assert string.contains(preview.body, "removed")
  assert get(env.redirect <> "/old", []).status == 301
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("step", "apply"),
      #("content", content),
    ])
  assert resp.status == 303
  assert location(get(env.redirect <> "/imported", [])) == "/landing"
  assert get(env.redirect <> "/old", []).status == 404

  let export = get(env.admin <> "/export", [#("cookie", cookie)])
  assert export.status == 200
  assert string.contains(export.body, "/imported")
  assert response.get_header(export, "content-disposition")
    |> result.map(string.contains(_, "redirects.json"))
    == Ok(True)

  let tester =
    get(
      env.admin
        <> "/test?"
        <> uri.query_to_string([#("url", "https://x.test/imported?a=1")]),
      [#("cookie", cookie)],
    )
  assert string.contains(tester.body, "/landing")

  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("content", "{broken"),
    ])
  assert resp.status == 422
}

/// Applying a previewed replace while the rules changed meanwhile shows the
/// updated preview instead of deleting rules that were never shown.
pub fn stale_import_preview_is_shown_again_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let content = "[{\"source\": \"/imported\", \"target\": \"/landing\"}]"
  let preview =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("content", content),
    ])
  let assert Ok(#(_, rest)) =
    string.split_once(preview.body, "name=\"version\" type=\"hidden\" value=\"")
  let assert Ok(#(version, _)) = string.split_once(rest, "\"")
  assert version != ""
  // another administrator adds a rule
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/added-meanwhile"),
      #("target", "/x"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("step", "apply"),
      #("version", version),
      #("content", content),
    ])
  assert resp.status == 200
  assert string.contains(resp.body, "were changed while you were reviewing")
  assert get(env.redirect <> "/added-meanwhile", []).status == 301
  assert get(env.redirect <> "/imported", []).status == 404
}

pub fn reload_from_disk_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\": \"/fresh\", \"target\": \"/reloaded\"}]",
    )
  let resp = post_form(env, "/reload", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert location(get(env.redirect <> "/fresh", [])) == "/reloaded"

  let assert Ok(Nil) = simplifile.write(env.dir <> "/redirects.json", "[{]")
  let resp = post_form(env, "/reload", cookie, [#("csrf_token", csrf)])
  assert resp.status == 422
  assert location(get(env.redirect <> "/fresh", [])) == "/reloaded"
}

pub fn api_clients_page_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let page = get(env.admin <> "/api-clients", [#("cookie", cookie)])
  assert page.status == 200
  assert string.contains(page.body, "No API client yet.")

  // create: the secret is shown once
  let resp =
    post_form(env, "/api-clients", cookie, [
      #("csrf_token", csrf),
      #("name", "deploy"),
      #("scope", "redirects:read"),
      #("scope", "redirects:ops"),
    ])
  assert resp.status == 201
  let secret = between(resp.body, "rps_", "<")
  let client_id = between(resp.body, "rp_", "<")
  assert string.length(secret) > 20

  // the client can obtain a token
  let token_resp =
    send(
      http.Post,
      env.admin <> "/oauth/token",
      [#("content-type", "application/x-www-form-urlencoded")],
      uri.query_to_string([
        #("grant_type", "client_credentials"),
        #("client_id", "rp_" <> client_id),
        #("client_secret", "rps_" <> secret),
      ]),
    )
  assert token_resp.status == 200
  assert string.contains(token_resp.body, "redirects:read redirects:ops")

  // the listing no longer shows the secret
  let page = get(env.admin <> "/api-clients", [#("cookie", cookie)])
  assert !string.contains(page.body, secret)
  assert string.contains(page.body, "deploy")

  // invalid: no scope
  let resp =
    post_form(env, "/api-clients", cookie, [
      #("csrf_token", csrf),
      #("name", "noscope"),
    ])
  assert resp.status == 422

  // rotate shows a new secret, then delete
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/rotate", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 200
  assert between(resp.body, "rps_", "<") != secret
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/delete", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 303
  let resp =
    post_form(env, "/api-clients/rp_" <> client_id <> "/delete", cookie, [
      #("csrf_token", csrf),
    ])
  assert resp.status == 404
}

pub fn admin_rule_tags_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("source", "/tagged"),
      #("target", "/x"),
      #("status", "301"),
      #("priority", "100"),
      #("enabled", "on"),
      #("tags", "Spring Sale, legacy"),
    ]).status
  let page = fn(path) { get(env.admin <> path, [#("cookie", cookie)]).body }
  let list = page("/rules?tag=legacy")
  assert string.contains(list, "/tagged")
  assert !string.contains(list, "/old")
  // each tag links to its filter
  assert string.contains(list, "href=\"/rules?tag=spring%20sale\"")
  assert !string.contains(page("/rules?tag=other"), "/tagged")
}

pub fn admin_csv_import_and_export_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "merge"),
      #("content", "source,target,status,tags\n/from-csv,/landing,302,sheet\n"),
    ])
  assert resp.status == 303
  let found = get(env.redirect <> "/from-csv", [])
  assert found.status == 302
  assert location(found) == "/landing"
  // errors name the line
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "merge"),
      #("content", "source,target,status\n/x,/y,moved\n"),
    ])
  assert resp.status == 422
  assert string.contains(resp.body, "line 2: status: must be a number")
  let export =
    get(env.admin <> "/export?format=csv&tag=sheet", [#("cookie", cookie)])
  assert response.get_header(export, "content-type")
    == Ok("text/csv; charset=utf-8")
  assert string.contains(export.body, "/from-csv,/landing,302")
  assert !string.contains(export.body, "/old,")
}

/// A rule whose id is not URL-safe (written in the rules file: imports
/// refuse such ids) can still be edited: links carry it percent-encoded.
pub fn rules_with_any_id_can_be_edited_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"id\": \"rule 1/é\", \"source\": \"/spaced\", \"target\": \"/t\"}]",
    )
  let resp = post_form(env, "/reload", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  // such a new id is refused; an existing one can be imported again
  let import_csv = fn(content) {
    let preview =
      post_form(env, "/import", cookie, [
        #("csrf_token", csrf),
        #("mode", "merge"),
        #("content", content),
      ])
    preview.status
  }
  assert import_csv("id,source,target\nrule 2/é,/other,/t\n") == 422
  assert import_csv("id,source,target\nrule 1/é,/spaced,/t2\n") == 303
  let edit = "/rules/" <> uri.percent_encode("rule 1/é")
  let page = get(env.admin <> edit <> "/edit", [#("cookie", cookie)])
  assert page.status == 200
  assert string.contains(page.body, "/spaced")
  let resp = post_form(env, edit <> "/toggle", cookie, [#("csrf_token", csrf)])
  assert resp.status == 303
  assert get(env.redirect <> "/spaced", []).status == 404
}

/// Applying a previewed import writes exactly what was previewed: a form
/// would turn the line breaks of a multi-line note into CRLF.
pub fn applied_imports_are_what_was_previewed_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let content =
    "[{\"source\": \"/multi\", \"target\": \"/t\", \"note\": \"a\\nb\"}]"
  let preview =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("content", content),
    ])
  assert preview.status == 200
  let resp =
    post_form(env, "/import", cookie, [
      #("csrf_token", csrf),
      #("mode", "replace"),
      #("step", "apply"),
      #("version", hidden_value(preview.body, "version")),
      #("content_base64", hidden_value(preview.body, "content_base64")),
    ])
  assert resp.status == 303
  let assert Ok(file) = simplifile.read(env.dir <> "/redirects.json")
  assert string.contains(file, "\"note\":\"a\\nb\"")
}

/// The rule history is in the audit log, for administrators only: editors
/// get no link to a page they cannot open.
pub fn history_link_is_for_administrators_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let assert 303 =
    post_form(env, "/rules", cookie, [
      #("csrf_token", csrf),
      #("host", "*"),
      #("match", "exact"),
      #("status", "301"),
      #("source", "/with-history"),
      #("target", "/x"),
      #("priority", "100"),
      #("enabled", "on"),
    ]).status
  let assert Ok(file) = simplifile.read(env.dir <> "/redirects.json")
  let id = find_id(file, "/with-history")
  let edit = env.admin <> "/rules/" <> id <> "/edit"
  assert string.contains(get(edit, [#("cookie", cookie)]).body, "History")
  let #(editor, _) = login_with_role(env, "ed-history", role.Editor)
  let page = get(edit, [#("cookie", editor)])
  assert page.status == 200
  assert !string.contains(page.body, "History")
}

pub fn rule_details_leave_out_unknown_dates_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  // written by hand: no timestamps, no author
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"id\": \"by-hand\", \"source\": \"/by-hand\", \"target\": \"/x\"},"
        <> "{\"id\": \"dated\", \"source\": \"/dated\", \"target\": \"/y\","
        <> "\"created_at\": \"2026-01-02T03:04:05Z\","
        <> "\"updated_at\": \"2026-02-03T04:05:06Z\", \"updated_by\": \"ann\"}]",
    )
  assert post_form(env, "/reload", cookie, [#("csrf_token", csrf)]).status
    == 303
  let page = fn(id) {
    get(env.admin <> "/rules/" <> id <> "/edit", [#("cookie", cookie)]).body
  }
  let by_hand = page("by-hand")
  assert !string.contains(by_hand, "Created ,")
  assert !string.contains(by_hand, " by  ·")
  assert string.contains(by_hand, ">0 hit(s)")
  assert string.contains(
    page("dated"),
    "Created 2026-01-02T03:04:05Z, updated 2026-02-03T04:05:06Z by ann · 0 hit(s)",
  )
}

/// A store too busy to answer in time (here waiting for the lock another
/// process holds): a 503 page with Retry-After and the change not made,
/// rather than a crash. Sent over a raw socket: httpc before OTP 28.4 retries
/// a 503 with Retry-After until it succeeds.
pub fn admin_busy_store_answers_503_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let lock = env.dir <> "/redirects.json.lock"
  let assert Ok(Nil) = simplifile.write(lock, "12345 cli@host\n")
  ffi.set_tunable("store_call_timeout", 200)
  let body =
    uri.query_to_string([
      #("csrf_token", csrf),
      #("match", "exact"),
      #("source", "/busy"),
      #("target", "/t"),
      #("status", "301"),
    ])
  let assert [_, port] = string.split(env.admin, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let raw =
    integration_support.raw_exchange(port, [
      <<
        "POST /rules HTTP/1.1\r\nhost: 127.0.0.1:",
        int.to_string(port):utf8,
        "\r\nconnection: close\r\norigin: ",
        env.admin:utf8,
        "\r\ncookie: ",
        cookie:utf8,
        "\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: ",
        int.to_string(string.byte_size(body)):utf8,
        "\r\n\r\n",
        body:utf8,
      >>,
    ])
  ffi.clear_tunable("store_call_timeout")
  let assert Ok(Nil) = simplifile.delete(lock)

  let assert Ok(raw) = bit_array.to_string(raw)
  let assert Ok(#(head, page)) = string.split_once(raw, "\r\n\r\n")
  let head = string.lowercase(head)
  assert string.starts_with(head, "http/1.1 503")
  assert string.contains(head, "\r\nretry-after: 1\r\n")
  assert string.contains(page, "your change was not made")
  // the change was skipped: the list (queued behind it) does not show it
  let rules = get(env.admin <> "/rules", [#("cookie", cookie)])
  assert rules.status == 200
  assert !string.contains(rules.body, "/busy")
  let assert Ok(content) = simplifile.read(env.dir <> "/redirects.json")
  assert !string.contains(content, "/busy")
}

/// Deleting every matching redirection confirms with the filters, not one
/// field per rule: thousands of ids would go past the form size limit.
pub fn bulk_delete_of_many_matching_rules_test() {
  let env = boot(config.default())
  let #(cookie, csrf) = login(env)
  let rules =
    int.range(0, 2000, [], fn(acc, n) {
      let i = int.to_string(n)
      [
        "{\"id\":\"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e"
          <> string.pad_start(i, 3, "0")
          <> "\",\"source\":\"/many/"
          <> i
          <> "\",\"target\":\"/t\"}",
        ..acc
      ]
    })
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[{\"source\":\"/kept\",\"target\":\"/t\"},"
        <> string.join(rules, ",")
        <> "]",
    )
  let assert 303 =
    post_form(env, "/reload", cookie, [#("csrf_token", csrf)]).status
  let confirm =
    post_form(env, "/rules/bulk", cookie, [
      #("csrf_token", csrf),
      #("action", "delete"),
      #("all_matching", "on"),
      #("filter_q", "/many/"),
      #("return_to", "/rules"),
    ])
  assert confirm.status == 200
  assert string.contains(confirm.body, "2000 redirection(s) will be removed")
  assert !string.contains(confirm.body, "name=\"ids\"")
  // not without the version the confirmation showed
  let unversioned =
    list.filter(confirm_fields(confirm.body), fn(kv) { kv.0 != "version" })
  assert post_form(env, "/rules/bulk", cookie, unversioned).status == 409
  assert get(env.redirect <> "/many/1999", []).status == 301
  let resp = post_form(env, "/rules/bulk", cookie, confirm_fields(confirm.body))
  assert resp.status == 303
  assert get(env.redirect <> "/many/1999", []).status == 404
  assert get(env.redirect <> "/kept", []).status == 301
}

/// The fields of the form of a bulk delete confirmation, as it posts them.
fn confirm_fields(page: String) -> List(#(String, String)) {
  let assert Ok(#(_, form)) = string.split_once(page, "action=\"/rules/bulk\"")
  form
  |> string.split("<input ")
  |> list.drop(1)
  |> list.filter_map(fn(input) {
    use #(_, rest) <- result.try(string.split_once(input, "name=\""))
    use #(name, rest) <- result.try(string.split_once(rest, "\""))
    use #(_, rest) <- result.try(string.split_once(rest, "value=\""))
    use #(value, _) <- result.try(string.split_once(rest, "\""))
    Ok(#(name, value))
  })
}
