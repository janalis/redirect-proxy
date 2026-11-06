import gleam/http
import gleam/http/request
import redirect_proxy/admin/auth/header
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/router
import redirect_proxy/config
import redirect_proxy/role
import wisp/simulate

pub fn roles_test() {
  assert role.allows(role.Admin, role.Editor)
  assert role.allows(role.Editor, role.Editor)
  assert !role.allows(role.Viewer, role.Editor)
  assert role.from_string("editor") == Ok(role.Editor)
  assert role.from_string("root") == Error(Nil)
  // the default only applies when no group matched
  assert role.highest([role.Viewer], role.Admin) == role.Viewer
  assert role.highest([], role.Admin) == role.Admin
  assert role.highest([role.Viewer, role.Admin, role.Editor], role.Viewer)
    == role.Admin
}

pub fn sso_groups_give_roles_test() {
  let d = config.default().oidc
  let cfg =
    config.OidcConfig(
      ..d,
      admin_groups: ["ops"],
      editor_groups: ["marketing", "web"],
      viewer_groups: ["staff"],
      default_role: "viewer",
    )
  let who = fn(groups) {
    oidc.role_for(
      cfg,
      oidc.Identity(subject: "s", username: "u", email: "", groups:),
    )
  }
  assert who(["staff", "web"]) == role.Editor
  assert who(["ops", "staff"]) == role.Admin
  assert who(["staff"]) == role.Viewer
  assert who(["other"]) == role.Viewer
  // nothing configured: the least role, admins are named on purpose
  assert oidc.role_for(
      d,
      oidc.Identity(subject: "s", username: "u", email: "", groups: []),
    )
    == role.Viewer
}

pub fn proxy_role_header_test() {
  let req = fn(headers) {
    request.Request(..simulate.request(http.Get, "/"), headers:)
  }
  let d = config.default().header_auth
  assert header.role(d, req([])) == role.Viewer
  let cfg = config.HeaderAuthConfig(..d, role_header: "x-forwarded-role")
  assert header.role(cfg, req([#("x-forwarded-role", "Editor")])) == role.Editor
  // missing, unknown or repeated: the least, not the default
  assert header.role(cfg, req([])) == role.Viewer
  assert header.role(cfg, req([#("x-forwarded-role", "root")])) == role.Viewer
  assert header.role(
      cfg,
      req([#("x-forwarded-role", "admin"), #("x-forwarded-role", "admin")]),
    )
    == role.Viewer
}

/// Routes nobody listed need the admin role: a new page is not open to
/// every role by mistake.
pub fn unlisted_routes_need_admin_test() {
  assert router.required_role(http.Get, ["rules"]) == role.Viewer
  assert router.required_role(http.Get, ["rules", "x", "edit"]) == role.Viewer
  assert router.required_role(http.Post, ["rules", "x"]) == role.Editor
  assert router.required_role(http.Post, ["rules", "x", "toggle"])
    == role.Editor
  assert router.required_role(http.Post, ["import"]) == role.Editor
  assert router.required_role(http.Get, ["users"]) == role.Admin
  assert router.required_role(http.Get, ["audit"]) == role.Admin
  assert router.required_role(http.Get, ["something", "new"]) == role.Admin
  assert router.required_role(http.Post, ["rules", "x", "new-action"])
    == role.Admin
}
