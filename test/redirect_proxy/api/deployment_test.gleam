//// Tests of where the API is served: disabled, shared with the admin, or on
//// its own port.

import api_support.{access_token, api, header, own_port}
import gleam/http.{Get, Post}
import gleam/string
import redirect_proxy/api/scope
import redirect_proxy/config
import redirect_proxy/config/validate as config_validate
import support

pub fn api_can_be_disabled_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(..d, api: config.ApiConfig(..d.api, enabled: False)),
    )
  // falls through to the admin, which asks for a login
  assert support.send(Get, env.api <> "/api/redirects", [], "").status == 303
}

pub fn api_on_its_own_port_test() {
  let env = own_port(True)
  assert env.api != env.admin
  assert support.send(Get, env.api <> "/healthz", [], "").status == 200

  // the API and token endpoint live on the API port...
  let token = access_token(env, [scope.Write])
  let resp =
    api(
      env,
      Post,
      "/api/redirects",
      token,
      "{\"source\":\"/d\",\"target\":\"/e\"}",
    )
  assert resp.status == 201
  assert support.send(Get, env.redirect <> "/d", [], "").status == 301
  assert support.send(Get, env.api <> "/api/openapi.json", [], "").status == 200
  // ...and the admin UI is not served there
  assert support.send(Get, env.api <> "/rules", [], "").status == 404
  assert support.send(Get, env.api <> "/login", [], "").status == 404

  // the admin listener no longer serves the API
  let resp =
    support.send(
      Get,
      env.admin <> "/api/redirects",
      [#("authorization", "Bearer " <> token)],
      "",
    )
  assert resp.status == 303
  assert support.send(Post, env.admin <> "/oauth/token", [], "").status != 200
  // while the admin UI keeps working on its own port
  assert support.send(Get, env.admin <> "/login", [], "").status == 200

  let resp = support.send(Get, env.api <> "/healthz", [], "")
  assert header(resp, "x-content-type-options") == "nosniff"
  assert support.send(Get, env.api <> "/readyz", [], "").body == "ready"
  // the metrics stay on the admin listener
  assert support.send(Get, env.api <> "/metrics", [], "").status != 200
}

pub fn api_without_admin_ui_test() {
  let env = own_port(False)
  let token = access_token(env, [scope.Read])
  assert api(env, Get, "/api/redirects", token, "").status == 200
  // probes and metrics would be nowhere else
  assert support.send(Get, env.api <> "/readyz", [], "").status == 200
  let metrics = support.send(Get, env.api <> "/metrics", [], "")
  assert metrics.status == 200
  assert string.contains(metrics.body, "redirect_proxy_requests_total")
}

pub fn api_port_rules_test() {
  let d = config.default()
  let with_api = fn(api) { config.Config(..d, api:) }
  // default and explicit admin port: shared listener
  assert config.api_on_admin(d)
  assert !config.api_dedicated(d)
  let same = with_api(config.ApiConfig(..d.api, port: d.admin.port))
  assert config.api_on_admin(same)
  assert config.api_public_url(same) == d.admin.public_url
  // another port: own listener, inheriting admin.listen
  let other = with_api(config.ApiConfig(..d.api, port: 8082))
  assert config.api_dedicated(other)
  assert !config.api_on_admin(other)
  assert config.api_listen(other) == d.admin.listen
  assert config.api_public_url(other) == "http://localhost:8082"
  let assert Ok(_) = config_validate.validate(other)
  // admin disabled: the API keeps the admin port on its own listener
  let no_admin =
    config.Config(..d, admin: config.AdminConfig(..d.admin, enabled: False))
  assert config.api_dedicated(no_admin)
  assert config.api_port(no_admin) == d.admin.port
  // invalid combinations
  let assert Error(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, port: d.server.port),
    ))
  let assert Error(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, listen: "0.0.0.0"),
    ))
  let assert Ok(_) =
    config_validate.validate(with_api(
      config.ApiConfig(..d.api, listen: "0.0.0.0", port: 8082),
    ))
}

/// Served over HTTPS (its public URL says so), the API on its own port
/// asks clients not to fall back to HTTP, as the admin does.
pub fn api_on_its_own_port_over_https_sends_hsts_test() {
  let d = config.default()
  let api_config = fn(public_url) {
    config.ApiConfig(..d.api, port: support.free_port(), public_url:)
  }
  let env =
    support.boot(config.Config(..d, api: api_config("https://api.test")))
  let resp = support.send(Get, env.api <> "/healthz", [], "")
  assert header(resp, "strict-transport-security") == "max-age=31536000"
  let env = support.boot(config.Config(..d, api: api_config("")))
  let resp = support.send(Get, env.api <> "/healthz", [], "")
  assert header(resp, "strict-transport-security") == ""
}
