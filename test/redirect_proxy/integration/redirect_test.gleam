//// End-to-end tests of the redirect listener: rules, access logs, HTTPS,
//// limits.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/charlist
import gleam/erlang/process
import gleam/http
import gleam/http/response
import gleam/int
import gleam/json
import gleam/result
import gleam/string
import integration_support.{
  access_lines, boot, get, lines_of, location, os_cmd, raw_exchange,
  reload_rules, send,
}
import redirect_proxy/config
import simplifile

pub fn redirect_listener_test() {
  let env = boot(config.default())

  let resp = get(env.redirect <> "/old", [#("host", "any.test")])
  assert resp.status == 301
  assert location(resp) == "https://example.com/new"
  assert response.get_header(resp, "cache-control")
    == Ok("public, max-age=3600")

  let resp =
    get(env.redirect <> "/v1/guide?lang=fr", [#("host", "docs.test:80")])
  assert resp.status == 302
  assert location(resp) == "https://docs.example.com/v2/guide?lang=fr"
  assert response.get_header(resp, "cache-control") == Ok("no-store")

  let resp = get(env.redirect <> "/v1/guide", [#("host", "other.test")])
  assert resp.status == 404

  let resp = get(env.redirect <> "/blog/42", [])
  assert resp.status == 308
  assert location(resp) == "/articles/42"

  let resp = send(http.Post, env.redirect <> "/old", [], "ignored body")
  assert resp.status == 301

  let resp = send(http.Head, env.redirect <> "/old", [], "")
  assert resp.status == 301

  let resp = send(http.Options, env.redirect <> "/old", [], "")
  assert resp.status == 204
  assert response.get_header(resp, "allow")
    == Ok("GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS")
}

pub fn access_log_test() {
  let env = boot(config.default())
  let _ =
    get(env.redirect <> "/old?email=someone@example.com", [
      #("referer", "https://ref.test/page?token=secret"),
      #("user-agent", "tester \"1\""),
    ])
  let _ = get(env.redirect <> "/missing", [])
  let lines = access_lines(env.dir, 2)
  let assert [hit, miss] = lines
  assert string.starts_with(hit, "127.0.0.0 - - [")
  assert string.contains(hit, "] \"GET /old HTTP/1.1\" 301 0 ")
  assert string.ends_with(
    hit,
    "\"https://ref.test/page\" \"tester \\x221\\x22\"",
  )
  assert !string.contains(hit, "someone")
  assert !string.contains(hit, "secret")
  assert string.contains(miss, "\"GET /missing HTTP/1.1\" 404 9 \"-\"")
}

pub fn access_log_json_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(
          ..d.access_log,
          format: "json",
          log_query: True,
          anonymize_ip: "none",
        ),
      ),
    )
  let _ = get(env.redirect <> "/blog/7?a=1", [])
  let assert [line] = access_lines(env.dir, 1)
  let decoder = {
    use addr <- decode.field("remote_addr", decode.string)
    use status <- decode.field("status", decode.int)
    use args <- decode.field("args", decode.string)
    use location <- decode.field("location", decode.string)
    use rule_id <- decode.field("rule_id", decode.string)
    decode.success(#(addr, status, args, location, rule_id))
  }
  let assert Ok(#("127.0.0.1", 308, "a=1", "/articles/7", rule_id)) =
    json.parse(line, decoder)
  assert rule_id != ""
}

pub fn access_log_admin_and_api_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(
          ..d.access_log,
          format: "$listener $request_method $uri $status",
          api: config.ListenerLogConfig(
            ..d.access_log.api,
            output: "{dir}/logs/api.log",
          ),
        ),
      ),
    )
  let _ = get(env.redirect <> "/old", [])
  let _ = get(env.admin <> "/login?next=/rules", [])
  let _ = get(env.admin <> "/api/openapi.json", [])
  let assert ["redirect GET /old 301", "admin GET /login 200"] =
    access_lines(env.dir, 2)
  let assert ["api GET /api/openapi.json 200"] =
    lines_of(env.dir <> "/logs/api.log", 1)
}

pub fn access_log_disabled_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, enabled: False),
      ),
    )
  let _ = get(env.redirect <> "/old", [])
  process.sleep(100)
  assert simplifile.read(env.dir <> "/logs/access.log")
    |> result.unwrap("")
    == ""
}

pub fn fallback_url_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(
          ..d.server,
          fallback_url: "https://home.test/",
        ),
      ),
    )
  let resp = get(env.redirect <> "/nothing", [])
  assert resp.status == 302
  assert location(resp) == "https://home.test/"
}

/// The redirect listener never reads request bodies: a body arriving after
/// the headers must not be parsed as a second request on the same connection.
/// A query with the characters browsers leave unescaped is kept as is in
/// the `location` of a `preserve_query` rule; CR and LF never get there.
pub fn preserved_queries_keep_browser_characters_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let assert Ok(received) =
    raw_exchange(port, [
      <<
        "GET /v1/guide?a[]=1&b={x}|y^z`w HTTP/1.1\r\nhost: docs.test\r\nconnection: close\r\n\r\n":utf8,
      >>,
    ])
    |> bit_array.to_string
  assert string.starts_with(received, "HTTP/1.1 302 ")
  assert string.contains(
    received,
    "\r\nlocation: https://docs.example.com/v2/guide?a[]=1&b={x}|y^z`w\r\n",
  )
  let assert Ok(received) =
    raw_exchange(port, [
      <<
        "GET /v1/guide?a=1\r\nset-cookie: x=1 HTTP/1.1\r\nhost: docs.test\r\n\r\n":utf8,
      >>,
    ])
    |> bit_array.to_string
  assert string.starts_with(received, "HTTP/1.1 400 ")
  assert !string.contains(string.lowercase(received), "set-cookie")
  assert !string.contains(received, "location")
}

pub fn unread_bodies_close_the_connection_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let smuggled = "GET /blog/7 HTTP/1.1\r\nhost: a.test\r\n\r\n"
  let headers =
    "POST /old HTTP/1.1\r\nhost: a.test\r\ncontent-length: "
    <> int.to_string(string.byte_size(smuggled))
    <> "\r\n\r\n"
  let assert Ok(received) =
    raw_exchange(port, [<<headers:utf8>>, <<smuggled:utf8>>])
    |> bit_array.to_string
  assert string.starts_with(received, "HTTP/1.1 301")
  assert string.contains(string.lowercase(received), "connection: close")
  assert !string.contains(received, "/articles/7")

  // without a body the connection stays open for the next request
  let assert Ok(received) =
    raw_exchange(port, [
      <<"GET /old HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
      <<"GET /blog/7 HTTP/1.1\r\nhost: a.test\r\n\r\n":utf8>>,
    ])
    |> bit_array.to_string
  assert string.contains(received, "/articles/7")
}

/// With `access_log.trusted_proxies`, only their `X-Forwarded-Proto`
/// skips the upgrade (the access log off: the peer is still looked up).
pub fn https_redirect_behind_trusted_proxies_test() {
  let d = config.default()
  let boot_trusting = fn(trusted) {
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, https_redirect: True),
        access_log: config.AccessLogConfig(
          ..d.access_log,
          enabled: False,
          trusted_proxies: trusted,
        ),
      ),
    )
  }
  let forwarded = [#("host", "shop.test"), #("x-forwarded-proto", "https")]
  let env = boot_trusting(["10.0.0.0/8"])
  let resp = get(env.redirect <> "/old", forwarded)
  assert resp.status == 301
  assert location(resp) == "https://shop.test/old"
  let env = boot_trusting(["127.0.0.1/32"])
  let resp = get(env.redirect <> "/old", forwarded)
  assert location(resp) == "https://example.com/new"
}

pub fn https_redirect_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(
          ..d.server,
          https_redirect: True,
          health_path: "/_health",
        ),
      ),
    )
  let resp = get(env.redirect <> "/old?a=1", [#("host", "Shop.Test:80")])
  assert resp.status == 301
  assert location(resp) == "https://shop.test/old?a=1"
  // other methods are repeated as they were
  let resp =
    send(http.Post, env.redirect <> "/form", [#("host", "shop.test")], "x=1")
  assert resp.status == 308
  assert location(resp) == "https://shop.test/form"
  // forwarded by a TLS proxy: the rules apply
  let resp =
    get(env.redirect <> "/old", [
      #("host", "shop.test"),
      #("x-forwarded-proto", "https"),
    ])
  assert resp.status == 301
  assert location(resp) == "https://example.com/new"
  assert get(env.redirect <> "/x", [#("x-forwarded-proto", "https")]).status
    == 404
  // a host that is not a host name is not redirected anywhere
  assert get(env.redirect <> "/old", [#("host", "evil.test/@x")]).status == 400
  // `_` is allowed, as in rule hosts
  let resp = get(env.redirect <> "/p", [#("host", "my_app.test")])
  assert resp.status == 301
  assert location(resp) == "https://my_app.test/p"
  // health probes are answered, not upgraded
  assert get(env.redirect <> "/_health", []).status == 200
}

pub fn overlong_paths_get_414_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, max_path_bytes: 300),
      ),
    )
  assert get(env.redirect <> "/" <> string.repeat("a", 299), []).status == 404
  let resp = get(env.redirect <> "/" <> string.repeat("a", 300), [])
  assert resp.status == 414
  let default_env = boot(d)
  assert get(default_env.redirect <> "/" <> string.repeat("a", 8192), []).status
    == 414
  assert get(default_env.redirect <> "/" <> string.repeat("a", 8191), []).status
    == 404
  // the query string does not count
  assert get(env.redirect <> "/old?" <> string.repeat("q", 400), []).status
    == 301
}

pub fn matching_features_over_http_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        server: config.ServerConfig(..d.server, trailing_slash: "ignore"),
      ),
    )
  let assert Ok(Nil) =
    simplifile.write(
      env.dir <> "/redirects.json",
      "[
        {\"source\": \"/café\", \"target\": \"/coffee\"},
        {\"host\": \"*.example.test\", \"source\": \"/w\", \"target\": \"/wild\"},
        {\"match\": \"prefix\", \"source\": \"/docs/\", \"target\": \"/manual/$1\"},
        {\"source\": \"/slash\", \"target\": \"/no-slash\"}
      ]",
    )
  let assert Ok(_) = reload_rules(env)
  // a browser sends the UTF-8 path percent-encoded
  let resp = get(env.redirect <> "/caf%C3%A9", [])
  assert resp.status == 301
  assert location(resp) == "/coffee"
  // wildcard hosts match subdomains only
  assert location(get(env.redirect <> "/w", [#("host", "a.example.test")]))
    == "/wild"
  assert get(env.redirect <> "/w", [#("host", "example.test")]).status == 404
  // Location is ASCII even when the capture holds decoded characters
  assert location(get(env.redirect <> "/docs/%C3%A9t%C3%A9", []))
    == "/manual/%C3%A9t%C3%A9"
  // trailing_slash = "ignore"
  assert location(get(env.redirect <> "/slash/", [])) == "/no-slash"
  // unsupported methods name the supported ones (httpc cannot send TRACE)
  let headers =
    os_cmd(charlist.from_string(
      "curl -s -o /dev/null -D - -X TRACE " <> env.redirect <> "/x",
    ))
    |> charlist.to_string
    |> string.lowercase
  assert string.contains(headers, " 405")
  assert string.contains(
    headers,
    "allow: get, head, post, put, delete, patch, options",
  )
}

/// Dot segments are removed before matching: a capture cannot climb out of
/// the target path (`/v1/../../x` would give `https://docs.example.com/x`).
pub fn dot_segments_cannot_escape_the_target_path_test() {
  let env = boot(config.default())
  let assert Ok(#(_, port)) = string.split_once(env.redirect, "127.0.0.1:")
  let assert Ok(port) = int.parse(port)
  let exchange = fn(path) {
    let request =
      "GET "
      <> path
      <> " HTTP/1.1\r\nhost: docs.test\r\nconnection: close\r\n\r\n"
    let assert Ok(text) =
      bit_array.to_string(raw_exchange(port, [bit_array.from_string(request)]))
    text
  }
  assert string.starts_with(exchange("/v1/../../x"), "HTTP/1.1 404 ")
  assert string.starts_with(exchange("/v1/%2E%2E/%2e%2E/x"), "HTTP/1.1 404 ")
  assert string.contains(
    exchange("/v1/a/../b"),
    "\r\nlocation: https://docs.example.com/v2/b\r\n",
  )
  // browsers read `\` as `/`: a raw backslash never reaches the matcher
  assert !string.contains(exchange("/v1/..\\..\\x"), "location:")
}

/// With truncated addresses (the default), a logged forwarding header is
/// truncated too: full addresses never reach the disk.
pub fn logged_forwarding_headers_are_truncated_test() {
  let d = config.default()
  let env =
    boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(
          ..d.access_log,
          format: "$remote_addr|$http_x_forwarded_for|$http_x_request_id",
        ),
      ),
    )
  let _ =
    get(env.redirect <> "/old", [
      #("x-forwarded-for", "198.51.100.77, 2001:db8:1:2::3"),
      #("x-request-id", "abc"),
    ])
  let assert [line] = access_lines(env.dir, 1)
  assert line == "127.0.0.0|198.51.100.0, 2001:db8:1::|abc"
}
