//// The OAuth 2.0 token endpoint (client credentials grant).

import gleam/bit_array
import gleam/bool
import gleam/http/request
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleam/uri
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/api/clients
import redirect_proxy/api/problem
import redirect_proxy/api/rule_json as _
import redirect_proxy/api/scope
import redirect_proxy/api/token
import redirect_proxy/api/web.{type Context} as _
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/metrics
import wisp.{type Request, type Response}

pub fn token_endpoint(req: Request, ctx: Context) -> Response {
  use form <- wisp.require_form(req)
  let field = fn(name) { list.key_find(form.values, name) |> result.unwrap("") }
  let basic = basic_credentials(req)
  let #(client_id, secret) = case basic {
    Ok(credentials) -> credentials
    Error(Nil) -> #(field("client_id"), field("client_secret"))
  }
  // Same scheme as admin logins: per client address and client id, per
  // address, and per client id (high, so that failures from elsewhere cannot
  // cheaply lock a deployment pipeline out).
  let client_id = case string.byte_size(client_id) > 128 {
    True -> ""
    False -> client_id
  }
  let pair_key = "token:" <> ctx.client_ip <> " " <> client_id
  let ip_key = "token-ip:" <> ctx.client_ip
  let client_key = "token-client:" <> client_id
  use <- bool.lazy_guard(
    ratelimit.is_blocked(pair_key, 10)
      || ratelimit.is_blocked(ip_key, 30)
      || ratelimit.is_blocked(client_key, 100),
    fn() {
      oauth_error(429, "slow_down", "Too many failed attempts, retry later.")
    },
  )
  use <- bool.lazy_guard(field("grant_type") != "client_credentials", fn() {
    oauth_error(
      400,
      "unsupported_grant_type",
      "Only the client_credentials grant is supported.",
    )
  })
  case client_id, clients.authenticate(ctx.clients, client_id, secret) {
    "", _ | _, Error(Nil) -> {
      ratelimit.record_failure(pair_key, 900)
      ratelimit.record_failure(ip_key, 900)
      ratelimit.record_failure(client_key, 900)
      metrics.incr(metrics.ApiAuthFailures)
      log.warning(
        "token request rejected for client="
        <> ffi.escape_newlines(client_id)
        <> " ip="
        <> ctx.client_ip,
      )
      let resp =
        oauth_error(401, "invalid_client", "Client authentication failed.")
      case basic {
        Ok(_) ->
          wisp.set_header(
            resp,
            "www-authenticate",
            "Basic realm=\"redirect-proxy\"",
          )
        Error(Nil) -> resp
      }
    }
    _, Ok(client) -> {
      let requested = case string.trim(field("scope")) {
        "" -> Ok(client.scopes)
        value -> {
          let names =
            value |> string.split(" ") |> list.filter(fn(s) { s != "" })
          let parsed = list.filter_map(names, scope.from_string)
          case
            list.length(parsed) == list.length(names)
            && list.all(parsed, scope.allows(client.scopes, _))
          {
            True -> Ok(list.unique(parsed))
            False -> Error(Nil)
          }
        }
      }
      case requested {
        Error(Nil) ->
          oauth_error(
            400,
            "invalid_scope",
            "The requested scope exceeds the scopes granted to the client.",
          )
        Ok(scopes) -> {
          ratelimit.reset(client_key)
          let ttl = ctx.config.api.token_ttl
          let access_token =
            token.issue(client.client_id, client.secret_hash, scopes, ttl)
          metrics.incr(metrics.TokensIssued)
          problem.json_response(
            200,
            json.object([
              #("access_token", json.string(access_token)),
              #("token_type", json.string("Bearer")),
              #("expires_in", json.int(ttl)),
              #("scope", json.string(scope.join(scopes))),
            ]),
          )
          |> wisp.set_header("pragma", "no-cache")
        }
      }
    }
  }
}

/// `Authorization: Basic` client credentials, form-urlencoded per RFC 6749
/// §2.3.1.
fn basic_credentials(req: Request) -> Result(#(String, String), Nil) {
  use value <- result.try(request.get_header(req, "authorization"))
  use #(scheme, encoded) <- result.try(string.split_once(
    string.trim(value),
    " ",
  ))
  use <- bool.guard(string.lowercase(scheme) != "basic", Error(Nil))
  use bits <- result.try(bit_array.base64_decode(string.trim(encoded)))
  use decoded <- result.try(bit_array.to_string(bits))
  use #(id, secret) <- result.try(string.split_once(decoded, ":"))
  let unescape = fn(v) { uri.percent_decode(v) |> result.unwrap(v) }
  Ok(#(unescape(id), unescape(secret)))
}

fn oauth_error(status: Int, error: String, description: String) -> Response {
  problem.json_response(
    status,
    json.object([
      #("error", json.string(error)),
      #("error_description", json.string(description)),
    ]),
  )
  |> wisp.set_header("pragma", "no-cache")
}
