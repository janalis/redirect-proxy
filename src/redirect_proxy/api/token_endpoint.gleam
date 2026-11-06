//// The OAuth 2.0 token endpoint (client credentials grant).

import gleam/bit_array
import gleam/bool
import gleam/http/request
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
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
import redirect_proxy/audit
import redirect_proxy/config
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/metrics
import wisp.{type Request, type Response}

/// Failed token requests allowed per window for one client id from one
/// address, and from one address (all client ids). There is no limit per
/// client id alone: secrets are 256 random bits, so it would not slow down
/// guessing, only let anyone lock a deployment pipeline out.
const pair_limit = 10

const ip_limit = 30

const window = 900

pub fn token_endpoint(req: Request, ctx: Context) -> Response {
  let ip = ffi.throttle_address(ctx.client_ip)
  let ip_key = "token-ip:" <> ip
  // before the body is read: a blocked address costs no parsing
  use <- throttled([#(ip_key, ip_limit)])
  use form <- wisp.require_form(req)
  let field = fn(name) { list.key_find(form.values, name) |> result.unwrap("") }
  let basic = basic_credentials(req)
  let #(client_id, secret) = case basic {
    Ok(credentials) -> credentials
    Error(Nil) -> #(field("client_id"), field("client_secret"))
  }
  let client_id = case string.byte_size(client_id) > 128 {
    True -> ""
    False -> client_id
  }
  let pair_key = "token:" <> ip <> " " <> client_id
  use <- throttled([#(pair_key, pair_limit)])
  use <- bool.lazy_guard(field("grant_type") != "client_credentials", fn() {
    oauth_error(
      400,
      "unsupported_grant_type",
      "Only the client_credentials grant is supported.",
    )
  })
  case client_id, clients.authenticate(ctx.clients, client_id, secret) {
    "", _ | _, Error(Nil) -> {
      ratelimit.record_failure(pair_key, window)
      ratelimit.record_failure(ip_key, window)
      metrics.incr(metrics.ApiAuthFailures)
      audit.record_failure(
        config.audit_path(ctx.config),
        "client:" <> client_id,
        "api.token_rejected",
        client_id,
        json.object([#("client_ip", json.string(ctx.client_ip))]),
      )
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
          // like admin logins: only this client's failures from this
          // address are forgiven; the per client id count keeps bounding
          // guesses spread over many addresses
          ratelimit.reset(pair_key)
          let ttl = ctx.config.api.token_ttl
          let access_token =
            token.issue(client.client_id, client.secret_hash, scopes, ttl)
          metrics.incr(metrics.TokensIssued)
          audit_token(ctx, client.client_id, "api.token_issued", [
            #("scope", json.string(scope.join(scopes))),
          ])
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

/// Records a token request in the audit trail, with the client address.
fn audit_token(
  ctx: Context,
  client_id: String,
  action: String,
  details: List(#(String, json.Json)),
) -> Nil {
  audit.record(
    config.audit_path(ctx.config),
    "client:" <> client_id,
    action,
    client_id,
    None,
    Some(json.object([#("client_ip", json.string(ctx.client_ip)), ..details])),
  )
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

fn throttled(checks: List(#(String, Int)), next: fn() -> Response) -> Response {
  case ratelimit.retry_after(checks) {
    Error(Nil) -> next()
    Ok(seconds) ->
      oauth_error(429, "slow_down", "Too many failed attempts, retry later.")
      |> wisp.set_header("retry-after", int.to_string(seconds))
  }
}
