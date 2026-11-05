//// Authentication delegated to a trusted reverse proxy (oauth2-proxy,
//// Authelia, Pomerium...) through request headers. Headers are only trusted
//// when the TCP peer address belongs to a configured trusted proxy CIDR.

import gleam/http/request
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/config.{type HeaderAuthConfig}
import redirect_proxy/ffi
import wisp

pub fn identify(
  cfg: HeaderAuthConfig,
  req: wisp.Request,
  peer_ip: String,
) -> Result(String, Nil) {
  case cfg.enabled && is_trusted(cfg, peer_ip) {
    False -> Error(Nil)
    True -> {
      let user =
        request.get_header(req, cfg.user_header)
        |> result.lazy_or(fn() { request.get_header(req, cfg.email_header) })
        |> result.map(string.trim)
      case user {
        Ok("") | Error(Nil) -> Error(Nil)
        Ok(value) -> Ok(string.lowercase(value))
      }
    }
  }
}

pub fn is_trusted(cfg: HeaderAuthConfig, peer_ip: String) -> Bool {
  list.any(cfg.trusted_proxies, ffi.ip_in_cidr(peer_ip, _))
}
