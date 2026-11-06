//// Authentication delegated to a trusted reverse proxy (oauth2-proxy,
//// Authelia, Pomerium...) through request headers. Headers are only trusted
//// when the TCP peer address belongs to a configured trusted proxy CIDR.

import gleam/list
import gleam/string
import redirect_proxy/config.{type HeaderAuthConfig}
import redirect_proxy/ffi
import redirect_proxy/log
import wisp

/// The user named by the identity header: `user_header`, or `email_header`
/// when `user_header` is empty. The two are never combined: a proxy that only
/// sets one of them may pass the other through from the client.
pub fn identify(
  cfg: HeaderAuthConfig,
  req: wisp.Request,
  peer_ip: String,
) -> Result(String, Nil) {
  case cfg.enabled && is_trusted(cfg, peer_ip) {
    False -> Error(Nil)
    True -> {
      let name = identity_header(cfg)
      // A proxy that appends to the header instead of replacing it leaves
      // the client's value first (`admin, alice`, or two header lines):
      // refuse such requests.
      let refuse = fn(why) {
        log.warning("proxy authentication refused: header " <> name <> why)
        Error(Nil)
      }
      case list.filter(req.headers, fn(h) { h.0 == name }) {
        [#(_, value)] ->
          case string.trim(value), string.contains(value, ",") {
            "", _ -> Error(Nil)
            _, True -> refuse(" holds several values")
            user, False -> Ok(string.lowercase(user))
          }
        [] -> Error(Nil)
        [_, _, ..] -> refuse(" sent more than once")
      }
    }
  }
}

pub fn identity_header(cfg: HeaderAuthConfig) -> String {
  case cfg.user_header {
    "" -> cfg.email_header
    name -> name
  }
}

pub fn is_trusted(cfg: HeaderAuthConfig, peer_ip: String) -> Bool {
  list.any(cfg.trusted_proxies, ffi.ip_in_cidr(peer_ip, _))
}
