//// Bindings to `redirect_proxy_access_ffi`: the access log writers, value
//// escaping, cached timestamps and IP anonymisation.

import gleam/string_tree.{type StringTree}
import mist
import redirect_proxy/listener.{type Listener}

/// Starts one access log writer per output, each taking the lines of the
/// listed listeners. Replaces any previous writers.
@external(erlang, "redirect_proxy_access_ffi", "start")
pub fn access_log_start(
  groups: List(#(String, List(Listener))),
  max_bytes: Int,
  max_files: Int,
  compress: Bool,
) -> Result(Nil, String)

/// Writes the lines still waiting, then stops the writers.
@external(erlang, "redirect_proxy_access_ffi", "stop")
pub fn access_log_stop() -> Nil

/// Sends a rendered line (without its line break) to the writer of
/// `listener`'s log, unless it has none.
@external(erlang, "redirect_proxy_access_ffi", "emit")
pub fn access_log_emit(listener: Listener, line: StringTree) -> Nil

/// `list.key_find` of a header list, in one call (names are compared
/// as they are: lower case in requests and responses).
@external(erlang, "redirect_proxy_access_ffi", "header")
pub fn header(
  headers: List(#(String, String)),
  name: String,
) -> Result(String, Nil)

// --- escaping ---------------------------------------------------------------

@external(erlang, "redirect_proxy_access_ffi", "escape_default")
pub fn escape_default(value: String) -> String

@external(erlang, "redirect_proxy_access_ffi", "escape_json")
pub fn escape_json(value: String) -> String

@external(erlang, "redirect_proxy_access_ffi", "escape_newlines")
pub fn escape_newlines(value: String) -> String

// --- timestamps -------------------------------------------------------------

/// Creates the time cache in the calling process, which owns it (`tables`).
/// Without it, each timestamp is formatted again.
@external(erlang, "redirect_proxy_access_ffi", "time_cache_init")
pub fn time_cache_init() -> Nil

@external(erlang, "redirect_proxy_access_ffi", "time_local")
pub fn time_local(micros: Int) -> String

@external(erlang, "redirect_proxy_access_ffi", "time_iso8601")
pub fn time_iso8601(micros: Int) -> String

// --- addresses --------------------------------------------------------------

@external(erlang, "redirect_proxy_access_ffi", "anonymize_ip")
pub fn anonymize_ip(ip: String) -> String

/// `mist.ip_address_to_string`, IPv4 addresses without a list.
@external(erlang, "redirect_proxy_access_ffi", "peer_to_string")
pub fn peer_to_string(ip: mist.IpAddress) -> String

/// `anonymize_ip` of a peer address, without the string round trip.
@external(erlang, "redirect_proxy_access_ffi", "anonymize_peer")
pub fn anonymize_peer(ip: mist.IpAddress) -> String
