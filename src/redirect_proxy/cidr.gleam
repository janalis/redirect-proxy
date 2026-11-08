//// Lists of networks (`trusted_proxies`), parsed once when the settings are
//// built so that a request compares integers instead of parsing text. The
//// same matches as `ffi.ip_in_cidr`, entry by entry: IPv4 addresses match
//// IPv4 networks, IPv6 addresses IPv6 networks, and IPv4-mapped IPv6
//// addresses also the IPv4 networks of their IPv4 address. Invalid entries
//// (which configuration validation rejects) match nothing.

import mist

/// Parsed networks.
pub type Cidrs

/// Parses networks: `10.0.0.0/8`, `::1/128`, or an address alone.
@external(erlang, "redirect_proxy_ffi", "compile_cidrs")
pub fn compile(cidrs: List(String)) -> Cidrs

/// Whether no network is listed (no valid one).
@external(erlang, "redirect_proxy_ffi", "cidrs_empty")
pub fn is_empty(cidrs: Cidrs) -> Bool

/// Whether a connection's address is in one of the networks.
@external(erlang, "redirect_proxy_ffi", "cidrs_contain_peer")
pub fn contains_peer(cidrs: Cidrs, ip: mist.IpAddress) -> Bool

/// Whether an address (text, from a header) is in one of the networks;
/// `False` when it is not an address.
@external(erlang, "redirect_proxy_ffi", "cidrs_contain")
pub fn contains(cidrs: Cidrs, ip: String) -> Bool

/// Whether a connection's address, when known, is in one of the networks.
@external(erlang, "redirect_proxy_ffi", "cidrs_contain_peer_result")
pub fn contains_peer_result(
  cidrs: Cidrs,
  peer: Result(mist.IpAddress, Nil),
) -> Bool
