//// Bindings to `redirect_proxy_net_ffi`: addresses, networks and header
//// items. Parsed network lists are bound by `cidr`.

/// Whether the text is an IPv4 or IPv6 address (no brackets, port or
/// prefix length).
@external(erlang, "redirect_proxy_net_ffi", "is_ip_address")
pub fn is_ip_address(text: String) -> Bool

/// The address throttling counts failures for: IPv6 addresses by /64.
@external(erlang, "redirect_proxy_net_ffi", "throttle_address")
pub fn throttle_address(ip: String) -> String

@external(erlang, "redirect_proxy_net_ffi", "ip_in_cidr")
pub fn ip_in_cidr(ip: String, cidr: String) -> Bool

@external(erlang, "redirect_proxy_net_ffi", "valid_cidr")
pub fn valid_cidr(cidr: String) -> Bool

/// An address the HTTP server can listen on: an IP address or "localhost".
@external(erlang, "redirect_proxy_net_ffi", "valid_listen_address")
pub fn valid_listen_address(address: String) -> Bool

/// "localhost" or a loopback IP address (IPv6 possibly in brackets, or
/// IPv4-mapped).
@external(erlang, "redirect_proxy_net_ffi", "is_loopback_address")
pub fn is_loopback_address(address: String) -> Bool

/// The first item of a comma-separated header value, trimmed and ASCII
/// lower-cased.
@external(erlang, "redirect_proxy_net_ffi", "first_item")
pub fn first_item(value: String) -> String
