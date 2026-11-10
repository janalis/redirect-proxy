import gleam/list
import mist
import redirect_proxy/cidr
import redirect_proxy/ffi

/// Addresses: IPv4, IPv6, IPv4-mapped IPv6, and text that is not one.
const addresses = [
  "0.0.0.0", "10.0.0.1", "10.255.255.255", "11.0.0.1", "127.0.0.1",
  "192.168.1.10", "192.168.2.10", "203.0.113.9", "255.255.255.255", "::", "::1",
  "::2", "fd00::1", "fdff:ffff::1", "fe80::1", "2001:db8::1", "2001:db9::1",
  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:10.0.0.1",
  "::ffff:11.0.0.1", "::ffff:127.0.0.1", "::ffff:a00:1", "::ffff:0.0.0.0",
  "::10.0.0.1", "", "garbage", "10.0.0.1/8", "10.0.0", "1.2.3.4:80", " 10.0.0.1",
  "[::1]",
]

/// Networks, with prefixes 0, 8, 32, 128 and in between, mapped ones, and
/// entries that are not networks (which validation rejects).
const networks = [
  "0.0.0.0/0", "10.0.0.0/8", "10.0.0.1/32", "10.0.0.1", "127.0.0.1",
  "192.168.1.0/24", "203.0.113.9/31", "::/0", "::1/128", "::1", "fd00::/8",
  "2001:db8::/32", "2001:db8::1/128", "::ffff:0:0/96", "::ffff:10.0.0.0/104",
  "::ffff:10.0.0.1/128", "fe80::/10", "10.0.0.0/33", "::/129", "nope/8",
  "10.0.0.0/-1", "10.0.0.0/", "garbage", "",
]

fn old(ip: String, cidrs: List(String)) -> Bool {
  list.any(cidrs, ffi.ip_in_cidr(ip, _))
}

pub fn same_as_ip_in_cidr_test() {
  list.each(addresses, fn(ip) {
    list.each(networks, fn(network) {
      assert cidr.contains(cidr.compile([network]), ip)
        == ffi.ip_in_cidr(ip, network)
    })
    assert cidr.contains(cidr.compile(networks), ip) == old(ip, networks)
    assert cidr.contains(cidr.compile([]), ip) == False
  })
}

/// The peers of all the IPv4 and IPv6 `addresses`, as the server gets them.
fn peers() -> List(mist.IpAddress) {
  [
    mist.IpV4(0, 0, 0, 0),
    mist.IpV4(10, 0, 0, 1),
    mist.IpV4(10, 255, 255, 255),
    mist.IpV4(11, 0, 0, 1),
    mist.IpV4(127, 0, 0, 1),
    mist.IpV4(192, 168, 1, 10),
    mist.IpV4(255, 255, 255, 255),
    mist.IpV6(0, 0, 0, 0, 0, 0, 0, 0),
    mist.IpV6(0, 0, 0, 0, 0, 0, 0, 1),
    mist.IpV6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
    mist.IpV6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    mist.IpV6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    mist.IpV6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
    mist.IpV6(0, 0, 0, 0, 0, 0xffff, 0x0a00, 1),
    mist.IpV6(0, 0, 0, 0, 0, 0xffff, 0x0b00, 1),
    mist.IpV6(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1),
    mist.IpV6(0, 0, 0, 0, 0, 0, 0x0a00, 1),
  ]
}

pub fn peer_same_as_ip_in_cidr_test() {
  list.each(peers(), fn(peer) {
    let text = mist.ip_address_to_string(peer)
    list.each(networks, fn(network) {
      assert cidr.contains_peer(cidr.compile([network]), peer)
        == ffi.ip_in_cidr(text, network)
    })
    assert cidr.contains_peer(cidr.compile(networks), peer)
      == old(text, networks)
    assert cidr.contains_peer_result(cidr.compile(networks), Ok(peer))
      == old(text, networks)
  })
  assert !cidr.contains_peer_result(cidr.compile(networks), Error(Nil))
}

pub fn contains_test() {
  let trusted = cidr.compile(["10.0.0.0/8", "::1/128", "fd00::/8"])
  assert cidr.contains(trusted, "10.1.2.3")
  assert !cidr.contains(trusted, "11.1.2.3")
  assert cidr.contains(trusted, "::1")
  assert cidr.contains(trusted, "fd12::1")
  assert !cidr.contains(trusted, "fe80::1")
  // IPv4-mapped IPv6 addresses match IPv4 networks
  assert cidr.contains(trusted, "::ffff:10.0.0.1")
  assert cidr.contains_peer(
    trusted,
    mist.IpV6(0, 0, 0, 0, 0, 0xffff, 0x0a00, 1),
  )
  // but IPv4 addresses do not match mapped networks
  assert !cidr.contains(cidr.compile(["::ffff:10.0.0.0/104"]), "10.0.0.1")
  assert cidr.contains(cidr.compile(["::ffff:10.0.0.0/104"]), "::ffff:10.0.0.1")
  // /0 matches every address of its family only
  assert cidr.contains(cidr.compile(["0.0.0.0/0"]), "1.2.3.4")
  assert !cidr.contains(cidr.compile(["0.0.0.0/0"]), "2001:db8::1")
  assert cidr.contains(cidr.compile(["::/0"]), "2001:db8::1")
  assert !cidr.contains(cidr.compile(["::/0"]), "1.2.3.4")
  assert !cidr.contains(trusted, "garbage")
}

pub fn is_empty_test() {
  assert cidr.is_empty(cidr.compile([]))
  // invalid entries are dropped (validation rejects them)
  assert cidr.is_empty(cidr.compile(["nope", "10.0.0.0/33"]))
  assert !cidr.is_empty(cidr.compile(["10.0.0.0/8"]))
  assert !cidr.is_empty(cidr.compile(["::1"]))
  assert !cidr.contains_peer(cidr.compile([]), mist.IpV4(10, 0, 0, 1))
}

/// The client in `X-Forwarded-For`: the rightmost hop that is not a trusted
/// proxy, over all the header lines.
pub fn forwarded_hop_test() {
  let trusted = cidr.compile(["10.0.0.0/8", "::1/128"])
  assert cidr.forwarded_hop(["203.0.113.9, 10.0.0.2"], trusted)
    == Ok("203.0.113.9")
  // a client's own line ahead of the proxy's
  assert cidr.forwarded_hop(["6.6.6.6", " 198.51.100.7 ,10.0.0.3"], trusted)
    == Ok("198.51.100.7")
  // every hop trusted: the leftmost
  assert cidr.forwarded_hop(["10.0.0.1,\t10.0.0.2"], trusted) == Ok("10.0.0.1")
  // the rightmost untrusted hop is not an address
  assert cidr.forwarded_hop(["203.0.113.9, unknown"], trusted) == Error(Nil)
  assert cidr.forwarded_hop([" , "], trusted) == Error(Nil)
  assert cidr.forwarded_hop(["::ffff:203.0.113.9, ::1"], trusted)
    == Ok("::ffff:203.0.113.9")
}
