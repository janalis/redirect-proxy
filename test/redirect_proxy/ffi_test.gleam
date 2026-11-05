import redirect_proxy/ffi

pub fn ip_in_cidr_test() {
  assert ffi.ip_in_cidr("10.1.2.3", "10.0.0.0/8")
  assert !ffi.ip_in_cidr("11.1.2.3", "10.0.0.0/8")
  assert ffi.ip_in_cidr("127.0.0.1", "127.0.0.1")
  assert ffi.ip_in_cidr("192.168.1.10", "192.168.1.0/24")
  assert !ffi.ip_in_cidr("192.168.2.10", "192.168.1.0/24")
  assert ffi.ip_in_cidr("::1", "::1/128")
  assert ffi.ip_in_cidr("fd00::1", "fd00::/8")
  assert !ffi.ip_in_cidr("fe80::1", "fd00::/8")
  // IPv4-mapped IPv6 peers match IPv4 networks
  assert ffi.ip_in_cidr("::ffff:10.0.0.1", "10.0.0.0/8")
  assert ffi.ip_in_cidr("1.2.3.4", "0.0.0.0/0")
  assert !ffi.ip_in_cidr("garbage", "0.0.0.0/0")
  assert !ffi.ip_in_cidr("10.0.0.1", "garbage")
}

pub fn valid_cidr_test() {
  assert ffi.valid_cidr("10.0.0.0/8")
  assert ffi.valid_cidr("::1/128")
  assert ffi.valid_cidr("127.0.0.1")
  assert !ffi.valid_cidr("10.0.0.0/33")
  assert !ffi.valid_cidr("::/129")
  assert !ffi.valid_cidr("nope/8")
}

pub fn strip_control_test() {
  assert ffi.strip_control("/a\r\nb\nc\rd") == "/abcd"
  assert ffi.strip_control("/plain") == "/plain"
}

pub fn secure_compare_test() {
  assert ffi.secure_compare(<<"abc":utf8>>, <<"abc":utf8>>)
  assert !ffi.secure_compare(<<"abc":utf8>>, <<"abd":utf8>>)
  assert !ffi.secure_compare(<<"abc":utf8>>, <<"ab":utf8>>)
}

pub fn regex_limit_test() {
  let assert Ok(re) = ffi.regex_compile("^(a+)+$", False)
  assert ffi.regex_run(re, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!")
    == Error(ffi.LimitExceeded)
  assert ffi.regex_run(re, "aaa") == Ok(["aaa", "aaa"])
  assert ffi.regex_run(re, "b") == Error(ffi.NoMatch)
}
