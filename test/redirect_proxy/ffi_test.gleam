import gleam/dict
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/ffi
import simplifile
import support

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

pub fn header_value_test() {
  assert ffi.header_value("https://new.example.com/a?b=c")
    == "https://new.example.com/a?b=c"
  assert ffi.header_value("https://x.test/a\r\nb\u{0}c") == "https://x.test/abc"
  assert ffi.header_value("https://x.test/café") == "https://x.test/caf%C3%A9"
  assert ffi.header_value("https://x.test/é\r\n") == "https://x.test/%C3%A9"
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

pub fn file_lock_test() {
  let path = support.temp_dir() <> "/data.json"
  let assert Ok(42) = ffi.with_file_lock(path, 100, fn() { 42 })
  // released afterwards
  assert simplifile.is_file(path <> ".lock") == Ok(False)
  // held by another process: times out with the owner in the message
  let assert Ok(Nil) = simplifile.write(path <> ".lock", "4242 cli@host\n")
  let assert Error(reason) = ffi.with_file_lock(path, 100, fn() { 1 })
  assert string.contains(reason, "4242 cli@host")
  let assert Error(_) = ffi.locked_file(path, 100, fn() { Ok(1) })
}

pub fn file_lock_release_keeps_a_lock_taken_over_test() {
  let path = support.temp_dir() <> "/data.json"
  let lock = path <> ".lock"
  // held past the stale delay: another process broke the lock and took it
  let assert Ok(Nil) =
    ffi.with_file_lock(path, 100, fn() {
      let assert Ok(Nil) = simplifile.write(lock, "4242 cli@host 1\n")
      Nil
    })
  assert simplifile.read(lock) == Ok("4242 cli@host 1\n")
}

pub fn stale_file_lock_is_broken_by_one_waiter_at_a_time_test() {
  let dir = support.temp_dir()
  let path = dir <> "/data.json"
  let marker = dir <> "/inside"
  let assert Ok(Nil) = simplifile.write(path <> ".lock", "4242 crashed@host\n")
  set_mtime(path <> ".lock", 60)
  let done = process.new_subject()
  let waiters = 8
  list.each(list.repeat(Nil, waiters), fn(_) {
    process.spawn(fn() {
      let outcome =
        ffi.with_file_lock(path, 10_000, fn() {
          // mutual exclusion: nobody else is inside
          let alone = simplifile.is_file(marker) == Ok(False)
          let assert Ok(Nil) = simplifile.write(marker, "")
          process.sleep(10)
          let assert Ok(Nil) = simplifile.delete(marker)
          alone
        })
      process.send(done, outcome)
    })
  })
  list.each(list.repeat(Nil, waiters), fn(_) {
    assert process.receive(done, 15_000) == Ok(Ok(True))
  })
  assert simplifile.is_file(path <> ".lock") == Ok(False)
  let assert Ok(files) = simplifile.read_directory(dir)
  assert !list.any(files, fn(f) { string.contains(f, ".break") })
}

pub fn atomic_write_failure_returns_an_error_test() {
  let dir = support.temp_dir()
  // the target is a non-empty directory: the final rename fails
  let target = dir <> "/target"
  let assert Ok(Nil) = simplifile.create_directory_all(target <> "/sub")
  let assert Error(_) = ffi.atomic_write(target, "content")
  let assert Ok(files) = simplifile.read_directory(dir)
  assert files == ["target"]
}

/// Sets a file's modification time `seconds_ago` in the past.
@external(erlang, "test_net_ffi", "set_mtime_ago")
fn set_mtime(path: String, seconds_ago: Int) -> Nil

pub fn memo_file_test() {
  let path = support.temp_dir() <> "/clients.json"
  let parse = fn() {
    case simplifile.read(path) {
      Ok("ok:" <> value) -> Ok(value)
      Ok(other) -> Error("corrupt: " <> other)
      Error(_) -> Error("missing")
    }
  }
  assert ffi.memo_file(path, parse) == Error("missing")
  let assert Ok(Nil) = ffi.atomic_write(path, "ok:one")
  assert ffi.memo_file(path, parse) == Ok("one")
  // cached: not recomputed while the file is unchanged
  assert ffi.memo_file(path, fn() { Error("not called") }) == Ok("one")
  // a write within the same second, of the same size, is still seen
  let assert Ok(Nil) = ffi.atomic_write(path, "ok:two")
  assert ffi.memo_file(path, parse) == Ok("two")
  // a broken file keeps the last good value
  let assert Ok(Nil) = ffi.atomic_write(path, "garbage")
  assert ffi.memo_file(path, parse) == Ok("two")
}

pub fn json_log_lines_test() {
  let line = format_json_log("warning", "said \"hi\"\nthen left")
  let assert Ok(fields) =
    json.parse(line, decode.dict(decode.string, decode.string))
  assert dict.get(fields, "level") == Ok("warning")
  assert dict.get(fields, "msg") == Ok("said \"hi\"\nthen left")
  assert dict.get(fields, "domain") == Ok("redirect_proxy.test")
  let assert Ok(time) = dict.get(fields, "time")
  assert string.ends_with(time, "Z")
}

@external(erlang, "test_net_ffi", "format_json_log")
fn format_json_log(level: String, message: String) -> String

/// Rewriting a file keeps its permissions instead of the umask default.
pub fn atomic_write_keeps_the_file_mode_test() {
  let path = support.temp_dir() <> "/kept-mode.json"
  let assert Ok(Nil) = ffi.atomic_write(path, "one")
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o640)
  let assert Ok(Nil) = ffi.atomic_write(path, "two")
  let assert Ok(info) = simplifile.file_info(path)
  assert simplifile.file_info_permissions_octal(info) == 0o640
  assert simplifile.read(path) == Ok("two")
}

pub fn host_helpers_test() {
  assert ffi.is_host_name("my_app-1.example.com")
  assert !ffi.is_host_name("")
  assert !ffi.is_host_name("Example.com")
  assert !ffi.is_host_name("x@evil.test")
  assert !ffi.is_host_name("café.example")
  assert ffi.lowercase_host("Shop.TEST:80") == "shop.test:80"
  assert ffi.lowercase_host("CAFÉ.Example") == "café.example"
  // only ASCII letters change; other bytes are kept
  assert ffi.lowercase_ascii("HTTPS://CAFÉ") == "https://cafÉ"
  assert ffi.url_host("example.com/a@b") == "example.com"
  assert ffi.url_host("user:pw@example.com?x") == "example.com"
  assert ffi.url_host("a@b@example.com#f") == "example.com"
  assert ffi.url_host("example.com\\x") == "example.com"
  assert ffi.url_host("") == ""
}

/// In a directory this process cannot write to, the lock cannot be taken,
/// and is not needed (nothing can be written there): the function runs.
pub fn file_lock_in_a_read_only_directory_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o500)
  let result = ffi.with_file_lock(dir <> "/redirects.json", 100, fn() { 7 })
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o700)
  assert result == Ok(7)
}

/// IPv6 addresses are throttled by /64: a host usually holds a whole one.
pub fn throttle_address_test() {
  assert ffi.throttle_address("192.0.2.7") == "192.0.2.7"
  assert ffi.throttle_address("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
  assert ffi.throttle_address("2001:db8:1:2:bbbb::9") == "2001:db8:1:2::/64"
  assert ffi.throttle_address("2001:db8:1:3::1") == "2001:db8:1:3::/64"
  assert ffi.throttle_address("::ffff:192.0.2.7") == "192.0.2.7"
  assert ffi.throttle_address("not an address") == "not an address"
  assert ffi.throttle_address("") == ""
}

fn mode(path: String) -> Int {
  let assert Ok(info) = simplifile.file_info(path)
  simplifile.file_info_permissions_octal(info)
}

/// Files with secrets are created 0600; an existing file keeps the
/// permissions it was given.
pub fn atomic_write_private_mode_test() {
  let dir = support.temp_dir()
  let path = dir <> "/users.json"
  let assert Ok(Nil) = ffi.atomic_write_private(path, "{}")
  assert mode(path) == 0o600
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o640)
  let assert Ok(Nil) = ffi.atomic_write_private(path, "{\"a\":1}")
  assert mode(path) == 0o640
  assert simplifile.read(path) == Ok("{\"a\":1}")
  // other files: the old permissions too
  let rules = dir <> "/redirects.json"
  let assert Ok(Nil) = ffi.atomic_write(rules, "[]")
  let assert Ok(Nil) = simplifile.set_permissions_octal(rules, 0o604)
  let assert Ok(Nil) = ffi.atomic_write(rules, "[ ]")
  assert mode(rules) == 0o604
}

/// Dates that do not exist are refused, not shifted to the next month.
pub fn rfc3339_is_strict_test() {
  assert ffi.parse_rfc3339("2026-12-01T00:00:00Z") == Ok(1_796_083_200)
  assert ffi.parse_rfc3339("2026-12-01T01:00:00+01:00") == Ok(1_796_083_200)
  assert ffi.parse_rfc3339("2026-12-01t00:00:00.250z") == Ok(1_796_083_200)
  assert ffi.parse_rfc3339("2028-02-29T00:00:00Z") |> result.is_ok
  list.each(
    [
      "2026-02-30T00:00:00Z", "2026-04-31T12:00:00Z", "2026-13-01T00:00:00Z",
      "2027-02-29T00:00:00Z", "2026-12-01x00:00:00Z", "2026-12-01T24:00:00Z",
      "2026-12-01T00:60:00Z", "2026-12-01T00:00:00+01:99", "2026-12-01T00:00:00",
      "2026-12-01T00:00:00.Z", "2026-1-01T00:00:00Z", "",
    ],
    fn(bad) {
      assert ffi.parse_rfc3339(bad) == Error(Nil)
    },
  )
}
