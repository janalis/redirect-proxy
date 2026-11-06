import gleam/erlang/process
import gleam/list
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
