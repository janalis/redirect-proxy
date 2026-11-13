import gleam/int
import gleam/json
import gleam/list
import gleam/option
import gleam/string
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/audit
import simplifile
import support

pub fn tail_reads_the_end_of_a_large_log_test() {
  let path = support.temp_dir() <> "/audit.jsonl"
  // over 1 MB of multi-byte entries: only the end is read, and the partial
  // first line (possibly cut inside a UTF-8 sequence) is dropped
  let line = fn(i) {
    "{\"at\":\"t\",\"actor\":\"é"
    <> string.repeat("é", 400)
    <> "\",\"action\":\"a"
    <> int.to_string(i)
    <> "\",\"target\":\"x\"}"
  }
  let content =
    int.range(from: 1, to: 2001, with: [], run: fn(acc, i) { [i, ..acc] })
    |> list.reverse
    |> list.map(line)
    |> string.join("\n")
  let assert Ok(Nil) = simplifile.write(path, content <> "\n")
  let entries = audit.tail(path, 5)
  assert list.map(entries, fn(e) { e.action })
    == ["a2000", "a1999", "a1998", "a1997", "a1996"]
}

pub fn changes_test() {
  let entry =
    audit.Entry(
      at: "t",
      actor: "a",
      action: "rules.import.merge",
      target: "",
      details: "{\"before\":{\"fingerprint\":\"x\",\"n\":1},\"after\":{\"fingerprint\":\"y\",\"n\":1,\"added_ids\":[\"a\",\"b\"]}}",
    )
  assert audit.changes(entry)
    == [#("added_ids", "", "a, b"), #("fingerprint", "x", "y")]
}

/// The log rotates at the size limit, keeps the configured number of files,
/// and searches go through all of them, newest first.
pub fn rotation_and_search_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let path = dir <> "/audit.jsonl"
  // about 4 entries (~115 bytes each) per file, 2 rotated files kept: 24
  // entries do not all fit
  audit.configure(400, 2)
  int.range(from: 1, to: 25, with: Nil, run: fn(_, i) {
    audit.record(
      path,
      "user" <> int.to_string(i % 2),
      "rule.update",
      "rule-" <> int.to_string(i),
      option.None,
      option.None,
    )
  })
  audit.configure(audit.default_max_bytes, audit.default_files)
  let assert Ok(files) = simplifile.read_directory(dir)
  assert list.sort(files, string.compare)
    == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
  let all = audit.search(path, audit.any, 100) |> list.map(fn(e) { e.target })
  // the newest first; the oldest entries went with the third rotated file
  let assert ["rule-24", "rule-23", ..] = all
  assert list.length(all) < 24
  assert !list.contains(all, "rule-1")
  // filters apply across files
  let by_user1 =
    audit.search(path, audit.Filter(..audit.any, actor: "user1"), 100)
  assert list.all(by_user1, fn(e) { e.actor == "user1" })
  assert list.length(by_user1) > 1
  assert list.length(audit.search(path, audit.any, 2)) == 2
  // time bounds
  assert audit.search(path, audit.Filter(..audit.any, since: 4_102_444_800), 10)
    == []
}

/// A torn write (a cut UTF-8 sequence) loses that line, not the file.
pub fn a_broken_line_does_not_hide_the_file_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let path = dir <> "/audit.jsonl"
  let line = fn(target) {
    "{\"at\":\"2026-01-01T00:00:00Z\",\"actor\":\"a\",\"action\":\"rule.update\",\"target\":\""
    <> target
    <> "\"}\n"
  }
  let assert Ok(Nil) =
    simplifile.write_bits(path, <<
      line("first"):utf8,
      "{\"at\":\"é":utf8,
      0xC3,
      "\n":utf8,
      line("last"):utf8,
    >>)
  assert audit.search(path, audit.any, 10) |> list.map(fn(e) { e.target })
    == ["last", "first"]
}

/// Failures need no credentials: past a budget per minute they are not
/// recorded, so that they cannot push real entries out of the files kept.
pub fn failures_have_a_budget_test() {
  ratelimit.init()
  ratelimit.reset("audit-failures")
  ratelimit.reset("audit-failures-noted")
  let path = support.temp_dir() <> "/audit.jsonl"
  int.range(from: 0, to: 70, with: Nil, run: fn(_, i) {
    audit.record_failure(
      path,
      "u" <> int.to_string(i),
      "auth.login_failed",
      "local",
      json.object([]),
    )
  })
  let entries = audit.tail(path, 100)
  let failed = list.filter(entries, fn(e) { e.action == "auth.login_failed" })
  assert list.length(failed) == 60
  let noted =
    list.filter(entries, fn(e) { e.action == "audit.failures_not_recorded" })
  assert list.length(noted) == 1
  ratelimit.reset("audit-failures")
  ratelimit.reset("audit-failures-noted")
}

pub fn rotation_keeps_active_and_archive_modes_test() {
  list.each([0o600, 0o640], fn(mode) {
    list.each([0, 2], fn(kept) {
      let dir = support.temp_dir()
      let path = dir <> "/audit.jsonl"
      let assert Ok(Nil) = simplifile.write(path, "initial\n")
      let assert Ok(Nil) = simplifile.set_permissions_octal(path, mode)
      audit.configure(1, kept)
      list.each(["first", "second", "third"], fn(target) {
        let assert Ok(previous) = simplifile.read(path)
        audit.record(path, "actor", "test", target, option.None, option.None)
        let assert Ok(info) = simplifile.file_info(path)
        assert simplifile.file_info_permissions_octal(info) == mode
        let assert [entry] = audit.tail(path, 1)
        assert entry.target == target
        case kept {
          0 -> {
            assert simplifile.is_file(path <> ".1") == Ok(False)
          }
          _ -> {
            assert simplifile.read(path <> ".1") == Ok(previous)
            let assert Ok(info) = simplifile.file_info(path <> ".1")
            assert simplifile.file_info_permissions_octal(info) == mode
          }
        }
      })
      case kept {
        0 -> Nil
        _ -> {
          assert simplifile.is_file(path <> ".2") == Ok(True)
          assert simplifile.is_file(path <> ".3") == Ok(False)
          let all = audit.tail(path, 10) |> list.map(fn(e) { e.target })
          assert all == ["third", "second", "first"]
        }
      }
      audit.configure(audit.default_max_bytes, audit.default_files)
    })
  })
}

pub fn archive_failure_keeps_active_audit_and_cleans_replacement_test() {
  let dir = support.temp_dir()
  let path = dir <> "/audit.jsonl"
  let assert Ok(Nil) = simplifile.write(path, "original\n")
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o600)
  let assert Ok(Nil) = simplifile.write(path <> ".1", "previous archive")
  let assert Ok(Nil) = simplifile.create_directory_all(path <> ".2")
  audit.configure(1, 2)
  // Recording failures are logged, without failing the administrative action.
  audit.record(path, "actor", "test", "new", option.None, option.None)
  audit.configure(audit.default_max_bytes, audit.default_files)
  assert simplifile.read(path) == Ok("original\n")
  assert simplifile.read(path <> ".1") == Ok("previous archive")
  let assert Ok(info) = simplifile.file_info(path)
  assert simplifile.file_info_permissions_octal(info) == 0o600
  let assert Ok(files) = simplifile.read_directory(dir)
  assert !list.any(files, string.contains(_, ".tmp."))
  assert !list.any(files, string.contains(_, ".rotate."))
}

pub fn rotation_preserves_archived_symlink_entries_test() {
  let dir = support.temp_dir()
  let path = dir <> "/audit.jsonl"
  let sentinel = dir <> "/sentinel"
  let assert Ok(Nil) = simplifile.write(sentinel, "untouched")
  let assert Ok(Nil) = simplifile.write(path, "current")
  let assert Ok(Nil) =
    simplifile.create_symlink(to: sentinel, from: path <> ".1")
  audit.configure(1, 2)
  audit.record(path, "actor", "test", "new", option.None, option.None)
  audit.configure(audit.default_max_bytes, audit.default_files)
  assert simplifile.read(path <> ".1") == Ok("current")
  assert simplifile.is_symlink(path <> ".2") == Ok(True)
  assert simplifile.read(sentinel) == Ok("untouched")
  let assert Ok(files) = simplifile.read_directory(dir)
  assert !list.any(files, string.contains(_, ".rotate."))
}
