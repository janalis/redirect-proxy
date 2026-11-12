//// The access log writers: batches written to a file, its rotation and
//// its reopening after logrotate renamed it.

import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/listener
import simplifile
import support

fn lines(path: String) -> List(String) {
  case simplifile.read(path) {
    Ok(text) -> string.split(text, "\n") |> list.filter(fn(l) { l != "" })
    Error(_) -> []
  }
}

fn emit(from: Int, to: Int) -> Nil {
  int.range(from, to + 1, Nil, fn(_, i) {
    ffi.access_log_emit(
      listener.RedirectListener,
      "line " <> string.pad_start(int.to_string(i), 3, "0"),
    )
  })
}

pub fn lines_are_written_in_order_test() {
  let path = support.temp_dir() <> "/logs/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 0, 7, False)
  // more than a batch: stopping writes them all
  emit(1, 3000)
  // lines of a listener with no writer are dropped quietly
  ffi.access_log_emit(listener.AdminListener, "elsewhere")
  ffi.access_log_stop()
  let written = lines(path)
  assert list.length(written) == 3000
  assert list.first(written) == Ok("line 001")
  assert list.last(written) == Ok("line 3000")
}

/// Past `max_bytes`, the file becomes `.0`, and older archives move up to
/// `.<max_files - 1>`: the oldest beyond are deleted.
pub fn files_rotate_test() {
  let path = support.temp_dir() <> "/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 20, 2, False)
  // "line 001\n" is 9 bytes: each write of more than 20 bytes rotates
  list.each([#(1, 3), #(4, 6), #(7, 9)], fn(batch) {
    emit(batch.0, batch.1)
    ffi.access_log_sync()
  })
  ffi.access_log_stop()
  assert lines(path <> ".0") == ["line 007", "line 008", "line 009"]
  assert lines(path <> ".1") == ["line 004", "line 005", "line 006"]
  assert simplifile.is_file(path <> ".2") == Ok(False)
  assert lines(path) == []
}

pub fn rotated_files_are_compressed_test() {
  let path = support.temp_dir() <> "/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 20, 3, True)
  emit(1, 3)
  ffi.access_log_sync()
  emit(4, 6)
  ffi.access_log_stop()
  assert simplifile.is_file(path <> ".0.gz") == Ok(True)
  assert simplifile.is_file(path <> ".1.gz") == Ok(True)
  assert simplifile.is_file(path <> ".0") == Ok(False)
  let assert Ok(newest) = simplifile.read_bits(path <> ".0.gz")
  let assert Ok(older) = simplifile.read_bits(path <> ".1.gz")
  assert gunzip(newest) == <<"line 004\nline 005\nline 006\n":utf8>>
  assert gunzip(older) == <<"line 001\nline 002\nline 003\n":utf8>>
}

/// logrotate renames the file: lines go to a new file of the name within a
/// second.
pub fn renamed_files_are_reopened_test() {
  let path = support.temp_dir() <> "/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 0, 7, False)
  emit(1, 1)
  ffi.access_log_sync()
  let assert Ok(Nil) = simplifile.rename(path, path <> ".1")
  process.sleep(1300)
  emit(2, 2)
  ffi.access_log_stop()
  assert lines(path <> ".1") == ["line 001"]
  assert lines(path) == ["line 002"]
}

/// The directory removed too: it is created again.
pub fn removed_directories_are_recreated_test() {
  let dir = support.temp_dir() <> "/logs"
  let path = dir <> "/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 0, 7, False)
  emit(1, 1)
  ffi.access_log_sync()
  let assert Ok(Nil) = simplifile.delete(dir)
  process.sleep(1300)
  emit(2, 2)
  ffi.access_log_stop()
  assert lines(path) == ["line 002"]
}

pub fn unwritable_outputs_are_refused_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.write(dir <> "/file", "")
  let assert Error(message) =
    ffi.access_log_start(
      [#(dir <> "/file/access.log", [listener.RedirectListener])],
      0,
      7,
      False,
    )
  assert string.starts_with(message, "cannot open access log")
}

@external(erlang, "zlib", "gunzip")
fn gunzip(data: BitArray) -> BitArray

pub fn compressed_archives_preserve_modes_and_replace_symlinks_test() {
  list.each([0o600, 0o640], fn(mode) {
    let dir = support.temp_dir()
    let path = dir <> "/access.log"
    let sentinel = dir <> "/sentinel"
    let assert Ok(Nil) = simplifile.write(path, "")
    let assert Ok(Nil) = simplifile.set_permissions_octal(path, mode)
    let assert Ok(Nil) = simplifile.write(sentinel, "untouched")
    let assert Ok(Nil) =
      simplifile.create_symlink(to: sentinel, from: path <> ".0.gz")
    let assert Ok(Nil) =
      ffi.access_log_start([#(path, [listener.RedirectListener])], 20, 1, True)
    emit(1, 3)
    ffi.access_log_stop()
    assert simplifile.read(sentinel) == Ok("untouched")
    assert simplifile.is_symlink(path <> ".0.gz") == Ok(False)
    let assert Ok(info) = simplifile.file_info(path <> ".0.gz")
    assert simplifile.file_info_permissions_octal(info) == mode
    let assert Ok(bits) = simplifile.read_bits(path <> ".0.gz")
    assert gunzip(bits) == <<"line 001\nline 002\nline 003\n":utf8>>
  })
}

pub fn failed_compression_keeps_raw_archive_and_cleans_temp_test() {
  let dir = support.temp_dir()
  let path = dir <> "/access.log"
  let assert Ok(Nil) = simplifile.create_directory_all(path <> ".0.gz")
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 20, 1, True)
  emit(1, 3)
  ffi.access_log_stop()
  assert lines(path <> ".0") == ["line 001", "line 002", "line 003"]
  assert simplifile.is_directory(path <> ".0.gz") == Ok(True)
  let assert Ok(files) = simplifile.read_directory(dir)
  assert !list.any(files, string.contains(_, ".tmp."))
}

pub fn recreated_active_logs_preserve_modes_test() {
  list.each([0o600, 0o640], fn(mode) {
    list.each([#(False, 0), #(False, 2), #(True, 2)], fn(rotation) {
      let path = support.temp_dir() <> "/access.log"
      let assert Ok(Nil) = simplifile.write(path, "")
      let assert Ok(Nil) = simplifile.set_permissions_octal(path, mode)
      let assert Ok(Nil) =
        ffi.access_log_start(
          [#(path, [listener.RedirectListener])],
          20,
          rotation.1,
          rotation.0,
        )
      emit(1, 3)
      ffi.access_log_sync()
      let assert Ok(info) = simplifile.file_info(path)
      assert simplifile.file_info_permissions_octal(info) == mode
      emit(4, 4)
      ffi.access_log_sync()
      assert lines(path) == ["line 004"]
      // A second rotation must keep the mode too.
      emit(5, 7)
      ffi.access_log_sync()
      let assert Ok(info) = simplifile.file_info(path)
      assert simplifile.file_info_permissions_octal(info) == mode
      ffi.access_log_stop()
    })
  })
}

pub fn external_replacement_keeps_operator_mode_test() {
  let path = support.temp_dir() <> "/access.log"
  let assert Ok(Nil) = simplifile.write(path, "")
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o600)
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 0, 2, False)
  emit(1, 1)
  ffi.access_log_sync()
  let assert Ok(Nil) = simplifile.rename(path, path <> ".old")
  let assert Ok(Nil) = simplifile.write(path, "operator\n")
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o640)
  process.sleep(1300)
  emit(2, 2)
  ffi.access_log_stop()
  let assert Ok(info) = simplifile.file_info(path)
  assert simplifile.file_info_permissions_octal(info) == 0o640
  assert lines(path) == ["operator", "line 002"]
  assert lines(path <> ".old") == ["line 001"]
}

@external(erlang, "test_access_writer_ffi", "reopen_race")
fn reopen_race(dir: String, replace: Bool) -> Nil

pub fn vanished_or_changed_fallback_files_get_safe_mode_test() {
  reopen_race(support.temp_dir(), False)
  reopen_race(support.temp_dir(), True)
}
