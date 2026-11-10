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
  emit(1, 500)
  // lines of a listener with no writer are dropped quietly
  ffi.access_log_emit(listener.AdminListener, "elsewhere")
  ffi.access_log_stop()
  let written = lines(path)
  assert list.length(written) == 500
  assert list.first(written) == Ok("line 001")
  assert list.last(written) == Ok("line 500")
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
    process.sleep(50)
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
  process.sleep(50)
  emit(4, 6)
  ffi.access_log_stop()
  assert simplifile.is_file(path <> ".0.gz") == Ok(True)
  assert simplifile.is_file(path <> ".1.gz") == Ok(True)
  assert simplifile.is_file(path <> ".0") == Ok(False)
}

/// logrotate renames the file: lines go to a new file of the name within a
/// second.
pub fn renamed_files_are_reopened_test() {
  let path = support.temp_dir() <> "/access.log"
  let assert Ok(Nil) =
    ffi.access_log_start([#(path, [listener.RedirectListener])], 0, 7, False)
  emit(1, 1)
  process.sleep(100)
  let assert Ok(Nil) = simplifile.rename(path, path <> ".1")
  process.sleep(1300)
  emit(2, 2)
  ffi.access_log_stop()
  assert lines(path <> ".1") == ["line 001"]
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
