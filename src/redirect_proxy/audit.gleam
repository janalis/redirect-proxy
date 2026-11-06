//// Append-only JSON Lines audit log of administrative changes.

import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/float
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/log
import simplifile

pub type Entry {
  Entry(
    at: String,
    actor: String,
    action: String,
    target: String,
    details: String,
  )
}

pub fn record(
  path: String,
  actor: String,
  action: String,
  target: String,
  before: Option(Json),
  after: Option(Json),
) -> Nil {
  let line =
    json.object([
      #("at", json.string(ffi.now_rfc3339())),
      #("actor", json.string(actor)),
      #("action", json.string(action)),
      #("target", json.string(target)),
      #("before", json.nullable(before, fn(j) { j })),
      #("after", json.nullable(after, fn(j) { j })),
    ])
    |> json.to_string
  // one writer at a time, across processes (the server and the CLI): a
  // rotation must not race another one or a write
  let written =
    ffi.locked_file(path, lock_timeout, fn() {
      rotate_if_full(path)
      ffi.append_line(path, line)
    })
  case written {
    Ok(Nil) -> Nil
    Error(reason) -> {
      // Never fail an admin action because of the audit log, but be loud.
      log.error("audit log write failed: " <> reason)
    }
  }
}

// --- rotation -----------------------------------------------------------------

const rotation_key = "audit_rotation"

/// How long a write waits for another process holding the audit lock.
const lock_timeout = 5000

/// `storage.audit_max_bytes` (0: never rotate) and `storage.audit_files`
/// (rotated files kept), set at start.
pub fn configure(max_bytes: Int, files: Int) -> Nil {
  ffi.snapshot_put(rotation_key, #(max_bytes, files))
}

pub const default_max_bytes = 10_485_760

pub const default_files = 5

fn rotation() -> #(Int, Int) {
  ffi.snapshot_get(rotation_key)
  |> result.unwrap(#(default_max_bytes, default_files))
}

/// `audit.jsonl` becomes `audit.jsonl.1` (and `.1` becomes `.2`...) once it
/// reaches the size limit; the oldest file beyond the number kept goes.
fn rotate_if_full(path: String) -> Nil {
  let #(max_bytes, files) = rotation()
  case max_bytes > 0, simplifile.file_info(path) {
    True, Ok(info) if info.size >= max_bytes -> {
      let numbered = fn(n) { path <> "." <> int.to_string(n) }
      let _ = simplifile.delete(numbered(files))
      list.reverse(numbers(1, files - 1))
      |> list.each(fn(n) {
        let _ = simplifile.rename(numbered(n), numbered(n + 1))
        Nil
      })
      case files > 0 {
        True -> {
          let _ = simplifile.rename(path, numbered(1))
          Nil
        }
        False -> {
          let _ = simplifile.delete(path)
          Nil
        }
      }
    }
    _, _ -> Nil
  }
}

/// `from` to `to`, in order ([] when `to` < `from`).
fn numbers(from: Int, to: Int) -> List(Int) {
  case from > to {
    True -> []
    False -> [from, ..numbers(from + 1, to)]
  }
}

/// The audit files, newest first: the current one, then the rotated ones.
fn files(path: String) -> List(String) {
  let #(_, kept) = rotation()
  [
    path,
    ..numbers(1, kept)
    |> list.map(fn(n) { path <> "." <> int.to_string(n) })
  ]
  |> list.filter(fn(f) { simplifile.is_file(f) == Ok(True) })
}

// --- search -------------------------------------------------------------------

pub type Filter {
  Filter(
    /// Exactly this actor ("" for any).
    actor: String,
    /// Actions starting with this (`rule.` for every rule change).
    action: String,
    /// Targets containing this.
    target: String,
    /// Entries at or after this time, in seconds since the epoch (0: any).
    since: Int,
    /// Entries before this time (0: any).
    until: Int,
  )
}

pub const any = Filter(actor: "", action: "", target: "", since: 0, until: 0)

/// The `limit` most recent entries matching `filter`, newest first, read
/// from the current file and the rotated ones.
pub fn search(path: String, filter: Filter, limit: Int) -> List(Entry) {
  search_files(files(path), filter, limit, [])
}

fn search_files(
  files: List(String),
  filter: Filter,
  limit: Int,
  found: List(Entry),
) -> List(Entry) {
  case files, list.length(found) >= limit {
    [], _ | _, True -> list.take(found, limit)
    [file, ..older], False -> {
      // bytes, decoded line by line: a torn write (a cut UTF-8 sequence)
      // loses that line, not the whole file
      let entries =
        simplifile.read_bits(file)
        |> result.unwrap(<<>>)
        |> ffi.split_lines
        |> list.reverse
        |> list.filter_map(fn(bits) {
          bit_array.to_string(bits) |> result.try(parse_line)
        })
        |> list.filter(matches(_, filter))
        |> list.take(limit - list.length(found))
      search_files(older, filter, limit, list.append(found, entries))
    }
  }
}

fn matches(e: Entry, f: Filter) -> Bool {
  let seconds = fn() { ffi.parse_rfc3339(e.at) |> result.unwrap(0) }
  { f.actor == "" || e.actor == f.actor }
  && { f.action == "" || string.starts_with(e.action, f.action) }
  && { f.target == "" || string.contains(e.target, f.target) }
  && { f.since == 0 || seconds() >= f.since }
  && { f.until == 0 || seconds() < f.until }
}

fn parse_line(line: String) -> Result(Entry, Nil) {
  case line {
    "" -> Error(Nil)
    _ ->
      json.parse(line, entry_decoder())
      |> result.map(fn(e) { Entry(..e, details: line) })
      |> result.replace_error(Nil)
  }
}

fn entry_decoder() -> decode.Decoder(Entry) {
  use at <- decode.field("at", decode.string)
  use actor <- decode.field("actor", decode.string)
  use action <- decode.field("action", decode.string)
  use target <- decode.optional_field("target", "", decode.string)
  decode.success(Entry(at:, actor:, action:, target:, details: ""))
}

/// The `limit` most recent entries, newest first.
pub fn tail(path: String, limit: Int) -> List(Entry) {
  search(path, any, limit)
}

/// The fields that differ between the `before` and `after` of an entry, as
/// `#(field, before, after)` ("" when absent), in field order.
pub fn changes(entry: Entry) -> List(#(String, String, String)) {
  let value =
    decode.one_of(decode.string, [
      decode.int |> decode.map(int.to_string),
      decode.bool
        |> decode.map(fn(b) {
          case b {
            True -> "true"
            False -> "false"
          }
        }),
      decode.float |> decode.map(float.to_string),
      decode.list(decode.string) |> decode.map(string.join(_, ", ")),
      decode.success("…"),
    ])
  let side = fn(name) {
    decode.optional_field(
      name,
      dict.new(),
      decode.optional(decode.dict(decode.string, value))
        |> decode.map(option.unwrap(_, dict.new())),
      decode.success,
    )
  }
  let decoder = {
    use before <- decode.then(side("before"))
    use after <- decode.then(side("after"))
    decode.success(#(before, after))
  }
  case json.parse(entry.details, decoder) {
    Error(_) -> []
    Ok(#(before, after)) ->
      list.append(dict.keys(before), dict.keys(after))
      |> list.unique
      |> list.sort(string.compare)
      |> list.filter_map(fn(field) {
        let old = dict.get(before, field) |> result.unwrap("")
        let new = dict.get(after, field) |> result.unwrap("")
        case old == new {
          True -> Error(Nil)
          False -> Ok(#(field, old, new))
        }
      })
  }
}
