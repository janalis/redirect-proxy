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
  case ffi.append_line(path, line) {
    Ok(Nil) -> Nil
    Error(reason) -> {
      // Never fail an admin action because of the audit log, but be loud.
      log.error("audit log write failed: " <> reason)
    }
  }
}

/// Only the end of the file is read: the audit log only grows.
const tail_bytes = 1_048_576

/// Reads the `limit` most recent entries, newest first.
pub fn tail(path: String, limit: Int) -> List(Entry) {
  let decoder = {
    use at <- decode.field("at", decode.string)
    use actor <- decode.field("actor", decode.string)
    use action <- decode.field("action", decode.string)
    use target <- decode.optional_field("target", "", decode.string)
    decode.success(Entry(at:, actor:, action:, target:, details: ""))
  }
  let content =
    ffi.read_tail(path, tail_bytes)
    |> result.try(bit_array.to_string)
  case content {
    Error(_) -> []
    Ok(content) ->
      content
      |> string.split("\n")
      |> list.filter(fn(l) { l != "" })
      |> list.reverse
      |> list.take(limit)
      |> list.filter_map(fn(line) {
        json.parse(line, decoder)
        |> result.map(fn(e) { Entry(..e, details: line) })
        |> result.replace_error(Nil)
      })
  }
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
