//// Hit counts kept across restarts in `<data_dir>/hits.json`.

import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/set
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/snapshot
import simplifile

/// Seconds between saves of the hit counts.
pub const interval = 60

/// Hit counts saved by an earlier run, added to the published rules. Only
/// at a fresh start: a store restarted after a crash has carried the counts
/// of the rules already published. `path` "": counts are not kept.
pub fn load(path: String) -> Nil {
  case path, matcher.hit_records(snapshot.current()) {
    "", _ | _, [_, ..] -> Nil
    path, [] ->
      case simplifile.read(path) {
        // first start, or counts never saved
        Error(_) -> Nil
        Ok(content) ->
          case json.parse(content, decoder()) {
            Ok(records) -> matcher.seed_hits(snapshot.current(), records)
            Error(_) ->
              log.warning(path <> " is not a valid hit count file: ignored")
          }
      }
  }
}

/// Saves the hit counts of the rules `rule_ids` (atomically), unless they are
/// `last_written`. Returns the content now in the file: a failure is logged
/// and retried at the next save.
pub fn save(
  path: String,
  rule_ids: List(String),
  last_written: String,
) -> String {
  case path {
    "" -> ""
    path -> {
      let ids = set.from_list(rule_ids)
      let records =
        matcher.hit_records(snapshot.current())
        |> list.filter(fn(h) { set.contains(ids, h.rule_id) })
      let content =
        json.object([
          #("version", json.int(1)),
          #(
            "hits",
            json.object(
              list.map(records, fn(h) {
                #(
                  h.rule_id,
                  json.object([
                    #("count", json.int(h.count)),
                    #("last", json.int(h.last)),
                  ]),
                )
              }),
            ),
          ),
        ])
        |> json.to_string
      let content = content <> "\n"
      case content == last_written {
        True -> content
        False ->
          case ffi.atomic_write(path, content) {
            Ok(Nil) -> content
            Error(reason) -> {
              log.warning("hit counts not saved: " <> reason)
              last_written
            }
          }
      }
    }
  }
}

fn decoder() -> decode.Decoder(List(matcher.HitRecord)) {
  let record = {
    use count <- decode.field("count", decode.int)
    use last <- decode.optional_field("last", 0, decode.int)
    decode.success(#(count, last))
  }
  use hits <- decode.field("hits", decode.dict(decode.string, record))
  decode.success(
    dict.to_list(hits)
    |> list.map(fn(entry) {
      let #(rule_id, #(count, last)) = entry
      matcher.HitRecord(rule_id:, count:, last:)
    }),
  )
}
