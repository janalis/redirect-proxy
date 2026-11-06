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

/// What is in the hits file, and whether the last save failed.
pub type Written {
  Written(content: String, failing: Bool)
}

pub const nothing_written = Written(content: "", failing: False)

/// Saves the hit counts of the rules `rule_ids` (atomically), unless they are
/// what `last` wrote. A failure is retried at the next save and logged once
/// until a save succeeds again (a replica on a read-only volume would
/// otherwise log it every minute).
pub fn save(path: String, rule_ids: List(String), last: Written) -> Written {
  case path {
    "" -> last
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
      case content == last.content {
        True -> last
        False ->
          case ffi.atomic_write(path, content) {
            Ok(Nil) -> Written(content:, failing: False)
            Error(reason) -> {
              case last.failing {
                True -> Nil
                False ->
                  log.warning(
                    "hit counts not saved: "
                    <> reason
                    <> " (not repeated until a save succeeds)",
                  )
              }
              Written(..last, failing: True)
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
