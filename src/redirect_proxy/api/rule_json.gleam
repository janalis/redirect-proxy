//// JSON representation of rules in the REST API, and JSON merge patches.

import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import redirect_proxy/ffi
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}

/// `rule.to_json` plus the version (the ETag of the rule) and the hits since
/// the server started (read only). Every field is present, including
/// those the rules file only holds when set.
pub fn rule_json(r: Rule) -> Json {
  let unset =
    list.flatten([
      case r.whole_segments {
        True -> []
        False -> [#("whole_segments", json.bool(False))]
      },
      case r.query {
        "" -> [#("query", json.string(""))]
        _ -> []
      },
      case r.starts_at {
        "" -> [#("starts_at", json.string(""))]
        _ -> []
      },
      case r.expires_at {
        "" -> [#("expires_at", json.string(""))]
        _ -> []
      },
      case r.tags {
        [] -> [#("tags", json.preprocessed_array([]))]
        _ -> []
      },
    ])
  json.object(
    list.flatten([
      rule.json_fields(r),
      unset,
      [
        #("version", json.string(rule.version(r))),
        #("hits", json.int(metrics.hits(r.id))),
        #(
          "last_hit_at",
          json.string(case metrics.last_hit(r.id) {
            0 -> ""
            at -> ffi.rfc3339(at)
          }),
        ),
      ],
    ]),
  )
}

pub fn field(
  name: String,
  inner: decode.Decoder(a),
  next: fn(Option(Option(a))) -> decode.Decoder(b),
) -> decode.Decoder(b) {
  decode.optional_field(
    name,
    None,
    decode.optional(inner) |> decode.map(Some),
    next,
  )
}

fn pick(patch: Option(Option(a)), current: a, default: a) -> a {
  case patch {
    None -> current
    Some(None) -> default
    Some(Some(value)) -> value
  }
}

/// JSON merge patch (RFC 7396) of the writable rule fields: absent fields are
/// kept, `null` resets a field to its default, other values replace it.
pub fn patch_decoder() -> decode.Decoder(fn(Rule) -> Rule) {
  let defaults = rule.blank()
  let kind_decoder = {
    use value <- decode.then(decode.string)
    case rule.kind_from_string(value) {
      Ok(kind) -> decode.success(kind)
      Error(Nil) -> decode.failure(rule.Exact, "exact | prefix | regex")
    }
  }
  use host <- field("host", decode.string)
  use kind <- field("match", kind_decoder)
  use source <- field("source", decode.string)
  use target <- field("target", decode.string)
  use status <- field("status", decode.int)
  use preserve_query <- field("preserve_query", decode.bool)
  use case_insensitive <- field("case_insensitive", decode.bool)
  use whole_segments <- field("whole_segments", decode.bool)
  use query <- field("query", decode.string)
  use priority <- field("priority", decode.int)
  use enabled <- field("enabled", decode.bool)
  use starts_at <- field("starts_at", decode.string)
  use expires_at <- field("expires_at", decode.string)
  use note <- field("note", decode.string)
  use tags <- field("tags", decode.list(decode.string))
  decode.success(fn(r: Rule) {
    rule.Rule(
      ..r,
      host: pick(host, r.host, defaults.host),
      kind: pick(kind, r.kind, defaults.kind),
      source: pick(source, r.source, defaults.source),
      target: pick(target, r.target, defaults.target),
      status: pick(status, r.status, defaults.status),
      preserve_query: pick(
        preserve_query,
        r.preserve_query,
        defaults.preserve_query,
      ),
      case_insensitive: pick(
        case_insensitive,
        r.case_insensitive,
        defaults.case_insensitive,
      ),
      whole_segments: pick(
        whole_segments,
        r.whole_segments,
        defaults.whole_segments,
      ),
      query: pick(query, r.query, defaults.query),
      priority: pick(priority, r.priority, defaults.priority),
      enabled: pick(enabled, r.enabled, defaults.enabled),
      starts_at: pick(starts_at, r.starts_at, defaults.starts_at),
      expires_at: pick(expires_at, r.expires_at, defaults.expires_at),
      note: pick(note, r.note, defaults.note),
      tags: pick(tags, r.tags, defaults.tags),
    )
  })
}
