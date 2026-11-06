//// JSON representation of rules in the REST API, and JSON merge patches.

import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}

/// `rule.to_json` plus the version (the ETag of the rule) and the hits since
/// the server started (read only).
pub fn rule_json(r: Rule) -> Json {
  json.object(
    list.append(rule.json_fields(r), [
      #("version", json.string(rule.version(r))),
      #("hits", json.int(metrics.hits(r.id))),
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
  use priority <- field("priority", decode.int)
  use enabled <- field("enabled", decode.bool)
  use note <- field("note", decode.string)
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
      priority: pick(priority, r.priority, defaults.priority),
      enabled: pick(enabled, r.enabled, defaults.enabled),
      note: pick(note, r.note, defaults.note),
    )
  })
}
