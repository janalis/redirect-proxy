//// Messages for JSON that cannot be read: rules files, request bodies,
//// `users.json` and `api_clients.json`.

import gleam/json
import gleam/list
import gleam/string

pub fn describe(error: json.DecodeError) -> String {
  case error {
    json.UnexpectedEndOfInput -> "unexpected end of JSON input"
    json.UnexpectedByte(byte) -> "unexpected byte " <> byte <> " in JSON input"
    json.UnexpectedSequence(seq) ->
      "unexpected sequence " <> seq <> " in JSON input"
    json.UnableToDecode(errors) ->
      errors
      |> list.map(fn(e) {
        "expected "
        <> e.expected
        <> " but found "
        <> e.found
        <> " at "
        <> string.join(e.path, ".")
      })
      |> string.join("; ")
  }
}
