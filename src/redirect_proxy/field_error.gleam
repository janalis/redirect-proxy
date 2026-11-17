//// Why a value was refused: the field it is about, and what is wrong with
//// it. Rule validation, the store, the API (the `errors` of a 422 problem)
//// and the admin forms (an error shown under its input) share it.

import gleam/list

pub type FieldError {
  /// `field` is "" for an error about no one field of the request (a line
  /// of an import, a rule of a set).
  FieldError(field: String, message: String)
}

/// An error about no one field.
pub fn general(message: String) -> FieldError {
  FieldError(field: "", message:)
}

/// `error` about a rule of a set (an import, a file), named by `context`
/// (`rule #2 (host/path)`): the field of that rule is told in the message,
/// as it is not a field of the request.
pub fn about(error: FieldError, context: String) -> FieldError {
  general(context <> ": " <> to_string(error))
}

/// `field: message`, or the message alone.
pub fn to_string(error: FieldError) -> String {
  case error.field {
    "" -> error.message
    field -> field <> ": " <> error.message
  }
}

pub fn to_strings(errors: List(FieldError)) -> List(String) {
  list.map(errors, to_string)
}
