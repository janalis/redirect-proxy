//// What a change of several rules asks for (an import mode, a bulk
//// action), and why a change of the rules was refused: the vocabulary the
//// store shares with the admin, the API and the CLI.

import redirect_proxy/field_error.{type FieldError}
import redirect_proxy/rule.{type Rule}

pub type ImportMode {
  /// Replace every rule with the imported ones.
  Replace
  /// Add imported rules; rules with an existing id are updated.
  Merge
}

/// `merge` or `replace`, as given to the admin form and the API.
pub fn import_mode_from_string(mode: String) -> Result(ImportMode, Nil) {
  case mode {
    "merge" -> Ok(Merge)
    "replace" -> Ok(Replace)
    _ -> Error(Nil)
  }
}

/// What a bulk change does to the rules it names.
pub type BulkAction {
  Enable
  Disable
  Remove
}

pub fn bulk_action_from_string(action: String) -> Result(BulkAction, Nil) {
  case action {
    "enable" -> Ok(Enable)
    "disable" -> Ok(Disable)
    "delete" -> Ok(Remove)
    _ -> Error(Nil)
  }
}

/// The name of a bulk action in its audit entry (`rules.bulk.<name>`).
@internal
pub fn bulk_action_to_string(action: BulkAction) -> String {
  case action {
    Enable -> "enable"
    Disable -> "disable"
    Remove -> "delete"
  }
}

/// Why a change was refused: nothing was written.
pub type ChangeError {
  /// The rule to change does not exist.
  NotFound
  /// A rule already has the id given to a new one (a retried creation).
  AlreadyExists
  /// The rule changed since the version the caller based its change on.
  Conflict(current: Rule)
  /// The rule set changed since the version (`store.versioned`) the caller
  /// based its change of the whole set (an import, a bulk change) on, such
  /// as an import preview.
  Stale(current: String)
  /// The change is invalid.
  Invalid(List(FieldError))
  /// Another process holds the lock of the redirections file past the
  /// wait: retrying soon may succeed.
  Busy(reason: String)
  /// The redirections file could not be read or written (permissions, a
  /// full disk), or was changed outside the server into a file that does
  /// not load.
  Storage(reason: String)
}
