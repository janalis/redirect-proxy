//// The rules file: loading, atomic writes and backups.

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/rule.{type Rule}
import redirect_proxy/store/rules.{validate_all}
import simplifile

/// Where the rules file and its backups live.
pub type Files {
  Files(rules_path: String, backups_dir: String, backups: Int)
}

/// SHA-256 of a file content: the version of the rule set.
pub fn fingerprint(content: BitArray) -> String {
  crypto.hash(crypto.Sha256, content) |> bit_array.base16_encode
}

pub type LoadMode {
  /// Server start: a missing file is created empty.
  FirstStart
  /// Reload: a missing file is an error, so that the current rules stay live
  /// while the file is being replaced or was moved away.
  Reloading
}

/// `load` holding the cross-process file lock, for callers that do not hold
/// it already: loading may write the file back.
pub fn load_locked(
  files: Files,
  mode: LoadMode,
  wait: Int,
) -> Result(#(List(Rule), String), String) {
  load_locked_or_busy(files, mode, wait)
  |> result.map_error(fn(failure) { failure.reason })
}

/// Why a load failed. `read` is the fingerprint of the content refused.
pub type LoadFailure {
  /// Another process held the lock: trying again soon may succeed.
  LockHeld(reason: String)
  /// The lock could not be created (a full disk): the content was not read.
  LockNotCreated(reason: String)
  /// The content is invalid.
  Invalid(reason: String, read: String)
  /// The content is valid, but the ids of its rules without one could not
  /// be written (a full disk, a read-only volume).
  IdsNotWritten(reason: String, read: String)
}

/// `load_locked`, saying why it failed (`LoadFailure`).
pub fn load_locked_or_busy(
  files: Files,
  mode: LoadMode,
  wait: Int,
) -> Result(#(List(Rule), String), LoadFailure) {
  case
    ffi.with_file_lock_detailed(files.rules_path, wait, fn() {
      load_failing(files, mode)
    })
  {
    Error(ffi.Held(message)) -> Error(LockHeld(message))
    Error(ffi.CannotCreate(message)) -> Error(LockNotCreated(message))
    Ok(loaded) -> loaded
  }
}

/// Reads, validates and returns the rules with the file fingerprint. Writes
/// the file when it is created or when ids were assigned, so the caller must
/// hold the file lock.
pub fn load(
  files: Files,
  mode: LoadMode,
) -> Result(#(List(Rule), String), String) {
  load_failing(files, mode) |> result.map_error(fn(failure) { failure.reason })
}

/// `load`, saying why it failed (`Invalid` or `IdsNotWritten`).
pub fn load_failing(
  files: Files,
  mode: LoadMode,
) -> Result(#(List(Rule), String), LoadFailure) {
  load_reading(files, mode)
  |> result.map_error(fn(failure) {
    case failure {
      #(reason, read, True) -> IdsNotWritten(reason, read)
      #(reason, read, False) -> Invalid(reason, read)
    }
  })
}

/// `load`, failing with the fingerprint of the content it read ("" if
/// none), and whether that content was valid.
fn load_reading(
  files: Files,
  mode: LoadMode,
) -> Result(#(List(Rule), String), #(String, String, Bool)) {
  let unread = fn(reason) { #(reason, "", False) }
  case simplifile.is_file(files.rules_path), mode {
    Ok(True), _ -> {
      use bits <- result.try(
        simplifile.read_bits(files.rules_path)
        |> result.map_error(fn(e) {
          unread(
            "cannot read "
            <> files.rules_path
            <> ": "
            <> simplifile.describe_error(e),
          )
        }),
      )
      load_content(files, bits)
      |> result.map_error(fn(failure) {
        #(failure.0, fingerprint(bits), failure.1)
      })
    }
    Ok(False), FirstStart -> {
      // First start: create an empty file so operators know where it lives.
      use fingerprint <- result.try(
        persist(files, []) |> result.map_error(unread),
      )
      Ok(#([], fingerprint))
    }
    Ok(False), Reloading ->
      Error(unread(files.rules_path <> ": file not found"))
    Error(e), _ ->
      Error(unread(
        "cannot read "
        <> files.rules_path
        <> ": "
        <> simplifile.describe_error(e),
      ))
  }
}

/// The rules of the content `bits` of the file, writing the ids it gives
/// back. Fails with whether the content was valid (only the write failed).
fn load_content(
  files: Files,
  bits: BitArray,
) -> Result(#(List(Rule), String), #(String, Bool)) {
  let invalid = fn(reason) { #(reason, False) }
  use content <- result.try(
    bit_array.to_string(bits)
    |> result.replace_error(invalid(files.rules_path <> ": not valid UTF-8")),
  )
  use rules <- result.try(
    rule.file_from_string(content)
    |> result.map_error(fn(e) { invalid(files.rules_path <> ": " <> e) }),
  )
  // Hand written files may omit ids: assign them on load and write them
  // back so that they stay stable across reloads.
  let missing_ids = list.any(rules, fn(r) { r.id == "" })
  let rules =
    list.map(rules, fn(r) {
      case r.id {
        "" -> rule.Rule(..r, id: id.uuid())
        _ -> r
      }
    })
  use rules <- result.try(
    validate_all(rules)
    |> result.map_error(fn(errors) {
      invalid(files.rules_path <> ": " <> string.join(errors, "; "))
    }),
  )
  case missing_ids {
    True ->
      persist(files, rules)
      |> result.map(fn(fingerprint) { #(rules, fingerprint) })
      |> result.map_error(fn(reason) { #(reason, True) })
    False -> Ok(#(rules, fingerprint(bits)))
  }
}

/// Backs up then atomically rewrites the file. Returns its fingerprint.
pub fn persist(files: Files, rules: List(Rule)) -> Result(String, String) {
  use Nil <- result.try(backup(files))
  let content = rule.file_to_string_cached(rules) <> "\n"
  use Nil <- result.try(ffi.atomic_write(files.rules_path, content))
  Ok(fingerprint(bit_array.from_string(content)))
}

fn backup(files: Files) -> Result(Nil, String) {
  case files.backups, simplifile.is_file(files.rules_path) {
    0, _ -> Ok(Nil)
    _, Ok(True) -> {
      // created when needed only: with backups off, the directory need
      // not be writable, nor exist
      use Nil <- result.try(
        simplifile.create_directory_all(files.backups_dir)
        |> result.map_error(simplifile.describe_error),
      )
      let name = backup_name(files.backups_dir, ffi.now_millis())
      // with the permissions of the file it copies (e.g. not readable by
      // others), from its creation
      use Nil <- result.try(ffi.copy_file_as(files.rules_path, name))
      prune_backups(files)
      Ok(Nil)
    }
    _, _ -> Ok(Nil)
  }
}

/// `redirects-<ms>.json`, bumping the timestamp while the name is taken (two
/// writes in the same millisecond) so names stay unique and sortable.
fn backup_name(dir: String, millis: Int) -> String {
  let name = dir <> "/redirects-" <> int.to_string(millis) <> ".json"
  case simplifile.is_file(name) {
    Ok(True) -> backup_name(dir, millis + 1)
    _ -> name
  }
}

/// The timestamp of a `redirects-<ms>.json` name, as `backup_name` makes
/// them: digits only (`int.parse` also takes a sign).
fn backup_millis(name: String) -> Result(Int, Nil) {
  case string.starts_with(name, "redirects-"), string.ends_with(name, ".json") {
    True, True -> {
      let digits = name |> string.drop_start(10) |> string.drop_end(5)
      case digits != "" && string.to_graphemes(digits) |> list.all(is_digit) {
        True -> int.parse(digits)
        False -> Error(Nil)
      }
    }
    _, _ -> Error(Nil)
  }
}

fn is_digit(c: String) -> Bool {
  case c {
    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" -> True
    _ -> False
  }
}

fn prune_backups(files: Files) -> Nil {
  case simplifile.read_directory(files.backups_dir) {
    Ok(names) -> {
      names
      // the backups only: another file there (`redirects-old.json`) is
      // neither counted nor deleted
      |> list.filter_map(fn(f) {
        backup_millis(f) |> result.map(fn(millis) { #(millis, f) })
      })
      // newest first, by timestamp (a name of another width sorts as text
      // among them otherwise)
      |> list.sort(fn(a, b) { int.compare(b.0, a.0) })
      |> list.map(fn(backup) { backup.1 })
      |> list.drop(files.backups)
      |> list.each(fn(f) {
        let _ = simplifile.delete(files.backups_dir <> "/" <> f)
        Nil
      })
    }
    Error(_) -> Nil
  }
}
