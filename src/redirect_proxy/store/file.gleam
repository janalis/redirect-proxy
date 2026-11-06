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
  ffi.with_file_lock(files.rules_path, wait, fn() { load(files, mode) })
  |> result.flatten
}

/// Reads, validates and returns the rules with the file fingerprint. Writes
/// the file when it is created or when ids were assigned, so the caller must
/// hold the file lock.
pub fn load(
  files: Files,
  mode: LoadMode,
) -> Result(#(List(Rule), String), String) {
  case simplifile.is_file(files.rules_path), mode {
    Ok(True), _ -> {
      use bits <- result.try(
        simplifile.read_bits(files.rules_path)
        |> result.map_error(fn(e) {
          "cannot read "
          <> files.rules_path
          <> ": "
          <> simplifile.describe_error(e)
        }),
      )
      use content <- result.try(
        bit_array.to_string(bits)
        |> result.replace_error(files.rules_path <> ": not valid UTF-8"),
      )
      use rules <- result.try(
        rule.file_from_string(content)
        |> result.map_error(fn(e) { files.rules_path <> ": " <> e }),
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
          files.rules_path <> ": " <> string.join(errors, "; ")
        }),
      )
      case missing_ids {
        True ->
          persist(files, rules)
          |> result.map(fn(fingerprint) { #(rules, fingerprint) })
        False -> Ok(#(rules, fingerprint(bits)))
      }
    }
    Ok(False), FirstStart -> {
      // First start: create an empty file so operators know where it lives.
      use fingerprint <- result.try(persist(files, []))
      Ok(#([], fingerprint))
    }
    Ok(False), Reloading -> Error(files.rules_path <> ": file not found")
    Error(e), _ ->
      Error(
        "cannot read "
        <> files.rules_path
        <> ": "
        <> simplifile.describe_error(e),
      )
  }
}

/// Backs up then atomically rewrites the file. Returns its fingerprint.
pub fn persist(files: Files, rules: List(Rule)) -> Result(String, String) {
  let describe = fn(e) { simplifile.describe_error(e) }
  use Nil <- result.try(
    simplifile.create_directory_all(files.backups_dir)
    |> result.map_error(describe),
  )
  use Nil <- result.try(backup(files))
  let content = rule.file_to_string(rules) <> "\n"
  use Nil <- result.try(ffi.atomic_write(files.rules_path, content))
  Ok(fingerprint(bit_array.from_string(content)))
}

fn backup(files: Files) -> Result(Nil, String) {
  case files.backups, simplifile.is_file(files.rules_path) {
    0, _ -> Ok(Nil)
    _, Ok(True) -> {
      let name = backup_name(files.backups_dir, ffi.now_millis())
      use Nil <- result.try(
        simplifile.copy_file(files.rules_path, name)
        |> result.map_error(simplifile.describe_error),
      )
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

fn prune_backups(files: Files) -> Nil {
  case simplifile.read_directory(files.backups_dir) {
    Ok(names) -> {
      names
      |> list.filter(fn(f) {
        string.starts_with(f, "redirects-") && string.ends_with(f, ".json")
      })
      // names embed a millisecond timestamp of constant width: sort newest first
      |> list.sort(fn(a, b) { string.compare(b, a) })
      |> list.drop(files.backups)
      |> list.each(fn(f) {
        let _ = simplifile.delete(files.backups_dir <> "/" <> f)
        Nil
      })
    }
    Error(_) -> Nil
  }
}
