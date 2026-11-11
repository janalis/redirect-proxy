import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import redirect_proxy/audit
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/rule.{Rule}
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/rules as store_rules
import simplifile
import support

fn settings(dir: String, backups: Int) -> store.Settings {
  store.Settings(
    rules_path: dir <> "/redirects.json",
    backups_dir: dir <> "/backups",
    backups:,
    audit_path: dir <> "/audit.jsonl",
    ignore_trailing_slash: False,
    watch_interval: 0,
    hits_path: dir <> "/hits.json",
  )
}

fn start(s: store.Settings) -> store.Store {
  let assert Ok(started) = store.start(s, process.new_name("store_test"))
  started.data
}

/// A store watching its file, then stopped once `run` returns: it would
/// try a file it could not load again later, during another test, and
/// publish its rules over that test's.
fn with_watching_store(s: store.Settings, run: fn(store.Store) -> Nil) -> Nil {
  let assert Ok(started) = store.start(s, process.new_name("store_test"))
  run(started.data)
  process.unlink(started.pid)
  process.kill(started.pid)
}

fn new_rule(source: String, target: String) -> rule.Rule {
  Rule(..rule.blank(), source:, target:)
}

fn redirect(path: String) -> Result(String, Nil) {
  case matcher.lookup(snapshot.current(), "test.local", path) {
    Ok(m) -> Ok(m.location)
    Error(Nil) -> Error(Nil)
  }
}

pub fn first_start_creates_empty_file_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  assert store.all(s) == []
  let assert Ok(content) = simplifile.read(dir <> "/redirects.json")
  assert rule.file_from_string(content) == Ok([])
}

pub fn crud_persists_and_publishes_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))

  let assert Ok(created) = store.create(s, new_rule("/a", "/b"), by: "tester")
  assert created.id != ""
  assert created.updated_by == "tester"
  assert created.created_at != ""
  assert redirect("/a") == Ok("/b")

  let assert Ok(updated) =
    store.update(s, Rule(..created, target: "/c"), by: "tester")
  assert updated.created_at == created.created_at
  assert redirect("/a") == Ok("/c")
  assert store.get(s, created.id) == Ok(updated)

  // restart: the file is the source of truth
  let s2 = start(settings(dir, 5))
  assert store.all(s2) == [updated]

  let assert Ok(_) = store.delete(s2, created.id, by: "tester")
  assert redirect("/a") == Error(Nil)
  assert store.all(s2) == []
  let assert Error(_) = store.delete(s2, created.id, by: "tester")

  let assert Ok(audit) = simplifile.read(dir <> "/audit.jsonl")
  let actions =
    audit
    |> string.split("\n")
    |> list.filter(fn(line) { line != "" })
  assert list.length(actions) == 3
}

pub fn invalid_rules_are_rejected_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let assert Error(errors) = store.create(s, new_rule("nope", "/b"), by: "t")
  assert errors == ["source: must start with /"]
  let assert Error(["id: rule not found"]) =
    store.update(s, Rule(..new_rule("/a", "/b"), id: "missing"), by: "t")
  assert store.all(s) == []
}

pub fn conflicts_are_rejected_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let assert Ok(_) = store.create(s, new_rule("/dup", "/one"), by: "t")
  let assert Error([error]) = store.create(s, new_rule("/dup", "/two"), by: "t")
  assert string.contains(error, "already matches")
  // same path on another host is fine
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/dup", "/two"), host: "other.test"),
      by: "t",
    )
  // disabled duplicates are allowed
  let assert Ok(_) =
    store.create(s, Rule(..new_rule("/dup", "/three"), enabled: False), by: "t")
  // self redirects are refused
  let assert Error([loop]) =
    store.create(s, new_rule("/loop", "/loop"), by: "t")
  assert string.contains(loop, "redirects to itself")
}

pub fn rules_that_never_match_are_refused_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let assert Error([query]) =
    store.create(s, new_rule("/page.php?id=5", "/page"), by: "t")
  assert string.contains(query, "query string")
  let assert Error([port]) =
    store.create(
      s,
      Rule(..new_rule("/a", "/b"), host: "example.com:8080"),
      by: "t",
    )
  assert string.contains(port, "port")
  let assert Ok(created) = store.create(s, new_rule("/a", "/b"), by: "t")
  let assert Error([_]) =
    store.update(s, Rule(..created, source: "/a?b"), by: "t")
  assert store.all(s) == [created]
}

pub fn rules_that_never_match_still_load_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"id\":\"q\",\"host\":\"example.com:8080\",\"match\":\"exact\",\"source\":\"/a?b\",\"target\":\"/c\"}]}",
    )
  let s = start(settings(dir, 5))
  let assert [loaded] = store.all(s)
  assert loaded.id == "q"
}

pub fn reload_keeps_rules_when_file_is_invalid_test() {
  let dir = support.temp_dir()
  let path = dir <> "/redirects.json"
  let s = start(settings(dir, 5))
  let assert Ok(_) = store.create(s, new_rule("/keep", "/kept"), by: "t")

  let assert Ok(Nil) =
    simplifile.write(path, "[{\"source\": \"/new\", \"target\": \"/fresh\"}]")
  assert store.reload(s, by: "t") == Ok(1)
  assert redirect("/new") == Ok("/fresh")
  assert redirect("/keep") == Error(Nil)
  // ids were assigned and written back
  let assert Ok(content) = simplifile.read(path)
  let assert Ok([written]) = rule.file_from_string(content)
  assert written.id != ""

  let assert Ok(Nil) = simplifile.write(path, "{ not json")
  let assert Error(_) = store.reload(s, by: "t")
  assert redirect("/new") == Ok("/fresh")
  assert list.length(store.all(s)) == 1
}

pub fn invalid_file_prevents_start_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "[{\"source\": \"relative\", \"target\": \"/x\"}]",
    )
  let assert Error(_) =
    store.start(settings(dir, 5), process.new_name("store_test"))
}

pub fn backups_are_rotated_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 2))
  list.each(["/1", "/2", "/3", "/4", "/5"], fn(source) {
    let assert Ok(_) = store.create(s, new_rule(source, "/x"), by: "t")
    // backup names have millisecond resolution
    process.sleep(2)
  })
  let assert Ok(files) = simplifile.read_directory(dir <> "/backups")
  assert list.length(files) == 2
}

/// A backup is readable by whoever can read the rules file, no one else.
/// Rotation counts and deletes the backups only, not other files in their
/// directory; with backups off, the directory is not created.
pub fn backups_rotation_ignores_other_files_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir <> "/backups")
  let assert Ok(Nil) =
    simplifile.write(dir <> "/backups/redirects-old.json", "")
  let s = start(settings(dir, 2))
  list.each(["/r1", "/r2", "/r3", "/r4"], fn(source) {
    let assert Ok(_) = store.create(s, new_rule(source, "/x"), by: "t")
  })
  let assert Ok(files) = simplifile.read_directory(dir <> "/backups")
  assert list.contains(files, "redirects-old.json")
  assert list.length(files) == 3

  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) = store.create(s, new_rule("/a", "/x"), by: "t")
  let assert Ok(_) = store.create(s, new_rule("/b", "/x"), by: "t")
  assert simplifile.is_directory(dir <> "/backups") == Ok(False)
}

pub fn backups_keep_the_rules_file_mode_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let assert Ok(_) = store.create(s, new_rule("/mode-1", "/x"), by: "t")
  let assert Ok(Nil) =
    simplifile.set_permissions_octal(dir <> "/redirects.json", 0o640)
  let assert Ok(_) = store.create(s, new_rule("/mode-2", "/x"), by: "t")
  let assert Ok(backups) = simplifile.read_directory(dir <> "/backups")
  let assert Ok(latest) = list.max(backups, string.compare)
  let assert Ok(info) = simplifile.file_info(dir <> "/backups/" <> latest)
  assert simplifile.file_info_permissions_octal(info) == 0o640
}

pub fn import_merge_and_replace_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(existing) = store.create(s, new_rule("/a", "/1"), by: "t")

  let incoming = [
    Rule(..existing, target: "/updated"),
    new_rule("/b", "/2"),
  ]
  assert store.import_rules(s, incoming, store.Merge, by: "t") == Ok(2)
  assert redirect("/a") == Ok("/updated")
  assert redirect("/b") == Ok("/2")
  assert list.length(store.all(s)) == 2

  assert store.import_rules(s, [new_rule("/c", "/3")], store.Replace, by: "t")
    == Ok(1)
  assert redirect("/a") == Error(Nil)
  assert redirect("/c") == Ok("/3")

  // all or nothing
  let assert Error(errors) =
    store.import_rules(
      s,
      [new_rule("/d", "/4"), new_rule("bad", "/5")],
      store.Merge,
      by: "t",
    )
  assert errors != []
  assert redirect("/d") == Error(Nil)
}

/// A CSV export has no creation date: importing it back keeps the dates of
/// the rules it updates.
pub fn import_keeps_creation_dates_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let created = "2020-01-01T00:00:00Z"
  let dated = Rule(..new_rule("/a", "/1"), id: "a", created_at: created)
  assert store.import_rules(s, [dated], store.Merge, by: "t") == Ok(1)
  let undated = Rule(..dated, target: "/2", created_at: "")
  assert store.import_rules(s, [undated], store.Merge, by: "t") == Ok(1)
  let assert Ok(after) = store.get(s, "a")
  assert after.target == "/2"
  assert after.created_at == created
  let fresh = Rule(..new_rule("/b", "/3"), created_at: "")
  let undated = Rule(..undated, target: "/4")
  assert store.import_rules(s, [undated, fresh], store.Replace, by: "t")
    == Ok(2)
  let assert Ok(after) = store.get(s, "a")
  assert after.created_at == created
  assert list.all(store.all(s), fn(r) { r.created_at != "" })
}

/// Imports and bulk enabling refuse rules that loop or can never apply, as
/// a change of one rule does; rules they leave alone are not checked.
pub fn set_changes_check_the_rules_they_change_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let a = Rule(..new_rule("/a", "/b"), id: "a")
  let b = Rule(..new_rule("/b", "/a"), id: "b")
  // a loop
  let assert Error(errors) = store.import_rules(s, [a, b], store.Merge, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  let assert Error(_) = store.preview_import(s, [a, b], store.Merge, by: "t")
  // a target that never redirects
  let unsafe = Rule(..new_rule("/u/", "https://$1x.com/"), kind: rule.Prefix)
  let assert Error([error]) =
    store.import_rules(s, [unsafe], store.Merge, by: "t")
  assert string.contains(error, "never redirect")
  // enabling the second half of a loop
  let off = Rule(..b, enabled: False)
  assert store.import_rules(s, [a, off], store.Merge, by: "t") == Ok(2)
  let assert Error(errors) =
    store.bulk_versioned(s, ["b"], store.Enable, None, by: "t")
  assert list.any(errors_of(errors), string.contains(_, "redirect loop"))
  // a file that loaded with a problem imports again, unchanged
  let legacy = Rule(..new_rule("/q?x=1", "/t"), id: "legacy")
  let assert Ok(Nil) =
    simplifile.write(dir <> "/redirects.json", store_rules.export([legacy]))
  let assert Ok(_) = store.reload(s, by: "t")
  assert store.import_rules(s, [legacy], store.Replace, by: "t") == Ok(1)
  assert store.bulk_versioned(s, ["legacy"], store.Disable, None, by: "t")
    == Ok(1)
}

/// A rule that loaded although it can never apply can be disabled one at a
/// time too (as in bulk), but not enabled.
pub fn rules_that_never_apply_can_be_disabled_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let legacy = Rule(..new_rule("/q?x=1", "/t"), id: "legacy")
  let assert Ok(Nil) =
    simplifile.write(dir <> "/redirects.json", store_rules.export([legacy]))
  let assert Ok(_) = store.reload(s, by: "t")
  let assert Ok(_) = store.update(s, Rule(..legacy, enabled: False), by: "t")
  let assert Error([error]) = store.update(s, legacy, by: "t")
  assert string.contains(error, "query string")
}

/// Importing rules again unchanged leaves them as they are: their version
/// (ETag), dates and author; changed ones are stamped.
pub fn unchanged_imported_rules_keep_their_version_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(a) =
    store.create(s, Rule(..new_rule("/a", "/t"), id: "a"), by: "alice")
  let assert Ok(b) =
    store.create(s, Rule(..new_rule("/b", "/t"), id: "b"), by: "alice")
  process.sleep(1100)
  let assert Ok(2) =
    store.import_rules(s, [a, Rule(..b, target: "/u")], store.Merge, by: "bob")
  let assert Ok(a2) = store.get(s, "a")
  let assert Ok(b2) = store.get(s, "b")
  assert rule.version(a2) == rule.version(a)
  assert #(a2.updated_at, a2.updated_by) == #(a.updated_at, "alice")
  assert b2.updated_by == "bob"
  assert rule.version(b2) != rule.version(b)
}

/// A file that loaded with a reserved id imports again: only new ids are
/// refused.
pub fn loaded_reserved_ids_import_again_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let export = Rule(..new_rule("/e", "/t"), id: "export")
  let assert Ok(Nil) =
    simplifile.write(dir <> "/redirects.json", store_rules.export([export]))
  let assert Ok(_) = store.reload(s, by: "t")
  assert store.import_rules(s, [export], store.Replace, by: "t") == Ok(1)
  assert store.import_rules(s, [export], store.Merge, by: "t") == Ok(1)
  let assert Ok(_) = store.preview_import(s, [export], store.Merge, by: "t")
  let bulk = Rule(..new_rule("/b", "/t"), id: "bulk")
  let assert Error([error]) =
    store.import_rules(s, [bulk], store.Merge, by: "t")
  assert string.contains(error, "reserved")
}

/// An id the file loaded with, spaces and all, names the same rule in an
/// import; a new one is trimmed.
pub fn loaded_ids_with_spaces_import_again_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let spaced = Rule(..new_rule("/s", "/t"), id: " a")
  let assert Ok(Nil) =
    simplifile.write(dir <> "/redirects.json", store_rules.export([spaced]))
  let assert Ok(_) = store.reload(s, by: "t")
  let fresh = Rule(..new_rule("/f", "/t"), id: " b ")
  assert store.import_rules(s, [spaced, fresh], store.Merge, by: "t") == Ok(2)
  assert list.map(store.all(s), fn(r) { r.id }) == [" a", "b"]
  // two ids that are one once trimmed are duplicates
  let assert Error(errors) =
    store.import_rules(
      s,
      [Rule(..fresh, id: "b"), Rule(..fresh, id: " b", source: "/g")],
      store.Merge,
      by: "t",
    )
  assert list.any(errors, string.contains(_, "duplicate"))
  let assert Error(_) =
    store.preview_import(
      s,
      [Rule(..fresh, id: "b"), Rule(..fresh, id: " b", source: "/g")],
      store.Merge,
      by: "t",
    )
}

/// A rule that starts later would loop once it starts: the loop is
/// followed with the rules active at its start.
pub fn scheduled_loops_are_refused_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) =
    store.create(s, Rule(..new_rule("/a", "/b"), id: "a"), by: "t")
  let later =
    Rule(..new_rule("/b", "/a"), id: "b", starts_at: "2999-01-01T00:00:00Z")
  let assert Error(errors) = store.create(s, later, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  let assert Error(errors) =
    store.import_rules(s, [later], store.Merge, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  let assert Ok(1) =
    store.import_rules(s, [Rule(..later, enabled: False)], store.Merge, by: "t")
  let assert Error(errors) =
    store.bulk_versioned(s, ["b"], store.Enable, None, by: "t")
  assert list.any(errors_of(errors), string.contains(_, "redirect loop"))
  // rules whose windows do not overlap do not loop
  let assert Ok(_) =
    store.update(
      s,
      Rule(
        ..later,
        enabled: True,
        starts_at: "",
        expires_at: "2000-01-01T00:00:00Z",
      ),
      by: "t",
    )
}

/// The other way round: a rule active now that loops with one that starts
/// later, once it starts.
pub fn loops_with_a_rule_that_starts_later_are_refused_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let later =
    Rule(..new_rule("/b", "/a"), id: "b", starts_at: "2999-01-01T00:00:00Z")
  let assert Ok(_) = store.create(s, later, by: "t")
  let now = Rule(..new_rule("/a", "/b"), id: "a")
  let assert Error(errors) = store.create(s, now, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  let assert Error(errors) = store.import_rules(s, [now], store.Merge, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  // one that expires before the other starts does not loop
  let assert Ok(_) =
    store.create(s, Rule(..now, expires_at: "2998-01-01T00:00:00Z"), by: "t")
  // nor do two rules whose windows do not overlap
  let assert Ok(_) =
    store.create(
      s,
      Rule(
        ..new_rule("/c", "/d"),
        id: "c",
        starts_at: "2999-01-01T00:00:00Z",
        expires_at: "2999-02-01T00:00:00Z",
      ),
      by: "t",
    )
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/d", "/c"), id: "d", starts_at: "2999-03-01T00:00:00Z"),
      by: "t",
    )
}

/// Rules that take turns on one path do not hide each other: the loop is
/// followed at each time the rules in effect change.
pub fn loops_through_rules_taking_turns_are_refused_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/a", "/b"), id: "a1", expires_at: "2999-01-01T00:00:00Z"),
      by: "t",
    )
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/a", "/x"), id: "a2", starts_at: "2999-01-01T00:00:00Z"),
      by: "t",
    )
  let x = Rule(..new_rule("/x", "/a"), id: "x")
  let assert Error(errors) = store.create(s, x, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
  let assert Error(errors) = store.import_rules(s, [x], store.Merge, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
}

/// Each rule of a change is followed at its own nearest times: the times
/// of the others do not use up its share.
pub fn each_imported_rule_is_followed_at_its_own_times_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  // eight times to come, all within the window of `a` below
  list.each([1, 2, 3, 4, 5, 6, 7, 8], fn(n) {
    let assert Ok(_) =
      store.create(
        s,
        Rule(
          ..new_rule("/f" <> int.to_string(n), "/t"),
          id: "f" <> int.to_string(n),
          starts_at: "29" <> int.to_string(80 + n) <> "-01-01T00:00:00Z",
        ),
        by: "t",
      )
  })
  let assert Ok(_) =
    store.create(s, Rule(..new_rule("/c", "/b"), id: "c"), by: "t")
  let a = Rule(..new_rule("/a", "/z"), id: "a")
  let b =
    Rule(..new_rule("/b", "/c"), id: "b", starts_at: "2999-01-01T00:00:00Z")
  let assert Error(errors) = store.import_rules(s, [a, b], store.Merge, by: "t")
  assert list.any(errors, string.contains(_, "redirect loop"))
}

/// Every check applies to disabled rules too, one at a time or in sets,
/// but for disabling a rule that loaded with a problem: it then still
/// imports again unchanged.
pub fn disabled_rules_are_checked_too_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let bad = Rule(..new_rule("/q?x=1", "/t"), id: "bad", enabled: False)
  let assert Error([_]) = store.create(s, bad, by: "t")
  let assert Error(_) = store.import_rules(s, [bad], store.Merge, by: "t")
}

fn errors_of(error: store.SetChangeError) -> List(String) {
  case error {
    store.Rejected(errors) -> errors
    _ -> []
  }
}

pub fn keep_created_at_test() {
  let at = fn(id, created, updated) {
    Rule(
      ..new_rule("/" <> id, "/x"),
      id:,
      created_at: created,
      updated_at: updated,
    )
  }
  let existing = [at("a", "2020", "2021"), at("b", "", "2021")]
  let imported = [at("a", "", "2030"), at("b", "", "2030"), at("c", "", "2030")]
  assert store_rules.keep_created_at(existing, imported)
    |> list.map(fn(r) { r.created_at })
    == ["2020", "2030", "2030"]
}

pub fn validate_all_reports_rule_numbers_test() {
  let assert Error([error]) =
    store_rules.validate_all([new_rule("/ok", "/x"), new_rule("bad", "/y")])
  assert string.starts_with(error, "rule #2")
}

// --- concurrent writers --------------------------------------------------------

/// Another process (the CLI, an editor) changed the file: the next mutation
/// reloads it first instead of overwriting it.
pub fn outside_changes_are_reloaded_before_writing_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let assert Ok(_) = store.create(s, new_rule("/mine", "/a"), by: "server")
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\": 1, \"rules\": [{\"source\": \"/theirs\", \"target\": \"/b\"}]}",
    )
  let assert Ok(_) = store.create(s, new_rule("/new", "/c"), by: "server")
  let sources = fn(rules: List(rule.Rule)) {
    list.map(rules, fn(r) { r.source }) |> list.sort(string.compare)
  }
  // the hand edit removed /mine and added /theirs: both are respected
  assert sources(store.all(s)) == ["/new", "/theirs"]
  let assert Ok(content) = simplifile.read(dir <> "/redirects.json")
  let assert Ok(on_disk) = rule.file_from_string(content)
  assert sources(on_disk) == ["/new", "/theirs"]
  assert redirect("/theirs") == Ok("/b")
}

pub fn invalid_outside_changes_are_not_overwritten_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 5))
  let broken = "{\"version\": 1, \"rules\": [ half written"
  let assert Ok(Nil) = simplifile.write(dir <> "/redirects.json", broken)
  let assert Error([reason]) =
    store.create(s, new_rule("/x", "/y"), by: "server")
  assert string.contains(reason, "changed outside the server")
  assert simplifile.read(dir <> "/redirects.json") == Ok(broken)
}

/// A rules file this process cannot read (replaced by a copy owned by
/// another user) is not taken for a missing one, and overwritten.
pub fn unreadable_outside_changes_are_not_overwritten_test() {
  let dir = support.temp_dir()
  let path = dir <> "/redirects.json"
  let s = start(settings(dir, 0))
  let theirs =
    "{\"version\": 1, \"rules\": [{\"id\": \"t\", \"source\": \"/theirs\", \"target\": \"/b\"}]}"
  let assert Ok(Nil) = simplifile.write(path, theirs)
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o200)
  let result = store.create(s, new_rule("/x", "/y"), by: "server")
  let assert Ok(Nil) = simplifile.set_permissions_octal(path, 0o600)
  let assert Error([reason]) = result
  assert string.contains(reason, "cannot be read")
  assert simplifile.read(path) == Ok(theirs)
}

/// Two stores on the same file stand for two OS processes (server and CLI):
/// concurrent writes from both are all kept.
pub fn concurrent_writers_lose_no_update_test() {
  let dir = support.temp_dir()
  let a = start(settings(dir, 0))
  let assert Ok(b) = store.start(settings(dir, 0), process.new_name("other"))
  let b = b.data
  let done = process.new_subject()
  list.each([#("a", a), #("b", b)], fn(writer) {
    process.spawn(fn() {
      list.each(int.range(from: 1, to: 16, with: [], run: list.prepend), fn(i) {
        let source = "/" <> writer.0 <> "/" <> string.inspect(i)
        let assert Ok(_) = store.create(writer.1, new_rule(source, "/t"), "t")
      })
      process.send(done, Nil)
    })
  })
  let assert Ok(Nil) = process.receive(done, 30_000)
  let assert Ok(Nil) = process.receive(done, 30_000)
  let assert Ok(content) = simplifile.read(dir <> "/redirects.json")
  let assert Ok(on_disk) = rule.file_from_string(content)
  assert list.length(on_disk) == 30
}

pub fn waits_for_the_file_lock_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let lock = dir <> "/redirects.json.lock"
  let assert Ok(Nil) = simplifile.write(lock, "12345 cli@host\n")
  process.spawn(fn() {
    process.sleep(300)
    let _ = simplifile.delete(lock)
  })
  let assert Ok(_) = store.create(s, new_rule("/x", "/y"), by: "server")
  assert simplifile.is_file(lock) == Ok(False)
}

pub fn stale_lock_is_broken_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let lock = dir <> "/redirects.json.lock"
  let assert Ok(Nil) = simplifile.write(lock, "12345 crashed@host\n")
  set_mtime(lock, 60)
  let assert Ok(_) = store.create(s, new_rule("/x", "/y"), by: "server")
}

pub fn backups_have_unique_names_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 50))
  let assert Ok(r) = store.create(s, new_rule("/a", "/b"), by: "t")
  list.each(int.range(from: 1, to: 11, with: [], run: list.prepend), fn(i) {
    let assert Ok(_) =
      store.update(s, Rule(..r, target: "/" <> string.inspect(i)), by: "t")
  })
  let assert Ok(files) = simplifile.read_directory(dir <> "/backups")
  // one backup per write after the first one (creation of the empty file)
  assert list.length(files) == 11
}

/// Sets a file's modification time `seconds_ago` in the past.
@external(erlang, "test_net_ffi", "set_mtime_ago")
fn set_mtime(path: String, seconds_ago: Int) -> Nil

pub fn reload_keeps_rules_when_the_file_is_missing_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) = store.create(s, new_rule("/a", "/b"), by: "t")
  // e.g. an editor or a deploy replacing the file non-atomically
  let assert Ok(Nil) = simplifile.delete(dir <> "/redirects.json")
  let assert Error(reason) = store.reload(s, by: "t")
  assert string.contains(reason, "not found")
  assert redirect("/a") == Ok("/b")
  assert list.length(store.all(s)) == 1
  // the file was not recreated empty
  assert simplifile.is_file(dir <> "/redirects.json") == Ok(False)
}

pub fn reload_assigns_missing_ids_under_the_lock_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"source\":\"/n\",\"target\":\"/m\"}]}",
    )
  let lock = dir <> "/redirects.json.lock"
  let assert Ok(Nil) = simplifile.write(lock, "12345 cli@host\n")
  process.spawn(fn() {
    process.sleep(300)
    let _ = simplifile.delete(lock)
  })
  // waits for the lock before writing the ids back
  let assert Ok(1) = store.reload(s, by: "t")
  let assert Ok(content) = simplifile.read(dir <> "/redirects.json")
  let assert Ok([r]) = rule.file_from_string(content)
  assert r.id != ""
}

pub fn creating_a_redirect_loop_is_refused_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let looping = Rule(..new_rule("/a/", "/a/b/$1"), kind: rule.Prefix)
  let assert Error([reason]) = store.create(s, looping, by: "t")
  assert string.contains(reason, "redirect loop")
  let assert Ok(_) =
    store.create(s, Rule(..looping, target: "/new/$1"), by: "t")
  // whole segments: `/w` -> `/w/x$1` is a loop (`/w/…` matches again)
  let segments =
    Rule(..new_rule("/w", "/w/x$1"), kind: rule.Prefix, whole_segments: True)
  let assert Error([reason]) = store.create(s, segments, by: "t")
  assert string.contains(reason, "redirect loop")
}

pub fn a_file_with_a_loop_still_loads_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"id\":\"p\",\"match\":\"prefix\",\"source\":\"/a/\",\"target\":\"/a/b/$1\"}]}",
    )
  let s = start(settings(dir, 0))
  assert list.length(store.all(s)) == 1
}

pub fn equivalent_exact_sources_conflict_test() {
  let a = Rule(..rule.blank(), id: "a", source: "/café", target: "/x")
  let b = Rule(..rule.blank(), id: "b", source: "/caf%C3%A9", target: "/y")
  let assert Error([reason]) = store_rules.check_conflicts([a, b])
  assert string.contains(reason, "already matches")
}

/// Hosts are compared as the matcher does: without port, trailing dot or
/// case (a file may hold `example.com:8080`).
pub fn equivalent_exact_hosts_conflict_test() {
  let on = fn(id, host) {
    Rule(..rule.blank(), id:, host:, source: "/a", target: "/x")
  }
  let assert Error([reason]) =
    store_rules.check_conflicts([
      on("a", "example.com"),
      on("b", "Example.com:8080"),
    ])
  assert string.contains(reason, "already matches")
  let assert Error(_) =
    store_rules.check_conflicts([
      on("a", "example.com"),
      on("b", "example.com."),
    ])
  assert store_rules.check_conflicts([
      on("a", "example.com"),
      on("b", "other.com"),
    ])
    == Ok(Nil)
}

pub fn imports_and_reloads_are_audited_with_their_changes_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(kept) = store.create(s, new_rule("/kept", "/k"), by: "t")
  let assert Ok(_) =
    store.import_rules(
      s,
      [
        Rule(..kept, target: "/k2"),
        Rule(..new_rule("/new", "/n"), id: "new-id"),
      ],
      store.Merge,
      by: "importer",
    )
  let assert [entry, ..] = audit.tail(dir <> "/audit.jsonl", 1)
  assert entry.action == "rules.import.merge"
  assert string.contains(entry.details, "\"added_ids\":[\"new-id\"]")
  assert string.contains(
    entry.details,
    "\"changed_ids\":[\"" <> kept.id <> "\"]",
  )
  assert string.contains(entry.details, "\"removed\":0")
  // a rejected reload is audited too
  let assert Ok(Nil) = simplifile.write(dir <> "/redirects.json", "{ broken")
  let assert Error(_) = store.reload(s, by: "operator")
  let assert [failed, ..] = audit.tail(dir <> "/audit.jsonl", 1)
  assert failed.action == "rules.reload_failed"
  assert failed.actor == "operator"
}

pub fn diff_test() {
  let a = Rule(..new_rule("/a", "/x"), id: "a")
  let b = Rule(..new_rule("/b", "/x"), id: "b")
  let c = Rule(..new_rule("/c", "/x"), id: "c")
  let d =
    store_rules.diff([a, b, c], [
      // only timestamps differ: unchanged
      Rule(..a, updated_at: "later", updated_by: "someone"),
      Rule(..b, target: "/y"),
      Rule(..new_rule("/d", "/x"), id: "d"),
    ])
  assert d.added == ["d"]
  assert d.removed == ["c"]
  assert d.changed == ["b"]
}

/// A store restarted after a crash keeps serving and editing the rules it
/// had when the file has become invalid in the meantime, instead of failing
/// until its supervisor stops the node. A first start still fails.
pub fn restart_with_an_invalid_file_keeps_the_last_rules_test() {
  let dir = support.temp_dir()
  let s = settings(dir, 0)
  let assert Ok(started) = store.start(s, process.new_name("store_test"))
  let assert Ok(_) =
    store.create(started.data, new_rule("/kept", "/target"), by: "test")
  let assert Ok(Nil) = simplifile.write(s.rules_path, "{ not json")
  process.unlink(started.pid)
  process.kill(started.pid)

  let assert Ok(restarted) = store.start(s, process.new_name("store_test"))
  assert list.map(store.all(restarted.data), fn(r) { r.source }) == ["/kept"]
  assert redirect("/kept") == Ok("/target")
  // a change re-reads the file first and refuses to overwrite it
  let assert Error(_) =
    store.create(restarted.data, new_rule("/new", "/x"), by: "test")
  // once fixed, changes go through again
  let assert Ok(Nil) = simplifile.write(s.rules_path, "[]")
  let assert Ok(_) =
    store.create(restarted.data, new_rule("/new", "/x"), by: "test")

  let other = settings(support.temp_dir(), 0)
  let assert Ok(Nil) = simplifile.write(other.rules_path, "{ not json")
  let assert Error(_) = store.start(other, process.new_name("store_test"))
}

/// With `watch_interval`, a file changed by another process is reloaded
/// without SIGHUP; the store's own writes and invalid files are not.
pub fn watched_file_is_reloaded_test() {
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  let store = start(s)
  let assert Ok(_) = store.create(store, new_rule("/own", "/write"), by: "test")
  process.sleep(100)
  // our own write was not taken for an outside change
  assert reloads(dir) == 0

  let assert Ok(Nil) =
    simplifile.write(
      s.rules_path,
      "[{\"source\": \"/watched\", \"target\": \"/reloaded\"}]",
    )
  support.wait_until(fn() { redirect("/watched") == Ok("/reloaded") }, 2000)
  assert list.map(store.all(store), fn(r) { r.source }) == ["/watched"]
  assert reloads(dir) == 1

  // an invalid file is reported once and the rules are kept
  let assert Ok(Nil) = simplifile.write(s.rules_path, "{ not json")
  support.wait_until(fn() { reload_failures(dir) == 1 }, 2000)
  process.sleep(100)
  assert reload_failures(dir) == 1
  assert redirect("/watched") == Ok("/reloaded")
}

@external(erlang, "test_log_ffi", "capture_stop")
fn captured_logs() -> List(String)

/// A file the watcher cannot read is reported once per change, though its
/// stamp stays recent, and read again, for a few ticks.
pub fn unreadable_watched_file_is_reported_once_test() {
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  let _ = start(s)
  process.sleep(50)
  capture_logs()
  let assert Ok(Nil) =
    simplifile.write(s.rules_path, "[{\"source\": \"/x\", \"target\": \"/y\"}]")
  let assert Ok(Nil) = simplifile.set_permissions_octal(s.rules_path, 0o200)
  process.sleep(1000)
  let logs = captured_logs()
  let assert Ok(Nil) = simplifile.set_permissions_octal(s.rules_path, 0o600)
  assert list.count(logs, string.contains(_, "cannot be read")) == 1
}

/// A file that could not be read for a moment, invalid before and after,
/// is still reported once.
pub fn invalid_watched_file_unreadable_for_a_moment_is_reported_once_test() {
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  let _ = start(s)
  process.sleep(50)
  let assert Ok(Nil) = simplifile.write(s.rules_path, "{ not json")
  support.wait_until(fn() { reload_failures(dir) == 1 }, 2000)
  let assert Ok(Nil) = simplifile.set_permissions_octal(s.rules_path, 0o200)
  process.sleep(100)
  let assert Ok(Nil) = simplifile.set_permissions_octal(s.rules_path, 0o600)
  process.sleep(300)
  assert reload_failures(dir) == 1
}

/// A replica reading a read-only volume cannot write the ids a file without
/// them needs: the file is reported once, not at every tick.
pub fn watched_file_a_replica_cannot_load_is_reported_once_test() {
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  use _ <- with_watching_store(s)
  // tried again every second, but not reported again
  ffi.set_tunable("rejected_retry_seconds", 1)
  process.sleep(50)
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o500)
  capture_logs()
  let assert Ok(Nil) =
    simplifile.write(s.rules_path, "[{\"source\": \"/x\", \"target\": \"/y\"}]")
  process.sleep(2500)
  ffi.clear_tunable("rejected_retry_seconds")
  let logs = captured_logs()
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o700)
  assert list.count(logs, string.contains(_, "reload rejected")) == 1
}

/// Valid content that could not be loaded because writing its ids failed
/// (a full disk) is tried again later, unchanged.
pub fn watched_valid_file_that_failed_to_load_is_tried_again_test() {
  ffi.set_tunable("rejected_retry_seconds", 1)
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  use st <- with_watching_store(s)
  // this store's rules (the stores of other tests, still watching, may
  // publish theirs)
  let loaded = fn() {
    list.any(store.all(st), fn(r: rule.Rule) { r.source == "/later" })
  }
  process.sleep(50)
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o500)
  let assert Ok(Nil) =
    simplifile.write(
      s.rules_path,
      "[{\"source\": \"/later\", \"target\": \"/y\"}]",
    )
  process.sleep(300)
  assert !loaded()
  // the disk has room again
  let assert Ok(Nil) = simplifile.set_permissions_octal(dir, 0o700)
  support.wait_until(loaded, 4000)
  ffi.clear_tunable("rejected_retry_seconds")
}

fn audit_actions(dir: String, action: String) -> Int {
  case simplifile.read(dir <> "/audit.jsonl") {
    Ok(content) ->
      string.split(content, "\n")
      |> list.count(string.contains(_, "\"action\":\"" <> action <> "\""))
    Error(_) -> 0
  }
}

fn reloads(dir: String) -> Int {
  audit_actions(dir, "rules.reload")
}

fn reload_failures(dir: String) -> Int {
  audit_actions(dir, "rules.reload_failed")
}

/// Imports and bulk changes based on an older version of the rule set are
/// refused, and nothing is written.
pub fn versioned_set_changes_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let #(_, before) = store.versioned(s)
  let assert Ok(a) = store.create(s, new_rule("/a", "/1"), by: "t")
  let #(_, current) = store.versioned(s)
  assert current != before
  let incoming = [new_rule("/b", "/2")]
  assert store.import_rules_versioned(
      s,
      incoming,
      store.Replace,
      Some(before),
      by: "t",
    )
    == Error(store.Stale(current))
  assert store.bulk_versioned(s, [a.id], store.Disable, Some(before), by: "t")
    == Error(store.Stale(current))
  assert store.all(s) == [a]
  // the preview tells which version it was computed against
  let assert Ok(#(_, previewed)) =
    store.preview_import(s, incoming, store.Replace, by: "t")
  assert previewed == current
  assert store.import_rules_versioned(
      s,
      incoming,
      store.Replace,
      Some(previewed),
      by: "t",
    )
    == Ok(1)
  assert store.bulk_versioned(s, [], store.Disable, Some("*"), by: "t")
    == Error(store.Rejected(["ids: select at least one rule"]))
}

/// Hit counts survive a restart: saved when a stop begins (and every
/// minute), restored by the next start.
pub fn hit_counts_survive_a_restart_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(created) = store.create(s, new_rule("/counted", "/x"), by: "t")
  matcher.record_hit(snapshot.current(), created.id)
  matcher.record_hit(snapshot.current(), created.id)
  support.with_draining(fn() { wait_for_file(dir <> "/hits.json", 30) })
  let assert Ok(saved) = simplifile.read(dir <> "/hits.json")
  assert string.contains(saved, created.id)
  // a fresh start (nothing published yet) restores them
  snapshot.publish(matcher.empty())
  let _ = start(settings(dir, 0))
  assert matcher.hit_count(snapshot.current(), created.id) == 2
  assert matcher.last_hit(snapshot.current(), created.id) > 0
}

/// Hits counted while draining (after the save that starts it) are kept:
/// the SIGTERM handler flushes them right before the node stops.
pub fn hits_counted_while_draining_are_kept_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(created) = store.create(s, new_rule("/drained", "/x"), by: "t")
  matcher.record_hit(snapshot.current(), created.id)
  support.with_draining(fn() {
    wait_for_file(dir <> "/hits.json", 30)
    // served during the grace period
    matcher.record_hit(snapshot.current(), created.id)
    matcher.record_hit(snapshot.current(), created.id)
    store.flush_hits(s)
  })
  snapshot.publish(matcher.empty())
  let _ = start(settings(dir, 0))
  assert matcher.hit_count(snapshot.current(), created.id) == 3
}

fn wait_for_file(path: String, attempts: Int) -> Nil {
  case simplifile.is_file(path), attempts {
    Ok(True), _ -> Nil
    _, 0 -> panic as "file not written in time"
    _, _ -> {
      process.sleep(100)
      wait_for_file(path, attempts - 1)
    }
  }
}

/// Two exact rules for one path may take turns; overlapping windows are
/// refused. The published rules follow `starts_at`/`expires_at` without any
/// change to the file.
pub fn scheduled_rules_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/sale", "/summer"), expires_at: "2000-01-01T00:00:00Z"),
      by: "t",
    )
  let assert Ok(_) =
    store.create(
      s,
      Rule(..new_rule("/sale", "/winter"), starts_at: "2000-01-01T00:00:00Z"),
      by: "t",
    )
  assert redirect("/sale") == Ok("/winter")
  let assert Error([overlap]) =
    store.create(s, new_rule("/sale", "/always"), by: "t")
  assert string.contains(overlap, "at the same time")

  // a rule starting in 2 seconds and expiring in 3
  let now = ffi.now_seconds()
  let assert Ok(_) =
    store.create(
      s,
      Rule(
        ..new_rule("/soon", "/started"),
        starts_at: ffi.rfc3339(now + 2),
        expires_at: ffi.rfc3339(now + 3),
      ),
      by: "t",
    )
  assert redirect("/soon") == Error(Nil)
  support.wait_until(fn() { redirect("/soon") == Ok("/started") }, 4000)
  support.wait_until(fn() { redirect("/soon") == Error(Nil) }, 4000)
}

/// Exact rules for one path with different query conditions are not in
/// conflict; the same conditions in another order are. A rule that sends
/// its own query back to itself is a loop.
pub fn query_rules_conflicts_and_loops_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(_) = store.create(s, new_rule("/q", "/plain"), by: "t")
  let assert Ok(_) =
    store.create(s, Rule(..new_rule("/q", "/a"), query: "a=1&b=2"), by: "t")
  let assert Error([same]) =
    store.create(s, Rule(..new_rule("/q", "/b"), query: "b=2&a=1"), by: "t")
  assert string.contains(same, "at the same time")
  let assert Error([loop]) =
    store.create(s, Rule(..new_rule("/l", "/l?x=1"), query: "x=1"), by: "t")
  assert string.contains(loop, "redirect loop")
  // the target keeps the query that matched: the same request again
  let assert Error([loop]) =
    store.create(
      s,
      Rule(..new_rule("/p", "/p"), query: "x=1", preserve_query: True),
      by: "t",
    )
  assert string.contains(loop, "redirect loop")
  // without it, the query is not asked again
  let assert Ok(_) =
    store.create(s, Rule(..new_rule("/p", "/p"), query: "x=1"), by: "t")
}

@external(erlang, "test_log_ffi", "capture_start")
fn capture_logs() -> Nil

/// Whether a captured message contains `text` within `timeout` ms.
@external(erlang, "test_log_ffi", "capture_until")
fn logged_within(text: String, timeout: Int) -> Bool

/// An update can uncover a loop it is not part of: the old version of the
/// rule shadowed a rule that loops. It is applied, and the loop is logged.
pub fn an_update_warns_about_an_uncovered_loop_test() {
  let dir = support.temp_dir()
  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  // `/a` (exact) shadows the looping prefix rule for `/a`; `/a/x` reaches it
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "{\"version\":1,\"rules\":[{\"id\":\"shadow\",\"source\":\"/a\",\"target\":\"/elsewhere\"},{\"id\":\"p\",\"match\":\"prefix\",\"source\":\"/a\",\"target\":\"/a$1\"}]}",
    )
  let s = start(settings(dir, 0))
  let assert Ok(shadow) = store.get(s, "shadow")
  capture_logs()
  let assert Ok(_) = store.update(s, Rule(..shadow, source: "/b"), by: "t")
  // logged after the change is answered, by the store's checker
  assert logged_within("redirect loop", 5000)
}

/// Unchanged hit counts are not written again (the file is replaced, so its
/// inode changes on every write).
pub fn unchanged_hits_are_not_rewritten_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(created) = store.create(s, new_rule("/idle", "/x"), by: "t")
  matcher.record_hit(snapshot.current(), created.id)
  store.flush_hits(s)
  let path = dir <> "/hits.json"
  let written = ffi.file_stamp(path)
  store.flush_hits(s)
  assert ffi.file_stamp(path) == written
  matcher.record_hit(snapshot.current(), created.id)
  store.flush_hits(s)
  assert ffi.file_stamp(path) != written
}

pub fn filter_by_tag_test() {
  let r = fn(source, tags) {
    Rule(..rule.blank(), id: source, source:, target: "/x", tags:)
  }
  let rules = [
    r("/a", ["campaign"]),
    r("/b", ["campaign", "legacy"]),
    r("/c", []),
  ]
  let ids = fn(f) { store_rules.filter(rules, f) |> list.map(fn(r) { r.id }) }
  let none =
    store_rules.Filter(text: "", host: "", kind: "", enabled: None, tag: "")
  assert ids(store_rules.Filter(..none, tag: "legacy")) == ["/b"]
  assert ids(store_rules.Filter(..none, tag: "Campaign")) == ["/a", "/b"]
  // the text search covers tags too
  assert ids(store_rules.Filter(..none, text: "legac")) == ["/b"]
}

/// Deleting a rule saves the counts at once: a crash before the next save
/// must not restore its count onto a new rule with the same id.
pub fn deleting_a_rule_saves_the_counts_at_once_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(created) =
    store.create(s, Rule(..new_rule("/promo", "/x"), id: "promo"), by: "t")
  matcher.record_hit(snapshot.current(), created.id)
  store.flush_hits(s)
  let assert Ok(saved) = simplifile.read(dir <> "/hits.json")
  assert string.contains(saved, "\"promo\"")
  let assert Ok(_) = store.delete(s, "promo", by: "t")
  let assert Ok(saved) = simplifile.read(dir <> "/hits.json")
  assert !string.contains(saved, "\"promo\"")
}

/// The counts file deleted while the server runs is written again, even
/// when the counts did not change; one that cannot be read is moved aside.
pub fn the_counts_file_is_kept_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let assert Ok(created) = store.create(s, new_rule("/kept", "/x"), by: "t")
  matcher.record_hit(snapshot.current(), created.id)
  store.flush_hits(s)
  let assert Ok(Nil) = simplifile.delete(dir <> "/hits.json")
  store.flush_hits(s)
  assert simplifile.is_file(dir <> "/hits.json") == Ok(True)

  let other = support.temp_dir()
  let assert Ok(Nil) = simplifile.write(other <> "/hits.json", "{ not json")
  snapshot.publish(matcher.empty())
  let _ = start(settings(other, 0))
  let assert Ok(files) = simplifile.read_directory(other)
  assert list.any(files, string.starts_with(_, "hits.json.corrupt-"))
}

/// Two writes of the same size within one second, in place, leave the
/// file's stamp (inode, mtime in seconds, size) as it was: the second one
/// is still picked up, from the content.
pub fn same_second_same_size_edits_are_seen_test() {
  let dir = support.temp_dir()
  let s = store.Settings(..settings(dir, 0), watch_interval: 20)
  let _store = start(s)
  let write = fn(target) {
    let assert Ok(Nil) =
      simplifile.write(
        s.rules_path,
        "[{\"id\": \"w\", \"source\": \"/watched\", \"target\": \""
          <> target
          <> "\"}]",
      )
    Nil
  }
  write("/first")
  support.wait_until(fn() { redirect("/watched") == Ok("/first") }, 2000)
  write("/again")
  support.wait_until(fn() { redirect("/watched") == Ok("/again") }, 2000)
}

/// A change whose caller stopped waiting (it timed out or exited) before the
/// store got to it is not made: the caller was not told it was.
pub fn changes_of_callers_gone_are_not_made_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let lock = dir <> "/redirects.json.lock"
  // the CLI holds the lock: the store waits for it in the first change, and
  // the second one is queued meanwhile
  let assert Ok(Nil) = simplifile.write(lock, "12345 cli@host\n")
  let first = process.new_subject()
  process.spawn(fn() {
    process.send(first, store.create(s, new_rule("/kept", "/t"), by: "first"))
  })
  process.sleep(100)
  let gone =
    process.spawn_unlinked(fn() {
      store.create(s, new_rule("/gone", "/t"), by: "gone")
    })
  process.sleep(100)
  process.kill(gone)
  let assert Ok(Nil) = simplifile.delete(lock)
  let assert Ok(Ok(_)) = process.receive(first, 5000)

  assert list.map(store.all(s), fn(r) { r.source }) == ["/kept"]
  let assert Ok(content) = simplifile.read(dir <> "/redirects.json")
  assert !string.contains(content, "/gone")
  let assert Ok(audit) = simplifile.read(dir <> "/audit.jsonl")
  assert !string.contains(audit, "/gone")
}

/// A change the store started, but whose caller gave up while the store
/// waited for the file lock, is not made either: the caller was told it
/// failed (503), so a retry must not find it made.
pub fn changes_abandoned_while_waiting_for_the_lock_are_not_made_test() {
  let dir = support.temp_dir()
  let s = start(settings(dir, 0))
  let lock = dir <> "/redirects.json.lock"
  let assert Ok(Nil) = simplifile.write(lock, "12345 cli@host\n")
  let gone =
    process.spawn_unlinked(fn() {
      store.create(s, new_rule("/gone", "/t"), by: "gone")
    })
  // the store has taken the change and waits for the lock
  process.sleep(200)
  process.kill(gone)
  let assert Ok(Nil) = simplifile.delete(lock)
  let assert Ok(_) = store.create(s, new_rule("/after", "/t"), by: "after")

  assert list.map(store.all(s), fn(r) { r.source }) == ["/after"]
  let assert Ok(audit) = simplifile.read(dir <> "/audit.jsonl")
  assert !string.contains(audit, "/gone")
}

/// A lock held longer than the stale delay (a long change by the CLI) is kept
/// fresh while it is held: a writer waiting for it does not take it over,
/// and both changes are kept.
pub fn a_lock_held_long_is_not_taken_over_test() {
  let dir = support.temp_dir()
  let path = dir <> "/redirects.json"
  let s = start(settings(dir, 0))
  ffi.set_tunable("stale_lock_seconds", 1)
  let held = process.new_subject()
  process.spawn(fn() {
    let assert Ok(Nil) =
      ffi.with_file_lock(path, 1000, fn() {
        let assert Ok(content) = simplifile.read(path)
        let assert Ok(rules) = rule.file_from_string(content)
        process.send(held, Nil)
        process.sleep(3000)
        let cli = Rule(..new_rule("/cli", "/t"), id: "cli")
        let assert Ok(Nil) =
          simplifile.write(path, rule.file_to_string(list.append(rules, [cli])))
        Nil
      })
    process.send(held, Nil)
  })
  let assert Ok(Nil) = process.receive(held, 1000)
  let created = store.create(s, new_rule("/server", "/t"), by: "server")
  let released = process.receive(held, 5000)
  ffi.clear_tunable("stale_lock_seconds")
  let assert Ok(_) = created
  let assert Ok(Nil) = released

  let assert Ok(content) = simplifile.read(path)
  let assert Ok(on_disk) = rule.file_from_string(content)
  assert list.map(on_disk, fn(r) { r.source }) == ["/cli", "/server"]
}
