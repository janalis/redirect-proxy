import gleam/erlang/process
import gleam/list
import gleam/string
import redirect_proxy/matcher
import redirect_proxy/rule.{Rule}
import redirect_proxy/snapshot
import redirect_proxy/store
import simplifile
import support

fn settings(dir: String, backups: Int) -> store.Settings {
  store.Settings(
    rules_path: dir <> "/redirects.json",
    backups_dir: dir <> "/backups",
    backups:,
    audit_path: dir <> "/audit.jsonl",
  )
}

fn start(s: store.Settings) -> store.Store {
  let assert Ok(started) = store.start(s, process.new_name("store_test"))
  started.data
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

pub fn validate_all_reports_rule_numbers_test() {
  let assert Error([error]) =
    store.validate_all([new_rule("/ok", "/x"), new_rule("bad", "/y")])
  assert string.starts_with(error, "rule #2")
}
