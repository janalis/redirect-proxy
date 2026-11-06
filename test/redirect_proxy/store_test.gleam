import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/string
import redirect_proxy/audit
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
