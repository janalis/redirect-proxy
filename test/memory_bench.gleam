//// Memory held by a loaded rule set: 10 000 exact, 1 000 prefix and 500
//// regex rules, loaded from a file by a store. Run with
//// `gleam run -m memory_bench`.

import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import redirect_proxy/ffi/system as system_ffi
import redirect_proxy/id
import redirect_proxy/rule.{type Rule, Rule}
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/commit
import redirect_proxy/store/rules/listing
import simplifile
import support

@external(erlang, "memory_bench_ffi", "flat_words")
fn flat_words(term: a) -> Int

@external(erlang, "memory_bench_ffi", "process_memory")
fn process_memory(pid: process.Pid) -> Int

@external(erlang, "memory_bench_ffi", "total_memory")
fn total_memory() -> Int

@external(erlang, "memory_bench_ffi", "binary_memory")
fn binary_memory() -> Int

@external(erlang, "memory_bench_ffi", "persistent_term_memory")
fn persistent_term_memory() -> Int

@external(erlang, "memory_bench_ffi", "gc_all")
fn gc_all() -> Nil

fn rule(i: Int, kind: rule.MatchKind, source: String, target: String) -> Rule {
  Rule(
    ..rule.blank(),
    id: id.uuid(),
    host: "*",
    kind:,
    source:,
    target:,
    note: case i % 3 {
      0 -> "migrated from the old site"
      _ -> ""
    },
    tags: case i % 2 {
      0 -> ["migration"]
      _ -> []
    },
    created_at: "2026-11-17T10:00:00Z",
    updated_at: "2026-11-17T10:00:00Z",
    updated_by: "admin@example.com",
  )
}

fn rules() -> List(Rule) {
  let n = int.to_string
  list.flatten([
    int.range(1, 10_001, [], list.prepend)
      |> list.map(fn(i) {
        rule(i, rule.Exact, "/exact/" <> n(i), "https://new.test/e/" <> n(i))
      }),
    int.range(1, 1001, [], list.prepend)
      |> list.map(fn(i) {
        rule(
          i,
          rule.Prefix,
          "/prefix/" <> n(i) <> "/",
          "https://new.test/p/" <> n(i) <> "/$1",
        )
      }),
    int.range(1, 501, [], list.prepend)
      |> list.map(fn(i) {
        rule(
          i,
          rule.Regex,
          "^/re/" <> n(i) <> "/(\\d+)$",
          "https://new.test/re/$1",
        )
      }),
  ])
}

pub fn main() -> Nil {
  let dir = support.temp_dir()
  let path = dir <> "/redirects.json"
  let assert Ok(Nil) = simplifile.write(path, listing.export(rules()))
  gc_all()
  let total_before = total_memory()
  let binary_before = binary_memory()
  let pt_before = persistent_term_memory()
  let settings =
    store.Settings(
      rules_path: path,
      backups_dir: dir <> "/backups",
      backups: 10,
      audit_path: dir <> "/audit.jsonl",
      ignore_trailing_slash: False,
      watch_interval: 0,
      hits_path: "",
    )
  let assert Ok(started) = store.start(settings, process.new_name("memory"))
  let assert Ok(#(view, _)) = commit.view(started.data)
  let matcher_words = flat_words(snapshot.current())
  let view_words = flat_words(view)
  let print = fn(label, value) { io.println(label <> ": " <> n(value)) }
  print("rules", list.length(view))
  print("matcher flat words", matcher_words)
  print("ets view flat words", view_words)
  print("persistent_term bytes added", persistent_term_memory() - pt_before)
  print("store actor bytes", process_memory(started.pid))
  gc_all()
  print("erlang:memory(total) added", total_memory() - total_before)
  print("erlang:memory(binary) added", binary_memory() - binary_before)
  // what reading the rules from the table instead of the actor's state
  // would cost each change
  list.each([1, 2, 3], fn(_) {
    let at = system_ffi.monotonic_micros()
    let assert Ok(_) = commit.view(started.data)
    print("ets view read us", system_ffi.monotonic_micros() - at)
  })
}

fn n(i: Int) -> String {
  int.to_string(i)
}
