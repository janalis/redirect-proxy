//// What one change costs with a large rule set: loading the file, then
//// creating, updating and deleting a rule (each one checks, rebuilds,
//// writes and publishes every rule). Run with `make bench-store`; the
//// first run of each step includes loading code, so they run twice.

import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import redirect_proxy/ffi
import redirect_proxy/rule.{type Rule, Rule}
import redirect_proxy/store
import simplifile
import support

const rule_count = 50_000

fn rules() -> List(Rule) {
  int.range(1, rule_count + 1, [], list.prepend)
  |> list.map(fn(i) {
    let n = int.to_string(i)
    let #(kind, source) = case i % 10 {
      0 -> #(rule.Prefix, "/p/" <> n <> "/")
      _ -> #(rule.Exact, "/p/" <> n)
    }
    Rule(
      ..rule.blank(),
      id: "r" <> n,
      host: "h" <> int.to_string(i % 200) <> ".test",
      kind:,
      source:,
      target: "/t/" <> n,
    )
  })
}

fn time(label: String, f: fn() -> a) -> a {
  let started = ffi.monotonic_micros()
  let result = f()
  let ms = { ffi.monotonic_micros() - started } / 1000
  io.println(label <> ": " <> int.to_string(ms) <> " ms")
  result
}

pub fn main() -> Nil {
  io.println(int.to_string(rule_count) <> " rules")
  let dir = support.temp_dir()
  let path = dir <> "/redirects.json"
  let assert Ok(Nil) = simplifile.write(path, rule.file_to_string(rules()))
  let settings =
    store.Settings(
      rules_path: path,
      backups_dir: dir <> "/backups",
      backups: 10,
      audit_path: dir <> "/audit.jsonl",
      ignore_trailing_slash: False,
      watch_interval: 0,
      hits_path: dir <> "/hits.json",
    )
  let assert Ok(started) =
    time("load", fn() { store.start(settings, process.new_name("bench")) })
  let s = started.data
  list.each([1, 2], fn(i) {
    let n = int.to_string(i)
    let assert Ok(created) =
      time("create", fn() {
        store.create(
          s,
          Rule(
            ..rule.blank(),
            host: "new.test",
            source: "/new/" <> n,
            target: "/x",
          ),
          by: "bench",
        )
      })
    let assert Ok(_) =
      time("update", fn() {
        store.update(s, Rule(..created, target: "/changed"), by: "bench")
      })
    let assert Ok(_) =
      time("delete", fn() { store.delete(s, created.id, by: "bench") })
  })
}
