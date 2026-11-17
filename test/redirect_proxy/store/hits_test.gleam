import gleam/erlang/process
import gleam/list
import gleam/string
import redirect_proxy/matcher
import redirect_proxy/rule
import redirect_proxy/snapshot
import redirect_proxy/store
import redirect_proxy/store/hits
import simplifile
import support

fn saved_rule(id: String) -> rule.Rule {
  rule.Rule(..rule.blank(), id:, source: "/" <> id, target: "/new")
}

pub fn invalid_hit_integers_quarantine_without_partial_seeding_test() {
  list.each(
    [
      "\"count\":-1,\"last\":1",
      "\"count\":9223372036854775808,\"last\":1",
      "\"count\":1267650600228229401496703205376,\"last\":1",
      "\"count\":1,\"last\":-1",
      "\"count\":1,\"last\":9223372036854775808",
      "\"count\":1,\"last\":1267650600228229401496703205376",
    ],
    fn(invalid) {
      let dir = support.temp_dir()
      let path = dir <> "/hits.json"
      let built = matcher.build([saved_rule("valid"), saved_rule("invalid")])
      snapshot.publish(built)
      let content =
        "{\"version\":1,\"hits\":{\"valid\":{\"count\":7,\"last\":10},\"invalid\":{"
        <> invalid
        <> "}}}"
      let assert Ok(Nil) = simplifile.write(path, content)
      hits.load(path)
      assert matcher.hit_count(built, "valid") == 0
      assert matcher.last_hit(built, "valid") == 0
      assert matcher.hit_count(built, "invalid") == 0
      assert matcher.last_hit(built, "invalid") == 0
      assert simplifile.is_file(path) == Ok(False)
      let assert Ok(files) = simplifile.read_directory(dir)
      let assert [aside] = files
      assert string.starts_with(aside, "hits.json.corrupt-")
      assert simplifile.read(dir <> "/" <> aside) == Ok(content)
    },
  )
}

pub fn saved_hit_integer_boundaries_and_missing_last_test() {
  let path = support.temp_dir() <> "/hits.json"
  let built =
    matcher.build([saved_rule("zero"), saved_rule("max"), saved_rule("old")])
  snapshot.publish(built)
  let assert Ok(Nil) =
    simplifile.write(
      path,
      "{\"hits\":{\"zero\":{\"count\":0,\"last\":0},\"max\":{\"count\":9223372036854775807,\"last\":9223372036854775807},\"old\":{\"count\":1}}}",
    )
  hits.load(path)
  assert matcher.hit_count(built, "zero") == 0
  assert matcher.last_hit(built, "zero") == 0
  assert matcher.hit_count(built, "max") == 9_223_372_036_854_775_807
  assert matcher.last_hit(built, "max") == 9_223_372_036_854_775_807
  assert matcher.hit_count(built, "old") == 1
  assert matcher.last_hit(built, "old") == 0
  assert simplifile.is_file(path) == Ok(True)
}

pub fn store_starts_with_out_of_range_saved_hits_test() {
  let dir = support.temp_dir()
  let rules = [saved_rule("invalid")]
  let assert Ok(Nil) =
    simplifile.write(dir <> "/redirects.json", rule.file_to_string(rules))
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/hits.json",
      "{\"hits\":{\"invalid\":{\"count\":1267650600228229401496703205376}}}",
    )
  snapshot.publish(matcher.empty())
  let settings =
    store.Settings(
      rules_path: dir <> "/redirects.json",
      backups_dir: dir <> "/backups",
      backups: 0,
      audit_path: dir <> "/audit.jsonl",
      ignore_trailing_slash: False,
      watch_interval: 0,
      hits_path: dir <> "/hits.json",
    )
  let assert Ok(started) =
    store.start(settings, process.new_name("hits_recovery"))
  assert list.length(store.all(started.data)) == 1
  assert matcher.hit_count(snapshot.current(), "invalid") == 0
  assert simplifile.is_file(dir <> "/hits.json") == Ok(False)
  process.unlink(started.pid)
  process.kill(started.pid)
}
