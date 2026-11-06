import gleam/int
import gleam/list
import gleam/string
import redirect_proxy/audit
import simplifile
import support

pub fn tail_reads_the_end_of_a_large_log_test() {
  let path = support.temp_dir() <> "/audit.jsonl"
  // over 1 MB of multi-byte entries: only the end is read, and the partial
  // first line (possibly cut inside a UTF-8 sequence) is dropped
  let line = fn(i) {
    "{\"at\":\"t\",\"actor\":\"é"
    <> string.repeat("é", 400)
    <> "\",\"action\":\"a"
    <> int.to_string(i)
    <> "\",\"target\":\"x\"}"
  }
  let content =
    int.range(from: 1, to: 2001, with: [], run: fn(acc, i) { [i, ..acc] })
    |> list.reverse
    |> list.map(line)
    |> string.join("\n")
  let assert Ok(Nil) = simplifile.write(path, content <> "\n")
  let entries = audit.tail(path, 5)
  assert list.map(entries, fn(e) { e.action })
    == ["a2000", "a1999", "a1998", "a1997", "a1996"]
}
