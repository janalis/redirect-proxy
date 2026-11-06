//// Matcher microbenchmark: the work of one redirect (lookup, hit count,
//// `Location`) in BEAM reductions, for request shapes the load test does
//// not cover (many prefix lengths, unindexed regexes, wildcard hosts, query
//// conditions, trailing slash retries). Reductions do not depend on the
//// load of the machine, so CI compares them with a baseline
//// (`scripts/matcher-bench.py`, `make bench-matcher`).
////
//// Run with `gleam run -m matcher_bench`: prints one JSON object.

import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/matcher
import redirect_proxy/rule.{type MatchKind, type Rule, Exact, Prefix, Regex}

/// Requests per scenario: reductions per request are an average.
const requests = 10_000

@external(erlang, "matcher_bench_ffi", "reductions")
fn reductions(f: fn() -> a) -> Int

fn seq(from: Int, to: Int) -> List(Int) {
  int.range(from, to + 1, [], list.prepend) |> list.reverse
}

fn new_rule(
  id: Int,
  host: String,
  kind: MatchKind,
  source: String,
  target: String,
) -> Rule {
  rule.Rule(
    ..rule.blank(),
    id: "rule-" <> int.to_string(id),
    host:,
    kind:,
    source:,
    target:,
  )
}

/// 10 000 exact rules, 1 000 prefix rules of 40 lengths, 300 regex rules
/// anchored on a literal, 50 that are not, rules on 200 hosts and
/// wildcard hosts, and exact rules with query conditions.
fn rules() -> List(Rule) {
  let n = int.to_string
  list.flatten([
    seq(1, 10_000)
      |> list.map(fn(i) {
        new_rule(
          i,
          "*",
          Exact,
          "/exact/" <> n(i),
          "https://new.test/e/" <> n(i),
        )
      }),
    seq(1, 1000)
      |> list.map(fn(i) {
        let source =
          "/p" <> n(i % 40) <> string.repeat("x", i % 40) <> "/" <> n(i) <> "/"
        new_rule(20_000 + i, "*", Prefix, source, "https://new.test/p/$1")
      }),
    seq(1, 300)
      |> list.map(fn(i) {
        let source = "^/re/" <> n(i) <> "/(\\d+)$"
        new_rule(30_000 + i, "*", Regex, source, "https://new.test/re/$1")
      }),
    seq(1, 50)
      |> list.map(fn(i) {
        let source = "/legacy-" <> n(i) <> "-(\\d+)\\.html$"
        new_rule(40_000 + i, "*", Regex, source, "https://new.test/l/$1")
      }),
    seq(1, 200)
      |> list.map(fn(i) {
        let host = "site" <> n(i) <> ".test"
        new_rule(50_000 + i, host, Exact, "/", "https://new.test/s/" <> n(i))
      }),
    seq(1, 20)
      |> list.map(fn(i) {
        let host = "*.zone" <> n(i) <> ".test"
        new_rule(60_000 + i, host, Prefix, "/", "https://${sub}.new.test/$1")
      }),
    seq(1, 100)
      |> list.map(fn(i) {
        rule.Rule(
          ..new_rule(
            70_000 + i,
            "*",
            Exact,
            "/q",
            "https://new.test/q/" <> n(i),
          ),
          query: "id=" <> n(i),
        )
      }),
  ])
}

pub fn main() -> Nil {
  let rules = rules()
  let started = ffi.monotonic_micros()
  let m = matcher.build(rules)
  let build_ms = { ffi.monotonic_micros() - started } / 1000
  let request = fn(tolerant, host, path, query) {
    fn() {
      let found = case tolerant {
        True -> matcher.lookup_tolerant_query(m, host, path, query)
        False -> matcher.lookup_query(m, host, path, query)
      }
      case found {
        Ok(found) -> {
          matcher.record_hit(m, found.rule.id)
          let _ = matcher.location(found, Ok(query))
          Nil
        }
        Error(Nil) -> Nil
      }
    }
  }
  let scenarios = [
    #("exact_hit", request(False, "www.test", "/exact/5000", "")),
    #("exact_miss", request(False, "www.test", "/exact/none", "")),
    #(
      "prefix_hit",
      request(False, "www.test", "/p7xxxxxxx/7/some/deep/path", ""),
    ),
    #("regex_indexed_hit", request(False, "www.test", "/re/150/42", "")),
    #(
      "regex_unindexed_last",
      request(False, "www.test", "/old/legacy-50-42.html", ""),
    ),
    #("host_hit", request(False, "site150.test", "/", "")),
    #("wildcard_hit", request(False, "a.b.zone7.test", "/x/y", "")),
    #("query_hit", request(False, "www.test", "/q", "id=90&utm=x")),
    #("miss", request(False, "www.test", "/nothing/here/at/all", "")),
    #("tolerant_miss", request(True, "www.test", "/nothing/here/at/all/", "")),
  ]
  let results =
    list.map(scenarios, fn(scenario) {
      let #(name, run) = scenario
      let total =
        reductions(fn() { int.range(0, requests, Nil, fn(_, _) { run() }) })
      #(name, json.int(total / requests))
    })
  json.object([
    #("rules", json.int(list.length(rules))),
    #("build_ms", json.int(build_ms)),
    #("reductions_per_request", json.object(results)),
  ])
  |> json.to_string
  |> io.println
}
