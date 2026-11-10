//// Committing a rule set: checking it, writing the redirections file, then
//// publishing the compiled matcher. Used by the store actor only.

import gleam/result
import redirect_proxy/ffi
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/metrics
import redirect_proxy/rule.{type Rule}
import redirect_proxy/snapshot
import redirect_proxy/store/checker
import redirect_proxy/store/file as store_file
import redirect_proxy/store/rules.{
  check_changed, check_conflicts, check_lint, check_loop,
}

/// Where a store writes and how it follows loops.
pub type Target {
  Target(files: store_file.Files, ignore_trailing_slash: Bool)
}

/// The last rules published, by file path: what a restarted store resumes
/// from when the file has become invalid.
const last_good_table = "redirect_proxy_store_last_good"

/// Creates the table of the last good rules. Called by the process starting
/// the store (the supervisor), so that it outlives the store process.
pub fn init() -> Nil {
  ffi.ets_new(last_good_table)
}

/// The rules last published from the file at `rules_path`.
pub fn last_good(rules_path: String) -> Result(List(Rule), Nil) {
  ffi.ets_get(last_good_table, rules_path)
}

/// Publishes `built`, the matcher of `rules`, keeping the hit counts.
pub fn publish(
  target: Target,
  built: matcher.Matcher,
  rules: List(Rule),
) -> Nil {
  ffi.ets_put(last_good_table, target.files.rules_path, rules)
  built
  |> matcher.carry_hits(from: snapshot.current())
  |> snapshot.publish
  // Building and parsing leave a lot of garbage in this long lived process.
  ffi.garbage_collect()
}

/// Publishes rules loaded from the file, then has them checked.
pub fn loaded(target: Target, rules: List(Rule), check: checker.Check) -> Nil {
  publish(target, matcher.build(rules), rules)
  checker.request(target.files.rules_path, check)
}

/// Checks then commits a change of one rule (`changed`, in `rules`): it
/// must be able to apply, conflict with no other rule and not loop. With
/// `uncovers`, loops the change uncovers elsewhere are logged (an updated
/// rule may no longer shadow one that loops). Returns the fingerprint of the
/// file.
pub fn one(
  target: Target,
  changed: Rule,
  rules: List(Rule),
  uncovers uncovers: Bool,
) -> Result(String, List(String)) {
  use Nil <- result.try(check_lint(changed))
  use Nil <- result.try(check_conflicts(rules))
  let built = matcher.build(rules)
  use Nil <- result.try(check_loop(built, changed, target.ignore_trailing_slash))
  use fingerprint <- result.try(write(target, rules, built))
  case uncovers {
    True -> checker.request(target.files.rules_path, checker.Loops)
    False -> Nil
  }
  Ok(fingerprint)
}

/// Commits a change of a set of rules (bulk, import, delete), checking
/// conflicts when the change can add some, and that none of the `changed`
/// rules can never apply or loops. Problems of the other rules (left by a
/// file that loaded with them) are logged.
pub fn many(
  target: Target,
  rules: List(Rule),
  changed changed: List(Rule),
  check_conflicts check: Bool,
) -> Result(String, List(String)) {
  use Nil <- result.try(case check {
    True -> check_conflicts(rules)
    False -> Ok(Nil)
  })
  let built = matcher.build(rules)
  use Nil <- result.try(check_changed(
    built,
    changed,
    target.ignore_trailing_slash,
  ))
  use fingerprint <- result.try(write(target, rules, built))
  checker.request(target.files.rules_path, checker.Problems)
  Ok(fingerprint)
}

/// Writes then publishes the rules (`built` is their matcher).
fn write(
  target: Target,
  rules: List(Rule),
  built: matcher.Matcher,
) -> Result(String, List(String)) {
  case store_file.persist(target.files, rules) {
    Ok(fingerprint) -> {
      publish(target, built, rules)
      Ok(fingerprint)
    }
    Error(reason) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("failed to persist redirections: " <> reason)
      Error(["storage: " <> reason])
    }
  }
}
