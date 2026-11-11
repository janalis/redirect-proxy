//// Committing a rule set: checking it, writing the redirections file, then
//// publishing the compiled matcher. Used by the store actor only.

import gleam/list
import gleam/option.{type Option, Some}
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

/// The rules in effect and their version (the fingerprint of the file), by
/// file path, and the file path of each store (by its subject). Reads take
/// them from here (`view`), so that they do not wait for a change in
/// progress (file lock, matcher build, fsyncs, audit); a restarted store
/// resumes from them when the file has become invalid (`last_good`). Set
/// just before the matcher is published, so that a reader that gets the
/// new redirects, or a caller whose change returned, gets the new rules too.
/// One copy of the rules: copying them into the table is most of what it
/// costs a change.
const rules_table = "redirect_proxy_store_last_good"

/// Creates the table of the rules in effect. Called by the process starting
/// the store (the supervisor), so that it outlives the store process.
pub fn init() -> Nil {
  ffi.ets_new(rules_table)
}

/// Says that `store` serves the rules of `rules_path`.
pub fn register(store: store, rules_path: String) -> Nil {
  ffi.ets_put(rules_table, store, rules_path)
}

/// Sets the rules in effect at `rules_path` and their version.
pub fn set_view(rules_path: String, rules: List(Rule), version: String) -> Nil {
  ffi.ets_put(rules_table, rules_path, #(rules, version))
}

/// The rules in effect for `store` and their version, once it has started.
pub fn view(store: store) -> Result(#(List(Rule), String), Nil) {
  use rules_path <- result.try(ffi.ets_find(rules_table, store))
  ffi.ets_find(rules_table, rules_path)
}

/// The rules last published from the file at `rules_path`.
pub fn last_good(rules_path: String) -> Result(List(Rule), Nil) {
  ffi.ets_find(rules_table, rules_path)
  |> result.map(fn(view: #(List(Rule), String)) { view.0 })
}

/// Publishes `built`, the matcher of `rules`, keeping the hit counts.
pub fn publish(
  target: Target,
  built: matcher.Matcher,
  rules: List(Rule),
  version: String,
) -> Nil {
  set_view(target.files.rules_path, rules, version)
  built
  |> matcher.carry_hits(from: snapshot.current())
  |> snapshot.publish
  // Building and parsing leave a lot of garbage in this long lived process.
  ffi.garbage_collect()
}

/// Publishes rules loaded from the file, then has them checked.
/// `version` is the fingerprint of the file they were loaded from.
pub fn loaded(
  target: Target,
  rules: List(Rule),
  version: String,
  check: checker.Check,
) -> Nil {
  publish(target, matcher.build(rules), rules, version)
  checker.request(target.files.rules_path, check)
}

/// Checks then commits a change of one rule (`changed`, in `rules`, the
/// new version of `previous`): it must be able to apply (see
/// `check_lint_change`), conflict with no other rule and not loop. With
/// `uncovers`, loops the change uncovers elsewhere are logged (an updated
/// rule may no longer shadow one that loops). Returns the fingerprint of the
/// file.
pub fn one(
  target: Target,
  changed: Rule,
  previous: Option(Rule),
  rules: List(Rule),
  uncovers uncovers: Bool,
) -> Result(String, List(String)) {
  use Nil <- result.try(check_lint_change(changed, previous))
  use Nil <- result.try(check_conflicts(rules))
  let built = matcher.build(rules)
  use Nil <- result.try(check_loop(
    built,
    rules,
    changed,
    target.ignore_trailing_slash,
  ))
  use fingerprint <- result.try(write(target, rules, built))
  case uncovers {
    True -> checker.request(target.files.rules_path, checker.Loops)
    False -> Nil
  }
  Ok(fingerprint)
}

/// A new rule must be able to apply. A changed one may keep the problems
/// it loaded with while it stays disabled, or enabled (a note, a tag, or
/// disabling it, as in bulk), but neither gain one nor be enabled with one.
fn check_lint_change(changed: Rule, previous: Option(Rule)) {
  case previous {
    Some(previous) if !changed.enabled || previous.enabled -> {
      let before = rule.lint(previous)
      case
        list.filter(rule.lint(changed), fn(p) { !list.contains(before, p) })
      {
        [] -> Ok(Nil)
        added -> Error(added)
      }
    }
    _ -> check_lint(changed)
  }
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
    rules,
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
      publish(target, built, rules, fingerprint)
      Ok(fingerprint)
    }
    Error(reason) -> {
      metrics.incr(metrics.StorageWriteFailures)
      log.error("failed to persist redirections: " <> reason)
      Error(["storage: " <> reason])
    }
  }
}
