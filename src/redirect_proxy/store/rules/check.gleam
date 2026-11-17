//// Checks of the rules a change touches: rules that could never apply as
//// written (lint) and redirect loops, now or when a scheduled rule starts
//// or expires; and the warnings logged for a rule set that loads with them.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import redirect_proxy/ffi
import redirect_proxy/field_error.{type FieldError, FieldError}
import redirect_proxy/log
import redirect_proxy/matcher
import redirect_proxy/matcher/loop as matcher_loop
import redirect_proxy/rule.{type Rule}

/// Refuses a change when a request to the changed rule would be redirected
/// back to it: now (`built`, the matcher of `rules`), or at a later time
/// within its window when the rules in effect change (a rule starts or
/// expires).
pub fn check_loop(
  built: matcher.Matcher,
  rules: List(Rule),
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> Result(Nil, List(FieldError)) {
  follow_loop(built, rules, later(rules), changed, ignore_trailing_slash).0
}

/// What a check knows of the times to come: when the rules in effect
/// change (a rule starts or expires), worked out once, and the matchers
/// of the times it built, kept for the other rules of the change.
type Later {
  Later(
    changes: List(Change),
    matchers: Dict(Int, matcher.Matcher),
    /// Past the matchers kept: one of every rule not expired, schedules
    /// aside (see `follow_loop`), built once.
    beyond: Option(matcher.Matcher),
    /// The last matcher built to confirm a loop found there, by time: the
    /// other rules of the change starting then reuse it.
    confirmed: Option(#(Int, matcher.Matcher)),
  )
}

/// A rule (`id`) starts, or expires, `at` a time to come.
type Change {
  Change(at: Int, id: String, expires: Bool)
}

fn later(rules: List(Rule)) -> Later {
  let now = ffi.now_seconds()
  let changes =
    list.fold(rules, [], fn(acc, r) {
      case r.enabled && { r.starts_at != "" || r.expires_at != "" } {
        False -> acc
        True -> {
          let #(starts, expires) = rule.window(r)
          let acc = case starts > now {
            True -> [Change(starts, r.id, False), ..acc]
            False -> acc
          }
          case expires > now && expires < rule.max_time {
            True -> [Change(expires, r.id, True), ..acc]
            False -> acc
          }
        }
      }
    })
    |> list.sort(fn(a, b) { int.compare(a.at, b.at) })
  Later(changes:, matchers: dict.new(), beyond: None, confirmed: None)
}

/// The most times to come a rule is followed at, the nearest (see
/// `follow_loop`), and the most matchers a check keeps for them, all rules
/// of a change together (each is a matcher of every rule).
const max_times_ahead = 8

const max_matchers_ahead = 32

fn follow_loop(
  built: matcher.Matcher,
  rules: List(Rule),
  later: Later,
  changed: Rule,
  ignore_trailing_slash: Bool,
) -> #(Result(Nil, List(FieldError)), Later) {
  use <- bool.guard(!changed.enabled, #(Ok(Nil), later))
  let found = fn(matcher) {
    matcher_loop.redirect_loop(matcher, changed, ignore_trailing_slash)
  }
  let refused = fn(cycle) {
    Error([FieldError("target", "redirect loop: " <> describe_cycle(cycle))])
  }
  let #(starts, _) = rule.window(changed)
  case found(built) {
    Ok(cycle) -> #(refused(cycle), later)
    Error(Nil) ->
      list.fold_until(
        changes_ahead(later.changes, changed),
        #(Ok(Nil), later),
        fn(acc, at) {
          let #(_, later) = acc
          let follow = fn(matcher, later) {
            case found(matcher) {
              Ok(cycle) -> list.Stop(#(refused(cycle), later))
              Error(Nil) -> list.Continue(#(Ok(Nil), later))
            }
          }
          case dict.get(later.matchers, at) {
            Ok(matcher) -> follow(matcher, later)
            Error(Nil) ->
              case dict.size(later.matchers) < max_matchers_ahead {
                True -> {
                  let matcher = matcher.build_at(rules, at)
                  follow(
                    matcher,
                    Later(
                      ..later,
                      matchers: dict.insert(later.matchers, at, matcher),
                    ),
                  )
                }
                // past them, the start of a rule that starts later is
                // still followed (it can only loop from then): first
                // through one matcher of every rule not expired, schedules
                // aside, built once; a loop found there is confirmed with
                // the rules in effect then (rarely: one matcher each). A
                // rule not in effect then (not started yet, or expired by
                // then) may hide one there, logged when it comes about (the store republishes the rules then,
                // and checks them), as is a loop at another time.
                False if at == starts -> {
                  let beyond = case later.beyond {
                    Some(beyond) -> beyond
                    None -> beyond_matcher(rules)
                  }
                  let later = Later(..later, beyond: Some(beyond))
                  case found(beyond) {
                    // not among the kept ones, which are bounded: only
                    // the last is
                    Ok(_) ->
                      case later.confirmed {
                        Some(#(time, matcher)) if time == at ->
                          follow(matcher, later)
                        _ -> {
                          let matcher = matcher.build_at(rules, at)
                          follow(
                            matcher,
                            Later(..later, confirmed: Some(#(at, matcher))),
                          )
                        }
                      }
                    Error(Nil) -> list.Continue(#(Ok(Nil), later))
                  }
                }
                False -> list.Continue(acc)
              }
          }
        },
      )
  }
}

/// A matcher of the rules not expired, their schedules aside.
fn beyond_matcher(rules: List(Rule)) -> matcher.Matcher {
  let now = ffi.now_seconds()
  rules
  |> list.filter(fn(r) { r.enabled && rule.window(r).1 > now })
  |> list.map(fn(r) { rule.Rule(..r, starts_at: "", expires_at: "") })
  |> matcher.build
}

/// The times to come, within the window of `changed`, at which the rules
/// in effect change: its start, and the starts and expiries of the other
/// rules; the nearest. None, the usual case, when no rule has a schedule.
fn changes_ahead(changes: List(Change), changed: Rule) -> List(Int) {
  let #(from, until) = rule.window(changed)
  changes
  |> list.filter(fn(c) {
    c.at >= from && c.at < until && !{ c.expires && c.id == changed.id }
  })
  |> list.map(fn(c) { c.at })
  |> list.unique
  |> list.take(max_times_ahead)
}

/// Refuses a change to a rule that could never apply as written.
pub fn check_lint(changed: Rule) -> Result(Nil, List(FieldError)) {
  case rule.lint(changed) {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

/// Refuses a change of several rules (`changed`, in the matcher `built`)
/// when one of them could never apply as written or loops, as a change of
/// one rule is. Rules the change leaves alone are not checked: a file that
/// loaded before can still be imported again.
pub fn check_changed(
  built: matcher.Matcher,
  rules: List(Rule),
  changed: List(Rule),
  ignore_trailing_slash: Bool,
) -> Result(Nil, List(FieldError)) {
  let #(errors, _) =
    list.fold(changed, #([], later(rules)), fn(acc, r) {
      let #(errors, later) = acc
      let #(loop, later) =
        follow_loop(built, rules, later, r, ignore_trailing_slash)
      let loop = case loop {
        Ok(Nil) -> []
        Error(errors) -> errors
      }
      let found =
        list.append(rule.lint(r), loop)
        |> list.map(field_error.about(
          _,
          "rule " <> r.id <> " (" <> r.host <> r.source <> ")",
        ))
      #([found, ..errors], later)
    })
  let errors = list.reverse(errors) |> list.flatten
  case errors {
    [] -> Ok(Nil)
    _ -> Error(errors)
  }
}

/// Logs the redirect loops of a rule set, each cycle once, and the rules that
/// can never apply (loading never fails on them, so that a file that loaded
/// before keeps loading).
pub fn warn_problems(
  built: matcher.Matcher,
  rules: List(Rule),
  ignore_trailing_slash: Bool,
) -> matcher.Matcher {
  list.each(rules, fn(r) {
    list.each(rule.lint(r), fn(problem) {
      log.warning(
        "rule "
        <> r.id
        <> " ("
        <> r.host
        <> r.source
        <> "): "
        <> field_error.to_string(problem),
      )
    })
  })
  warn_loops(built, rules, ignore_trailing_slash)
}

/// Logs the redirect loops of a rule set, each cycle once: for changes that
/// may uncover a loop without being part of it (a rule that no longer
/// shadows another, a scheduled rule starting or expiring).
pub fn warn_loops(
  built: matcher.Matcher,
  rules: List(Rule),
  ignore_trailing_slash: Bool,
) -> matcher.Matcher {
  let _ =
    rules
    |> list.filter(fn(r) { r.enabled })
    |> list.fold(set.new(), fn(reported, r) {
      case matcher_loop.redirect_loop(built, r, ignore_trailing_slash) {
        Error(Nil) -> reported
        Ok(cycle) -> {
          let key =
            cycle
            |> list.map(fn(r) { r.id })
            |> list.unique
            |> list.sort(string.compare)
          case set.contains(reported, key) {
            True -> reported
            False -> {
              log.warning("redirect loop: " <> describe_cycle(cycle))
              set.insert(reported, key)
            }
          }
        }
      }
    })
  built
}

fn describe_cycle(cycle: List(Rule)) -> String {
  cycle
  |> list.map(fn(r) { r.host <> r.source })
  |> string.join(" -> ")
}
