//// Bindings to `redirect_proxy_regex_ffi`: regular expressions run with a
//// backtracking budget (a ReDoS guard), and the count of runs it stopped.

pub type CompiledRegex

pub type RegexError {
  NoMatch
  LimitExceeded
}

@external(erlang, "redirect_proxy_regex_ffi", "regex_compile")
pub fn regex_compile(
  pattern: String,
  case_insensitive: Bool,
) -> Result(CompiledRegex, String)

/// Runs a compiled regex. On success returns every capture, group 0 first.
/// Unset groups are returned as empty strings.
@external(erlang, "redirect_proxy_regex_ffi", "regex_run")
pub fn regex_run(
  regex: CompiledRegex,
  subject: String,
) -> Result(List(String), RegexError)

/// Reductions spent by the calling process so far.
@external(erlang, "redirect_proxy_regex_ffi", "reductions")
pub fn reductions() -> Int

/// Creates the counter of regex runs that exhausted their budget.
@external(erlang, "redirect_proxy_regex_ffi", "regex_limit_init")
pub fn regex_limit_init() -> Nil

/// Counts one regex run stopped by a budget (the
/// `redirect_proxy_regex_limit_exceeded_total` metric).
@external(erlang, "redirect_proxy_regex_ffi", "count_regex_limit")
pub fn count_regex_limit() -> Nil

/// Regex runs that exhausted their budget since boot.
@external(erlang, "redirect_proxy_regex_ffi", "regex_limit_count")
pub fn regex_limit_count() -> Int
