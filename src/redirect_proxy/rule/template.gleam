//// Target templates (`$1`, `${host}`, `${sub}`...) and the guard that keeps
//// their substitutions on the host the template allows (no open
//// redirect through a capture).

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import redirect_proxy/ffi

/// What a request gives to `${host}` and `${sub}` in targets.
pub type RequestVars {
  RequestVars(
    /// The request host: lower case, without port ("" when not a valid
    /// host name, so that a target using it never redirects).
    host: String,
    /// The part of the request host matched by the `*` of a wildcard rule
    /// host (`a.b` for `a.b.example.com` and `*.example.com`), else "".
    sub: String,
  )
}

pub const no_vars = RequestVars(host: "", sub: "")

/// Expands `$0`..`$9`, `${n}` and `$$` in a target template using captures.
pub fn expand(template: String, captures: List(String)) -> String {
  do_expand(template, captures, [], "")
}

/// `expand`, with `${host}` and `${sub}` from the request too.
pub fn expand_with(
  template: String,
  captures: List(String),
  vars: RequestVars,
) -> String {
  do_expand(template, captures, [#("host", vars.host), #("sub", vars.sub)], "")
}

fn do_expand(
  rest: String,
  captures: List(String),
  named: List(#(String, String)),
  acc: String,
) -> String {
  let do_expand = fn(rest, acc) { do_expand(rest, captures, named, acc) }
  case string.split_once(rest, "$") {
    Error(Nil) -> acc <> rest
    Ok(#(before, after)) -> {
      let acc = acc <> before
      case string.pop_grapheme(after) {
        Ok(#("$", tail)) -> do_expand(tail, acc <> "$")
        Ok(#("{", tail)) ->
          case string.split_once(tail, "}") {
            Ok(#(name, tail2)) ->
              case int.parse(name), list.key_find(named, name) {
                Ok(n), _ if n >= 0 ->
                  do_expand(tail2, acc <> capture(captures, n))
                _, Ok(value) -> do_expand(tail2, acc <> value)
                _, _ -> do_expand(tail, acc <> "${")
              }
            Error(_) -> do_expand(tail, acc <> "${")
          }
        Ok(#(c, tail)) ->
          case int.parse(c) {
            Ok(n) -> do_expand(tail, acc <> capture(captures, n))
            Error(_) -> do_expand(after, acc <> "$")
          }
        Error(Nil) -> acc <> "$"
      }
    }
  }
}

/// A target template parsed once (when the matcher is built), so that a
/// redirect does not parse it again: the same result as `expand_with`.
pub opaque type Template {
  Template(parts: List(Part))
}

type Part {
  Literal(String)
  Capture(Int)
  RequestHostPart
  SubPart
}

/// Parses a target template, the way `expand_with` reads it.
pub fn compile_template(template: String) -> Template {
  Template(compile_parts(template, []) |> merge_literals([]))
}

fn compile_parts(rest: String, parts: List(Part)) -> List(Part) {
  case string.split_once(rest, "$") {
    Error(Nil) -> list.reverse([Literal(rest), ..parts])
    Ok(#(before, after)) -> {
      let parts = [Literal(before), ..parts]
      case string.pop_grapheme(after) {
        Ok(#("$", tail)) -> compile_parts(tail, [Literal("$"), ..parts])
        Ok(#("{", tail)) ->
          case string.split_once(tail, "}") {
            Ok(#(name, tail2)) ->
              case int.parse(name), name {
                Ok(n), _ if n >= 0 -> compile_parts(tail2, [Capture(n), ..parts])
                _, "host" -> compile_parts(tail2, [RequestHostPart, ..parts])
                _, "sub" -> compile_parts(tail2, [SubPart, ..parts])
                _, _ -> compile_parts(tail, [Literal("${"), ..parts])
              }
            Error(_) -> compile_parts(tail, [Literal("${"), ..parts])
          }
        Ok(#(c, tail)) ->
          case int.parse(c) {
            Ok(n) -> compile_parts(tail, [Capture(n), ..parts])
            Error(_) -> compile_parts(after, [Literal("$"), ..parts])
          }
        Error(Nil) -> list.reverse([Literal("$"), ..parts])
      }
    }
  }
}

/// Joins neighbouring literals and drops empty ones.
fn merge_literals(parts: List(Part), merged: List(Part)) -> List(Part) {
  case parts, merged {
    [], _ -> list.reverse(merged)
    [Literal(""), ..rest], _ -> merge_literals(rest, merged)
    [Literal(a), ..rest], [Literal(b), ..done] ->
      merge_literals(rest, [Literal(b <> a), ..done])
    [part, ..rest], _ -> merge_literals(rest, [part, ..merged])
  }
}

/// `expand_with` for a compiled template.
pub fn expand_template(
  template: Template,
  captures: List(String),
  vars: RequestVars,
) -> String {
  case template.parts {
    // no placeholder: nothing to build
    [] -> ""
    [Literal(text)] -> text
    parts ->
      list.fold(parts, "", fn(acc, part) {
        case part {
          Literal(text) -> acc <> text
          Capture(n) -> acc <> capture(captures, n)
          RequestHostPart -> acc <> vars.host
          SubPart -> acc <> vars.sub
        }
      })
  }
}

fn capture(captures: List(String), index: Int) -> String {
  captures
  |> list.drop(index)
  |> list.first
  |> result.unwrap("")
}

// --- substitution guard ---------------------------------------------------------

/// What a target template allows its substitutions to produce. Captures come
/// from the request path, so without a guard `/old/(.*)` -> `/$1` would send
/// `/old//evil.com` to `//evil.com`, and `https://example.com$1` would send
/// `/go.evil.com` or `/go@evil.com` to another host (open redirects).
pub type TargetGuard {
  /// No placeholder: the target is used as is.
  Static
  /// A path on the same host: leading `/` and `\` runs are collapsed to one
  /// `/`, so the result never becomes protocol-relative.
  SameHostPath
  /// The result must keep this host (`example.com`, with its port if any).
  FixedHost(String)
  /// This host, which the literal text before the first placeholder holds
  /// whole, up to the `/`, `\`, `?` or `#` that ends it
  /// (`https://example.com/$1`): no substitution can change it, so the
  /// result is not parsed again.
  LiteralHost(String)
  /// `https://${host}/...`: the result must keep the request's host.
  RequestHost
  /// The result must stay a host ending with this suffix (`.example.com`),
  /// for templates such as `https://$1.example.com/`.
  SubdomainOf(String)
  /// Placeholders inside the host in another shape: never redirect.
  Unsafe
}

pub fn target_guard(template: String) -> TargetGuard {
  case string.contains(template, "$") {
    False -> Static
    True ->
      case authority(template) {
        Error(Nil) -> SameHostPath
        // `${host}`, then only placeholders (`https://${host}$1`): the
        // result is checked to keep the request's host
        Ok("${host}" <> rest) if rest == "" -> RequestHost
        Ok("${host}" <> rest) ->
          case expand(rest, []) {
            "" -> RequestHost
            _ -> Unsafe
          }
        Ok(host) ->
          case string.split_once(host, "$") {
            Error(Nil) ->
              case literal_authority(template) {
                True -> LiteralHost(host)
                False -> FixedHost(host)
              }
            Ok(#(literal, from_placeholder)) ->
              case expand("$" <> from_placeholder, []) {
                // only placeholders after the literal (`example.com$1`): they
                // must not extend the host
                "" if literal != "" -> FixedHost(literal)
                // `https://$1/`: the host is only placeholders
                "" -> Unsafe
                // `$1.example.com`: the host starts with the placeholders
                _ if literal == "" -> subdomain_guard(host)
                _ -> Unsafe
              }
          }
      }
  }
}

/// Whether the text before the first `$` of an absolute or protocol-relative
/// URL template ends its authority: after the scheme and slashes, it holds a
/// `/`, `\`, `?` or `#` (the host is then complete before any placeholder).
fn literal_authority(template: String) -> Bool {
  let literal = case string.split_once(template, "$") {
    Ok(#(literal, _)) -> literal
    Error(Nil) -> template
  }
  case authority_start(literal) {
    // a terminator itself, not a change by url_host, which also drops
    // user info (`https://a@b$1@example.com/` has no fixed host)
    Ok(after) -> {
      let rest = drop_slashes(ffi.byte_drop(literal, after))
      list.any(["/", "\\", "?", "#"], string.contains(rest, _))
    }
    Error(Nil) -> False
  }
}

/// `$1.example.com`: placeholders, then a literal domain starting with `.`
/// of at least two labels (`$1.com` would allow any `.com` domain).
fn subdomain_guard(host: String) -> TargetGuard {
  let suffix = case list.last(string.split(host, "$")) {
    // drop the digits or `{n}` of the last placeholder
    Ok(last) ->
      case string.pop_grapheme(last) {
        Ok(#("{", rest)) ->
          string.split_once(rest, "}") |> result.map(fn(p) { p.1 })
        _ -> Ok(drop_digits(last))
      }
    Error(Nil) -> Error(Nil)
  }
  case suffix {
    Ok(suffix) -> {
      let labels = string.split(suffix, ".") |> list.drop(1)
      case
        string.starts_with(suffix, ".")
        && list.length(labels) >= 2
        && !list.contains(labels, "")
      {
        True -> SubdomainOf(suffix)
        False -> Unsafe
      }
    }
    Error(Nil) -> Unsafe
  }
}

fn drop_digits(text: String) -> String {
  case string.pop_grapheme(text) {
    Ok(#(c, rest)) ->
      case int.parse(c) {
        Ok(_) -> drop_digits(rest)
        Error(_) -> text
      }
    Error(Nil) -> text
  }
}

/// Checks an expanded location against the guard of its template. Returns
/// the location to send, or `Error(Nil)` when it would leave the allowed
/// host. Tabs and line breaks, which browsers ignore in URLs, are removed.
pub fn guard_location(
  guard: TargetGuard,
  location: String,
  vars: RequestVars,
) -> Result(String, Nil) {
  case guard {
    Static -> Ok(location)
    Unsafe -> Error(Nil)
    RequestHost -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) if host == vars.host && host != "" -> Ok(location)
        _ -> Error(Nil)
      }
    }
    SameHostPath -> {
      let location = strip_url_whitespace(location)
      // byte patterns: `/` and `\` are ASCII; the usual location, one `/`
      // then a path, is returned as it is
      case location {
        "/" <> rest ->
          case rest {
            "/" <> _ | "\\" <> _ -> Ok("/" <> drop_slashes(rest))
            _ -> Ok(location)
          }
        "\\" <> rest -> Ok("/" <> drop_slashes(rest))
        _ -> Ok(location)
      }
    }
    LiteralHost(_) -> Ok(strip_url_whitespace(location))
    FixedHost(expected) -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) if host == expected -> Ok(location)
        _ -> Error(Nil)
      }
    }
    SubdomainOf(suffix) -> {
      let location = strip_url_whitespace(location)
      case authority(location) {
        Ok(host) ->
          case string.ends_with(host, suffix) {
            True -> {
              let sub = string.drop_end(host, string.length(suffix))
              case ffi.is_host_name(sub) {
                True -> Ok(location)
                False -> Error(Nil)
              }
            }
            False -> Error(Nil)
          }
        Error(Nil) -> Error(Nil)
      }
    }
  }
}

fn drop_slashes(text: String) -> String {
  case text {
    "/" <> rest | "\\" <> rest -> drop_slashes(rest)
    _ -> text
  }
}

fn strip_url_whitespace(url: String) -> String {
  ffi.strip_url_whitespace(url)
}

/// The host (with port, without user info), lower-cased, of an absolute or
/// protocol-relative URL, parsed the way browsers do for http(s): `\` counts
/// as `/` and extra slashes after the scheme are ignored. `Error(Nil)` for a
/// path.
fn authority(url: String) -> Result(String, Nil) {
  // only the scheme is lowered here (ASCII): the host is lowered below,
  // with Unicode case mapping if it is not ASCII (`ffi.lowercase_host`)
  use after <- result.map(authority_start(url))
  let rest = ffi.byte_drop(url, after)
  rest |> drop_slashes |> ffi.url_host |> ffi.lowercase_host
}

/// Where the authority of an absolute (http, https) or protocol-relative
/// URL starts, in bytes (before extra slashes); `Error(Nil)` for a path.
fn authority_start(url: String) -> Result(Int, Nil) {
  // only the scheme is lowered here (ASCII)
  case ffi.lowercase_ascii(ffi.byte_take(url, 8)) {
    "http://" <> _ | "http:\\\\" <> _ -> Ok(7)
    "https://" <> _ | "https:\\\\" <> _ -> Ok(8)
    "//" <> _ | "/\\" <> _ | "\\/" <> _ | "\\\\" <> _ -> Ok(2)
    _ -> Error(Nil)
  }
}
