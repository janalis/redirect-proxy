//// Access log line formats: nginx style templates compiled once at startup
//// and rendered by each request process.

import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/string_tree
import redirect_proxy/cidr.{type Cidrs}
import redirect_proxy/ffi

/// How variable values are escaped.
pub type Escape {
  /// nginx default: `"`, `\`, control and non ASCII bytes as `\xHH`; empty
  /// values as `-`.
  EscapeDefault
  /// JSON string escaping (without the surrounding quotes).
  EscapeJson
  /// Raw values (only CR and LF are escaped, so a line stays a line).
  EscapeNone
}

pub type Field {
  RemoteAddr
  RemoteUser
  TimeLocal
  TimeIso8601
  Msec
  Request
  RequestMethod
  RequestUri
  Uri
  Args
  ServerProtocol
  Status
  BodyBytesSent
  RequestTime
  Host
  HttpReferer
  HttpUserAgent
  Location
  RuleId
  /// `redirect`, `admin` or `api`.
  ListenerName
  /// Any other request header, `$http_x_request_id` -> `x-request-id`.
  Header(name: String)
}

pub type Segment {
  Literal(String)
  Var(Field)
}

pub type Format {
  Format(segments: List(Segment), escape: Escape)
}

/// One request, as seen by the redirect listener.
pub type Entry {
  Entry(
    /// Listener that served the request (`redirect`, `admin`, `api`).
    listener: String,
    /// Client address, already resolved and anonymised.
    client_ip: String,
    method: String,
    host: String,
    path: String,
    /// Raw query string without `?` ("" when absent).
    query: String,
    protocol: String,
    status: Int,
    bytes: Int,
    /// Request headers, lower case names.
    headers: List(#(String, String)),
    /// Redirect target ("" when not redirected).
    location: String,
    /// Matched rule ("" when none).
    rule_id: String,
    /// Wall clock time the request was received, in microseconds.
    time_us: Int,
    /// Time spent handling the request, in microseconds.
    duration_us: Int,
  )
}

pub const combined =
  "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""

pub const common =
  "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent"

pub const json =
  "{\"time\":\"$time_iso8601\",\"listener\":\"$listener\",\"remote_addr\":\"$remote_addr\",\"request_method\":\"$request_method\",\"host\":\"$host\",\"uri\":\"$uri\",\"args\":\"$args\",\"server_protocol\":\"$server_protocol\",\"status\":$status,\"body_bytes_sent\":$body_bytes_sent,\"request_time\":$request_time,\"http_referer\":\"$http_referer\",\"http_user_agent\":\"$http_user_agent\",\"location\":\"$location\",\"rule_id\":\"$rule_id\"}"

/// Compiles a preset name or a template. `escape` (`default`, `json` or
/// `none`) only applies to custom templates.
pub fn parse(format: String, escape: String) -> Result(Format, String) {
  case format {
    "combined" -> compile(combined, EscapeDefault)
    "common" -> compile(common, EscapeDefault)
    "json" -> compile(json, EscapeJson)
    template -> {
      use escape <- result.try(case escape {
        "default" -> Ok(EscapeDefault)
        "json" -> Ok(EscapeJson)
        "none" -> Ok(EscapeNone)
        other -> Error("unknown escape mode " <> other)
      })
      compile(template, escape)
    }
  }
}

fn compile(template: String, escape: Escape) -> Result(Format, String) {
  use <- bool.guard(template == "", Error("the template is empty"))
  use segments <- result.try(segments(template, []))
  Ok(Format(segments: merge_literals(segments, []), escape:))
}

fn segments(rest: String, acc: List(Segment)) -> Result(List(Segment), String) {
  case string.split_once(rest, "$") {
    Error(Nil) -> Ok(list.reverse(add_literal(acc, rest)))
    Ok(#(before, after)) -> {
      let acc = add_literal(acc, before)
      case variable(after) {
        Ok(#("", rest)) -> segments(rest, [Literal("$"), ..acc])
        Ok(#(name, rest)) -> {
          use field <- result.try(field(name))
          segments(rest, [Var(field), ..acc])
        }
        Error(e) -> Error(e)
      }
    }
  }
}

fn add_literal(acc: List(Segment), text: String) -> List(Segment) {
  case text {
    "" -> acc
    _ -> [Literal(text), ..acc]
  }
}

fn merge_literals(
  segments: List(Segment),
  acc: List(Segment),
) -> List(Segment) {
  case segments, acc {
    [], _ -> list.reverse(acc)
    [Literal(b), ..rest], [Literal(a), ..acc] ->
      merge_literals(rest, [Literal(a <> b), ..acc])
    [s, ..rest], _ -> merge_literals(rest, [s, ..acc])
  }
}

/// Reads a variable name after `$`: `name` or `{name}`.
fn variable(after: String) -> Result(#(String, String), String) {
  case after {
    "{" <> braced ->
      case string.split_once(braced, "}") {
        Ok(#(name, rest)) -> Ok(#(name, rest))
        Error(Nil) -> Error("unterminated ${ in the template")
      }
    _ ->
      case string.to_graphemes(after) {
        // `$1`, `$ `: not a variable (nginx names start with a letter)
        [c, ..] as chars ->
          case is_name_char(c) && !is_digit(c) {
            True -> Ok(take_name(chars, ""))
            False -> Ok(#("", after))
          }
        [] -> Ok(#("", ""))
      }
  }
}

fn is_digit(c: String) -> Bool {
  case c {
    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" -> True
    _ -> False
  }
}

fn take_name(chars: List(String), name: String) -> #(String, String) {
  case chars {
    [c, ..rest] ->
      case is_name_char(c) {
        True -> take_name(rest, name <> c)
        False -> #(name, string.concat(chars))
      }
    [] -> #(name, "")
  }
}

fn is_name_char(c: String) -> Bool {
  case c {
    "_" -> True
    _ ->
      case string.to_utf_codepoints(c) {
        [cp] -> {
          let i = string.utf_codepoint_to_int(cp)
          { i >= 97 && i <= 122 } || { i >= 48 && i <= 57 }
        }
        _ -> False
      }
  }
}

fn field(name: String) -> Result(Field, String) {
  case name {
    "remote_addr" -> Ok(RemoteAddr)
    "remote_user" -> Ok(RemoteUser)
    "time_local" -> Ok(TimeLocal)
    "time_iso8601" -> Ok(TimeIso8601)
    "msec" -> Ok(Msec)
    "request" -> Ok(Request)
    "request_method" -> Ok(RequestMethod)
    "request_uri" -> Ok(RequestUri)
    "uri" -> Ok(Uri)
    "args" | "query_string" -> Ok(Args)
    "server_protocol" -> Ok(ServerProtocol)
    "status" -> Ok(Status)
    "body_bytes_sent" | "bytes_sent" -> Ok(BodyBytesSent)
    "request_time" -> Ok(RequestTime)
    "host" -> Ok(Host)
    "http_referer" -> Ok(HttpReferer)
    "http_user_agent" -> Ok(HttpUserAgent)
    "location" | "sent_http_location" -> Ok(Location)
    "rule_id" -> Ok(RuleId)
    "listener" -> Ok(ListenerName)
    "http_" <> header if header != "" ->
      // `${http_Proxy-Authorization}` names the same header as
      // `$http_proxy_authorization`: refuse credentials by header name
      case string.lowercase(string.replace(header, "_", "-")) {
        "authorization" | "proxy-authorization" | "cookie" ->
          Error(
            "$" <> name <> " is refused: it would write credentials to the log",
          )
        header -> Ok(Header(header))
      }
    _ -> Error("unknown variable $" <> name)
  }
}

// --- rendering ----------------------------------------------------------------

/// Renders one line (without the trailing newline).
pub fn render(format: Format, log_query: Bool, entry: Entry) -> String {
  list.fold(format.segments, string_tree.new(), fn(tree, segment) {
    case segment {
      Literal(text) -> string_tree.append(tree, text)
      Var(field) ->
        string_tree.append(
          tree,
          escape(format.escape, value(field, log_query, entry)),
        )
    }
  })
  |> string_tree.to_string
}

fn value(field: Field, log_query: Bool, e: Entry) -> String {
  case field {
    RemoteAddr -> e.client_ip
    RemoteUser -> ""
    TimeLocal -> ffi.time_local(e.time_us)
    TimeIso8601 -> ffi.time_iso8601(e.time_us)
    Msec -> decimal(e.time_us / 1000, 1000)
    Request -> e.method <> " " <> request_uri(log_query, e) <> " " <> e.protocol
    RequestMethod -> e.method
    RequestUri -> request_uri(log_query, e)
    Uri -> e.path
    Args ->
      case log_query {
        True -> e.query
        False -> ""
      }
    ServerProtocol -> e.protocol
    Status -> int.to_string(e.status)
    BodyBytesSent -> int.to_string(e.bytes)
    RequestTime -> decimal(e.duration_us / 1000, 1000)
    Host -> e.host
    HttpReferer -> strip_query(log_query, header(e, "referer"))
    HttpUserAgent -> header(e, "user-agent")
    Location -> strip_query(log_query, e.location)
    RuleId -> e.rule_id
    ListenerName -> e.listener
    Header(name) -> header(e, name)
  }
}

fn request_uri(log_query: Bool, e: Entry) -> String {
  case log_query, e.query {
    True, q if q != "" -> e.path <> "?" <> q
    _, _ -> e.path
  }
}

fn header(e: Entry, name: String) -> String {
  case list.key_find(e.headers, name) {
    Ok(v) -> v
    Error(Nil) -> ""
  }
}

/// Drops the query string and fragment of a URL unless queries are logged.
pub fn strip_query(log_query: Bool, url: String) -> String {
  case log_query {
    True -> url
    False ->
      case string.split_once(url, "?") {
        Ok(#(base, _)) -> base
        Error(Nil) ->
          case string.split_once(url, "#") {
            Ok(#(base, _)) -> base
            Error(Nil) -> url
          }
      }
  }
}

/// `value / scale` with three decimals (`1234 / 1000` -> `1.234`).
fn decimal(value: Int, scale: Int) -> String {
  let fraction = int.to_string(value % scale)
  int.to_string(value / scale)
  <> "."
  <> string.pad_start(fraction, to: 3, with: "0")
}

fn escape(mode: Escape, value: String) -> String {
  case mode, value {
    EscapeDefault, "" -> "-"
    EscapeDefault, v -> ffi.escape_default(v)
    EscapeJson, v -> ffi.escape_json(v)
    EscapeNone, v -> ffi.escape_newlines(v)
  }
}

// --- client address -------------------------------------------------------------

/// The client address: the TCP peer, or the address forwarded by a trusted
/// proxy (rightmost untrusted `X-Forwarded-For` hop, then `X-Real-IP`). A
/// forwarded value that is not an IP address is not used: it keys every
/// throttle, so free text would give a client a fresh budget per request.
pub fn client_ip(
  peer: String,
  headers: List(#(String, String)),
  trusted: Cidrs,
) -> String {
  case cidr.contains(trusted, peer) {
    False -> peer
    True -> forwarded_client_ip(peer, headers, trusted)
  }
}

/// `client_ip` when the peer is known to be one of the `trusted` proxies.
pub fn forwarded_client_ip(
  peer: String,
  headers: List(#(String, String)),
  trusted: Cidrs,
) -> String {
  // several header lines are one comma-separated list, in order: a client
  // can send its own line ahead of the proxy's
  case list.key_filter(headers, "x-forwarded-for") {
    [_, ..] as lines ->
      cidr.forwarded_hop(lines, trusted) |> result.unwrap(peer)
    [] ->
      case list.key_find(headers, "x-real-ip") |> result.map(string.trim) {
        Ok(ip) ->
          case ffi.is_ip_address(ip) {
            True -> ip
            False -> peer
          }
        Error(Nil) -> peer
      }
  }
}

/// Truncates an address (IPv4 to /24, IPv6 to /48). Values that are not IP
/// addresses are dropped.
/// Request headers that carry client addresses: with addresses truncated,
/// a `$http_...` variable for one of them is truncated the same way, hop by
/// hop, rather than writing full addresses to the disk.
pub const address_headers = [
  "x-forwarded-for", "x-real-ip", "forwarded", "true-client-ip",
  "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip", "fastly-client-ip",
]

/// The address headers the format logs (`$http_x_forwarded_for`...).
pub fn logged_address_headers(format: Format) -> List(String) {
  list.filter_map(format.segments, fn(segment) {
    case segment {
      Var(Header(name)) ->
        case list.contains(address_headers, name) {
          True -> Ok(name)
          False -> Error(Nil)
        }
      _ -> Error(Nil)
    }
  })
}

/// An address header's value with each address truncated: the hops of
/// `X-Forwarded-For` one by one, the `for=` of `Forwarded`, anything that is
/// not an address dropped.
pub fn anonymize_header(value: String) -> String {
  value
  |> string.split(",")
  |> list.map(fn(hop) {
    let hop = string.trim(hop)
    case string.contains(hop, "=") {
      // Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
      True ->
        hop
        |> string.split(";")
        |> list.filter_map(fn(pair) {
          case string.split_once(string.trim(pair), "=") {
            Ok(#(key, v)) -> {
              let key = string.lowercase(key)
              case key == "for" || key == "by" {
                True -> Ok(key <> "=" <> anonymize(forwarded_address(v)))
                False -> Ok(key <> "=" <> v)
              }
            }
            Error(Nil) -> Error(Nil)
          }
        })
        |> string.join(";")
      False -> anonymize(hop)
    }
  })
  |> string.join(", ")
}

/// The address of a `Forwarded` `for=` value: `"[2001:db8::1]:4711"` is
/// `2001:db8::1`, `192.0.2.60:8080` is `192.0.2.60`.
fn forwarded_address(value: String) -> String {
  let v = case value {
    "\"" <> rest -> string.drop_end(rest, 1)
    _ -> value
  }
  case v {
    "[" <> rest ->
      case string.split_once(rest, "]") {
        Ok(#(address, _)) -> address
        Error(Nil) -> v
      }
    _ ->
      case string.split(v, ":") {
        [address, _port] -> address
        _ -> v
      }
  }
}

pub fn anonymize(ip: String) -> String {
  ffi.anonymize_ip(ip)
}
