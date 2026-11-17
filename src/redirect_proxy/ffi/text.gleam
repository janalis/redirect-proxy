//// Bindings to `redirect_proxy_text_ffi`: bytes and text on the request
//// path (header and URL guards, path normalisation, hosts, byte slicing).

/// One form for equivalent URL paths: escapes of unreserved characters and
/// of valid UTF-8 are decoded, the others are written in upper case.
@external(erlang, "redirect_proxy_text_ffi", "normalise_path")
pub fn normalise_path(path: String) -> String

/// Whether every byte is ASCII.
@external(erlang, "redirect_proxy_text_ffi", "is_ascii")
pub fn is_ascii(text: String) -> Bool

/// False when `string.trim` would return `text` unchanged for sure: its
/// first and last bytes are visible ASCII characters.
@external(erlang, "redirect_proxy_text_ffi", "needs_trim")
pub fn needs_trim(text: String) -> Bool

/// `list.map(items, encode)`, reusing what the calling process encoded
/// last time for an equal item. Only the last list's encodings are kept.
@external(erlang, "redirect_proxy_text_ffi", "encode_cached")
pub fn encode_cached(items: List(a), encode: fn(a) -> String) -> List(String)

/// The lines of some bytes, split on `\n`, not decoded.
@external(erlang, "redirect_proxy_text_ffi", "split_lines")
pub fn split_lines(bits: BitArray) -> List(BitArray)

// --- bytes ------------------------------------------------------------------

/// The first `bytes` bytes of a string (all of it when shorter). The result
/// may end inside a UTF-8 sequence: use it only as a lookup key.
@external(erlang, "redirect_proxy_text_ffi", "binary_take")
pub fn byte_take(string: String, bytes: Int) -> String

/// Whether `string` holds the bytes of `pattern`. Unlike `string.contains`,
/// which compares graphemes, it finds `"` in `"` followed by a combining mark.
@external(erlang, "redirect_proxy_text_ffi", "binary_contains")
pub fn byte_contains(string: String, pattern: String) -> Bool

/// Replaces every occurrence of the bytes of `pattern` (see `byte_contains`).
@external(erlang, "redirect_proxy_text_ffi", "binary_replace_all")
pub fn byte_replace(string: String, pattern: String, with: String) -> String

/// A string without its first `bytes` bytes, which must end on a character
/// boundary.
@external(erlang, "redirect_proxy_text_ffi", "binary_drop")
pub fn byte_drop(string: String, bytes: Int) -> String

// --- headers and URLs -------------------------------------------------------

/// Removes tabs and line breaks, which browsers drop from URLs.
@external(erlang, "redirect_proxy_text_ffi", "strip_url_whitespace")
pub fn strip_url_whitespace(url: String) -> String

/// `strip_control` (CR, LF and NUL bytes removed), then non-ASCII bytes
/// percent-encoded, in one scan for the usual value that needs neither.
@external(erlang, "redirect_proxy_text_ffi", "header_value")
pub fn header_value(value: String) -> String

/// Whether a string has no control characters (below 32, and DEL).
@external(erlang, "redirect_proxy_text_ffi", "no_control_chars")
pub fn no_control_chars(value: String) -> Bool

/// The host part of what follows `scheme://`: before the first `/`, `\`,
/// `?` or `#`, after the last `@`.
@external(erlang, "redirect_proxy_text_ffi", "url_host")
pub fn url_host(rest: String) -> String

// --- hosts ------------------------------------------------------------------

/// A host without its port (`[::1]:8080` is `[::1]`, `a.test:80` is
/// `a.test`).
@external(erlang, "redirect_proxy_text_ffi", "strip_port")
pub fn strip_port(host: String) -> String

/// Whether a (lower-case) host holds only letters, digits, `-`, `_` and `.`.
@external(erlang, "redirect_proxy_text_ffi", "is_host_name")
pub fn is_host_name(host: String) -> Bool

/// A host from the redirect listener (ASCII, without a port), normalised
/// like `matcher.normalise_request_host`, and whether it is a host name
/// (`is_host_name`), in one scan.
@external(erlang, "redirect_proxy_text_ffi", "listener_host")
pub fn listener_host(host: String) -> #(String, Bool)

/// `string.lowercase`, with a fast path for ASCII (request hosts).
@external(erlang, "redirect_proxy_text_ffi", "lowercase_host")
pub fn lowercase_host(host: String) -> String

/// Lowers the ASCII letters only (other bytes are kept as they are).
@external(erlang, "redirect_proxy_text_ffi", "lowercase_ascii")
pub fn lowercase_ascii(text: String) -> String
