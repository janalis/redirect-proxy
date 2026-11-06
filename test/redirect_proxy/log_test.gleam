import gleam/dynamic/decode
import gleam/json
import gleam/list
import redirect_proxy/log

@external(erlang, "test_log_ffi", "handler_level")
fn handler_level() -> String

@external(erlang, "test_log_ffi", "primary_level")
fn primary_level() -> String

@external(erlang, "test_log_ffi", "formatter_module")
fn formatter_module() -> String

@external(erlang, "test_log_ffi", "format_json")
fn format_json(kind: String, with_domain: Bool) -> String

/// The level of the application handler follows the setting, while the
/// primary level stays at info (or debug) so that the access log, emitted at
/// info, is never filtered out.
pub fn configure_sets_handler_levels_test() {
  let levels =
    list.map(
      ["debug", "info", "warning", "error", "critical", "none", "bogus"],
      fn(level) {
        log.configure(level)
        #(level, primary_level(), handler_level())
      },
    )
  // back to the quiet level of the test run
  log.configure("critical")
  assert levels
    == [
      #("debug", "debug", "debug"),
      #("info", "info", "info"),
      #("warning", "info", "warning"),
      #("error", "info", "error"),
      #("critical", "info", "critical"),
      #("none", "info", "critical"),
      #("bogus", "info", "info"),
    ]
}

pub fn json_format_switches_the_formatter_test() {
  log.configure_with("critical", "json")
  let json_formatter = formatter_module()
  log.configure("critical")
  assert json_formatter == "redirect_proxy_log_json"
  assert formatter_module() != "redirect_proxy_log_json"
}

pub fn json_lines_test() {
  let line = format_json("string", True)
  let assert Ok(#(time, level, msg, domain)) = json.parse(line, fields())
  assert time == "2026-11-06T09:30:05.123456Z"
  assert level == "warning"
  assert msg == "plain \"text\""
  assert domain == "redirect_proxy.access"

  let assert Ok(#(_, _, msg, domain)) =
    json.parse(format_json("format", False), fields())
  assert msg == "n=42"
  assert domain == ""

  let assert Ok(#(_, _, msg, _)) =
    json.parse(format_json("report", False), fields())
  assert msg == "#{key => value}"
}

fn fields() {
  use time <- decode.field("time", decode.string)
  use level <- decode.field("level", decode.string)
  use msg <- decode.field("msg", decode.string)
  use domain <- decode.optional_field("domain", "", decode.string)
  decode.success(#(time, level, msg, domain))
}
