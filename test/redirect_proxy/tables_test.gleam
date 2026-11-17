//// The long-lived ETS tables belong to a supervised owner: they outlive a
//// store crash and, when several applications run in one VM (as here),
//// the owner that created them.

import gleam/erlang/process.{type Pid}
import gleam/list
import redirect_proxy/app
import redirect_proxy/config
import redirect_proxy/ffi/ets as ets_ffi
import redirect_proxy/store
import simplifile
import support

const tables = [
  "redirect_proxy_sessions", "redirect_proxy_header_sessions",
  "redirect_proxy_ratelimit", "redirect_proxy_slots", "redirect_proxy_oidc",
  "redirect_proxy_oidc_flows", "redirect_proxy_api_tokens",
  "redirect_proxy_store_last_good", "redirect_proxy_store_checkers",
  "redirect_proxy_memo", "redirect_proxy_access_time",
]

/// A row of one of the tables, to tell kept tables from new ones: the memo,
/// which no test creates.
const marked = "redirect_proxy_memo"

@external(erlang, "test_tables_ffi", "owner")
fn owner(table: String) -> Result(Pid, Nil)

@external(erlang, "test_tables_ffi", "heir")
fn heir(table: String) -> Result(Pid, Nil)

/// Whether the table belongs to the table owner of an application.
@external(erlang, "test_tables_ffi", "held_by_an_owner")
fn held_by_an_owner(table: String) -> Bool

@external(erlang, "test_tables_ffi", "child")
fn child(supervisor: Pid, id: Int) -> Result(Pid, Nil)

fn config(dir: String) -> config.Config {
  let d = config.default()
  config.Config(
    ..d,
    server: config.ServerConfig(..d.server, listen: "127.0.0.1", port: 0),
    admin: config.AdminConfig(..d.admin, enabled: False),
    api: config.ApiConfig(..d.api, enabled: False),
    storage: config.StorageConfig(
      ..d.storage,
      data_dir: dir,
      backups: 0,
      watch_interval: 0,
    ),
    access_log: config.AccessLogConfig(..d.access_log, enabled: False),
  )
}

fn start() -> app.Running {
  let dir = support.temp_dir()
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "/redirects.json",
      "[{\"source\": \"/old\", \"target\": \"/new\"}]",
    )
  let assert Ok(running) = app.start(config(dir))
  running
}

/// The first child of the application's supervisor: the table owner.
fn table_owner(running: app.Running) -> Pid {
  let assert Ok(pid) = child(running.supervisor, 0)
  pid
}

/// Every table is held by the owner of an application accepted by `by`,
/// but those a test created in its own process (unit tests of sessions,
/// rate limits, a store started alone), which stay that process's. No test
/// creates the memo.
fn all_held(by accept: fn(Pid) -> Bool) -> Bool {
  list.all(tables, fn(table) {
    case owner(table), held_by_an_owner(table) {
      Ok(pid), True -> accept(pid)
      Ok(_), False -> table != marked
      Error(Nil), _ -> False
    }
  })
}

/// The owners holding tables.
fn holders() -> List(Pid) {
  list.filter_map(tables, fn(table) {
    case held_by_an_owner(table) {
      True -> owner(table)
      False -> Error(Nil)
    }
  })
  |> list.unique
}

fn all_inherited_by(pid: Pid) -> Bool {
  list.all(tables, fn(table) {
    heir(table) == Ok(pid) || !held_by_an_owner(table)
  })
}

/// `support.wait_until`, saying which wait failed.
fn wait(condition: fn() -> Bool, timeout_ms: Int, what: String) -> Nil {
  case condition(), timeout_ms <= 0 {
    True, _ -> Nil
    False, True -> panic as { "not in time: " <> what }
    False, False -> {
      process.sleep(20)
      wait(condition, timeout_ms - 20, what)
    }
  }
}

fn store_pid(running: app.Running) -> Result(Pid, Nil) {
  process.subject_owner(running.store)
}

pub fn tables_outlive_the_services_test() {
  // the applications of earlier tests may still run, and hold the tables
  let _ = start()
  wait(fn() { all_held(by: fn(_) { True }) }, 10_000, "an owner")
  ets_ffi.ets_put(marked, "tables_test", True)
  let holders = holders()
  assert !list.is_empty(holders)

  // another application finds the tables, and is their heir: they pass to
  // it when their owner stops
  let second = start()
  let second_owner = table_owner(second)
  wait(fn() { all_inherited_by(second_owner) }, 5000, "the heir")
  list.each(holders, process.kill)
  wait(
    fn() { all_held(by: fn(pid) { pid == second_owner }) },
    10_000,
    "the second owner",
  )
  assert ets_ffi.ets_find(marked, "tables_test") == Ok(True)

  // a store crash: the store restarts, the tables stay
  let assert Ok(crashed) = store_pid(second)
  process.kill(crashed)
  wait(
    fn() {
      case store_pid(second) {
        Ok(pid) -> pid != crashed
        Error(Nil) -> False
      }
    },
    10_000,
    "the store restart",
  )
  assert all_held(by: fn(pid) { pid == second_owner })
  assert ets_ffi.ets_find(marked, "tables_test") == Ok(True)
  let assert [_] = store.all(second.store)

  // an owner crash: its tables pass to its heir (the other application's
  // owner, which asked), and the services restart
  let assert Ok(restarted) = store_pid(second)
  process.kill(second_owner)
  wait(
    fn() {
      case child(second.supervisor, 0) {
        Ok(pid) -> pid != second_owner && process.is_alive(pid)
        Error(Nil) -> False
      }
    },
    10_000,
    "a new owner",
  )
  wait(
    fn() {
      case store_pid(second) {
        Ok(pid) -> pid != restarted
        Error(Nil) -> False
      }
    },
    10_000,
    "the services restart",
  )
  wait(fn() { all_held(by: fn(_) { True }) }, 10_000, "an owner again")
  let assert [_] = store.all(second.store)
}
