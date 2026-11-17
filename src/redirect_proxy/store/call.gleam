//// How callers wait for the store: a change (`call`) or a read (`read`),
//// each with a timeout that makes the store unavailable rather than hang
//// the caller (`store_timeout`, caught by `store.or_unavailable`).

import gleam/erlang/process.{type Subject}
import gleam/result
import redirect_proxy/ffi/file as file_ffi

/// Calls the store, waiting up to `waiting` milliseconds (unless a test
/// shortened it) for the reply.
///
/// The reply goes to a process linked to the caller, which forwards it: when
/// the caller times out (or exits), that process is gone, and the store
/// skips a change nobody waits for any more (`mutate.run`), rather than make
/// one reported as failed.
pub fn call(
  store: Subject(message),
  waiting default: Int,
  sending make: fn(Subject(reply)) -> message,
) -> reply {
  let store_pid = store_pid(store)
  let caller = process.self()
  let forwarded = process.new_subject()
  let forwarder =
    process.spawn(fn() {
      let reply = process.new_subject()
      process.send(store, make(reply))
      let value = process.receive_forever(reply)
      // no exit message for a caller trapping exits
      process.unlink(caller)
      process.send(forwarded, value)
    })
  let forwarder_down = process.monitor(forwarder)
  let store_down = process.monitor(store_pid)
  let outcome =
    process.new_selector()
    |> process.select_map(forwarded, Ok)
    |> process.select_specific_monitor(store_down, fn(_) { Error(True) })
    |> process.selector_receive(file_ffi.tunable("store_call_timeout", default))
    |> result.unwrap(Error(False))
  process.demonitor_process(store_down)
  case outcome {
    Ok(value) -> {
      process.demonitor_process(forwarder_down)
      value
    }
    Error(store_exited) -> {
      process.unlink(forwarder)
      process.kill(forwarder)
      // a reply sent before the kill arrives before the forwarder's exit
      let late =
        process.new_selector()
        |> process.select_map(forwarded, Ok)
        |> process.select_specific_monitor(forwarder_down, fn(_) { Error(Nil) })
        |> process.selector_receive_forever
      process.demonitor_process(forwarder_down)
      case late, store_exited {
        Ok(value), _ -> value
        Error(Nil), True -> panic as "the store exited before replying"
        Error(Nil), False -> store_timeout()
      }
    }
  }
}

/// Calls the store for a read, waiting up to `waiting` milliseconds: the
/// reply comes straight back (a read has nothing to skip, and the rule list
/// is not copied twice). A reply arriving after the timeout stays in the
/// caller's mailbox, as with `process.call`; callers are request processes.
pub fn read(
  store: Subject(message),
  waiting default: Int,
  sending make: fn(Subject(reply)) -> message,
) -> reply {
  let store_down = process.monitor(store_pid(store))
  let reply = process.new_subject()
  process.send(store, make(reply))
  let outcome =
    process.new_selector()
    |> process.select_map(reply, Ok)
    |> process.select_specific_monitor(store_down, fn(_) { Error(True) })
    |> process.selector_receive(file_ffi.tunable("store_call_timeout", default))
    |> result.unwrap(Error(False))
  process.demonitor_process(store_down)
  case outcome {
    Ok(value) -> value
    Error(True) -> panic as "the store exited before replying"
    Error(False) -> store_timeout()
  }
}

/// The store's process; while the supervisor restarts it, the store is
/// unavailable, as when it is too busy.
fn store_pid(store: Subject(message)) -> process.Pid {
  case process.subject_owner(store) {
    Ok(pid) -> pid
    Error(Nil) -> store_timeout()
  }
}

/// Raises the error of a store call that timed out.
@external(erlang, "redirect_proxy_system_ffi", "store_timeout")
fn store_timeout() -> a

/// Runs `f`, or `unavailable` when a store call in it timed out
/// (`store_timeout`).
@external(erlang, "redirect_proxy_system_ffi", "rescue_store_timeout")
pub fn rescue_store_timeout(f: fn() -> a, unavailable: fn() -> a) -> a
