//// Boots the application: storage, supervision tree and both listeners.

import envoy
import gleam/erlang/application
import gleam/erlang/process
import gleam/http/request
import gleam/int
import gleam/option.{type Option}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/otp/supervision
import gleam/result
import gleam/string
import mist
import redirect_proxy/access_log
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/admin/auth/session
import redirect_proxy/admin/router
import redirect_proxy/api/clients
import redirect_proxy/api/deprecation
import redirect_proxy/api/router as api_router
import redirect_proxy/api/token
import redirect_proxy/config.{type Config}
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/password
import redirect_proxy/proxy/server
import redirect_proxy/store
import redirect_proxy/users
import simplifile
import wisp/wisp_mist

pub type Running {
  Running(
    supervisor: process.Pid,
    store: store.Store,
    redirect_port: Int,
    admin_port: Int,
    /// Port of the API's own listener (0 when the API shares the admin
    /// listener or is disabled).
    api_port: Int,
  )
}

/// Initialises the ETS tables and counters. Must run in a process that lives
/// as long as the application (it owns the tables).
pub fn init_tables() -> Nil {
  metrics.init()
  session.init()
  ratelimit.init()
  oidc.init()
  token.init()
}

pub fn clients_settings(cfg: Config) -> clients.Settings {
  clients.Settings(
    path: config.api_clients_path(cfg),
    audit_path: config.audit_path(cfg),
  )
}

pub fn users_settings(cfg: Config) -> users.Settings {
  users.Settings(
    path: config.users_path(cfg),
    audit_path: config.audit_path(cfg),
  )
}

pub fn store_settings(cfg: Config) -> store.Settings {
  store.Settings(
    rules_path: config.rules_path(cfg),
    backups_dir: config.backups_dir(cfg),
    backups: cfg.storage.backups,
    audit_path: config.audit_path(cfg),
  )
}

pub fn start(cfg: Config) -> Result(Running, String) {
  use Nil <- result.try(
    simplifile.create_directory_all(cfg.storage.data_dir)
    |> result.map_error(fn(e) {
      "cannot create data directory "
      <> cfg.storage.data_dir
      <> ": "
      <> simplifile.describe_error(e)
    }),
  )
  init_tables()
  use secret <- result.try(secret_key_base(cfg))
  bootstrap_admin(cfg)
  let static_dir = static_directory()

  let store_name = process.new_name("redirect_proxy_store")
  let store_subject = process.named_subject(store_name)
  let ports = process.new_subject()

  use access <- result.try(start_access_log(cfg))

  let redirect_child =
    mist.new(server.handler(cfg.server, access))
    |> mist.bind(cfg.server.listen)
    |> mist.port(cfg.server.port)
    |> mist.after_start(fn(port, _, _) {
      log.info(
        "redirect listener on "
        <> cfg.server.listen
        <> ":"
        <> int.to_string(port),
      )
      process.send(ports, #("redirect", port))
    })
    |> mist.supervised

  let admin_handler = fn(req: request.Request(mist.Connection)) {
    let peer_ip = case mist.get_connection_info(req.body) {
      Ok(info) -> mist.ip_address_to_string(info.ip_address)
      Error(Nil) -> ""
    }
    let ctx =
      router.Context(
        config: cfg,
        store: store_subject,
        users: users_settings(cfg),
        clients: clients_settings(cfg),
        static_dir:,
        peer_ip:,
      )
    wisp_mist.handler(router.handle(_, ctx), secret)(req)
  }

  let api_handler = fn(req: request.Request(mist.Connection)) {
    let peer_ip = case mist.get_connection_info(req.body) {
      Ok(info) -> mist.ip_address_to_string(info.ip_address)
      Error(Nil) -> ""
    }
    let ctx =
      api_router.Context(
        config: cfg,
        store: store_subject,
        clients: clients_settings(cfg),
        peer_ip:,
        deprecations: deprecation.registry(),
      )
    wisp_mist.handler(api_router.handle_dedicated(_, ctx), secret)(req)
  }

  let builder =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.restart_tolerance(intensity: 10, period: 60)
    |> supervisor.add(
      supervision.worker(fn() { store.start(store_settings(cfg), store_name) }),
    )
    |> supervisor.add(redirect_child)

  let builder = case cfg.admin.enabled {
    False -> builder
    True ->
      supervisor.add(
        builder,
        mist.new(admin_handler)
          |> mist.bind(cfg.admin.listen)
          |> mist.port(cfg.admin.port)
          |> mist.after_start(fn(port, _, _) {
            log.info(
              "admin listener on "
              <> cfg.admin.listen
              <> ":"
              <> int.to_string(port),
            )
            process.send(ports, #("admin", port))
          })
          |> mist.supervised,
      )
  }

  let builder = case config.api_dedicated(cfg) {
    False -> builder
    True ->
      supervisor.add(
        builder,
        mist.new(api_handler)
          |> mist.bind(config.api_listen(cfg))
          |> mist.port(config.api_port(cfg))
          |> mist.after_start(fn(port, _, _) {
            log.info(
              "API listener on "
              <> config.api_listen(cfg)
              <> ":"
              <> int.to_string(port),
            )
            process.send(ports, #("api", port))
          })
          |> mist.supervised,
      )
  }

  use started <- result.try(
    supervisor.start(builder)
    |> result.map_error(describe_start_error),
  )

  let redirect_port = wait_port(ports, "redirect")
  let admin_port = case cfg.admin.enabled {
    True -> wait_port(ports, "admin")
    False -> 0
  }
  let api_port = case config.api_dedicated(cfg) {
    True -> wait_port(ports, "api")
    False -> 0
  }

  ffi.on_sighup(fn() { store.reload_async(store_subject) })
  start_janitor()

  Ok(Running(
    supervisor: started.pid,
    store: store_subject,
    redirect_port:,
    admin_port:,
    api_port:,
  ))
}

/// Installs the access log handler. Returns the request-time settings, or
/// `None` when access logging is disabled.
fn start_access_log(
  cfg: Config,
) -> Result(Option(access_log.Settings), String) {
  use Nil <- result.try(access_log.start(cfg.access_log))
  case cfg.access_log.enabled {
    False -> Ok(option.None)
    True -> access_log.settings(cfg.access_log) |> result.map(option.Some)
  }
}

fn wait_port(ports: process.Subject(#(String, Int)), name: String) -> Int {
  case process.receive(ports, 10_000) {
    Ok(#(n, port)) if n == name -> port
    Ok(other) -> {
      // ports may arrive out of order: requeue and retry
      process.send(ports, other)
      wait_port(ports, name)
    }
    Error(Nil) -> 0
  }
}

fn describe_start_error(error: actor.StartError) -> String {
  case error {
    actor.InitTimeout -> "startup timed out"
    actor.InitFailed(reason) -> reason
    actor.InitExited(reason) -> "startup failed: " <> string.inspect(reason)
  }
}

/// Uses the configured secret or a random one persisted in the data dir.
fn secret_key_base(cfg: Config) -> Result(String, String) {
  case cfg.admin.secret_key_base {
    "" -> {
      let path = config.secret_path(cfg)
      case simplifile.read(path) {
        Ok(secret) if secret != "" -> Ok(string.trim(secret))
        _ -> {
          let secret = id.token(48)
          use Nil <- result.try(
            ffi.atomic_write(path, secret)
            |> result.map_error(fn(e) { "cannot write " <> path <> ": " <> e }),
          )
          let _ = simplifile.set_permissions_octal(path, 0o600)
          log.info("generated a new cookie signing secret in " <> path)
          Ok(secret)
        }
      }
    }
    secret -> Ok(secret)
  }
}

/// Creates the first administrator from RP_BOOTSTRAP_ADMIN_USERNAME and
/// RP_BOOTSTRAP_ADMIN_PASSWORD when no local user exists yet.
fn bootstrap_admin(cfg: Config) -> Nil {
  let settings = users_settings(cfg)
  case
    cfg.local_auth.enabled,
    users.count(settings),
    envoy.get("RP_BOOTSTRAP_ADMIN_USERNAME"),
    envoy.get("RP_BOOTSTRAP_ADMIN_PASSWORD")
  {
    True, 0, Ok(username), Ok(pass) ->
      case password.validate_strength(pass) {
        Error(reason) -> log.error("bootstrap admin not created: " <> reason)
        Ok(Nil) ->
          case
            users.create(settings, username, password.hash(pass), "bootstrap")
          {
            Ok(_) ->
              log.info("bootstrap administrator " <> username <> " created")
            Error(reason) ->
              log.error("bootstrap admin not created: " <> reason)
          }
      }
    True, 0, _, _ if cfg.admin.enabled ->
      log.warning(
        "no local administrator exists: create one with `redirect-proxy user add <name>`",
      )
    _, _, _, _ -> Nil
  }
}

fn static_directory() -> String {
  case application.priv_directory("redirect_proxy") {
    Ok(priv) -> priv <> "/static"
    Error(Nil) -> "priv/static"
  }
}

/// Periodically purges expired sessions, rate limit windows and OIDC flows.
fn start_janitor() -> Nil {
  let _ = process.spawn(fn() { janitor_loop() })
  Nil
}

fn janitor_loop() -> Nil {
  process.sleep(60_000)
  let _ = session.purge_expired()
  let _ = ratelimit.purge_expired()
  let _ = oidc.purge_expired()
  let _ = token.purge_expired()
  janitor_loop()
}
