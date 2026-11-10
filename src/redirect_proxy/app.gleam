//// Boots the application: storage, supervision tree and both listeners.

import envoy
import gleam/erlang/application
import gleam/erlang/process
import gleam/http/request
import gleam/int
import gleam/list
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/otp/supervision
import gleam/result
import gleam/string
import mist
import redirect_proxy/access_log
import redirect_proxy/access_log_format
import redirect_proxy/admin/auth/oidc
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/admin/auth/session
import redirect_proxy/admin/router
import redirect_proxy/admin/web as admin_web
import redirect_proxy/api/clients
import redirect_proxy/api/deprecation
import redirect_proxy/api/router as api_router
import redirect_proxy/api/token
import redirect_proxy/api/web as api_web
import redirect_proxy/audit
import redirect_proxy/cidr
import redirect_proxy/config.{type Config}
import redirect_proxy/config/env as config_env
import redirect_proxy/config/validate as config_validate
import redirect_proxy/ffi
import redirect_proxy/id
import redirect_proxy/listener
import redirect_proxy/log
import redirect_proxy/metrics
import redirect_proxy/password
import redirect_proxy/proxy/http as proxy_http
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
    ignore_trailing_slash: config.ignore_trailing_slash(cfg),
    watch_interval: cfg.storage.watch_interval * 1000,
    hits_path: cfg.storage.data_dir <> "/hits.json",
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
  audit.configure(cfg.storage.audit_max_bytes, cfg.storage.audit_files)
  use secret <- result.try(secret_key_base(cfg))
  bootstrap_admin(cfg)
  list.each(config_validate.runtime_warnings(cfg), log.warning)
  let static_dir = static_directory()

  let store_name = process.new_name("redirect_proxy_store")
  let store_subject = process.named_subject(store_name)
  let ports = process.new_subject()

  use access <- result.try(access_log.start(cfg.access_log))

  let redirect_child =
    proxy_http.supervised(
      server.handler_with_identity(
        cfg.server,
        cfg.admin.metrics_token,
        access.redirect,
        cfg.access_log.trusted_proxies,
        // only an enabled `auth.header` makes them the admin's identity:
        // else they may be an authenticating proxy's for the upstream
        case cfg.header_auth.enabled {
          True -> [
            cfg.header_auth.user_header,
            cfg.header_auth.email_header,
            cfg.header_auth.role_header,
          ]
          False -> []
        },
        cfg.header_auth.trusted_proxies,
      ),
      cfg.server.listen,
      cfg.server.port,
      server.http_options(
        cfg.server,
        access.redirect,
        cfg.access_log.trusted_proxies,
      ),
      fn(port) {
        log.info(
          "redirect listener on "
          <> cfg.server.listen
          <> ":"
          <> int.to_string(port),
        )
        process.send(ports, #("redirect", port))
      },
    )

  let trusted_proxies = cidr.compile(cfg.access_log.trusted_proxies)
  let admin_handler = fn(req: request.Request(mist.Connection)) {
    let #(peer_ip, client_ip) = addresses(trusted_proxies, req)
    let ctx =
      admin_web.Context(
        config: cfg,
        store: store_subject,
        users: users_settings(cfg),
        clients: clients_settings(cfg),
        static_dir:,
        peer_ip:,
        client_ip:,
      )
    wisp_mist.handler(router.handle(_, ctx), secret)(req)
  }
  // The admin listener also serves the API when they share a port.
  let admin_handler =
    access_log.wrap(admin_handler, fn(req: request.Request(mist.Connection)) {
      case config.api_on_admin(cfg) && access_log.is_api_path(req.path) {
        True -> #(listener.ApiListener, access.api)
        False -> #(listener.AdminListener, access.admin)
      }
    })

  let api_handler = fn(req: request.Request(mist.Connection)) {
    let #(peer_ip, client_ip) = addresses(trusted_proxies, req)
    let ctx =
      api_web.Context(
        config: cfg,
        store: store_subject,
        clients: clients_settings(cfg),
        peer_ip:,
        client_ip:,
        deprecations: deprecation.registry(),
      )
    wisp_mist.handler(api_router.handle_dedicated(_, ctx), secret)(req)
  }
  let api_handler =
    access_log.wrap(api_handler, fn(_) { #(listener.ApiListener, access.api) })

  let builder =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.restart_tolerance(intensity: 10, period: 60)
    |> supervisor.add(
      supervision.worker(fn() { store.start(store_settings(cfg), store_name) }),
    )
    |> supervisor.add(redirect_child)
    |> supervisor.add(supervision.worker(start_janitor))

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
  ffi.on_sigterm_drain(cfg.server.shutdown_grace * 1000, fn() {
    store.flush_hits(store_subject)
  })

  Ok(Running(
    supervisor: started.pid,
    store: store_subject,
    redirect_port:,
    admin_port:,
    api_port:,
  ))
}

fn wait_port(ports: process.Subject(#(String, Int)), name: String) -> Int {
  case process.receive(ports, 10_000) {
    Ok(#(n, port)) if n == name -> port
    Ok(other) -> {
      // ports may arrive out of order: requeue and retry
      process.send(ports, other)
      wait_port(ports, name)
    }
    Error(Nil) -> {
      log.error(name <> " listener did not report its port within 10 seconds")
      0
    }
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
/// Without the admin, nothing is signed for later (the API sets no
/// cookies): a random secret is enough, and a read-only data dir (a
/// replica serving a ConfigMap) is not written to.
fn secret_key_base(cfg: Config) -> Result(String, String) {
  case cfg.admin.secret_key_base {
    "" if !cfg.admin.enabled -> Ok(id.token(48))
    "" -> {
      let path = config.secret_path(cfg)
      case simplifile.read(path) {
        Ok(secret) ->
          case string.trim(secret) {
            "" -> new_secret_key_base(path)
            secret ->
              case string.length(secret) < 64 {
                True ->
                  Error(
                    path
                    <> " holds a cookie signing secret shorter than 64 characters: delete it to generate a new one",
                  )
                False -> Ok(secret)
              }
          }
        Error(_) -> new_secret_key_base(path)
      }
    }
    secret -> Ok(secret)
  }
}

fn new_secret_key_base(path: String) -> Result(String, String) {
  let secret = id.token(48)
  use Nil <- result.try(
    ffi.atomic_write_private(path, secret)
    |> result.map_error(fn(e) { "cannot write " <> path <> ": " <> e }),
  )
  log.info("generated a new cookie signing secret in " <> path)
  Ok(secret)
}

/// Creates the first administrator from RP_BOOTSTRAP_ADMIN_USERNAME and
/// RP_BOOTSTRAP_ADMIN_PASSWORD (or RP_BOOTSTRAP_ADMIN_PASSWORD_FILE) when no
/// local user exists yet. Exposed for tests.
pub fn bootstrap_admin(cfg: Config) -> Nil {
  let settings = users_settings(cfg)
  let from_env = envoy.get("RP_BOOTSTRAP_ADMIN_PASSWORD")
  let bootstrap_password = case envoy.get("RP_BOOTSTRAP_ADMIN_PASSWORD_FILE") {
    Ok(path) -> config_env.read_secret_file(path) |> result.replace_error(Nil)
    Error(Nil) -> from_env
  }
  let count = users.count(settings)
  case from_env, count {
    // the plain-text password stays readable in the container configuration
    // and /proc/<pid>/environ long after it was used
    Ok(_), n if n > 0 ->
      log.warning(
        "RP_BOOTSTRAP_ADMIN_PASSWORD is still set although administrators exist: remove it, or use RP_BOOTSTRAP_ADMIN_PASSWORD_FILE",
      )
    _, _ -> Nil
  }
  case
    cfg.local_auth.enabled,
    count,
    envoy.get("RP_BOOTSTRAP_ADMIN_USERNAME"),
    bootstrap_password
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

type JanitorTick {
  Purge
}

const janitor_interval = 60_000

/// Periodically purges expired sessions, rate limit windows, OIDC flows and
/// tokens. Supervised: if a purge crashes, it is restarted (before, the loop
/// died silently and nothing was purged any more).
fn start_janitor() -> Result(
  actor.Started(process.Subject(JanitorTick)),
  actor.StartError,
) {
  actor.new_with_initialiser(1000, fn(subject) {
    process.send_after(subject, janitor_interval, Purge)
    actor.initialised(subject) |> actor.returning(subject) |> Ok
  })
  |> actor.on_message(fn(subject, _tick) {
    let _ = session.purge_expired()
    let _ = ratelimit.purge_expired()
    let _ = oidc.purge_expired()
    let _ = token.purge_expired()
    process.send_after(subject, janitor_interval, Purge)
    actor.continue(subject)
  })
  |> actor.start
}

/// The peer address, and the client address used for login and token
/// throttling: the TCP peer, or the address forwarded by one of
/// `access_log.trusted_proxies` (`trusted`, the same resolution as the
/// access log).
fn addresses(
  trusted: cidr.Cidrs,
  req: request.Request(mist.Connection),
) -> #(String, String) {
  case mist.get_connection_info(req.body) {
    Ok(info) -> {
      let peer_ip = mist.ip_address_to_string(info.ip_address)
      case cidr.contains_peer(trusted, info.ip_address) {
        True -> #(
          peer_ip,
          access_log_format.forwarded_client_ip(peer_ip, req.headers, trusted),
        )
        False -> #(peer_ip, peer_ip)
      }
    }
    Error(Nil) -> #("", access_log_format.client_ip("", req.headers, trusted))
  }
}
