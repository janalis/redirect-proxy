//// The request context of the REST API.

import redirect_proxy/api/clients
import redirect_proxy/api/deprecation.{type Deprecation}
import redirect_proxy/config.{type Config}
import redirect_proxy/store.{type Store}

pub type Context {
  Context(
    config: Config,
    store: Store,
    clients: clients.Settings,
    peer_ip: String,
    /// Client address used for throttling (see the admin router).
    client_ip: String,
    deprecations: List(Deprecation),
  )
}
