//// The listeners whose traffic is served (and access logged).

pub type Listener {
  RedirectListener
  AdminListener
  ApiListener
}

pub const all = [RedirectListener, AdminListener, ApiListener]

pub fn name(listener: Listener) -> String {
  case listener {
    RedirectListener -> "redirect"
    AdminListener -> "admin"
    ApiListener -> "api"
  }
}
