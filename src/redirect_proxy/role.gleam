//// What an admin session may do. Each role includes the ones before it:
////
//// - `Viewer`: see the rules, test URLs, export.
//// - `Editor`: also change rules, import and reload.
//// - `Admin`: also manage users and API clients, and read the audit log
////   (which records sign-ins with client addresses).

import gleam/list

pub type Role {
  Viewer
  Editor
  Admin
}

pub const all = [Viewer, Editor, Admin]

pub fn to_string(role: Role) -> String {
  case role {
    Viewer -> "viewer"
    Editor -> "editor"
    Admin -> "admin"
  }
}

pub fn from_string(value: String) -> Result(Role, Nil) {
  list.find(all, fn(r) { to_string(r) == value })
}

fn rank(role: Role) -> Int {
  case role {
    Viewer -> 0
    Editor -> 1
    Admin -> 2
  }
}

/// Whether `role` may do what `required` may.
pub fn allows(role: Role, required: Role) -> Bool {
  rank(role) >= rank(required)
}

/// The highest of some roles; `default` only when there are none (a viewer
/// group does not inherit an admin default).
pub fn highest(roles: List(Role), default: Role) -> Role {
  case roles {
    [] -> default
    [first, ..rest] ->
      list.fold(rest, first, fn(best, r) {
        case rank(r) > rank(best) {
          True -> r
          False -> best
        }
      })
  }
}

pub fn label(role: Role) -> String {
  case role {
    Viewer -> "Viewer"
    Editor -> "Editor"
    Admin -> "Admin"
  }
}
