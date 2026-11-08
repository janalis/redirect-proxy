import gleam/erlang/process
import gleam/list
import redirect_proxy/password
import redirect_proxy/role
import redirect_proxy/users
import simplifile
import support

fn settings() -> users.Settings {
  let dir = support.temp_dir()
  users.Settings(path: dir <> "/users.json", audit_path: dir <> "/audit.jsonl")
}

pub fn create_list_get_test() {
  let s = settings()
  assert users.count(s) == 0
  let assert Ok(user) =
    users.create(s, " Alice ", password.hash_with("pw", 10), by: "t")
  assert user.username == "alice"
  let assert Ok(found) = users.get(s, "ALICE")
  assert password.verify("pw", found.password_hash)
  let assert Error(_) = users.create(s, "alice", "x", by: "t")
  let assert Ok(all) = users.list(s)
  assert list.map(all, fn(u) { u.username }) == ["alice"]
}

pub fn invalid_usernames_test() {
  let s = settings()
  ["a", "with space", "semi;colon", ""]
  |> list.each(fn(name) {
    let assert Error(_) = users.create(s, name, "x", by: "t")
  })
}

pub fn password_change_test() {
  let s = settings()
  let assert Ok(_) =
    users.create(s, "bob", password.hash_with("old", 10), by: "t")
  let assert Ok(Nil) =
    users.set_password(s, "bob", password.hash_with("new", 10), by: "t")
  let assert Ok(bob) = users.get(s, "bob")
  assert password.verify("new", bob.password_hash)
  assert !password.verify("old", bob.password_hash)
  let assert Error(_) = users.set_password(s, "nobody", "x", by: "t")
}

pub fn rehash_keeps_a_password_changed_meanwhile_test() {
  let s = settings()
  let old = password.hash_with("old", 10)
  let assert Ok(_) = users.create(s, "bob", old, by: "t")
  // the hash checked at login is still stored: replaced
  let stronger = password.hash_with("old", 20)
  assert users.rehash_password(s, "bob", old, stronger) == Ok(True)
  let assert Ok(bob) = users.get(s, "bob")
  assert bob.password_hash == stronger
  // an administrator reset the password during the login: kept
  let reset = password.hash_with("new", 10)
  let assert Ok(Nil) = users.set_password(s, "bob", reset, by: "admin")
  assert users.rehash_password(
      s,
      "bob",
      stronger,
      password.hash_with("old", 30),
    )
    == Ok(False)
  let assert Ok(bob) = users.get(s, "bob")
  assert bob.password_hash == reset
}

pub fn last_user_cannot_be_deleted_test() {
  let s = settings()
  let assert Ok(_) = users.create(s, "one", "x", by: "t")
  let assert Ok(_) = users.create(s, "two", "x", by: "t")
  let assert Ok(Nil) = users.delete(s, "one", by: "t")
  let assert Error(_) = users.delete(s, "two", by: "t")
  let assert Error(_) = users.delete(s, "ghost", by: "t")
  assert users.count(s) == 1
}

/// The CLI (another OS process) holds users.json.lock: the server waits for
/// it instead of writing at the same time.
pub fn waits_for_another_process_test() {
  let s = settings()
  let lock = s.path <> ".lock"
  let assert Ok(Nil) = simplifile.write(lock, "4242 cli@host\n")
  let released = process.new_subject()
  process.spawn(fn() {
    process.sleep(300)
    // told before the lock goes: a change that waited for it finds this
    process.send(released, Nil)
    let _ = simplifile.delete(lock)
  })
  let assert Ok(_) =
    users.create(s, "alice", password.hash_with("x", 1000), by: "test")
  assert process.receive(released, 0) == Ok(Nil)
  assert users.count(s) == 1
}

pub fn roles_test() {
  let s = settings()
  let assert Ok(admin) = users.create(s, "root", "h", by: "t")
  assert admin.role == role.Admin
  let assert Ok(ed) = users.create_with_role(s, "ed", "h", role.Editor, by: "t")
  assert ed.role == role.Editor
  let assert Ok(Nil) = users.set_role(s, "ed", role.Viewer, by: "t")
  let assert Ok(ed) = users.get(s, "ed")
  assert ed.role == role.Viewer
  // the last administrator keeps their role and cannot be deleted
  let assert Error(_) = users.set_role(s, "root", role.Editor, by: "t")
  let assert Error(_) = users.delete(s, "root", by: "t")
  let assert Ok(Nil) = users.set_role(s, "ed", role.Admin, by: "t")
  let assert Ok(Nil) = users.set_role(s, "root", role.Editor, by: "t")
}

/// Accounts stored before roles existed are administrators.
pub fn users_without_a_role_are_admins_test() {
  let s = settings()
  let assert Ok(Nil) =
    simplifile.write(
      s.path,
      "{\"version\":1,\"users\":[{\"username\":\"old\",\"password_hash\":\"h\"}]}",
    )
  let assert Ok(old) = users.get(s, "old")
  assert old.role == role.Admin
}
