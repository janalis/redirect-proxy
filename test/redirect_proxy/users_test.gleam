import gleam/list
import redirect_proxy/password
import redirect_proxy/users
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

pub fn last_user_cannot_be_deleted_test() {
  let s = settings()
  let assert Ok(_) = users.create(s, "one", "x", by: "t")
  let assert Ok(_) = users.create(s, "two", "x", by: "t")
  let assert Ok(Nil) = users.delete(s, "one", by: "t")
  let assert Error(_) = users.delete(s, "two", by: "t")
  let assert Error(_) = users.delete(s, "ghost", by: "t")
  assert users.count(s) == 1
}
