//// Tests of the OAuth 2.0 token endpoint and of API clients.

import api_support.{basic, field, header, new_client, token_request}
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/string
import redirect_proxy/admin/auth/ratelimit
import redirect_proxy/api/clients
import redirect_proxy/api/scope
import redirect_proxy/config
import redirect_proxy/ffi
import simplifile
import support

pub fn token_endpoint_test() {
  let env = support.boot(config.default())
  let #(id, secret) = new_client(env, [scope.Write, scope.Ops])
  let grant = [#("grant_type", "client_credentials")]

  // client_secret_basic
  let resp = token_request(env, [basic(id, secret)], grant)
  assert resp.status == 200
  assert header(resp, "cache-control") == "no-store"
  assert field(resp.body, ["token_type"], decode.string) == "Bearer"
  assert field(resp.body, ["expires_in"], decode.int) == 3600
  assert field(resp.body, ["scope"], decode.string)
    == "redirects:write redirects:ops"

  // client_secret_post and scope narrowing
  let resp =
    token_request(env, [], [
      #("client_id", id),
      #("client_secret", secret),
      #("scope", "redirects:read"),
      ..grant
    ])
  assert resp.status == 200
  assert field(resp.body, ["scope"], decode.string) == "redirects:read"

  // scope wider than granted
  let resp =
    token_request(env, [basic(id, secret)], [
      #("scope", "redirects:read bogus"),
      ..grant
    ])
  assert resp.status == 400
  assert field(resp.body, ["error"], decode.string) == "invalid_scope"

  // wrong secret
  let resp = token_request(env, [basic(id, "nope")], grant)
  assert resp.status == 401
  assert field(resp.body, ["error"], decode.string) == "invalid_client"
  assert string.starts_with(header(resp, "www-authenticate"), "Basic")

  // unknown client, unsupported grant
  assert token_request(env, [basic("rp_nobody", secret)], grant).status == 401
  let resp =
    token_request(env, [basic(id, secret)], [#("grant_type", "password")])
  assert resp.status == 400
  assert field(resp.body, ["error"], decode.string) == "unsupported_grant_type"
}

pub fn token_requests_are_audited_test() {
  let env = support.boot(config.default())
  // other tests spend the audit log's budget for failures
  ratelimit.reset("audit-failures")
  let #(id, secret) = new_client(env, [scope.Read])
  let ok =
    token_request(env, [basic(id, secret)], [
      #("grant_type", "client_credentials"),
    ])
  assert ok.status == 200
  let bad =
    token_request(env, [basic(id, "wrong")], [
      #("grant_type", "client_credentials"),
    ])
  assert bad.status == 401
  let assert Ok(audit) = simplifile.read(config.audit_path(env.config))
  assert string.contains(audit, "\"action\":\"api.token_issued\"")
  assert string.contains(audit, "\"action\":\"api.token_rejected\"")
  assert string.contains(audit, "\"scope\":\"redirects:read\"")
  // a wrong secret for a real client is filed under that client
  assert string.contains(audit, "\"actor\":\"client:" <> id <> "\"")
  // an unknown client id is not taken as the actor
  let unknown =
    token_request(env, [basic("rp_nobody", "x")], [
      #("grant_type", "client_credentials"),
    ])
  assert unknown.status == 401
  let assert Ok(audit) = simplifile.read(config.audit_path(env.config))
  assert !string.contains(audit, "\"actor\":\"client:rp_nobody\"")
  assert string.contains(audit, "\"target\":\"rp_nobody\"")
}

pub fn token_endpoint_throttling_test() {
  let env = support.boot(config.default())
  let #(id, _) = new_client(env, [scope.Read])
  let statuses =
    list.repeat(Nil, 11)
    |> list.map(fn(_) {
      token_request(env, [basic(id, "wrong")], [
        #("grant_type", "client_credentials"),
      ]).status
    })
  assert list.take(statuses, 10) == list.repeat(401, 10)
  assert list.last(statuses) == Ok(429)
  let resp =
    token_request(env, [basic(id, "wrong")], [
      #("grant_type", "client_credentials"),
    ])
  let assert Ok(seconds) = int.parse(header(resp, "retry-after"))
  assert seconds > 0 && seconds <= 900
}

/// Failures from many addresses do not lock a client out: its secret is
/// too long to guess, a limit per client would only help a denial of
/// service.
pub fn token_client_is_not_locked_out_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, secret) = new_client(env, [scope.Read])
  let request = fn(secret, ip) {
    token_request(env, [basic(id, secret), #("x-forwarded-for", ip)], [
      #("grant_type", "client_credentials"),
    ]).status
  }
  list.each(int.range(1, 13, [], list.prepend), fn(n) {
    list.each(list.repeat(Nil, 10), fn(_) {
      assert request("wrong", "198.51.100." <> int.to_string(100 + n)) == 401
    })
  })
  assert request(secret, "198.51.100.200") == 200
}

/// One IPv6 host holds a whole /64: its addresses share their limits.
pub fn token_throttling_counts_ipv6_by_64_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, _) = new_client(env, [scope.Read])
  let statuses =
    int.range(1, 12, [], list.prepend)
    |> list.map(fn(n) {
      token_request(
        env,
        [
          basic(id, "wrong"),
          #("x-forwarded-for", "2001:db8:77:1::" <> int.to_string(n)),
        ],
        [#("grant_type", "client_credentials")],
      ).status
    })
  assert list.take(statuses, 10) == list.repeat(401, 10)
  assert list.last(statuses) == Ok(429)
}

/// Token requests are small: a large body is refused before it is read.
pub fn token_request_body_is_limited_test() {
  let env = support.boot(config.default())
  let resp =
    token_request(env, [], [
      #("grant_type", "client_credentials"),
      #("padding", string.repeat("x", 70_000)),
    ])
  assert resp.status == 413
}

/// A successful token request forgives that client's failures from that
/// address (a pipeline that recovered is not one failure from a 429).
pub fn token_success_resets_the_address_failures_test() {
  let d = config.default()
  let env =
    support.boot(
      config.Config(
        ..d,
        access_log: config.AccessLogConfig(..d.access_log, trusted_proxies: [
          "127.0.0.1/32",
        ]),
      ),
    )
  let #(id, secret) = new_client(env, [scope.Read])
  // its own address: the per address count must not block other tests
  let request = fn(secret) {
    token_request(
      env,
      [basic(id, secret), #("x-forwarded-for", "198.51.100.30")],
      [#("grant_type", "client_credentials")],
    ).status
  }
  assert list.map(list.repeat(Nil, 9), fn(_) { request("wrong") })
    == list.repeat(401, 9)
  assert request(secret) == 200
  assert list.map(list.repeat(Nil, 10), fn(_) { request("wrong") })
    == list.repeat(401, 10)
  assert request("wrong") == 429
}

pub fn clients_store_unit_test() {
  let dir = support.temp_dir()
  let settings =
    clients.Settings(
      path: dir <> "/api_clients.json",
      audit_path: dir <> "/audit.jsonl",
    )
  let assert Error(_) = clients.create(settings, "", [scope.Read], by: "t")
  let assert Error(_) = clients.create(settings, "x", [], by: "t")
  let assert Ok(#(c, secret)) =
    clients.create(settings, "ci", [scope.Read], by: "t")
  assert string.starts_with(c.client_id, "rp_")
  let assert Ok(_) = clients.authenticate(settings, c.client_id, secret)
  let assert Error(Nil) = clients.authenticate(settings, c.client_id, "x")
  let assert Ok(new_secret) = clients.rotate(settings, c.client_id, by: "t")
  let assert Error(Nil) = clients.authenticate(settings, c.client_id, secret)
  let assert Ok(_) = clients.authenticate(settings, c.client_id, new_secret)
  let assert Ok(Nil) = clients.delete(settings, c.client_id, by: "t")
  let assert Error(_) = clients.delete(settings, c.client_id, by: "t")
  let assert Error(_) = clients.rotate(settings, c.client_id, by: "t")
  // the secret hash never leaks in the public representation
  assert !string.contains(json.to_string(clients.public_json(c)), c.secret_hash)
}

/// The CLI holds api_clients.json.lock: client changes wait for it, while
/// authentication never waits (it only skips the last-use update).
pub fn clients_wait_for_another_process_test() {
  let dir = support.temp_dir()
  let s =
    clients.Settings(
      path: dir <> "/api_clients.json",
      audit_path: dir <> "/audit.jsonl",
    )
  let assert Ok(#(client, secret)) =
    clients.create(s, "ci", [scope.Read], by: "test")
  let lock = s.path <> ".lock"
  let assert Ok(Nil) = simplifile.write(lock, "4242 cli@host\n")
  // well under the 5 s a change waits for the lock
  let started = ffi.now_millis()
  let assert Ok(_) = clients.authenticate(s, client.client_id, secret)
  assert ffi.now_millis() - started < 4000
  let released = process.new_subject()
  process.spawn(fn() {
    process.sleep(300)
    // told before the lock goes: a change that waited for it finds this
    process.send(released, Nil)
    let _ = simplifile.delete(lock)
  })
  let assert Ok(_) = clients.rotate(s, client.client_id, by: "test")
  assert process.receive(released, 0) == Ok(Nil)
}
