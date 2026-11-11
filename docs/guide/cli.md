# Command line

```text
redirect-proxy [serve] [--config FILE]
redirect-proxy check-config [--config FILE]
redirect-proxy user add <username> [--role ROLE] [--config FILE]
redirect-proxy user role <username> <ROLE> [--config FILE]
redirect-proxy user passwd <username> [--config FILE]
redirect-proxy user delete <username> [--config FILE]
redirect-proxy user list [--config FILE]
redirect-proxy client add <name> [--scope SCOPE]... [--config FILE]
redirect-proxy client list|rotate <client_id>|delete <client_id> [--config FILE]
redirect-proxy rules validate [FILE] [--config FILE]
redirect-proxy rules export [--config FILE]
redirect-proxy rules import <FILE> [--replace] [--config FILE]
redirect-proxy version
redirect-proxy help
```

## Configuration

Every command reads the same configuration as the server, from the first
of:

1. `--config FILE` (or `--config=FILE`), anywhere on the command line;
2. the `RP_CONFIG` environment variable;
3. `/etc/redirect-proxy/config.toml`, when that file exists (the packages
   install it there);
4. no file: the defaults.

Environment variables override the file, as for the server (see
[Configuration](configuration)). Commands that manage users, API clients
or rules work on the files of the configured data directory
(`storage.data_dir`), so run them with the server's configuration and as
the server's user. `sudo` drops `RP_CONFIG`, which is why the packaged
file is used without it. Commands that change something print the data
directory they change on standard error, and warn when root changes a
directory owned by another user (the files it creates would belong to
root, and the service could not read them): run them as that user, for
example `sudo -u redirect-proxy redirect-proxy user add alice`.

Before the configuration is loaded, the command's own log follows
`RP_LOG_LEVEL` and `RP_LOG_FORMAT`.

## Exit status

`0` on success. On any error (an invalid configuration, an unknown
command or argument, a rule or password that is refused, a file that
cannot be read) the command prints the reason after `error:` on standard
error and exits with `1`; an unknown command also prints the usage.

## `serve`

```sh
redirect-proxy serve --config /etc/redirect-proxy/config.toml
```

Starts the redirect listener, and the admin and API listeners when they
are enabled. `serve` is the default: `redirect-proxy` alone does the same.
It runs until it is stopped; see [Operations](operations) for signals
(`SIGHUP` reloads the rules, `SIGTERM` drains then stops).

## `check-config`

```sh
redirect-proxy check-config --config config.toml
```

Loads the configuration as the server would and prints `configuration
OK`, then warnings (unknown keys such as a misspelt section, risky
settings, a data directory that is not writable), the data directory, the
listeners and the sign-in methods. An invalid configuration exits with
`1`, so the command can gate a deployment.

## `user add`

```sh
redirect-proxy user add alice --role editor
RP_PASSWORD='a-long-password' redirect-proxy user add ci-admin
```

Creates a local account. The role is `viewer`, `editor` or `admin`, and
defaults to **`admin`**: pass `--role` (before or after the name) for
anyone else. The password is read from `RP_PASSWORD`, or prompted for
twice; weak passwords are refused. See [Roles](authentication#roles).

## `user role`

```sh
redirect-proxy user role alice viewer
```

Changes a user's role. The change applies to the user's sessions at once.
The last administrator cannot be demoted.

## `user passwd`

```sh
redirect-proxy user passwd alice
```

Sets a new password, from `RP_PASSWORD` or prompted for.

## `user delete`

```sh
redirect-proxy user delete alice
```

Deletes a local account. The last administrator cannot be deleted.

## `user list`

```sh
redirect-proxy user list
```

One line per local account: name, role and creation date, separated by
tabs.

## `client add`

```sh
redirect-proxy client add deploy --scope redirects:read --scope redirects:write
```

Creates an [API client](api) and prints its `client_id` and
`client_secret`. **The secret is shown only once**: store it now (it is
kept hashed). `--scope` (or `--scope=SCOPE`) can be repeated; without it
the client gets `redirects:write`. The scopes:

| Scope | Allows |
| --- | --- |
| `redirects:read` | Listing, exporting and testing rules. |
| `redirects:write` | Also creating, changing, deleting and importing rules (implies `redirects:read`). |
| `redirects:ops` | Reloading `redirects.json` from disk. |
| `audit:read` | Reading the audit log. |

## `client list`

```sh
redirect-proxy client list
```

One line per client: `client_id`, name, scopes and when it was last used,
separated by tabs. Secrets are never shown.

## `client rotate`

```sh
redirect-proxy client rotate rp_xxxxxxxxxxxxxxxx
```

Prints a new secret, shown once, and revokes the access tokens issued
with the previous one, on a running server too.

## `client delete`

```sh
redirect-proxy client delete rp_xxxxxxxxxxxxxxxx
```

Deletes a client and revokes its tokens.

## `rules validate`

```sh
redirect-proxy rules validate redirects.csv
redirect-proxy rules validate
```

Checks a rules file, JSON or [CSV](rules#csv), as an import would: the
format, every rule, ids that are reserved or not URL-safe, duplicate ids
and exact sources, redirect loops, and rules that can never apply. It
does not compare the file with the current rules, which a merge may
conflict with. It prints `<file>: N valid rule(s)`, or the errors and
exits with `1`. Without `FILE`, it checks the configured data directory's
`redirects.json` as loading does, for example after editing it by hand
and before sending `SIGHUP`. It needs no running server: use it in CI (see
[Rules in git](api#rules-in-git)).

## `rules export`

```sh
redirect-proxy rules export > redirects-backup.json
```

Prints the configured data directory's rules to standard output as JSON,
in the format of `redirects.json`, without hit counts. `GET
/api/redirects/export` does the same over the API, and also as CSV.

## `rules import`

```sh
redirect-proxy rules import new-rules.csv
redirect-proxy rules import redirects.json --replace
```

Imports a JSON or CSV file into the configured data directory's
`redirects.json`, all or nothing. By default the rules are merged by
`id`: a rule whose `id` exists replaces it, the others are added (without
an `id`, as new rules: keep ids in files you import more than once, see
[Migrating](migration#importing-more-than-once)). `--replace` makes the
file the whole rule set. The previous file is kept in the backups.

The command writes the file; it does not reach a running server. The
server applies it on `SIGHUP`, *Reload from disk* in the admin, `POST
/api/reload`, or by itself within `storage.watch_interval` seconds when
that is set. To change the rules of a running server directly, import
through the admin or `POST /api/redirects/import`.

## `version`

```sh
redirect-proxy version
```

Prints `redirect-proxy` and its version. `--version` and `-v` do the
same.

## `help`

```sh
redirect-proxy help
```

Prints the usage. `--help` and `-h` do the same.
