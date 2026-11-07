# Command line

```text
redirect-proxy [serve] [--config FILE]
redirect-proxy check-config [--config FILE]   # also warns about unknown keys
redirect-proxy user add <username> [--role ROLE] | user passwd|delete <username> | user role <username> <ROLE> | user list
redirect-proxy client add <name> [--scope SCOPE]... | client list | client rotate|delete <client_id>
redirect-proxy rules validate [FILE] | rules export | rules import <FILE> [--replace]
redirect-proxy version | help
```

`user add` and `user passwd` read the password from `$RP_PASSWORD` or prompt
for it. `rules import` writes the file; a running server applies it on
`SIGHUP` or "Reload from disk".
