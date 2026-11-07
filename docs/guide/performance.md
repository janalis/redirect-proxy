# Performance

## Compared with other servers

The *Benchmark* workflow serves 10 000 exact, 1 000 prefix and 500 regex
rules with redirect-proxy and with the servers people usually turn to for
redirects: nginx, HAProxy, Caddy, Traefik and Apache httpd. It runs every
week and after each release, then publishes the new numbers (a server that
fails its check holds them back for review), so the results below follow
both redirect-proxy and the latest stable release of each server.

<BenchmarkResults />

How it is measured (`scripts/bench-compare.py`):

- Every server runs from its official Docker image (`nginx:stable`,
  `haproxy:lts`, `caddy:2`, `traefik:v3`, `httpd:2.4`; redirect-proxy from
  the commit being measured) and is limited to half of the CPUs. The load
  generator, [oha](https://github.com/hatoo/oha) in a container too, gets
  the other half. Both are on a private Docker network.
- Each server gets the rules in the form it serves fastest: a hash map for
  exact rules where it has one, and its own prefix and regular expression
  constructs. "How each server is configured" above lists them.
- Before being timed, each server must answer every scenario with the
  expected status and `Location`; one that does not is shown as failed.
- Each scenario runs for 10 s with 100 keep-alive connections, after a 2 s
  warm-up, three times. The median is kept. Access logs are off everywhere.
- The client and the servers share one machine, which is a shared CI
  runner: compare the servers with each other, not with your own traffic.

`make bench-compare` runs it on your machine (Docker only). `--only
nginx,caddy` measures some of the servers, and `EXACT`, `PREFIX`, `REGEX`,
`DURATION`, `RUNS`, `CONCURRENCY` and `SERVER_CPUS` change the parameters.

## redirect-proxy alone

`make bench` (or the *Benchmark* workflow) generates the same rules
and runs redirect-proxy from the checkout. It load-tests four scenarios with
[oha](https://github.com/hatoo/oha), falling back to ApacheBench:

- An exact hit.
- A prefix hit.
- The last regex.
- A miss. Prefix and regex rules starting with a literal are indexed, so a
  miss does not try every rule; regex rules that do not start with `^` and
  a literal are all run.

It reports throughput, latency percentiles and memory. The access log is
written to a file during the run, as it is enabled by default
(`RP_ACCESS_LOG_ENABLED=false` measures without it).

Rule lookup itself, measured in-process with the same 11 500 rules, takes
about 0.4 µs for an exact hit, 1.2 µs for a prefix hit, 1.9 µs for the last
regex rule and 0.7 µs for a miss.

`make bench-handler` times the rest of the work of a request in the
process that serves it, without the network: parsing the request head and
running the handler (lookup, metrics, response), best of 15 runs. It does
not depend on the load of other processes as much as a load test does.

`make bench-matcher` measures the work of one redirect in-process (lookup,
hit count and `Location`), in BEAM reductions, for more request shapes:
many prefix lengths, unindexed regexes, many hosts and wildcard hosts,
query conditions and trailing slash retries. Reductions do not depend on
the load of the machine, so CI compares them with
`scripts/matcher-bench-baseline.json` and fails a change that makes a
scenario more than 10 % more expensive (`scripts/matcher-bench.py
--update` writes a new baseline).

Memory:

- An idle node with no rules uses about 70 MB RSS in the container image.
- Loading 11 500 rules adds about 5 MB to the shared snapshot.

Run the benchmark on your own hardware before sizing.

## The redirect listener

The traffic port is served by a small HTTP server made for redirects, not
by the general purpose one of the admin and the API: one process per
connection, one read and one write per request, and nothing else.

- HTTP/1.1 and 1.0, with keep-alive and pipelining. No TLS or HTTP/2 on
  this port: put a TLS proxy in front (`server.https_redirect` redirects
  the requests it does not mark `X-Forwarded-Proto: https`).
- A connection idle for 10 s, or that takes as long to send a request
  head, is closed.
- A request head (request line and headers) is limited to
  `server.max_path_bytes` + 64 KiB: a longer request line gets 414, longer
  headers 431.
- Request bodies are never read: the request is answered, then its
  connection is closed.
- Malformed requests get 400 and the connection is closed: a request target
  that is not an absolute path, or has characters a URI cannot hold (a raw
  backslash, space, quote or non-ASCII byte); anything but one space
  between the parts of the request line, or after `HTTP/1.x`; a header name
  that is not a token or is followed by whitespace; control characters or
  invalid UTF-8 in a header value; a folded header line; a second `Host`;
  an HTTP/1.1 request without `Host`. Any other
  HTTP version than 1.0 and 1.1 gets 505.
