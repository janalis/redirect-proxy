# Performance

`make bench` (or the *Benchmark* workflow) generates 10 000 exact, 1 000
prefix and 500 regex rules. It then load-tests four scenarios with
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

Measured locally on a laptop with the self-contained bundle, using
ApacheBench (single-threaded, so the client is the bottleneck): redirects
ran at about 14 000 requests/s.

Rule lookup itself, measured in-process with the same 11 500 rules, takes
about 0.4 µs for an exact hit, 1.2 µs for a prefix hit, 1.9 µs for the last
regex rule and 0.7 µs for a miss.

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
