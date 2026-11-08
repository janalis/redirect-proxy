#!/usr/bin/env python3
"""Load tests redirect-proxy and other servers people use for redirects
(nginx, HAProxy, Caddy, Traefik, Apache httpd) with the same rules and the
same requests, and writes the results for the documentation and the README.

    scripts/bench-compare.py                   # every server
    scripts/bench-compare.py --only nginx      # some of them
    scripts/bench-compare.py --readme          # also rewrite the README table
    scripts/bench-compare.py --from FILE --readme   # README from saved results

Needs Docker. Every server runs from its official image (floating stable
tag, the exact version and digest are recorded) in a container limited to
half of the CPUs, and the load generator (oha, also a container) gets the
other half, on a private Docker network. Access logs are off everywhere:
HAProxy cannot write them to a file, and log shipping is not what is
measured.

Each server is first checked: a server that does not answer every scenario
with the expected redirection is reported as failed, and not timed.

Environment: EXACT=10000 PREFIX=1000 REGEX=500 (rules), DURATION=10s
WARMUP=2s RUNS=3 CONCURRENCY=100 (load), SERVER_CPUS=<n> (default half),
RP_IMAGE=ghcr.io/janalis/redirect-proxy:dev (built by `make docker`),
RP_PULL=1 (RP_IMAGE is a published image: pull it, record its digest),
RP_VERSION=<label> (shown instead of the version the image reports, e.g.
`main (7c2583c)` for an image built from main), RP_ERL_FLAGS=<flags> (VM
flags of redirect-proxy, through ERL_FLAGS).

Variants of redirect-proxy, for an A/B on the same machine (runners differ
from run to run: only numbers from one run compare):

    RP_VARIANTS='sbwt-short=+sbwt short; 0.7.0@ghcr.io/janalis/redirect-proxy:0.7.0'
    RP_VARIANTS='log-on|RP_ACCESS_LOG_ENABLED=true,RP_ACCESS_LOG_FORMAT=json'

Each `label[@image][=ERL_FLAGS][|K=V,K=V]` entry (`;` or newline separated)
is measured after redirect-proxy itself, as `redirect-proxy (label)`, with
RP_IMAGE when it names no image, and the environment variables after `|`
(upper-case names; a value may hold commas, `;` and `|` are reserved).
The results then go to build/benchmark-variants.json, never to the
documentation.

EXTRA_SCENARIOS=mixed,exact-churn,upstream,upstream-churn (comma separated)
adds scenarios that are never published either (same file as variants):

- `mixed`: MIXED_URLS (10000) random URLs, 70 % exact hits, 15 % prefix
  hits, 5 % regex hits and 10 % misses, with browser-like headers (about
  600 bytes); a sample of each kind is checked first. It is followed by
  `mixed-rate`: the same requests at a fixed rate, FIXED_RATE req/s
  (default: FIXED_RATE_SHARE=0.5 of the first server's `mixed` median, then
  the same rate for every server), latencies corrected for coordinated
  omission. `mixed-rate` alone needs FIXED_RATE.
- `exact-churn`: the exact hit, one connection per request.
- `upstream`, `upstream-churn` (redirect-proxy only): a miss forwarded to
  an nginx upstream (RP_SERVER_UPSTREAM) answering 200 with a small body,
  with keep-alive and with one connection per request. redirect-proxy is
  restarted with the upstream after its other scenarios.

SOAK=10m (redirect-proxy only, no EXTRA_SCENARIOS or --profile): instead
of the scenarios, the `mixed` requests for that long (at SOAK_RATE req/s,
default as fast as possible) with the access log on (rotated file; a
variant's environment overrides these settings), sampling the container's
anonymous memory (cgroup `anon`, without the log's page cache), `docker
stats` (page cache included) and the server's metrics (memory, processes,
requests) every SOAK_INTERVAL=15 s; reports the memory slopes in MiB/min
after the first SOAK_WARMUP=60 s, under load only (the sample taken once
the load stopped is reported apart, as `after`), and the slopes of the
second half of those samples alone: memory that grows in steps then
levels off (allocator carriers) has a positive slope overall but a flat
second half, a leak keeps growing in both.

--profile: during the first run of the PROFILE_SCENARIO scenario (default
exact), microstate accounting of each redirect-proxy (where its schedulers
spend their time) and, when `sudo perf` works, a CPU profile, written to
build/profile-<label>.txt.
"""
import argparse
import datetime
import http.client
import json
import os
import pathlib
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "data" / "benchmark.json"
README = ROOT / "README.md"
OHA = ("ghcr.io/hatoo/oha:1.16.0@sha256:"
       "3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f")
NETWORK = "redirect-proxy-bench"
SERVER = "redirect-proxy-bench-server"
TARGET = "https://new.example.com"

EXACT = int(os.environ.get("EXACT", "10000"))
PREFIX = int(os.environ.get("PREFIX", "1000"))
REGEX = int(os.environ.get("REGEX", "500"))
DURATION = os.environ.get("DURATION", "10s")
WARMUP = os.environ.get("WARMUP", "2s")
RUNS = int(os.environ.get("RUNS", "3"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "100"))
RP_IMAGE = os.environ.get("RP_IMAGE", "ghcr.io/janalis/redirect-proxy:dev")
RP_PULL = os.environ.get("RP_PULL") == "1"
RP_VERSION = os.environ.get("RP_VERSION", "")
RP_ERL_FLAGS = os.environ.get("RP_ERL_FLAGS", "")

# name -> (path, expected status, expected Location)
SCENARIOS = {
    "exact": (f"/exact/{EXACT - 1}", 301, f"{TARGET}/e/{EXACT - 1}"),
    "prefix": (f"/prefix/{PREFIX - 1}/some/page", 302,
               f"{TARGET}/p/{PREFIX - 1}/some/page"),
    "regex": (f"/regex/{REGEX - 1}/42", 308, f"{TARGET}/r/{REGEX - 1}/42"),
    "miss": ("/nothing/here", 404, None),
}

# Extra scenarios (EXTRA_SCENARIOS), never published: name -> settings.
# `statuses`: the expected ones (a 3xx stands for any 3xx, see check);
# `urls`: the mixed URL file instead of one path; `headers`: browser-like;
# `rate`: at FIXED_RATE; `upstream`: redirect-proxy forwarding to UPSTREAM.
MIXED_STATUSES = (301, 302, 308, 404)
EXTRA = {
    "mixed": {"urls": True, "headers": True, "statuses": MIXED_STATUSES},
    "mixed-rate": {"urls": True, "headers": True, "rate": True,
                   "statuses": MIXED_STATUSES},
    "exact-churn": {"path": SCENARIOS["exact"][0], "churn": True,
                    "statuses": (301,)},
    "upstream": {"path": "/site/page", "headers": True, "upstream": True,
                 "statuses": (200,)},
    "upstream-churn": {"path": "/site/page", "headers": True, "churn": True,
                       "upstream": True, "statuses": (200,)},
}
MIX = (("exact", 70), ("prefix", 15), ("regex", 5), ("miss", 10))
MIXED_URLS = int(os.environ.get("MIXED_URLS", "10000"))
FIXED_RATE = int(os.environ.get("FIXED_RATE", "0"))
FIXED_RATE_SHARE = float(os.environ.get("FIXED_RATE_SHARE", "0.5"))
PROFILE_SCENARIO = os.environ.get("PROFILE_SCENARIO", "exact")
# What a browser sends when it follows a link over plain HTTP (about 600
# bytes; no client hints, which are for HTTPS)
BROWSER_HEADERS = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language: en-US,en;q=0.9,fr;q=0.8",
    "Referer: https://www.example.org/blog/2026/10/an-article?utm_source=news",
    "Cookie: _ga=GA1.1.1234567890.1760000000; "
    "_ga_ABCDEF1234=GS1.1.1760000000.1.1.1760000100.0.0.0; "
    "session=4f9d2c6a8b7e1f3a5c9d0e2b4a6c8e0f",
    "Sec-Fetch-Dest: document",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-Site: cross-site",
    "Sec-Fetch-User: ?1",
    "Upgrade-Insecure-Requests: 1",
]
# One connection per request: enough ports on both sides of the churn
CHURN_SYSCTLS = ["net.ipv4.tcp_tw_reuse=1",
                 "net.ipv4.ip_local_port_range=1024 65535"]
UPSTREAM = "redirect-proxy-bench-upstream"
UPSTREAM_BODY = "hello from the upstream\n"

SOAK = os.environ.get("SOAK", "")
SOAK_RATE = int(os.environ.get("SOAK_RATE", "0"))
SOAK_INTERVAL = int(os.environ.get("SOAK_INTERVAL", "15"))
SOAK_WARMUP = int(os.environ.get("SOAK_WARMUP", "60"))
METRICS_PATH = "/bench-metrics"
METRICS_TOKEN = "bench-only-metrics-token-not-a-secret"
SOAK_ENV = {
    "RP_ACCESS_LOG_ENABLED": "true",
    "RP_ACCESS_LOG_OUTPUT": "/etc/bench/access.log",
    "RP_ACCESS_LOG_MAX_BYTES": str(64 * 1024 * 1024),
    "RP_ACCESS_LOG_MAX_FILES": "2",
    "RP_SERVER_METRICS_PATH": METRICS_PATH,
    "RP_ADMIN_METRICS_TOKEN": METRICS_TOKEN,
}

# Files the load generator reads (mixed URLs) and the upstream's
# configuration, mounted at /bench; set by main
SHARED = None
# FIXED_RATE once known (the first `mixed` median otherwise)
RATE = {"rps": FIXED_RATE or None}


# --- configurations ----------------------------------------------------------
# Each takes the directory mounted at /etc/bench (read-only, except for
# redirect-proxy, which keeps its hit counts next to the rules) and returns
# the container settings. Every server uses its fastest idiomatic construct
# for each kind of rule; where it has none, `notes` says what it uses.

def redirect_proxy(d):
    rules = (
        [{"source": f"/exact/{i}", "target": f"{TARGET}/e/{i}"}
         for i in range(EXACT)]
        + [{"match": "prefix", "source": f"/prefix/{i}/",
            "target": f"{TARGET}/p/{i}/$1", "status": 302}
           for i in range(PREFIX)]
        + [{"match": "regex", "source": f"^/regex/{i}/(\\d+)$",
            "target": f"{TARGET}/r/{i}/$1", "status": 308}
           for i in range(REGEX)]
    )
    (d / "redirects.json").write_text(
        json.dumps({"version": 1, "rules": rules}))
    d.chmod(0o777)
    return {
        "image": RP_IMAGE,
        "pull": RP_PULL,  # by default, built from this checkout
        "label": RP_VERSION,
        "writable": True,
        "env": {
            "RP_STORAGE_DATA_DIR": "/etc/bench",
            "RP_ADMIN_ENABLED": "false",
            "RP_ACCESS_LOG_ENABLED": "false",
            "RP_STORAGE_BACKUPS": "0",
            "RP_LOG_LEVEL": "warning",
            **({"ERL_FLAGS": RP_ERL_FLAGS} if RP_ERL_FLAGS else {}),
            # before a variant's environment, which wins
            **(SOAK_ENV if SOAK else {}),
        },
        "version": ["/opt/redirect-proxy/bin/redirect-proxy", "version"],
        "notes": [],
    }


def nginx(d):
    (d / "exact.map").write_text("".join(
        f"/exact/{i} {TARGET}/e/{i};\n" for i in range(EXACT)))
    prefix = "".join(
        f"    location ^~ /prefix/{i}/ {{ rewrite ^/prefix/{i}/(.*)$ "
        f"{TARGET}/p/{i}/$1 redirect; }}\n" for i in range(PREFIX))
    regex = "".join(
        f"    location ~ ^/regex/{i}/(\\d+)$ {{ return 308 {TARGET}/r/{i}/$1; }}\n"
        for i in range(REGEX))
    (d / "nginx.conf").write_text(f"""\
worker_processes auto;
error_log stderr warn;
pid /tmp/nginx.pid;
events {{ worker_connections 4096; }}
http {{
  access_log off;
  keepalive_requests 1000000;
  map_hash_max_size {2 * EXACT};
  map_hash_bucket_size 128;
  map $uri $exact {{
    default "";
    include /etc/bench/exact.map;
  }}
  server {{
    listen 8080;
    if ($exact) {{ return 301 $exact; }}
{prefix}{regex}    location / {{ return 404; }}
  }}
}}
""")
    return {
        "image": "nginx:stable",
        "cmd": ["nginx", "-c", "/etc/bench/nginx.conf", "-g", "daemon off;"],
        "version": ["nginx", "-v"],
        "notes": ["exact rules in a `map` (hash), prefix rules are `^~` "
                  "locations with one `rewrite` each, regex rules are "
                  "`~` locations"],
    }


def haproxy(d):
    (d / "exact.map").write_text("".join(
        f"/exact/{i} {TARGET}/e/{i}\n" for i in range(EXACT)))
    (d / "prefix.map").write_text("".join(
        f"/prefix/{i}/ {TARGET}/p/{i}/\n" for i in range(PREFIX)))
    (d / "prefix-length.map").write_text("".join(
        f"/prefix/{i}/ {len(f'/prefix/{i}/')}\n" for i in range(PREFIX)))
    (d / "regex.map").write_text("".join(
        f"^/regex/{i}/([0-9]+)$ {TARGET}/r/{i}/\\1\n" for i in range(REGEX)))
    (d / "haproxy.cfg").write_text("""\
global
  maxconn 20000

defaults
  mode http
  timeout connect 5s
  timeout client 60s
  timeout server 60s

frontend web
  bind :8080
  http-request set-var(txn.exact) path,map_str(/etc/bench/exact.map)
  http-request redirect location %[var(txn.exact)] code 301 if { var(txn.exact) -m found }
  http-request set-var(txn.prefix) path,map_beg(/etc/bench/prefix.map)
  http-request set-var(txn.length) path,map_beg(/etc/bench/prefix-length.map) if { var(txn.prefix) -m found }
  http-request redirect location %[var(txn.prefix)]%[path,bytes(txn.length)] code 302 if { var(txn.prefix) -m found }
  http-request set-var(txn.regex) path,map_regm(/etc/bench/regex.map)
  http-request redirect location %[var(txn.regex)] code 308 if { var(txn.regex) -m found }
  http-request return status 404
""")
    return {
        "image": "haproxy:lts",
        "cmd": ["haproxy", "-f", "/etc/bench/haproxy.cfg"],
        "version": ["haproxy", "-v"],
        "notes": ["`map_str` for exact rules, `map_beg` for prefix rules, "
                  "`map_regm` for regex rules"],
    }


def caddy(d):
    exact = "".join(f"\t\t/exact/{i} {TARGET}/e/{i}\n" for i in range(EXACT))
    prefix = "".join(
        f"\thandle_path /prefix/{i}/* {{\n\t\tredir {TARGET}/p/{i}{{path}} 302\n\t}}\n"
        for i in range(PREFIX))
    regex = "".join(
        f"\t@r{i} path_regexp r{i} ^/regex/{i}/(\\d+)$\n"
        f"\tredir @r{i} {TARGET}/r/{i}/{{re.r{i}.1}} 308\n"
        for i in range(REGEX))
    (d / "Caddyfile").write_text(f"""\
{{
\tadmin off
\tauto_https off
\tpersist_config off
\tlog {{
\t\tlevel WARN
\t}}
}}

:8080 {{
\tmap {{path}} {{exact}} {{
{exact}\t\tdefault ""
\t}}
\t@exact not vars {{exact}} ""
\tredir @exact {{exact}} 301
{regex}{prefix}\thandle {{
\t\trespond 404
\t}}
}}
""")
    return {
        "image": "caddy:2",
        "cmd": ["caddy", "run", "--config", "/etc/bench/Caddyfile",
                "--adapter", "caddyfile"],
        "version": ["caddy", "version"],
        "notes": ["exact rules in a `map`, prefix rules are `handle_path` "
                  "blocks, regex rules are `path_regexp` matchers"],
    }


def traefik(d):
    routers, middlewares = [], []

    def add(name, rule, regex, replacement, permanent):
        routers.append(
            f"    {name}:\n      rule: \"{rule}\"\n      entryPoints: [web]\n"
            f"      middlewares: [{name}]\n      service: noop@internal\n")
        middlewares.append(
            f"    {name}:\n      redirectRegex:\n        regex: '{regex}'\n"
            f"        replacement: '{replacement}'\n"
            f"        permanent: {'true' if permanent else 'false'}\n")

    for i in range(EXACT):
        add(f"e{i}", f"Path(`/exact/{i}`)", "^.*$", f"{TARGET}/e/{i}", True)
    for i in range(PREFIX):
        add(f"p{i}", f"PathPrefix(`/prefix/{i}/`)",
            f"^[^/]+//[^/]+/prefix/{i}/(.*)$", f"{TARGET}/p/{i}/${{1}}", False)
    for i in range(REGEX):
        add(f"r{i}", f"PathRegexp(`^/regex/{i}/[0-9]+$`)",
            f"^[^/]+//[^/]+/regex/{i}/([0-9]+)$", f"{TARGET}/r/{i}/${{1}}", True)
    (d / "dynamic.yml").write_text(
        "http:\n  routers:\n" + "".join(routers)
        + "  middlewares:\n" + "".join(middlewares))
    return {
        "image": "traefik:v3",
        "cmd": ["traefik", "--entryPoints.web.address=:8080",
                "--providers.file.filename=/etc/bench/dynamic.yml",
                "--log.level=WARN"],
        "version": ["traefik", "version"],
        "notes": ["one router (`Path`, `PathPrefix` or `PathRegexp`) and one "
                  "`redirectRegex` middleware per rule; `redirectRegex` "
                  "only answers 301 or 302"],
    }


def apache(d):
    (d / "exact.txt").write_text("".join(
        f"/exact/{i} {TARGET}/e/{i}\n" for i in range(EXACT)))
    prefix = "".join(
        f"RewriteRule ^/prefix/{i}/(.*)$ {TARGET}/p/{i}/$1 [R=302,L]\n"
        for i in range(PREFIX))
    regex = "".join(
        f"RewriteRule ^/regex/{i}/(\\d+)$ {TARGET}/r/{i}/$1 [R=308,L]\n"
        for i in range(REGEX))
    (d / "httpd.conf").write_text(f"""\
ServerRoot "/usr/local/apache2"
ServerName localhost
Listen 8080
LoadModule mpm_worker_module modules/mod_mpm_worker.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule rewrite_module modules/mod_rewrite.so
User daemon
Group daemon
PidFile /tmp/httpd.pid
ErrorLog /proc/self/fd/2
LogLevel warn
KeepAlive On
MaxKeepAliveRequests 0
# worker MPM, fixed pool: the event MPM, and stopping spare processes,
# close keep-alive connections under load
ServerLimit 8
StartServers 8
ThreadsPerChild 25
MaxRequestWorkers 200
MinSpareThreads 25
MaxSpareThreads 200
DocumentRoot "/usr/local/apache2/htdocs"

RewriteEngine On
RewriteMap exact "txt:/etc/bench/exact.txt"
RewriteCond ${{exact:%{{REQUEST_URI}}|NONE}} !=NONE
RewriteRule ^ ${{exact:%{{REQUEST_URI}}}} [R=301,L]
{prefix}{regex}""")
    return {
        "image": "httpd:2.4",
        "cmd": ["httpd-foreground", "-f", "/etc/bench/httpd.conf"],
        "version": ["httpd", "-v"],
        "notes": ["exact rules in a `RewriteMap txt:` (cached), prefix and "
                  "regex rules are `RewriteRule` regexes, tried in order; worker MPM "
                  "(the event MPM drops keep-alive connections under this "
                  "load)"],
    }


PRODUCTS = {
    "redirect-proxy": ("redirect-proxy", redirect_proxy),
    "nginx": ("nginx", nginx),
    "haproxy": ("HAProxy", haproxy),
    "caddy": ("Caddy", caddy),
    "traefik": ("Traefik", traefik),
    "apache": ("Apache httpd", apache),
}


ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")


def parse_variant(entry):
    """`label[@image][=ERL_FLAGS][|K=V,K=V]` -> (label, image, flags, env).
    Names are upper case; a value may hold commas (lists) when what follows
    is not `NAME=` (`,b=2` in a URL is not)."""
    head, _, env_spec = entry.partition("|")
    head, _, flags = head.partition("=")
    label, _, image = head.partition("@")
    env = {}
    for pair in re.split(r",\s*(?=[A-Z_][A-Z0-9_]*=)", env_spec.strip()):
        if not pair.strip():
            continue
        key, sep, value = pair.partition("=")
        if not sep or not ENV_NAME.fullmatch(key.strip()):
            raise ValueError(f"not K=V: {pair.strip()!r}")
        env[key.strip()] = value.strip()
    return label.strip(), image.strip(), flags.strip(), env


def variants(spec):
    """`label[@image][=ERL_FLAGS][|K=V,K=V]` entries -> [(key, name,
    configure)]."""
    out = []
    for entry in re.split(r"[;\n]", spec):
        entry = entry.strip()
        if not entry:
            continue
        try:
            label, image, flags, env = parse_variant(entry)
        except ValueError as e:
            sys.exit(f"RP_VARIANTS: {e} in {entry!r}")
        if not label:
            sys.exit(f"RP_VARIANTS: no label in {entry!r}")

        def configure(d, image=image, flags=flags, label=label, env=env):
            spec = redirect_proxy(d)
            if image:
                spec["image"] = image
                # a published image, unless it was built here
                spec["pull"] = docker("image", "inspect", image,
                                      check=False).returncode != 0
            if flags:
                spec["env"]["ERL_FLAGS"] = flags
            spec["env"].update(env)
            spec["label"] = label
            spec["notes"] = ([f"ERL_FLAGS={flags}"] if flags else []) \
                + [f"{k}={v}" for k, v in env.items()]
            return spec

        out.append((f"redirect-proxy:{label}", f"redirect-proxy ({label})",
                    configure))
    return out


def extra_scenarios(spec):
    """EXTRA_SCENARIOS -> the names to measure, in order; `mixed` brings
    its fixed-rate pass, `mixed-rate`, right after it (its rate comes from
    the `mixed` median, unless FIXED_RATE)."""
    names = []
    for name in (n.strip() for n in spec.split(",")):
        if not name or name in names or name == "mixed-rate":
            continue
        if name not in EXTRA:
            sys.exit(f"EXTRA_SCENARIOS: unknown {name!r} "
                     f"(known: {', '.join(EXTRA)})")
        names.append(name)
        if name == "mixed":
            names.append("mixed-rate")
    if "mixed-rate" in (n.strip() for n in spec.split(",")) \
            and "mixed" not in names:
        if not FIXED_RATE:
            sys.exit("EXTRA_SCENARIOS: mixed-rate without mixed needs "
                     "FIXED_RATE")
        names.append("mixed-rate")
    return names


def mixed_paths(n, seed=1):
    """`n` request paths for the mixed scenario, in random order: 70 %
    exact hits on random rules, 15 % prefix hits, 5 % regex hits, 10 %
    misses (see MIX), for the rules the configurations above generate."""
    rng = random.Random(seed)
    counts = {kind: n * share // 100 for kind, share in MIX}
    counts["exact"] += n - sum(counts.values())
    paths = (
        [f"/exact/{rng.randrange(EXACT)}" for _ in range(counts["exact"])]
        + [f"/prefix/{rng.randrange(PREFIX)}/page/{rng.randrange(1000)}"
           for _ in range(counts["prefix"])]
        + [f"/regex/{rng.randrange(REGEX)}/{rng.randrange(100000)}"
           for _ in range(counts["regex"])]
        + [f"/missing/{rng.randrange(1000000)}" for _ in range(counts["miss"])])
    rng.shuffle(paths)
    return paths


def mixed_expected(path):
    """(kind, status, Location) a mixed path must be answered with."""
    for kind, pattern, status, target in (
            ("exact", r"/exact/(\d+)", 301, "/e/{0}"),
            ("prefix", r"/prefix/(\d+)/(.*)", 302, "/p/{0}/{1}"),
            ("regex", r"/regex/(\d+)/(\d+)", 308, "/r/{0}/{1}")):
        match = re.fullmatch(pattern, path)
        if match:
            return kind, status, TARGET + target.format(*match.groups())
    return "miss", 404, None


def mixed_sample(paths, per_kind=20):
    """The first `per_kind` paths of each kind of a mixed URL list."""
    out, seen = [], {}
    for path in paths:
        kind = mixed_expected(path)[0]
        if seen.get(kind, 0) < per_kind:
            seen[kind] = seen.get(kind, 0) + 1
            out.append(path)
    return out


def parse_metrics(text):
    """Unlabelled samples of a Prometheus text exposition: name -> value."""
    out = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([a-zA-Z_:][a-zA-Z0-9_:]*) (\S+)", line.strip())
        if match:
            try:
                out[match.group(1)] = float(match.group(2))
            except ValueError:
                pass
    return out


def slope(points):
    """Least-squares slope of [(x, y)], None with fewer than 2 distinct x."""
    points = [(x, y) for x, y in points if y is not None]
    if len({x for x, _ in points}) < 2:
        return None
    mx = statistics.fmean(x for x, _ in points)
    my = statistics.fmean(y for _, y in points)
    return (sum((x - mx) * (y - my) for x, y in points)
            / sum((x - mx) ** 2 for x, _ in points))


# --- running -----------------------------------------------------------------

def docker(*args, check=True, capture=True):
    return subprocess.run(["docker", *args], check=check, text=True,
                          capture_output=capture)


def cpu_split():
    total = int(docker("info", "--format", "{{.NCPU}}").stdout.strip())
    server = int(os.environ.get("SERVER_CPUS", max(1, total // 2)))
    if total < 2:
        sys.exit("needs at least 2 CPUs for Docker")
    server = min(server, total - 1)
    return (f"0-{server - 1}" if server > 1 else "0",
            f"{server}-{total - 1}" if total - server > 1 else str(server),
            server, total)


def image_info(image, version_cmd, pull):
    if pull:
        docker("pull", "-q", image)
    digest = docker("image", "inspect", "--format",
                    "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
                    image, check=False).stdout.strip()
    out = docker("run", "--rm", "--entrypoint", version_cmd[0], image,
                 *version_cmd[1:], check=False)
    match = re.search(r"\d+\.\d+\.\d+", out.stdout + out.stderr)
    return ((match.group(0) if match else "?"),
            digest.partition("@")[2] if pull else "")


def fetch(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        res = conn.getresponse()
        body = res.read()
        return res.status, res.getheader("Location"), body
    finally:
        conn.close()


def get(port, path):
    return fetch(port, path)[:2]


def published_port(name):
    out = docker("port", name, "8080/tcp", check=False).stdout
    if not out.strip():
        raise ConnectionError("port not published yet")
    return int(out.split()[0].rsplit(":", 1)[1])


def start(spec, d, cpus):
    docker("rm", "-f", SERVER, check=False)
    args = ["run", "-d", "--name", SERVER, "--network", NETWORK,
            "--cpuset-cpus", cpus, "-p", "127.0.0.1::8080",
            "-v", f"{d}:/etc/bench{'' if spec.get('writable') else ':ro'}"]
    for sysctl in spec.get("sysctls", []):
        args += ["--sysctl", sysctl]
    for key, value in spec.get("env", {}).items():
        args += ["-e", f"{key}={value}"]
    args.append(spec["image"])
    args += spec.get("cmd", [])
    began = time.monotonic()
    docker(*args)
    path, status, location = SCENARIOS["exact"]
    deadline = began + 180
    port = None
    while time.monotonic() < deadline:
        running = docker("inspect", "--format", "{{.State.Running}}", SERVER)
        if running.stdout.strip() != "true":
            raise RuntimeError("exited: " + logs())
        try:
            if port is None:
                port = published_port(SERVER)
            if get(port, path) == (status, location):
                return port, round((time.monotonic() - began) * 1000)
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("did not answer in 180 s: " + logs())


def logs():
    out = docker("logs", "--tail", "20", SERVER, check=False)
    return (out.stdout + out.stderr).strip()[-2000:]


def check(port):
    """Every scenario answers the expected status and Location. Returns
    notes for redirections with the right Location but another 3xx."""
    notes = []
    for name, (path, status, location) in SCENARIOS.items():
        note = verify(port, name, path, status, location)
        if note:
            notes.append(note)
    return notes


def verify(port, name, path, status, location):
    """Raises unless `path` answers `status` (or another 3xx for a 3xx)
    with `location`; returns a note for another 3xx, else None."""
    got_status, got_location = get(port, path)
    if got_location != location or (
            got_status != status
            and not (300 <= got_status < 400 and 300 <= status < 400)):
        raise RuntimeError(
            f"{name}: {path} answered {got_status} {got_location}, "
            f"expected {status} {location}")
    if got_status != status:
        return (f"answers {got_status} instead of {status} "
                f"for the {name} rule")
    return None


def check_mixed(port):
    """A sample of every kind of mixed URL answers as check() requires
    (the load test only counts unexpected statuses, not wrong Locations)."""
    for path in mixed_sample(mixed_paths(MIXED_URLS)):
        kind, status, location = mixed_expected(path)
        verify(port, f"mixed {kind}", path, status, location)


def check_upstream(port):
    """A miss is forwarded to the upstream and its answer relayed."""
    path = EXTRA["upstream"]["path"]
    deadline = time.monotonic() + 30
    while True:
        try:
            status, _, body = fetch(port, path)
            if status == 200 and body.decode() == UPSTREAM_BODY:
                return
        except OSError as e:
            status, body = type(e).__name__, b""
        if time.monotonic() > deadline:
            raise RuntimeError(f"upstream: {path} answered {status} "
                               f"{body[:80]!r}, expected 200 "
                               f"{UPSTREAM_BODY!r}")
        time.sleep(0.5)


def oha_args(name):
    """The load generator's arguments (target included) for a scenario."""
    if name in SCENARIOS:
        return [f"http://{SERVER}:8080{SCENARIOS[name][0]}"]
    sc = EXTRA[name]
    args = []
    if sc.get("churn"):
        args.append("--disable-keepalive")
    if sc.get("rate"):
        args += ["-q", str(RATE["rps"]), "--latency-correction"]
    if sc.get("headers"):
        for header in BROWSER_HEADERS:
            args += ["-H", header]
    if sc.get("urls"):
        args += ["--urls-from-file", "/bench/mixed.txt"]
    else:
        args.append(f"http://{SERVER}:8080{sc['path']}")
    return args


def statuses_of(name):
    return (SCENARIOS[name][1],) if name in SCENARIOS \
        else EXTRA[name]["statuses"]


def oha_command(args, duration, cpus):
    cmd = ["run", "--rm", "--network", NETWORK, "--cpuset-cpus", cpus]
    if SHARED is not None:
        cmd += ["-v", f"{SHARED}:/bench:ro"]
    if "--disable-keepalive" in args:
        for sysctl in CHURN_SYSCTLS:
            cmd += ["--sysctl", sysctl]
    return cmd + [OHA, "--no-tui", "--output-format", "json", "-z", duration,
                  "-w", "-c", str(CONCURRENCY), "--redirect", "0", *args]


def load(args, duration, cpus):
    return json.loads(docker(*oha_command(args, duration, cpus)).stdout)


def expected_count(codes, statuses):
    """Responses with an expected status; any 3xx when a 3xx is expected
    (an accepted other 3xx, see check)."""
    redirect = any(300 <= s < 400 for s in statuses)
    return sum(v for k, v in codes.items()
               if int(k) in statuses or (redirect and 300 <= int(k) < 400))


def summarize(r, statuses):
    """One oha JSON result -> rps, latencies (ms) and errors."""
    codes = r.get("statusCodeDistribution", {})
    total = sum(codes.values()) + sum(r.get("errorDistribution", {}).values())
    pct = r["latencyPercentiles"]
    return {
        "rps": r["summary"]["requestsPerSec"],
        "p50_ms": pct["p50"] * 1000,
        "p99_ms": pct["p99"] * 1000,
        "p999_ms": (pct.get("p99.9") or 0) * 1000,
        "max_ms": (r["summary"].get("slowest") or 0) * 1000,
        "errors": total - expected_count(codes, statuses),
    }


def seconds(duration):
    match = re.fullmatch(r"(\d+)(ms|s|m|h)?", duration)
    if not match:
        sys.exit(f"cannot read the duration {duration!r}")
    n, unit = int(match.group(1)), match.group(2) or "s"
    return max(1, {"ms": n // 1000, "s": n, "m": n * 60, "h": n * 3600}[unit])


def measure(name, client_cpus, profile=None):
    args, statuses = oha_args(name), statuses_of(name)
    load(args, WARMUP, client_cpus)
    runs = []
    for i in range(RUNS):
        if profile is not None and i == 0:
            with profile():
                r = load(args, DURATION, client_cpus)
        else:
            r = load(args, DURATION, client_cpus)
        runs.append(summarize(r, statuses))
    best = sorted(runs, key=lambda x: x["rps"])[len(runs) // 2]
    print(f"  {name:<14} {best['rps']:>10,.0f} req/s  p50 {best['p50_ms']:.2f} ms"
          f"  p99 {best['p99_ms']:.2f} ms  p99.9 {best['p999_ms']:.2f} ms"
          f"  max {best['max_ms']:.1f} ms  errors {best['errors']}",
          flush=True)
    result = {
        "rps": round(statistics.median(r["rps"] for r in runs)),
        "p50_ms": round(best["p50_ms"], 3),
        "p99_ms": round(best["p99_ms"], 3),
        "p999_ms": round(best["p999_ms"], 3),
        "max_ms": round(best["max_ms"], 3),
        "errors": max(r["errors"] for r in runs),
    }
    if EXTRA.get(name, {}).get("rate"):
        result["target_rps"] = RATE["rps"]
    if name == "mixed" and RATE["rps"] is None:
        # the fixed rate of every server's mixed-rate
        RATE["rps"] = max(1, round(result["rps"] * FIXED_RATE_SHARE))
        print(f"  fixed rate: {RATE['rps']:,} req/s", flush=True)
    return result


def metrics_sample(port):
    """The server's own memory, process count and request count
    (server.metrics_path), {} when it does not answer."""
    try:
        status, _, body = fetch(port, METRICS_PATH, {
            "Authorization": f"Bearer {METRICS_TOKEN}"})
    except OSError:
        return {}
    return parse_metrics(body.decode()) if status == 200 else {}


def soak(port, client_cpus):
    """SOAK of mixed requests, sampled every SOAK_INTERVAL seconds."""
    args = oha_args("mixed")
    if SOAK_RATE:
        args = ["-q", str(SOAK_RATE), "--latency-correction", *args]
    out = SHARED / "soak.json"
    requests = metrics_sample(port).get("redirect_proxy_requests_total")
    with out.open("w") as f:
        proc = subprocess.Popen(
            ["docker", *oha_command(args, SOAK, client_cpus)],
            stdout=f, stderr=subprocess.PIPE, text=True)
    began, samples = time.monotonic(), []
    previous = None if requests is None else (0, requests)
    print(f"  {'t':>6} {'anon':>10} {'docker':>10} {'VM':>10} "
          f"{'processes':>10} {'req/s':>10}", flush=True)
    while True:
        try:
            proc.wait(timeout=SOAK_INTERVAL)
            done = True
        except subprocess.TimeoutExpired:
            done = False
        t = time.monotonic() - began
        sample, previous = soak_sample(port, t, previous)
        print(f"  {sample['t_s']:>5}s {sample.get('anon_mib') or 0:>6.1f} MiB "
              f"{sample.get('docker_mib') or 0:>6.1f} MiB "
              f"{sample.get('vm_mib', 0):>6.1f} MiB "
              f"{sample.get('processes', 0):>10} {sample.get('rps', 0):>10,}"
              + ("  (load stopped)" if done else ""), flush=True)
        if done:
            # after the load: not a steady-state sample
            after = sample
            break
        samples.append(sample)
    stderr = proc.stderr.read()
    if proc.returncode == 0:
        summary = summarize(json.loads(out.read_text()), MIXED_STATUSES)
        load = {
            "rps": round(summary["rps"]),
            **{k: round(v, 3) for k, v in summary.items()
               if k.endswith("_ms")},
            "errors": summary["errors"],
        }
    elif samples:
        # oha keeps every result in memory and can be killed (137) at the
        # end of a long soak at full speed: the memory samples still
        # stand, the server's request rate stands in for oha's, latencies
        # and errors are unknown
        print(f"  oha exited {proc.returncode}: {stderr[-300:]}; reporting "
              "the samples (latencies unknown; set SOAK_RATE for long soaks)",
              flush=True)
        load = {
            "rps": round(statistics.fmean(s.get("rps", 0) for s in samples)),
            "p50_ms": None, "p99_ms": None, "p999_ms": None, "max_ms": None,
            "errors": None,
            "client_error": f"oha exited {proc.returncode}",
        }
    else:
        raise RuntimeError(f"oha exited {proc.returncode}: {stderr[-300:]}")
    result = {
        "duration": SOAK, "interval_s": SOAK_INTERVAL,
        "rate": SOAK_RATE or None,
        **load,
        **soak_summary(samples),
        "samples": samples,
        "after": after,
    }

    def latency(name, value, digits):
        return "" if value is None else f"{name} {value:.{digits}f} ms  "

    print(f"  soak: {result['rps']:,} req/s  "
          + latency("p99", result["p99_ms"], 2)
          + latency("p99.9", result["p999_ms"], 2)
          + latency("max", result["max_ms"], 1)
          + f"errors {'unknown' if result['errors'] is None else result['errors']}  memory {result['anon_mib_per_min']} "
          f"MiB/min (anon; second half {result['anon_mib_per_min_late']}), "
          f"{result['vm_mib_per_min']} MiB/min (VM; second half "
          f"{result['vm_mib_per_min_late']}), "
          f"{result['docker_mib_per_min']} MiB/min (docker, page cache "
          f"included)", flush=True)
    return result


def soak_sample(port, t, previous):
    """One soak sample at `t` s; `previous` is (t, requests) of the last
    one. Returns the sample and the new `previous`."""
    m = metrics_sample(port)
    sample = {"t_s": round(t), "anon_mib": anon_mib(),
              "docker_mib": memory_mib()}
    if "redirect_proxy_memory_bytes" in m:
        sample["vm_mib"] = round(m["redirect_proxy_memory_bytes"] / 2**20, 1)
    if "redirect_proxy_processes" in m:
        sample["processes"] = int(m["redirect_proxy_processes"])
    requests = m.get("redirect_proxy_requests_total")
    if previous is not None and requests is not None and t > previous[0]:
        sample["rps"] = round((requests - previous[1]) / (t - previous[0]))
    if requests is not None:
        previous = (t, requests)
    return sample, previous


def soak_summary(samples):
    """Memory slopes (MiB/min) of the samples taken under load after
    SOAK_WARMUP (all of them when fewer than 3), and the first and last of
    those samples."""
    steady = [s for s in samples if s["t_s"] >= SOAK_WARMUP]
    if len(steady) < 3:
        steady = samples

    late = steady[len(steady) // 2:]

    def per_min(field, among=steady):
        rate = slope([(s["t_s"] / 60, s.get(field)) for s in among])
        return None if rate is None else round(rate, 3)

    return {
        "warmup_s": SOAK_WARMUP,
        "anon_mib_per_min": per_min("anon_mib"),
        "vm_mib_per_min": per_min("vm_mib"),
        "docker_mib_per_min": per_min("docker_mib"),
        "anon_mib_per_min_late": per_min("anon_mib", late),
        "vm_mib_per_min_late": per_min("vm_mib", late),
        "max_processes": max((s.get("processes", 0) for s in samples),
                             default=0),
        "first": steady[0] if steady else None,
        "last": steady[-1] if steady else None,
    }


def idle_cpu_pct():
    """CPU used by the server once the load stopped (busy-waiting
    schedulers, timers), in % of one CPU."""
    time.sleep(5)
    out = docker("stats", "--no-stream", "--format", "{{.CPUPerc}}",
                 SERVER).stdout.strip().rstrip("%")
    try:
        return round(float(out), 1)
    except ValueError:
        return None


class Profile:
    """Microstate accounting (RP_BENCH_MSACC, see redirect_proxy_msacc.erl)
    and, when `sudo perf` works, a perf profile of the server during one
    load run."""

    def __init__(self, label):
        self.label = label
        slug = re.sub(r"[^\w.-]+", "-", label).strip("-")
        self.out = ROOT / "build" / f"profile-{slug}.txt"
        self.perf = None

    def __enter__(self):
        docker("exec", SERVER, "touch", "/tmp/rp-msacc-start")
        pid = docker("inspect", "--format", "{{.State.Pid}}", SERVER).stdout.strip()
        self.pid = pid
        self.data = pathlib.Path(tempfile.mkdtemp(prefix="bench-perf-")) / "perf.data"
        if shutil.which("perf") or shutil.which("sudo"):
            try:
                self.perf = subprocess.Popen(
                    ["sudo", "-n", "perf", "record", "-F", "999", "-g",
                     "-o", str(self.data), "-p", pid, "--", "sleep",
                     str(seconds(DURATION) - 1)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            except OSError:
                self.perf = None
        return self

    def __exit__(self, *exc):
        report = []
        if self.perf is not None:
            _, err = self.perf.communicate()
            if self.perf.returncode == 0:
                # JIT symbols: the map the VM wrote (+JPperf true) as PID 1 of
                # its container, under the PID perf saw
                docker("cp", f"{SERVER}:/tmp/perf-1.map",
                       f"/tmp/perf-{self.pid}.map", check=False)
                def perf_report(*sort):
                    return subprocess.run(
                        ["sudo", "-n", "perf", "report", "-f", "-i",
                         str(self.data), "--no-children", "--stdio", "-q",
                         "-g", "none", "--percent-limit", "0.3", *sort],
                        capture_output=True, text=True, check=False).stdout
                report += ["== perf, by shared object (self time)",
                           perf_report("--sort", "dso"),
                           "== perf, by symbol (self time, >= 0.3 %)",
                           perf_report("--sort", "dso,symbol")]
                pathlib.Path(f"/tmp/perf-{self.pid}.map").unlink(missing_ok=True)
            else:
                report += ["== perf unavailable: " + (err or "").strip()[-300:]]
        # the measurement ends a second after the run
        time.sleep(2)
        msacc = [line for line in logs_all().splitlines() if line.startswith("msacc ")]
        report = ["== microstate accounting (share of each thread type's time)",
                  *msacc, ""] + report
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text("\n".join(report) + "\n")
        print(f"  profile: {self.out.relative_to(ROOT)}", flush=True)
        for line in msacc:
            print(f"  {line}", flush=True)
        shutil.rmtree(self.data.parent, ignore_errors=True)
        return False


def logs_all():
    out = docker("logs", SERVER, check=False)
    return out.stdout + out.stderr


def anon_mib():
    """The container's anonymous memory (cgroup v2 `anon`: heap and stacks,
    not the page cache of the files it writes), None when unreadable."""
    out = docker("exec", SERVER, "cat", "/sys/fs/cgroup/memory.stat",
                 check=False).stdout
    match = re.search(r"^anon (\d+)$", out, re.M)
    return round(int(match.group(1)) / 2**20, 1) if match else None


def memory_mib():
    out = docker("stats", "--no-stream", "--format", "{{.MemUsage}}",
                 SERVER).stdout
    match = re.match(r"([\d.]+)\s*([KMG]i?B)", out.strip())
    if not match:
        return None
    scale = {"KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1,
             "GiB": 1024, "GB": 1024}
    return round(float(match.group(1)) * scale.get(match.group(2), 1), 1)


def start_upstream(cpus):
    """nginx answering 200 with UPSTREAM_BODY to every request, keeping
    connections alive, on the load generator's CPUs (it is not measured)."""
    (SHARED / "upstream.conf").write_text(f"""\
worker_processes auto;
error_log stderr warn;
pid /tmp/nginx.pid;
events {{ worker_connections 16384; }}
http {{
  access_log off;
  keepalive_requests 1000000;
  keepalive_timeout 75s;
  server {{
    listen 8080;
    location / {{
      default_type text/plain;
      return 200 {json.dumps(UPSTREAM_BODY)};
    }}
  }}
}}
""")
    docker("rm", "-f", UPSTREAM, check=False)
    docker("run", "-d", "--name", UPSTREAM, "--network", NETWORK,
           "--cpuset-cpus", cpus, "-p", "127.0.0.1::8080",
           *[a for s in CHURN_SYSCTLS for a in ("--sysctl", s)],
           "-v", f"{SHARED}:/bench:ro", "nginx:stable",
           "nginx", "-c", "/bench/upstream.conf", "-g", "daemon off;")
    deadline = time.monotonic() + 60
    while True:
        try:
            status, _, body = fetch(published_port(UPSTREAM), "/")
            if status == 200 and body.decode() == UPSTREAM_BODY:
                return
        except OSError:
            pass
        if time.monotonic() > deadline:
            out = docker("logs", "--tail", "20", UPSTREAM, check=False)
            raise RuntimeError("upstream did not answer: "
                               + (out.stdout + out.stderr)[-1000:])
        time.sleep(0.2)


def bench(key, label, configure, server_cpus, client_cpus, profile=False,
          extras=()):
    print(f"\n== {label}", flush=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="bench-compare-"))
    # read by the servers' own users (haproxy, daemon...), not ours
    work.chmod(0o755)
    try:
        spec = configure(work)
        version, digest = image_info(spec["image"], spec["version"],
                                     spec.get("pull", True))
        version = spec.get("label") or version
        result = {"key": key, "name": label, "image": spec["image"],
                  "version": version, "digest": digest,
                  "notes": list(spec["notes"])}
        rp = key.startswith("redirect-proxy")
        profiled = profile and rp
        if profiled:
            env = spec["env"]
            env["RP_BENCH_MSACC"] = str(max(1, seconds(DURATION) - 1))
            env["ERL_FLAGS"] = (env.get("ERL_FLAGS", "") + " +JPperf true").strip()
        upstream = [n for n in extras if EXTRA[n].get("upstream")]
        if upstream and not rp:
            result["notes"].append("upstream scenarios: redirect-proxy only")
            upstream = []

        def run(name):
            return measure(name, client_cpus,
                           (lambda: Profile(label))
                           if profiled and name == PROFILE_SCENARIO else None)

        try:
            port, startup = start(spec, work, server_cpus)
            result["notes"] += check(port)
            if SOAK or "mixed" in extras or "mixed-rate" in extras:
                check_mixed(port)
            result["startup_ms"] = startup
            if SOAK:
                result["soak"] = soak(port, client_cpus)
            else:
                result["scenarios"] = {
                    name: run(name)
                    for name in [*SCENARIOS, *extras]
                    if not EXTRA.get(name, {}).get("upstream")}
            result["memory_mib"] = memory_mib()
            result["idle_cpu_pct"] = idle_cpu_pct()
            if upstream and not SOAK:
                # misses forwarded instead of answered 404: a new server
                spec["env"]["RP_SERVER_UPSTREAM"] = f"http://{UPSTREAM}:8080"
                spec["sysctls"] = CHURN_SYSCTLS
                port, _ = start(spec, work, server_cpus)
                check_upstream(port)
                result["scenarios"].update({name: run(name) for name in upstream})
            result["status"] = "ok"
        except (RuntimeError, subprocess.CalledProcessError, OSError,
                json.JSONDecodeError, KeyError) as e:
            detail = getattr(e, "stderr", None) or str(e)
            print(f"  failed: {detail}", file=sys.stderr, flush=True)
            result["status"] = "failed"
            result["error"] = str(detail).strip().splitlines()[0][:300] \
                if str(detail).strip() else type(e).__name__
        return result
    finally:
        docker("rm", "-f", SERVER, check=False)
        shutil.rmtree(work, ignore_errors=True)


def runner():
    info = docker("info", "--format",
                  "{{.NCPU}}|{{.KernelVersion}}|{{.Architecture}}").stdout
    ncpu, kernel, arch = info.strip().split("|")
    cpu = ""
    try:
        for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        cpu = platform.processor() or platform.machine()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        host = f"GitHub Actions {os.environ.get('RUNNER_OS', '')} runner".replace("  ", " ")
    else:
        host = "local machine"
    return {"host": host, "cpu": cpu, "vcpus": int(ncpu), "kernel": kernel,
            "arch": arch}


def commit():
    out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=False)
    return out.stdout.strip()


# --- reporting ---------------------------------------------------------------

def kilo(n):
    return f"{n / 1000:,.1f} k" if n >= 1000 else str(n)


def table(results):
    head = ["Server", "Version", "Exact", "Prefix", "Regex", "Miss", "Memory"]
    rows = []
    for r in results["products"]:
        if r["status"] != "ok":
            rows.append([r["name"], r["version"], "failed", "", "", "", ""])
            continue
        s = r.get("scenarios", {})
        rows.append([r["name"], r["version"]]
                    + [kilo(s[k]["rps"]) if k in s else "" for k in SCENARIOS]
                    + [f"{r['memory_mib']:.0f} MiB"
                       if r.get("memory_mib") is not None else "?"])
    return markdown_table(head, rows, 2)


def markdown_table(head, rows, left):
    lines = ["| " + " | ".join(head) + " |",
             "| " + " | ".join(["---"] * left + ["---:"] * (len(head) - left))
             + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def ms(value):
    return "" if value is None else f"{value:.2f} ms"


def extra_table(results):
    """Latencies of every scenario other than the published four, and of
    those when there are others."""
    names = [n for n in EXTRA if any(
        n in r.get("scenarios", {}) for r in results["products"])]
    if not names:
        return ""
    rows = []
    for r in results["products"]:
        s = r.get("scenarios", {})
        for name in [*SCENARIOS, *names]:
            if name in s:
                x = s[name]
                rows.append([r["name"], name, kilo(x["rps"]),
                             ms(x["p50_ms"]), ms(x["p99_ms"]),
                             ms(x.get("p999_ms")), ms(x.get("max_ms")),
                             str(x["errors"])])
    return markdown_table(["Server", "Scenario", "Requests/s", "p50", "p99",
                           "p99.9", "Max", "Errors"], rows, 2)


def soak_table(results):
    rows = []
    for r in results["products"]:
        s = r.get("soak")
        if not s:
            continue
        first, last = s.get("first") or {}, s.get("last") or {}
        # anon (no page cache) when the cgroup could be read, else the VM's
        field = "anon_mib" if s.get("anon_mib_per_min") is not None \
            else "vm_mib"
        rows.append([r["name"], kilo(s["rps"]), ms(s["p99_ms"]),
                     ms(s["p999_ms"]), ms(s["max_ms"]),
                     str(s["errors"]) if s["errors"] is not None
                     else s.get("client_error", ""),
                     f"{first.get(field)} → {last.get(field)} MiB "
                     f"({field.removesuffix('_mib')})",
                     str(s.get("anon_mib_per_min")),
                     str(s.get("anon_mib_per_min_late")),
                     str(s["vm_mib_per_min"]),
                     str(s.get("vm_mib_per_min_late")),
                     str(s["docker_mib_per_min"]),
                     str(s["max_processes"])])
    if not rows:
        return ""
    return markdown_table(["Server", "Requests/s", "p99", "p99.9", "Max",
                           "Errors", "Memory (under load)", "MiB/min (anon)",
                           "2nd half (anon)", "MiB/min (VM)",
                           "2nd half (VM)", "MiB/min (docker, with cache)",
                           "Processes (max)"], rows, 1)


def report(results):
    soaked = all("soak" in r for r in results["products"]
                 if r["status"] == "ok")
    main = table(results) if not soaked or any(
        r["status"] != "ok" for r in results["products"]) else ""
    return "\n\n".join(t for t in (main, extra_table(results),
                                   soak_table(results)) if t)


def readme_block(results):
    r = results["rules"]
    return (
        "<!-- benchmark:start -->\n"
        f"Requests per second on a {results['runner']['host']} "
        f"({results['runner']['vcpus']} vCPUs, {results['server_cpus']} for "
        f"the server) with {r['exact']:,} exact, {r['prefix']:,} prefix and "
        f"{r['regex']:,} regex rules, measured on {results['date']}:\n\n"
        f"{table(results)}\n\n"
        "Updated every week from the *Benchmark* workflow. See "
        "[Performance](https://janalis.github.io/redirect-proxy/guide/performance#compared-with-other-servers) "
        "for the method, latencies and configurations.\n"
        "<!-- benchmark:end -->")


def write_readme(results):
    text = README.read_text()
    block = re.compile(r"<!-- benchmark:start -->.*?<!-- benchmark:end -->",
                       re.S)
    if not block.search(text):
        sys.exit("README.md has no <!-- benchmark:start --> block")
    README.write_text(block.sub(lambda _: readme_block(results), text))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", help="comma-separated: " + ",".join(PRODUCTS))
    parser.add_argument("--output", type=pathlib.Path,
                        help=f"results file (default {OUTPUT.relative_to(ROOT)}, "
                        "or build/benchmark.json with --only)")
    parser.add_argument("--readme", action="store_true",
                        help="rewrite the table in README.md")
    parser.add_argument("--from", dest="source", type=pathlib.Path,
                        help="do not run: read results from this file")
    parser.add_argument("--profile", action="store_true",
                        help="profile redirect-proxy during the "
                        "PROFILE_SCENARIO scenario (default exact)")
    args = parser.parse_args()
    extra = variants(os.environ.get("RP_VARIANTS", ""))
    extras = extra_scenarios(os.environ.get("EXTRA_SCENARIOS", ""))
    if args.readme and (extra or extras or SOAK):
        parser.error("RP_VARIANTS, EXTRA_SCENARIOS, SOAK: the results are "
                     "not for the README")
    if args.source:
        results = json.loads(args.source.read_text())
        print(report(results))
        if args.readme:
            write_readme(results)
        return
    if SOAK:
        seconds(SOAK)  # exits when it does not parse
        if args.profile:
            parser.error("SOAK and --profile: the profile is of a scenario, "
                         "and a soak runs none")
        if extras:
            parser.error("SOAK replaces the scenarios: no EXTRA_SCENARIOS "
                         "(nor the workflow's scenarios or upstream)")
    if args.profile and PROFILE_SCENARIO not in [*SCENARIOS, *extras]:
        parser.error(f"PROFILE_SCENARIO={PROFILE_SCENARIO} is not measured "
                     f"(scenarios: {', '.join([*SCENARIOS, *extras])})")
    keys = list(PRODUCTS)
    if args.only:
        keys = [k.strip() for k in args.only.split(",")]
        unknown = [k for k in keys if k not in PRODUCTS]
        if unknown:
            parser.error(f"unknown: {', '.join(unknown)}")
    if SOAK and any(k != "redirect-proxy" for k in keys):
        parser.error("SOAK measures redirect-proxy only: --only redirect-proxy")
    output = args.output or (
        ROOT / "build" / "benchmark-variants.json" if extra or extras or SOAK
        else ROOT / "build" / "benchmark.json" if args.only else OUTPUT)
    runs = [(k, *PRODUCTS[k]) for k in keys] + extra

    global SHARED
    SHARED = pathlib.Path(tempfile.mkdtemp(prefix="bench-shared-"))
    SHARED.chmod(0o755)
    (SHARED / "mixed.txt").write_text("".join(
        f"http://{SERVER}:8080{p}\n" for p in mixed_paths(MIXED_URLS)))
    server_cpus, client_cpus, n_server, _ = cpu_split()
    docker("pull", "-q", OHA)
    docker("network", "rm", NETWORK, check=False)
    docker("network", "create", NETWORK)
    try:
        if any(EXTRA[n].get("upstream") for n in extras) and not SOAK:
            start_upstream(client_cpus)
        products = [bench(k, label, configure, server_cpus, client_cpus,
                          args.profile, extras)
                    for k, label, configure in runs]
    finally:
        docker("rm", "-f", SERVER, UPSTREAM, check=False)
        docker("network", "rm", NETWORK, check=False)
        shutil.rmtree(SHARED, ignore_errors=True)

    load_info = {"tool": "oha 1.16.0", "duration": DURATION, "runs": RUNS,
                 "concurrency": CONCURRENCY, "keep_alive": True}
    if extras or SOAK:
        load_info.update({
            "extra_scenarios": extras,
            "mixed": {"urls": MIXED_URLS, "mix": dict(MIX),
                      "header_bytes": sum(len(h) + 2 for h in BROWSER_HEADERS)},
            "fixed_rate_rps": RATE["rps"] if "mixed-rate" in extras else None,
            "soak": SOAK or None,
        })
    results = {
        "date": datetime.date.today().isoformat(),
        "commit": commit(),
        "runner": runner(),
        "server_cpus": n_server,
        "load": load_info,
        "rules": {"exact": EXACT, "prefix": PREFIX, "regex": REGEX},
        "scenarios": {k: {"path": p, "status": s}
                      for k, (p, s, _) in SCENARIOS.items()},
        "products": products,
    }
    for name in extras:
        sc = EXTRA[name]
        results["scenarios"][name] = {
            "path": "mixed URLs" if sc.get("urls") else sc["path"],
            "status": list(sc["statuses"]),
            "keep_alive": not sc.get("churn"),
            **({"upstream": True} if sc.get("upstream") else {}),
            **({"rate_rps": RATE["rps"]} if sc.get("rate") else {}),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\n{report(results)}\n\nwritten to {output}")
    if args.readme:
        write_readme(results)
    failed = [p["name"] for p in products
              if p["key"].startswith("redirect-proxy") and p["status"] != "ok"]
    if failed:
        sys.exit(f"failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
