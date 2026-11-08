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

    RP_VARIANTS='sbwt-short=+sbwt short; main@ghcr.io/janalis/redirect-proxy:main'

Each `label[@image][=ERL_FLAGS]` entry (`;` or newline separated) is
measured after redirect-proxy itself, as `redirect-proxy (label)`, with
RP_IMAGE when it names no image. The results then go to
build/benchmark-variants.json, never to the documentation.

--profile: during the first run of the exact scenario, microstate accounting
of each redirect-proxy (where its schedulers spend their time) and, when
`sudo perf` works, a CPU profile, written to build/profile-<label>.txt.
"""
import argparse
import datetime
import http.client
import json
import os
import pathlib
import platform
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


def variants(spec):
    """`label[@image][=ERL_FLAGS]` entries -> [(key, name, configure)]."""
    out = []
    for entry in re.split(r"[;\n]", spec):
        entry = entry.strip()
        if not entry:
            continue
        head, _, flags = entry.partition("=")
        label, _, image = head.strip().partition("@")
        label, image, flags = label.strip(), image.strip(), flags.strip()
        if not label:
            sys.exit(f"RP_VARIANTS: no label in {entry!r}")

        def configure(d, image=image, flags=flags, label=label):
            spec = redirect_proxy(d)
            if image:
                spec["image"] = image
                # a published image, unless it was built here
                spec["pull"] = docker("image", "inspect", image,
                                      check=False).returncode != 0
            if flags:
                spec["env"]["ERL_FLAGS"] = flags
            spec["label"] = label
            spec["notes"] = [f"ERL_FLAGS={flags}"] if flags else []
            return spec

        out.append((f"redirect-proxy:{label}", f"redirect-proxy ({label})",
                    configure))
    return out


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


def get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        res.read()
        return res.status, res.getheader("Location")
    finally:
        conn.close()


def start(spec, d, cpus):
    docker("rm", "-f", SERVER, check=False)
    args = ["run", "-d", "--name", SERVER, "--network", NETWORK,
            "--cpuset-cpus", cpus, "-p", "127.0.0.1::8080",
            "-v", f"{d}:/etc/bench{'' if spec.get('writable') else ':ro'}"]
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
                out = docker("port", SERVER, "8080/tcp", check=False).stdout
                if not out.strip():
                    raise ConnectionError("port not published yet")
                port = int(out.split()[0].rsplit(":", 1)[1])
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
        got_status, got_location = get(port, path)
        if got_location != location or (
                got_status != status
                and not (300 <= got_status < 400 and 300 <= status < 400)):
            raise RuntimeError(
                f"{name}: {path} answered {got_status} {got_location}, "
                f"expected {status} {location}")
        if got_status != status:
            notes.append(f"answers {got_status} instead of {status} "
                         f"for the {name} rule")
    return notes


def load(path, duration, cpus):
    out = docker("run", "--rm", "--network", NETWORK, "--cpuset-cpus", cpus,
                 OHA, "--no-tui", "--output-format", "json", "-z", duration,
                 "-w", "-c", str(CONCURRENCY), "--redirect", "0",
                 f"http://{SERVER}:8080{path}").stdout
    return json.loads(out)


def seconds(duration):
    match = re.fullmatch(r"(\d+)(ms|s|m)?", duration)
    if not match:
        sys.exit(f"cannot read the duration {duration!r}")
    n, unit = int(match.group(1)), match.group(2) or "s"
    return max(1, {"ms": n // 1000, "s": n, "m": n * 60}[unit])


def measure(name, path, status, client_cpus, profile=None):
    load(path, WARMUP, client_cpus)
    runs = []
    for i in range(RUNS):
        if profile is not None and i == 0:
            with profile():
                r = load(path, DURATION, client_cpus)
        else:
            r = load(path, DURATION, client_cpus)
        codes = r.get("statusCodeDistribution", {})
        total = sum(codes.values()) + sum(r.get("errorDistribution", {}).values())
        expected = codes.get(str(status), 0)
        if expected == 0:
            # an accepted other 3xx (see check)
            expected = sum(v for k, v in codes.items() if k.startswith("3")) \
                if 300 <= status < 400 else 0
        runs.append({
            "rps": r["summary"]["requestsPerSec"],
            "p50_ms": r["latencyPercentiles"]["p50"] * 1000,
            "p99_ms": r["latencyPercentiles"]["p99"] * 1000,
            "errors": total - expected,
        })
    best = sorted(runs, key=lambda x: x["rps"])[len(runs) // 2]
    print(f"  {name:<7} {best['rps']:>10,.0f} req/s  p50 {best['p50_ms']:.2f} ms"
          f"  p99 {best['p99_ms']:.2f} ms  errors {best['errors']}",
          flush=True)
    return {
        "rps": round(statistics.median(r["rps"] for r in runs)),
        "p50_ms": round(best["p50_ms"], 3),
        "p99_ms": round(best["p99_ms"], 3),
        "errors": max(r["errors"] for r in runs),
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


def memory_mib():
    out = docker("stats", "--no-stream", "--format", "{{.MemUsage}}",
                 SERVER).stdout
    match = re.match(r"([\d.]+)\s*([KMG]i?B)", out.strip())
    if not match:
        return None
    scale = {"KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1,
             "GiB": 1024, "GB": 1024}
    return round(float(match.group(1)) * scale.get(match.group(2), 1), 1)


def bench(key, label, configure, server_cpus, client_cpus, profile=False):
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
        profiled = profile and key.startswith("redirect-proxy")
        if profiled:
            env = spec["env"]
            env["RP_BENCH_MSACC"] = str(max(1, seconds(DURATION) - 1))
            env["ERL_FLAGS"] = (env.get("ERL_FLAGS", "") + " +JPperf true").strip()
        try:
            port, startup = start(spec, work, server_cpus)
            result["notes"] += check(port)
            result["startup_ms"] = startup
            result["scenarios"] = {
                name: measure(name, path, status, client_cpus,
                              (lambda: Profile(label))
                              if profiled and name == "exact" else None)
                for name, (path, status, _) in SCENARIOS.items()}
            result["memory_mib"] = memory_mib()
            result["idle_cpu_pct"] = idle_cpu_pct()
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
        s = r["scenarios"]
        rows.append([r["name"], r["version"]]
                    + [kilo(s[k]["rps"]) for k in SCENARIOS]
                    + [f"{r['memory_mib']:.0f} MiB"
                       if r.get("memory_mib") is not None else "?"])
    lines = ["| " + " | ".join(head) + " |",
             "| " + " | ".join(["---"] * 2 + ["---:"] * 5) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


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
                        help="profile redirect-proxy during the exact scenario")
    args = parser.parse_args()
    extra = variants(os.environ.get("RP_VARIANTS", ""))
    if extra and args.readme:
        parser.error("RP_VARIANTS: the results are not for the README")
    if args.source:
        results = json.loads(args.source.read_text())
        print(table(results))
        if args.readme:
            write_readme(results)
        return
    keys = list(PRODUCTS)
    if args.only:
        keys = [k.strip() for k in args.only.split(",")]
        unknown = [k for k in keys if k not in PRODUCTS]
        if unknown:
            parser.error(f"unknown: {', '.join(unknown)}")
    output = args.output or (
        ROOT / "build" / "benchmark-variants.json" if extra
        else ROOT / "build" / "benchmark.json" if args.only else OUTPUT)
    runs = [(k, *PRODUCTS[k]) for k in keys] + extra

    server_cpus, client_cpus, n_server, _ = cpu_split()
    docker("pull", "-q", OHA)
    docker("network", "rm", NETWORK, check=False)
    docker("network", "create", NETWORK)
    try:
        products = [bench(k, label, configure, server_cpus, client_cpus,
                          args.profile)
                    for k, label, configure in runs]
    finally:
        docker("rm", "-f", SERVER, check=False)
        docker("network", "rm", NETWORK, check=False)

    results = {
        "date": datetime.date.today().isoformat(),
        "commit": commit(),
        "runner": runner(),
        "server_cpus": n_server,
        "load": {"tool": "oha 1.16.0", "duration": DURATION, "runs": RUNS,
                 "concurrency": CONCURRENCY, "keep_alive": True},
        "rules": {"exact": EXACT, "prefix": PREFIX, "regex": REGEX},
        "scenarios": {k: {"path": p, "status": s}
                      for k, (p, s, _) in SCENARIOS.items()},
        "products": products,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\n{table(results)}\n\nwritten to {output}")
    if args.readme:
        write_readme(results)
    failed = [p["name"] for p in products
              if p["key"].startswith("redirect-proxy") and p["status"] != "ok"]
    if failed:
        sys.exit(f"failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
