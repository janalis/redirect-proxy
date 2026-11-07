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
RP_IMAGE=ghcr.io/janalis/redirect-proxy:dev (built by `make docker`).
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
        "pull": False,  # built from this checkout
        "writable": True,
        "env": {
            "RP_STORAGE_DATA_DIR": "/etc/bench",
            "RP_ADMIN_ENABLED": "false",
            "RP_ACCESS_LOG_ENABLED": "false",
            "RP_STORAGE_BACKUPS": "0",
            "RP_LOG_LEVEL": "warning",
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
LoadModule mpm_event_module modules/mod_mpm_event.so
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
StartServers 4
MinSpareThreads 100
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
                  "regex rules are `RewriteRule` regexes, tried in order"],
    }


PRODUCTS = {
    "redirect-proxy": ("redirect-proxy", redirect_proxy),
    "nginx": ("nginx", nginx),
    "haproxy": ("HAProxy", haproxy),
    "caddy": ("Caddy", caddy),
    "traefik": ("Traefik", traefik),
    "apache": ("Apache httpd", apache),
}


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
    port = int(docker("port", SERVER, "8080/tcp").stdout.split(":")[-1])
    path, status, location = SCENARIOS["exact"]
    deadline = began + 180
    while time.monotonic() < deadline:
        running = docker("inspect", "--format", "{{.State.Running}}", SERVER)
        if running.stdout.strip() != "true":
            raise RuntimeError("exited: " + logs())
        try:
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


def measure(name, path, status, client_cpus):
    load(path, WARMUP, client_cpus)
    runs = []
    for _ in range(RUNS):
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


def memory_mib():
    out = docker("stats", "--no-stream", "--format", "{{.MemUsage}}",
                 SERVER).stdout
    match = re.match(r"([\d.]+)\s*([KMG]i?B)", out.strip())
    if not match:
        return None
    scale = {"KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1,
             "GiB": 1024, "GB": 1024}
    return round(float(match.group(1)) * scale.get(match.group(2), 1), 1)


def bench(key, server_cpus, client_cpus):
    label, configure = PRODUCTS[key]
    print(f"\n== {label}", flush=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="bench-compare-"))
    try:
        spec = configure(work)
        version, digest = image_info(spec["image"], spec["version"],
                                     spec.get("pull", True))
        result = {"key": key, "name": label, "image": spec["image"],
                  "version": version, "digest": digest,
                  "notes": list(spec["notes"])}
        try:
            port, startup = start(spec, work, server_cpus)
            result["notes"] += check(port)
            result["startup_ms"] = startup
            result["scenarios"] = {
                name: measure(name, path, status, client_cpus)
                for name, (path, status, _) in SCENARIOS.items()}
            result["memory_mib"] = memory_mib()
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
    args = parser.parse_args()
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
        ROOT / "build" / "benchmark.json" if args.only else OUTPUT)

    server_cpus, client_cpus, n_server, _ = cpu_split()
    docker("pull", "-q", OHA)
    docker("network", "rm", NETWORK, check=False)
    docker("network", "create", NETWORK)
    try:
        products = [bench(k, server_cpus, client_cpus) for k in keys]
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
    ours = next((p for p in products if p["key"] == "redirect-proxy"), None)
    if ours is not None and ours["status"] != "ok":
        sys.exit("redirect-proxy failed")


if __name__ == "__main__":
    main()
