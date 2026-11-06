#!/bin/sh
# Load test of the redirect listener with a large generated rule set.
#
#   scripts/bench.sh [BUNDLE_DIR]
#
# Uses `oha` when available, otherwise ApacheBench (`ab`). Environment:
#   EXACT=10000 PREFIX=1000 REGEX=500   rule counts
#   REQUESTS=200000 CONCURRENCY=100     load parameters
#   PORT=18180                          redirect listener port
#   ACCESS_LOG=<file>                   access log output (default: a temp
#                                       file; RP_ACCESS_LOG_ENABLED=false
#                                       measures without it)
set -eu

bundle=${1:-}
exact=${EXACT:-10000}
prefix=${PREFIX:-1000}
regex=${REGEX:-500}
requests=${REQUESTS:-200000}
concurrency=${CONCURRENCY:-100}
port=${PORT:-18180}

work=$(mktemp -d "${TMPDIR:-/tmp}/redirect-proxy-bench.XXXXXX")
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT INT TERM

awk -v e="$exact" -v p="$prefix" -v r="$regex" 'BEGIN {
  printf "{\"version\":1,\"rules\":["
  sep = ""
  for (i = 0; i < e; i++) { printf "%s{\"source\":\"/exact/%d\",\"target\":\"https://new.example.com/e/%d\"}", sep, i, i; sep = "," }
  for (i = 0; i < p; i++) { printf "%s{\"match\":\"prefix\",\"source\":\"/prefix/%d/\",\"target\":\"https://new.example.com/p/%d/$1\",\"status\":302}", sep, i, i }
  for (i = 0; i < r; i++) { printf "%s{\"match\":\"regex\",\"source\":\"^/regex/%d/(\\\\d+)$\",\"target\":\"https://new.example.com/r/%d/$1\",\"status\":308}", sep, i, i }
  printf "]}\n"
}' >"$work/redirects.json"

export RP_STORAGE_DATA_DIR="$work" RP_SERVER_PORT="$port" RP_SERVER_LISTEN=127.0.0.1 \
  RP_ADMIN_ENABLED=false RP_STORAGE_BACKUPS=0 RP_LOG_LEVEL=warning \
  RP_ACCESS_LOG_OUTPUT="${ACCESS_LOG:-$work/access.log}"
if [ -n "$bundle" ]; then
  "$bundle/bin/redirect-proxy" serve &
else
  gleam run -- serve &
fi
pid=$!

i=0
until curl -s -o /dev/null "http://127.0.0.1:$port/"; do
  i=$((i + 1))
  [ "$i" -gt 300 ] && { echo "server did not start" >&2; exit 1; }
  sleep 0.2
done

# the BEAM process may be a child of `gleam run`
beam_pid=$(pgrep -f "RP_STORAGE_DATA_DIR|redirect_proxy@@main" | tail -1 || echo "$pid")

run() {
  label=$1
  path=$2
  url="http://127.0.0.1:$port$path"
  echo
  echo "== $label ($path)"
  if command -v oha >/dev/null 2>&1; then
    oha --no-tui -n "$requests" -c "$concurrency" --redirect 0 "$url" |
      grep -E "Requests/sec|Slowest|Fastest|Average|99.00%|\[3"
  else
    ab -q -k -n "$requests" -c "$concurrency" "$url" |
      grep -E "Requests per second|Non-2xx|Failed requests|  99%|Time per request.*mean\)"
  fi
}

run "exact rule (O(1) lookup)" "/exact/$((exact - 1))"
run "prefix rule" "/prefix/$((prefix - 1))/some/page"
run "regex rule (last of $regex)" "/regex/$((regex - 1))/42"
run "no match (worst case: every rule tried)" "/nothing/here"

rss_kb=$(ps -o rss= -p "$beam_pid" 2>/dev/null | tr -d ' ' || echo "?")
echo
echo "== memory: RSS ${rss_kb} KiB with $((exact + prefix + regex)) rules"
if [ -f "$work/access.log" ]; then
  echo "== access log: $(wc -l <"$work/access.log" | tr -d ' ') lines written"
fi
