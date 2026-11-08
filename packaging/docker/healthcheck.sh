#!/bin/sh
# Container health check. Probes the admin listener's /healthz. When the
# admin is disabled, probes the redirect listener's RP_SERVER_HEALTH_PATH
# when it is set (503 while draining), else checks that the redirect listener
# accepts connections. Addresses and ports follow RP_ADMIN_LISTEN /
# RP_ADMIN_PORT and RP_SERVER_LISTEN / RP_SERVER_PORT; settings made only in
# a config file need a HEALTHCHECK override.
set -eu

# The address to probe for a listen address: loopback for the wildcard
# addresses, the address itself otherwise (a listener bound to one interface
# does not answer on 127.0.0.1).
probe_address() {
  case "$1" in
    "" | 0.0.0.0) echo 127.0.0.1 ;;
    :: | "[::]") echo ::1 ;;
    "["*"]") echo "$1" | tr -d '[]' ;;
    *) echo "$1" ;;
  esac
}

# The address as a URL host: IPv6 addresses go in brackets.
url_host() {
  case "$1" in
    *:*) echo "[$1]" ;;
    *) echo "$1" ;;
  esac
}

case "$(printf '%s' "${RP_ADMIN_ENABLED:-true}" | tr '[:upper:]' '[:lower:]')" in
  0 | false | no | off)
    address="$(probe_address "${RP_SERVER_LISTEN:-}")"
    port="${RP_SERVER_PORT:-8080}"
    case "${RP_SERVER_HEALTH_PATH:-}" in
      "") exec nc -z "$address" "$port" ;;
      # a path, starting with / (check-config refuses others)
      *) exec wget -q -O /dev/null "http://$(url_host "$address"):${port}${RP_SERVER_HEALTH_PATH}" ;;
    esac
    ;;
  *)
    host="$(url_host "$(probe_address "${RP_ADMIN_LISTEN:-}")")"
    exec wget -q -O /dev/null "http://${host}:${RP_ADMIN_PORT:-8081}/healthz"
    ;;
esac
