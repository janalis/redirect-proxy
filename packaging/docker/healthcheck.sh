#!/bin/sh
# Container health check. Probes the admin listener's /healthz, or, when the
# admin is disabled, checks that the redirect listener accepts connections.
# Ports follow RP_ADMIN_PORT / RP_SERVER_PORT; ports set only in a config file
# need a HEALTHCHECK override.
set -eu

case "$(printf '%s' "${RP_ADMIN_ENABLED:-true}" | tr '[:upper:]' '[:lower:]')" in
  0 | false | no | off)
    exec nc -z 127.0.0.1 "${RP_SERVER_PORT:-8080}"
    ;;
  *)
    exec wget -q -O /dev/null "http://127.0.0.1:${RP_ADMIN_PORT:-8081}/healthz"
    ;;
esac
