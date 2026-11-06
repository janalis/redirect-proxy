#!/bin/sh
# Installs a built .deb on this (disposable, systemd) machine, then checks
# that it starts, that an upgrade keeps a disabled service disabled, that
# remove keeps the data and that purge removes everything. Used by CI and
# the release workflow; needs sudo.
#
#   scripts/test-deb.sh VERSION ARCH
set -eu

version=${1:?usage: test-deb.sh VERSION ARCH}
arch=${2:?usage: test-deb.sh VERSION ARCH}
deb="./dist/redirect-proxy_${version}_${arch}.deb"

fail() {
  echo "::error::$1"
  exit 1
}

echo "--- install and start"
sudo apt-get install -y "$deb"
redirect-proxy version
sudo -u redirect-proxy RP_CONFIG=/etc/redirect-proxy/config.toml redirect-proxy check-config
sudo systemctl start redirect-proxy
for _ in $(seq 1 50); do curl -fsS http://127.0.0.1:8081/healthz && break; sleep 0.2; done
sudo systemctl is-active redirect-proxy
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/missing)" = "404" ||
  fail "the redirect listener does not answer"

echo "--- an upgrade keeps a disabled service disabled"
sudo systemctl disable --now redirect-proxy
sudo apt-get install -y --reinstall "$deb"
if systemctl is-enabled --quiet redirect-proxy; then
  fail "the upgrade re-enabled the service"
fi

echo "--- remove keeps data, purge removes it"
sudo apt-get remove -y redirect-proxy
test -d /var/lib/redirect-proxy || fail "remove deleted the data"
getent passwd redirect-proxy >/dev/null || fail "remove deleted the user"
sudo apt-get purge -y redirect-proxy
for path in /var/lib/redirect-proxy /var/log/redirect-proxy; do
  if test -e "$path"; then fail "purge left $path"; fi
done
if getent passwd redirect-proxy >/dev/null; then
  fail "purge left the redirect-proxy user"
fi
