#!/bin/sh
# Fails when the Dockerfile does not use the versions of .tool-versions. The
# base image tag is written out (Dependabot updates it), so it can drift.
set -eu
dir=$(dirname "$0")/..
eval "$("$dir/scripts/tool-versions.sh")"
status=0
if ! grep -q "^FROM erlang:${OTP_VERSION}-alpine@" "$dir/Dockerfile"; then
  echo "Dockerfile: the erlang base image is not erlang:${OTP_VERSION}-alpine (.tool-versions)" >&2
  status=1
fi
if ! grep -q "^ARG GLEAM_VERSION=${GLEAM_VERSION}\$" "$dir/Dockerfile"; then
  echo "Dockerfile: GLEAM_VERSION is not ${GLEAM_VERSION} (.tool-versions)" >&2
  status=1
fi
# --online: the pinned checksums are the ones Gleam published for the version
if [ "${1:-}" = "--online" ]; then
  for pair in AMD64:x86_64 ARM64:aarch64; do
    var=${pair%%:*}
    arch=${pair#*:}
    pinned=$(sed -n "s/^ARG GLEAM_SHA256_${var}=//p" "$dir/Dockerfile")
    url="https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-${arch}-unknown-linux-musl.tar.gz.sha256"
    if ! published=$(curl -fsSL "$url" | cut -d' ' -f1); then
      echo "cannot fetch $url" >&2
      status=1
    elif [ "$pinned" != "$published" ]; then
      echo "Dockerfile: GLEAM_SHA256_${var} is not the published checksum of gleam ${GLEAM_VERSION} (${published})" >&2
      status=1
    fi
  done
fi
[ "$status" -eq 0 ] && echo "versions match .tool-versions: gleam ${GLEAM_VERSION}, erlang ${OTP_VERSION}"
exit "$status"
