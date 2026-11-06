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
[ "$status" -eq 0 ] && echo "versions match .tool-versions: gleam ${GLEAM_VERSION}, erlang ${OTP_VERSION}"
exit "$status"
