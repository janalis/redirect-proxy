#!/bin/sh
# Prints the tool versions of .tool-versions (the single source) as
# environment assignments: GLEAM_VERSION=..., OTP_VERSION=...
#   scripts/tool-versions.sh >> "$GITHUB_ENV"
set -eu
dir=$(dirname "$0")/..
awk '
  $1 == "gleam" { print "GLEAM_VERSION=" $2 }
  $1 == "erlang" { print "OTP_VERSION=" $2 }
' "$dir/.tool-versions"
