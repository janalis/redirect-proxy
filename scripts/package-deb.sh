#!/bin/sh
# Builds a Debian/Ubuntu package from a bundle that embeds the Erlang runtime.
#
#   scripts/package-deb.sh VERSION ARCH BUNDLE_DIR
#
# ARCH is the Debian architecture (amd64, arm64). MAINTAINER may be set in
# the environment ("Name <email>"). Uses `nfpm` when installed, otherwise the
# goreleaser/nfpm container image.
set -eu

version=${1:?usage: package-deb.sh VERSION ARCH BUNDLE_DIR}
arch=${2:?usage: package-deb.sh VERSION ARCH BUNDLE_DIR}
bundle=${3:?usage: package-deb.sh VERSION ARCH BUNDLE_DIR}
maintainer=${MAINTAINER:-Janalis}
nfpm_image=goreleaser/nfpm:v2.48.0

rm -rf dist/deb-root
mkdir -p dist
cp -R "$bundle" dist/deb-root
sed -e "s|@VERSION@|$version|g" -e "s|@ARCH@|$arch|g" -e "s|@MAINTAINER@|$maintainer|g" \
  nfpm.yaml >dist/nfpm.yaml

if command -v nfpm >/dev/null 2>&1; then
  nfpm package --config dist/nfpm.yaml --packager deb --target dist/
else
  docker run --rm -v "$PWD:/work" -w /work "$nfpm_image" \
    package --config dist/nfpm.yaml --packager deb --target dist/
fi
rm -rf dist/deb-root dist/nfpm.yaml
ls dist/*.deb
