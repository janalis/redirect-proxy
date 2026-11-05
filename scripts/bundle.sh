#!/bin/sh
# Builds a release bundle from the Gleam Erlang shipment.
#
#   scripts/bundle.sh VERSION TARGET [--with-erts]
#
# TARGET is a free-form label (linux-amd64, linux-arm64, erlang...).
# --with-erts copies the Erlang runtime of the `erl` found in PATH into the
# bundle, so the result runs on machines without Erlang installed (the
# runtime is platform specific: build on the target OS/architecture).
#
# Output: dist/redirect-proxy-VERSION-TARGET.tar.gz (+ .sha256)
set -eu

version=${1:?usage: bundle.sh VERSION TARGET [--with-erts]}
target=${2:?usage: bundle.sh VERSION TARGET [--with-erts]}
with_erts=${3:-}

name="redirect-proxy-$version-$target"
out="dist/$name"

rm -rf "$out" "dist/$name.tar.gz" "dist/$name.tar.gz.sha256"
mkdir -p "$out/bin" "$out/lib" "$out/share/redirect-proxy"

gleam export erlang-shipment >/dev/null
for app in build/erlang-shipment/*/; do
  app_name=$(basename "$app")
  mkdir -p "$out/lib/$app_name"
  cp -R "$app/ebin" "$out/lib/$app_name/"
  if [ -d "$app/priv" ]; then
    cp -R "$app/priv" "$out/lib/$app_name/"
  fi
done

cp packaging/bin/redirect-proxy "$out/bin/redirect-proxy"
chmod 755 "$out/bin/redirect-proxy"
cp config.example.toml LICENSE README.md CHANGELOG.md "$out/share/redirect-proxy/"

if [ "$with_erts" = "--with-erts" ]; then
  root=$(erl -noshell -eval 'io:format("~s", [code:root_dir()]), halt().')
  erts_version=$(erl -noshell -eval 'io:format("~s", [erlang:system_info(version)]), halt().')
  mkdir -p "$out/erts/bin" "$out/erts/lib"
  cp -R "$root/erts-$erts_version" "$out/erts/"
  # remove what is only needed to build NIFs or debug the VM
  rm -rf "$out/erts/erts-$erts_version/include" \
    "$out/erts/erts-$erts_version/lib" \
    "$out/erts/erts-$erts_version/src" \
    "$out/erts/erts-$erts_version/doc" \
    "$out/erts/erts-$erts_version/man"
  rm -f "$out/erts/erts-$erts_version"/bin/*.debug "$out/erts/erts-$erts_version"/bin/*.valgrind \
    "$out/erts/erts-$erts_version"/bin/*.asan
  cp "$root"/bin/*.boot "$out/erts/bin/"
  for otp_app in kernel stdlib crypto asn1 public_key ssl inets; do
    for dir in "$root"/lib/"$otp_app"-*; do
      dest="$out/erts/lib/$(basename "$dir")"
      mkdir -p "$dest"
      cp -R "$dir/ebin" "$dest/"
      if [ -d "$dir/priv" ]; then
        cp -R "$dir/priv" "$dest/"
      fi
    done
  done
  rm -rf "$out"/erts/lib/*/priv/obj "$out"/erts/lib/*/priv/src
fi

tar -C dist -czf "dist/$name.tar.gz" "$name"
(
  cd dist
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$name.tar.gz" >"$name.tar.gz.sha256"
  else
    shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256"
  fi
)
echo "dist/$name.tar.gz"
