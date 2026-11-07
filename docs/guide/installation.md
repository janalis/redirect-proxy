# Installation

| Platform | Install with |
| --- | --- |
| Any (container) | `docker pull ghcr.io/janalis/redirect-proxy` (linux/amd64, linux/arm64) |
| Debian 12+ / Ubuntu 22.04+ | `.deb` from the [releases](https://github.com/janalis/redirect-proxy/releases) |
| macOS | `brew install janalis/tap/redirect-proxy` |
| Linux (other) | `redirect-proxy-<version>-linux-<arch>.tar.gz`, which includes the Erlang runtime |
| Anywhere with Erlang/OTP 27+ | `redirect-proxy-<version>-erlang.tar.gz` |

## Debian / Ubuntu

```sh
sudo apt install ./redirect-proxy_<version>_amd64.deb
sudo -u redirect-proxy RP_CONFIG=/etc/redirect-proxy/config.toml redirect-proxy user add admin
sudo systemctl start redirect-proxy
```

The package installs these files:

- The application, in `/usr/lib/redirect-proxy`. It bundles the Erlang
  runtime, so there is no system Erlang dependency.
- A hardened systemd unit.
- `/etc/redirect-proxy/config.toml`.
- The data directory, `/var/lib/redirect-proxy`.

The unit can bind ports 80 and 443 without root. `systemctl reload
redirect-proxy` re-reads the redirections file only: changes to
`config.toml` need `systemctl restart redirect-proxy`.

## Homebrew

```sh
brew install janalis/tap/redirect-proxy
RP_CONFIG=$(brew --prefix)/etc/redirect-proxy/config.toml \
RP_STORAGE_DATA_DIR=$(brew --prefix)/var/lib/redirect-proxy \
  redirect-proxy user add admin
brew services start redirect-proxy
```

## Verifying a download

Every release asset comes with a `SHA256SUMS` file and a build provenance
attestation signed by the release workflow, so you can check that a file was
built by this repository's CI from the tagged commit:

```sh
# the files are intact
sha256sum -c --ignore-missing SHA256SUMS
# they were built by janalis/redirect-proxy's release workflow (GitHub CLI)
gh attestation verify redirect-proxy-<version>-linux-amd64.tar.gz \
  --repo janalis/redirect-proxy
# the same for the container image
gh attestation verify oci://ghcr.io/janalis/redirect-proxy:<version> \
  --repo janalis/redirect-proxy
```

On macOS, use `shasum -a 256 -c --ignore-missing SHA256SUMS`.

## From source

You need Gleam 1.19+ and Erlang/OTP 27+.

```sh
git clone https://github.com/janalis/redirect-proxy && cd redirect-proxy
make dev          # admin / change-me-please, data in ./data
make bundle       # self-contained bundle in dist/
```

Next: [getting started](getting-started).
