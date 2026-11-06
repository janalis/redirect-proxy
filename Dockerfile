# syntax=docker/dockerfile:1

# Base images are pinned by digest and written out (no ARG) so that
# Dependabot can update them. Keep the runtime Alpine release equal to the
# one of the erlang image: the bundled runtime links against its OpenSSL.

# --- build ------------------------------------------------------------------
FROM erlang:29.1.2-alpine@sha256:0ac9b63db11be156be4e2834546e44aa0d7446aaffb05fedd4aea8c5a33ad998 AS build

ARG GLEAM_VERSION=1.19.2
ARG VERSION=dev
ARG TARGETARCH

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN apk add --no-cache curl tar \
 && case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
    | tar -xz -C /usr/local/bin \
 && gleam --version

WORKDIR /src
COPY gleam.toml manifest.toml ./
RUN gleam deps download
COPY . .
RUN scripts/bundle.sh "${VERSION}" container --with-erts \
 && mv "dist/redirect-proxy-${VERSION}-container" /opt/redirect-proxy

# --- runtime ----------------------------------------------------------------
FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a

RUN apk add --no-cache libstdc++ libgcc ncurses-libs openssl zlib lksctp-tools \
 && addgroup -S -g 10001 redirect-proxy \
 && adduser -S -D -H -u 10001 -G redirect-proxy -h /var/lib/redirect-proxy redirect-proxy \
 && mkdir -p /var/lib/redirect-proxy \
 && chown redirect-proxy:redirect-proxy /var/lib/redirect-proxy

COPY --from=build /opt/redirect-proxy /opt/redirect-proxy
COPY --chmod=0755 packaging/docker/healthcheck.sh /usr/local/bin/healthcheck

ENV RP_STORAGE_DATA_DIR=/var/lib/redirect-proxy \
    RP_SERVER_LISTEN=0.0.0.0 \
    RP_SERVER_PORT=8080 \
    RP_ADMIN_LISTEN=0.0.0.0 \
    RP_ADMIN_PORT=8081 \
    LANG=C.UTF-8

USER 10001:10001
WORKDIR /var/lib/redirect-proxy
VOLUME ["/var/lib/redirect-proxy"]
EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/opt/redirect-proxy/bin/redirect-proxy"]
CMD ["serve"]
