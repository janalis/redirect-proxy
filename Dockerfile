# syntax=docker/dockerfile:1

# Keep ALPINE_VERSION equal to the Alpine release of the erlang image: the
# bundled runtime links against the system OpenSSL of that release.
ARG ERLANG_VERSION=29.1.2
ARG ALPINE_VERSION=3.24

# --- build ------------------------------------------------------------------
FROM erlang:${ERLANG_VERSION}-alpine AS build

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
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache libstdc++ libgcc ncurses-libs openssl zlib \
 && addgroup -S -g 10001 redirect-proxy \
 && adduser -S -D -H -u 10001 -G redirect-proxy -h /var/lib/redirect-proxy redirect-proxy \
 && mkdir -p /var/lib/redirect-proxy \
 && chown redirect-proxy:redirect-proxy /var/lib/redirect-proxy

COPY --from=build /opt/redirect-proxy /opt/redirect-proxy

ENV RP_STORAGE_DATA_DIR=/var/lib/redirect-proxy \
    RP_SERVER_LISTEN=0.0.0.0 \
    RP_SERVER_PORT=8080 \
    RP_ADMIN_LISTEN=0.0.0.0 \
    RP_ADMIN_PORT=8081 \
    LANG=C.UTF-8

USER redirect-proxy
WORKDIR /var/lib/redirect-proxy
VOLUME ["/var/lib/redirect-proxy"]
EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -q -O /dev/null http://127.0.0.1:8081/healthz || exit 1

ENTRYPOINT ["/opt/redirect-proxy/bin/redirect-proxy"]
CMD ["serve"]
