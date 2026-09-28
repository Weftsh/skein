# syntax=docker/dockerfile:1
# The Skein image: one binary (server, admin CLI and UI) on debian-slim.
#
#   docker build -t skein .
#   docker compose up -d --build --wait     # with PostgreSQL and MinIO
#
# Corporate/CI proxies: pass a CA via `--secret id=extra_ca,src=…`;
# absent, the step no-ops.

FROM rust:1.96-bookworm AS build
WORKDIR /src
# The toolchain is the image's own. Without this, rust-toolchain.toml's
# component list sends rustup to the network on every build for
# rustfmt and clippy, which a release build does not use.
ENV RUSTUP_TOOLCHAIN=1.96.0
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then \
      cp /run/secrets/extra_ca /usr/local/share/ca-certificates/extra-ca.crt \
      && update-ca-certificates; fi
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p skein-server \
    && cp target/release/skein /skein \
    && strip /skein

FROM debian:bookworm-slim AS base
# `ca-certificates` is not optional, and `--no-install-recommends` would
# leave it out: the npm proxy reaches registry.npmjs.org over TLS, and an
# S3 endpoint on AWS is TLS. stratum-core shipped an image without it
# once and every outbound HTTPS call failed certificate verification.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -d /nonexistent -s /usr/sbin/nologin skein
ENV SKEIN_BIND=0.0.0.0:8080
EXPOSE 8080
# Liveness only: /readyz touches the database and the bucket, and a
# probe that runs every few seconds should not.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["curl", "-fsS", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/skein"]

# The release workflow's image: the static binaries it already built
# and tested, one per architecture, rather than a second compile under
# emulation. `docker buildx build --target release` with dist/<arch>/.
FROM base AS release
ARG TARGETARCH
COPY --chmod=755 dist/${TARGETARCH}/skein /usr/local/bin/skein
USER skein

# The default: built from this checkout, which is what compose.yml uses.
FROM base AS runtime
COPY --from=build /skein /usr/local/bin/skein
USER skein
