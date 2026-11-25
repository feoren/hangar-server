# Hangar server: static musl binary in a distroless image.
#
# Build (one platform):     docker build -t hangar-server .
# Build (amd64 and arm64):  docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hangar-server:<version> --push .
#   Each platform builds natively in the Alpine image (under QEMU for the foreign architecture:
#   slow, but without a cross toolchain for SQLite and ring).
#
# The base images are pinned by digest (multi-platform index) so that a release build is
# reproducible; Dependabot proposes new digests. To update by hand:
#   docker buildx imagetools inspect rust:1-alpine   (first "Digest:" line)

FROM rust:1-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
# sqlx stores a checksum over the exact bytes of each migration: a file with CRLF (a Windows
# checkout with core.autocrlf) would not match a database migrated by an LF build, and the
# server would refuse to start on it.
RUN if grep -l "$(printf '\015')" migrations/*.sql; then echo 'migrations with CRLF' >&2; exit 1; fi
COPY src ./src
COPY vendor ./vendor
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/hangar-server /hangar-server \
 && mkdir -p /data-empty

# Only the static binary, for the release downloads (native install without Docker):
#   docker buildx build --target binary --output type=local,dest=out .
FROM scratch AS binary
COPY --from=build /hangar-server /hangar-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /hangar-server /usr/local/bin/hangar-server
# The data volume belongs to the user nonroot (65532) so that SQLite and the ticket key can be
# written.
COPY --from=build --chown=65532:65532 /data-empty /data
ENV DATA_DIR=/data \
    BIND_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/hangar-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hangar-server"]
CMD ["serve"]
