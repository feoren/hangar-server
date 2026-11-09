# Hangar-Teamserver: statisches musl-Binary in einem distroless-Image.
#
# Bauen (eine Plattform):   docker build -t hangar-team-server .
# Bauen (amd64 und arm64):  docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hangar-team-server:<version> --push .
#   Jede Plattform baut nativ im Alpine-Image (unter QEMU für die fremde Architektur: langsam,
#   aber ohne Cross-Toolchain für SQLite und ring).
#
# Basis-Images vor einer Veröffentlichung mit Digest pinnen (`rust:1-alpine@sha256:...`).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY vendor ./vendor
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/hangar-team-server /hangar-team-server \
 && mkdir -p /data-empty

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /hangar-team-server /usr/local/bin/hangar-team-server
# Das Datenvolumen gehört dem Nutzer nonroot (65532), damit SQLite und der Ticketschlüssel
# geschrieben werden können.
COPY --from=build --chown=65532:65532 /data-empty /data
ENV DATA_DIR=/data \
    BIND_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/hangar-team-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hangar-team-server"]
CMD ["serve"]
