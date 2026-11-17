# Install methods: Docker image, Docker Compose, install.sh

Status: approved 2026-11-17. Target release: 0.5.0.

## Intent

Self-hosting should be as simple as the common ways people install a server: pull an image,
download one Compose file, or run one install script. Today the Compose file builds from source
(clone plus a slow Rust build), needs a separate `Caddyfile` and four settings, and there is no
install script and no way to run the server without Docker.

## Goals

- **Image:** unchanged path, `ghcr.io/feoren/hangar-server:X.Y.Z` (amd64, arm64), now under the
  new name.
- **Compose:** one `docker-compose.yml` that uses the published image, with the Caddy
  configuration inline. `.env` needs only `PUBLIC_URL` and `SERVER_SECRET`.
- **install.sh:** one script for both ways, `curl -fsSL <release>/install.sh | sudo sh`:
  - `docker`: Compose plus Caddy under `/opt/hangar-server`.
  - `native`: static binary, systemd service, Caddy from its official apt repository.
  - It asks for domain, way and admin e-mail, generates the secret, starts the server, creates
    the first team and prints the sign-in link. Running it again updates and keeps the settings.
- **Release assets:** every tag `vX.Y.Z` publishes a GitHub release with the static binaries
  (x86_64 and aarch64 Linux, musl), `SHA256SUMS`, `install.sh` and `docker-compose.yml`.
- **Single source:** the official website stops generating its own install script and Compose
  file and points to the release assets instead.

## Non-goals

- Windows, macOS, RPM or Debian packages, Helm charts.
- An uninstall command (the docs list the manual steps).
- Built-in TLS in the server; HTTPS stays with Caddy or the operator's own reverse proxy.

## Anti-goals

- A second build pipeline that could produce a binary different from the one in the image.
- An installer that silently overwrites an existing web server configuration or existing data.
- Breaking existing Compose installations: the data volume keeps its name.

## Approaches considered

1. **install.sh in the repository, published per release (chosen).** One script for Docker and
   native, versioned with the server; the website links to it. No duplicated installer code.
2. Keep the website's Docker installer and add a native-only script to the repository. Two
   scripts maintained separately; rejected for duplication.
3. Two complete, independent installers. Most duplicated maintenance; rejected.

For the binaries, building them in a separate Rust job was rejected in favour of exporting them
from the same Docker build stage as the image (same toolchain, same flags, same cache).

## Decisions

### Server

- New built-in default for `LICENSE_PUBLIC_KEYS`: the public key of the official website
  (`prod-20261109:7pwgqsy67kGFeqcHXk-59mFmkXESTE4xt33Y9bxwuJc`, from
  `https://hangar.feoren.com/api/v1/keys`). Used only when the variable is empty; a non-empty
  value replaces it. A key rotation therefore needs a release or the variable.
- Version 0.5.0.

### Dockerfile and release workflow

- A stage `FROM scratch AS binary` holding only `/hangar-server`, placed before the final stage
  so the default target stays the image.
- The release workflow additionally runs `docker buildx build --platform linux/amd64,linux/arm64
  --target binary --output type=local,dest=out` (cache from the image build), renames the files
  to `hangar-server-x86_64-linux-musl` and `hangar-server-aarch64-linux-musl`, writes
  `SHA256SUMS` and creates the release with these, `install.sh` and `docker-compose.yml`
  (`gh release create`, `contents: write`).
- `install.sh` and `docker-compose.yml` carry the default version (`HANGAR_VERSION`); CI fails
  when it differs from `Cargo.toml`, like the existing tag check.

### Compose

- `image: ghcr.io/feoren/hangar-server:${HANGAR_VERSION:-X.Y.Z}`, service name `server`.
- Caddy configuration inline (`configs:` with `content:`), site address `{$PUBLIC_URL}`; the
  separate `Caddyfile` and `TEAM_DOMAIN` go away.
- `IDENTITY: ${IDENTITY:-local}`, `TRUST_PROXY: "true"`, hardening as today.
- Building from source moves to `docker-compose.build.yml`
  (`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`).
- No top-level `name:`; the project name stays the directory name so existing volumes keep their
  names.

### install.sh

- POSIX `sh`, Linux, run as root. Options `--docker`, `--native`, `--version X.Y.Z`; environment
  `HANGAR_DOMAIN`, `HANGAR_EMAIL`, `HANGAR_TEAM`, `HANGAR_MODE` for unattended runs. Default way:
  ask, preselecting `docker` when Docker is installed.
- An existing installation is detected (`/opt/hangar-server/.env` or
  `/etc/hangar-server/.env`) and updated in place.
- **Docker:** writes `.env` (mode 600) and downloads `docker-compose.yml` of that version into
  `/opt/hangar-server`; installs Docker via get.docker.com only after confirmation.
- **Native:**
  - downloads the binary for `uname -m` and `SHA256SUMS`, verifies the checksum, installs to
    `/usr/local/lib/hangar-server/hangar-server-X.Y.Z` with a `current` symlink;
  - system user `hangar-server`, data in `/var/lib/hangar-server`, settings in
    `/etc/hangar-server/.env` (root:hangar-server, 640), `BIND_ADDR=127.0.0.1:8080`,
    `TRUST_PROXY=true`;
  - systemd unit `hangar-server.service` with `EnvironmentFile`, hardening (`ProtectSystem=strict`,
    `NoNewPrivileges`, `PrivateTmp`, `ReadWritePaths` for the data directory) and
    `MemoryMax=512M`;
  - admin wrapper `/usr/local/bin/hangar-server` that runs the binary as `hangar-server` from
    `/etc/hangar-server` (dotenvy reads `.env` there): `sudo hangar-server invite Team a@b`;
  - Caddy: installed from Caddy's official apt repository after confirmation when missing and
    `apt-get` exists. A stock package `Caddyfile` is replaced (backup kept); a customised one gets
    an `import` line for `/etc/caddy/hangar-server.caddy`. If ports 80/443 belong to another web
    server, Caddy is skipped and the script prints the reverse-proxy settings instead.
- Values in `.env` that contain spaces are double-quoted so systemd and dotenvy read them alike.

### Website (with the 0.5.0 release)

- The self-hosting page shows the install command and links the release's
  `docker-compose.yml`; the generated install script and Compose file are removed.
- Default image `ghcr.io/feoren/hangar-server`; references to the old name updated.

### Documentation

- README: three short ways (install script, Compose, image) plus admin commands for each.
- `docs/operations.md`: native operation (service, logs, backups, update), Compose details.

## Left to the builder

- Exact prompts, messages and option parsing in `install.sh`.
- How the release job reuses the build cache.
- Wording and layout of the website page within its own rules.
