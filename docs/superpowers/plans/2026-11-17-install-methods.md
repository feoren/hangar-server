# Install Methods Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Self-hosting via published image, a single Compose file, or one `install.sh` (Docker or native systemd), released together as 0.5.0.

**Architecture:** The server gets a built-in default license key. Compose uses the published image with Caddy configured inline. The release workflow exports the static binaries from the Docker build stage and attaches them with `install.sh` and `docker-compose.yml` to a GitHub release. `install.sh` is one POSIX script with a Docker and a native branch.

**Tech Stack:** Rust (axum, sqlx), Docker Buildx, Docker Compose v2.23+, Caddy 2, POSIX sh, systemd, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-17-install-methods-design.md`

## Global Constraints

- Everything in the repository is English; no Claude attribution in commits.
- Never touch `migrations/`.
- Names: binary/crate/image `hangar-server`, image `ghcr.io/feoren/hangar-server:X.Y.Z`, Compose service `server`, system user `hangar-server`.
- Paths: Docker `/opt/hangar-server`; native `/usr/local/lib/hangar-server/`, `/etc/hangar-server/.env`, `/var/lib/hangar-server`, wrapper `/usr/local/bin/hangar-server`, unit `hangar-server.service`, Caddy snippet `/etc/caddy/hangar-server.caddy`.
- Release assets: `hangar-server-x86_64-linux-musl`, `hangar-server-aarch64-linux-musl`, `SHA256SUMS`, `install.sh`, `docker-compose.yml`.
- Default version in `install.sh` and `docker-compose.yml` equals `Cargo.toml` version; target 0.5.0.
- Official license key: `prod-20261109:7pwgqsy67kGFeqcHXk-59mFmkXESTE4xt33Y9bxwuJc`.
- Check suite: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`; plus `shellcheck install.sh` and `docker compose config -q`.

## Review Focus

1. Re-running `install.sh` on an existing installation must keep `.env` (secret, mail settings) and data; covered by the CI install smoke test running the script twice.
2. A customised `/etc/caddy/Caddyfile` must never be overwritten; covered by `tests/install/caddyfile.sh`.
3. Checksum mismatch of a downloaded binary must abort before anything is installed; covered by the CI smoke test with a corrupted `SHA256SUMS`.
4. `MAIL_FROM` with spaces and angle brackets must be read identically by systemd and dotenvy; covered by the native smoke test calling `sudo hangar-server teams` after the service started.
5. Existing Compose installs (cloned directory `hangar-team-server`) keep their volume; no top-level `name:` in Compose, checked by `docker compose config` in CI asserting the volume key `team-data`.

---

### Task 1: Built-in official license key

**Files:**
- Modify: `src/license.rs` (constant), `src/config.rs:371-372`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Produces: `pub const OFFICIAL_LICENSE_KEYS: &str` in `src/license.rs`; `pub fn license_keys_from(raw: &str) -> Result<KeySet, ConfigError>` in `src/config.rs`.

- [ ] **Step 1: Failing tests** `license_keys_default_to_official` (`license_keys_from("")` and `license_keys_from("  ")` contain kid `prod-20261109`) and `license_keys_env_replaces_default` (a test key `t1:<43 chars>` yields a set without `prod-20261109`).
- [ ] **Step 2:** `cargo test --lib config` → FAIL (function missing).
- [ ] **Step 3:** Implement; `from_env` calls `license_keys_from(&var("LICENSE_PUBLIC_KEYS").unwrap_or_default())`. Update `.env.example` comment: empty = key of hangar.feoren.com.
- [ ] **Step 4:** Full check suite green.
- [ ] **Step 5:** `git commit -m "feat(license): default to the official website key"`

### Task 2: Compose with the published image

**Files:**
- Modify: `docker-compose.yml`, `.env.example`, `.github/workflows/ci.yml`
- Create: `docker-compose.build.yml`, `tools/check-versions.sh`
- Delete: `Caddyfile`

**Interfaces:**
- Produces: `tools/check-versions.sh` (exit 1 with a message when the default version in `docker-compose.yml` or `install.sh` differs from `Cargo.toml`; skips a missing file).

- [ ] **Step 1:** `docker-compose.yml`: service `server` with `image: ghcr.io/feoren/hangar-server:${HANGAR_VERSION:-0.5.0}`, `env_file: .env`, `IDENTITY: ${IDENTITY:-local}`, `TRUST_PROXY: "true"`, existing hardening and limits; service `caddy` with `PUBLIC_URL` passed in and `configs: [{source: caddyfile, target: /etc/caddy/Caddyfile}]`; top-level `configs.caddyfile.content` = today's Caddyfile with site address `{$$PUBLIC_URL}` and upstream `server:8080`. No top-level `name:`.
- [ ] **Step 2:** `docker-compose.build.yml` overriding `server` with `build: .` and `image: hangar-server:local`.
- [ ] **Step 3:** `.env.example`: drop `TEAM_DOMAIN`; top block lists the two required values for self-hosting.
- [ ] **Step 4:** `tools/check-versions.sh` and a CI step in the `docker` job: `tools/check-versions.sh`, `docker compose config -q` (with a dummy `.env`), and `docker compose config --volumes | grep -qx team-data`.
- [ ] **Step 5:** Local: `cp .env.example .env.ci` style dummy, `docker compose --env-file … config -q` passes; `docker compose -f docker-compose.yml -f docker-compose.build.yml config -q` passes.
- [ ] **Step 6:** `git commit -m "feat(compose): run the published image with Caddy configured inline"`

### Task 3: Release binaries

**Files:**
- Modify: `Dockerfile`, `.github/workflows/release.yml`

- [ ] **Step 1:** `Dockerfile`: stage `FROM scratch AS binary` with `COPY --from=build /hangar-server /hangar-server`, placed before the final stage.
- [ ] **Step 2:** Local: `docker buildx build --target binary --output type=local,dest=out .` produces `out/hangar-server`; `file out/hangar-server` says statically linked.
- [ ] **Step 3:** `release.yml`: after the image push, same job: buildx `--platform linux/amd64,linux/arm64 --target binary --output type=local,dest=out` with `cache-from: type=gha`; rename `out/linux_amd64/hangar-server` and `out/linux_arm64/hangar-server` to the asset names; `sha256sum` → `SHA256SUMS`; run `tools/check-versions.sh`; `gh release create "$GITHUB_REF_NAME" … --title "$GITHUB_REF_NAME" --generate-notes`. Job permissions `contents: write`, `packages: write`; `GH_TOKEN: ${{ github.token }}`.
- [ ] **Step 4:** `actionlint` (if available) or careful review; CI `docker` job still builds the default target.
- [ ] **Step 5:** `git commit -m "ci: attach static binaries and install files to each release"`

### Task 4: install.sh, common part and Docker way

**Files:**
- Create: `install.sh`, `tests/install/caddyfile.sh`
- Modify: `.github/workflows/ci.yml` (job `install`)

**Interfaces:**
- Produces in `install.sh`: `HANGAR_VERSION` default `0.5.0`; test overrides `HANGAR_IMAGE`, `HANGAR_COMPOSE_FILE` (local file instead of download), `HANGAR_BINARY` + `HANGAR_SUMS` (local files for Task 5), `HANGAR_SKIP_CADDY=1`; functions `ask`, `confirm`, `fail`, `random_secret`, `write_env FILE`, `caddy_site DOMAIN` (prints the site block), `caddy_configure` (used in Task 5).

- [ ] **Step 1:** Skeleton: `set -eu`, root check, option parsing (`--docker`, `--native`, `--version X.Y.Z`, `--help`), env `HANGAR_DOMAIN`, `HANGAR_EMAIL`, `HANGAR_TEAM` (default `Team`), `HANGAR_MODE`; validation regexes as in the website's current installer; existing-install detection → update branch.
- [ ] **Step 2:** `write_env` writes mode 600: `IDENTITY=local`, `PUBLIC_URL=https://$DOMAIN`, `SERVER_SECRET` (64 hex from `/dev/urandom`), `SIGNUP=invite`, `MAIL_TRANSPORT=none`, `MAIL_FROM="Hangar <$EMAIL>"`, empty SMTP block, plus for native `DATA_DIR`, `BIND_ADDR=127.0.0.1:8080`, `TRUST_PROXY=true`.
- [ ] **Step 3:** Docker way: optional Docker install via get.docker.com after `confirm`; `/opt/hangar-server/{.env,docker-compose.yml}` (download from `https://github.com/feoren/hangar-server/releases/download/v$V/docker-compose.yml` unless `HANGAR_COMPOSE_FILE`); `HANGAR_VERSION=$V` written to `.env` so Compose pins it; `docker compose up -d`; wait until `docker inspect -f '{{.State.Health.Status}}'` of the server container is `healthy` (60 s); `create-team` and `login-link` via `docker compose run --rm -T server`; final instructions. Update branch: replace compose file and `HANGAR_VERSION`, `docker compose up -d --remove-orphans`.
- [ ] **Step 4:** `tests/install/caddyfile.sh`: sources `install.sh` functions with `HANGAR_LIB_ONLY=1` and asserts: stock Debian Caddyfile (contains `The Caddyfile is an easy way`) → replaced, `.bak` created; custom Caddyfile → unchanged except one appended `import /etc/caddy/hangar-server.caddy` line, idempotent on a second run. (The function itself lands in Task 5; this test must fail until then.)
- [ ] **Step 5:** CI job `install` (ubuntu-latest): `shellcheck install.sh`; build image `hangar-server:ci`; run `sudo HANGAR_MODE=docker HANGAR_DOMAIN=team.example.org HANGAR_EMAIL=ci@example.org HANGAR_IMAGE=hangar-server:ci HANGAR_COMPOSE_FILE=$PWD/docker-compose.yml sh install.sh` twice; assert after the second run that `SERVER_SECRET` in `/opt/hangar-server/.env` is unchanged and `docker compose run --rm -T server teams` lists `Team`.
- [ ] **Step 6:** `git commit -m "feat: install.sh for the Docker way"`

### Task 5: install.sh, native way

**Files:**
- Modify: `install.sh`, `.github/workflows/ci.yml` (job `install`)

**Interfaces:**
- Consumes: Task 4 functions and overrides; Task 3 asset names.

- [ ] **Step 1:** Native install: arch from `uname -m` (`x86_64`, `aarch64`/`arm64`, else fail); download binary and `SHA256SUMS` (or `HANGAR_BINARY`/`HANGAR_SUMS`), verify with `sha256sum -c --ignore-missing` before touching the system; user `hangar-server` (`useradd --system --home /var/lib/hangar-server --shell /usr/sbin/nologin`); binary to `/usr/local/lib/hangar-server/hangar-server-$V`, symlink `current`; `/etc/hangar-server/.env` root:hangar-server 640; wrapper `/usr/local/bin/hangar-server` = `cd /etc/hangar-server && exec runuser -u hangar-server -- /usr/local/lib/hangar-server/current "$@"` (root check inside).
- [ ] **Step 2:** Unit `hangar-server.service`: `User=hangar-server`, `WorkingDirectory=/etc/hangar-server`, `EnvironmentFile=/etc/hangar-server/.env`, `ExecStart=/usr/local/lib/hangar-server/current serve`, `Restart=on-failure`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths=/var/lib/hangar-server`, `MemoryMax=512M`, `TimeoutStopSec=20`; `systemctl daemon-reload && systemctl enable --now`; wait for `curl -fsS http://127.0.0.1:8080/health`.
- [ ] **Step 3:** `caddy_configure`: skip with `HANGAR_SKIP_CADDY=1`; if ports 80/443 are held by a process other than `caddy` → print reverse-proxy instructions (upstream `127.0.0.1:8080`, WebSocket on `/v1/live`) and skip; if `caddy` is missing and `apt-get` exists → `confirm`, then Caddy's official apt repo (`https://dl.cloudsmith.io/public/caddy/stable/gpg.key`, `debian.deb.txt`); write `/etc/caddy/hangar-server.caddy` from `caddy_site`; stock Caddyfile → replace with an `import` of the snippet (backup `.bak`); custom → append the `import` line once; `systemctl reload caddy`.
- [ ] **Step 4:** Update branch: new binary verified and linked, `systemctl restart hangar-server`, `.env` untouched.
- [ ] **Step 5:** `sh tests/install/caddyfile.sh` → PASS. CI: export the binary (`--target binary`), write `SHA256SUMS` for it, run `sudo HANGAR_MODE=native … HANGAR_BINARY=… HANGAR_SUMS=… HANGAR_SKIP_CADDY=1 sh install.sh` twice; assert `/health` ok, unchanged secret, `sudo hangar-server teams` lists `Team`; then a run with a corrupted `SHA256SUMS` exits non-zero and leaves `current` unchanged.
- [ ] **Step 6:** `git commit -m "feat: install.sh for the native way with systemd and Caddy"`

### Task 6: Documentation and version 0.5.0

**Files:**
- Modify: `README.md`, `docs/operations.md`, `docs/development.md`, `Cargo.toml` (`version = "0.5.0"`), `Cargo.lock`

- [ ] **Step 1:** README "Set up your own server": (1) install script one-liner from `releases/latest/download/install.sh`, (2) Compose: download `docker-compose.yml`, two values in `.env`, `docker compose up -d`, (3) image only: `docker run` with the required variables behind your own proxy. Admin commands for Docker (`docker compose run --rm server …`) and native (`sudo hangar-server …`).
- [ ] **Step 2:** `docs/operations.md`: native section (service, `journalctl -u hangar-server`, backup of `/var/lib/hangar-server/hangar-team.db` with `sqlite3 .backup`, update by re-running the script, manual uninstall steps); Compose section updated for the inline Caddy config and `docker-compose.build.yml`. `docs/development.md`: release procedure lists the new assets.
- [ ] **Step 3:** Version bump; `tools/check-versions.sh` and the full check suite pass.
- [ ] **Step 4:** `git commit -m "docs: three ways to self-host; version 0.5.0"`

### Task 7: Release and follow-ups (needs the owner's go)

- [ ] **Step 1:** Push `main`, CI green.
- [ ] **Step 2:** After the owner's confirmation: `git tag v0.5.0 && git push github v0.5.0`; release workflow green; release lists the five assets; `docker pull ghcr.io/feoren/hangar-server:0.5.0` works without login (set the package public if needed).
- [ ] **Step 3:** Website (own repository and rules, German): self-hosting page shows the install command and the release `docker-compose.yml` link; remove the generated installer and Compose file (`InstallFiles`, `SelfHostingFileController`, routes, tests); default `SELFHOST_IMAGE` `ghcr.io/feoren/hangar-server`, `SELFHOST_VERSION` `0.5.0`; old name in comments, docs and wiki; `composer check` green.
- [ ] **Step 4:** Local notes: images folder guide and project notes name the new image.
