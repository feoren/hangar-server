# Development

Code layout, the check pipeline, the app's crates under `vendor/` and open items. For operations
see [operations.md](operations.md), for the routes [http-api.md](http-api.md).

## Layout

```
Cargo.toml, Cargo.lock      one crate, pinned versions
migrations/                 0001_relay.sql (relay), 0002_identity.sql (self-hosting),
                            0003_magic_link_browser.sql (magic link bound to the browser)
                            through 0010_removed_device_log_index.sql (log index of the
                            device removal, grace period of the removed device)
src/
  main.rs                   commands: serve, healthcheck, login-link, create-team, invite, teams
  lib.rs                    wiring (also for the tests)
  config.rs                 environment/.env, validation on startup
  wire.rs                   names from the app's protocol crate (see below)
  signed.rs, ticket.rs, license.rs   signed documents
  relay/                    conn (WebSocket), team (log, sequence, replay, snapshot),
                            reservations ("first wins"), claims (hash comparison), store (SQLite)
  identity/                 auth (tokens, magic link, device flow), teams (invitations, seats,
                            license, tickets), api (account API /api/v1 like the website),
                            account (/account/devices), pages (browser pages)
  mail/                     sending (SMTP/log/none), templates, texts in 12 languages
  http/                     router, security headers, rate limiting
tests/                      relay.rs, identity.rs, account_api.rs, vectors.rs (integration tests)
testdata/                   test vectors for tickets and licenses
tools/php/verify_vectors.php  cross-check of the vectors with PHP/libsodium
docs/                       formats, protocol, wishes for the protocol crate, security, dependencies
Dockerfile, docker-compose.yml, Caddyfile, .env.example
```

### The app's crates (protocol and crypto)

Two crates belong to the app (MIT) and are kept as **fixed, unmodified copies** under `vendor/`,
included as path dependencies (origin and commit per crate in `ORIGIN.md`, currently
`79c68ca`). This way the image builds without access to the app repository or GitHub.

| Crate | Contents | In the relay |
| --- | --- | --- |
| `hangar-team-protocol` (step C) | wire format, keyed hashes, reservation book, claims, event log, retries, hash chain of the log | `src/wire.rs` passes the names through; rules come directly from the crate |
| `hangar-team-crypto` (step E) | device keys, signed membership log (`LogVerifier`), epochs, rotation, key packages, relay checks (`relay::check_wrap`, `relay::check_registered_keys`) | checks every log entry, every rotation, every device removal and every key package before it is stored |

The relay neither holds nor derives keys; it only checks signatures, permissions and chains. Do
not change anything in `vendor/` by hand. What the crates still lack for the server:
[docs/protocol-wishes.md](protocol-wishes.md).

> **Crypto design not audited.** The E2E scheme (device keys, log, epochs, HPKE, recovery) is a
> custom protocol. It needs an external cryptographic audit before real team data is used (see
> docs/security.md).

#### Updating the crates (by hand)

When the app commits a new state:

1. Look up the commit hash in the app repository (clone of https://github.com/feoren/hangar,
   here next to this repository as `../hangar`):
   `git -C ../hangar log -1 --format=%H -- crates/hangar-team-protocol crates/hangar-team-crypto`
   (mind the branch).
2. Replace both copies, without `Cargo.lock`:
   ```sh
   rm -rf vendor/hangar-team-protocol vendor/hangar-team-crypto
   mkdir -p vendor
   git -C ../hangar archive <hash> crates/hangar-team-protocol crates/hangar-team-crypto | tar -x -C vendor --strip-components=1
   rm -f vendor/*/Cargo.lock
   ```
   Without Git: copy the folders `crates/hangar-team-protocol` and `crates/hangar-team-crypto`
   from the app repository to `vendor/` and delete `Cargo.lock` and `target/` inside them.
3. Enter the hash and date in `vendor/*/ORIGIN.md`.
4. `cargo update -p hangar-team-protocol -p hangar-team-crypto`, then `cargo fmt --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`.
5. Check that the copies are unmodified (`diff -r` against a fresh `git archive`).
6. If tests break: read the change list in the protocol crate's README ("Changelog") and update
   `docs/protocol.md`; then build a new image.

## Building and checking

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
php tools/php/verify_vectors.php testdata/tickets.json testdata/licenses.json
```

Rust stable (tested with 1.99.1), edition 2021.

Image: `docker build -t hangar-team-server .`; for amd64 and arm64:
`docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hangar-team-server:<version> --push .`
(static musl binary, distroless, user `nonroot`).


## Open items

- Docker image: after every new state of the app's crates, renew the copies in `vendor/` (see
  "Updating the crates (by hand)").
- External crypto audit of the E2E scheme (app, step E).
- Embed the official public license keys at build time (instead of configuration only) so that
  self-hosters cannot issue their own licenses.
- Account deletion, data export, ownership transfer (self-hosting).
- Passkeys and OIDC; merge queue and further steps of G.
- Multiple nodes (Postgres, shared rate limiting).
- arm64 image only described, not built locally.
- Legal review of the license texts, CLA for contributions, `TRADEMARKS.md` (ADR 0005).
