# Dependencies

Versions are pinned in `Cargo.lock` (`cargo build --locked`). Selection as of: 2026-11-09.
All runtime dependencies are licensed under MIT, Apache-2.0, BSD-3-Clause or ISC (or dual
licenses combining them) and are compatible with the server's Elastic License 2.0. The protocol
crate adds `unicode-normalization` ((MIT OR Apache-2.0) AND Unicode-3.0, a permissive exception
for the Unicode tables documented by the app).

| Crate | Version | License | Purpose and rationale | Alternative |
| --- | --- | --- | --- | --- |
| hangar-team-crypto | copy from `79c68ca` (`vendor/`) | MIT | Verification of the membership log, rotations, device removals and key packages (step E); owned by the app, no secrets in the relay. Brings in `hpke` 0.15, `chacha20poly1305` 0.11, `ed25519-dalek` 3, `hkdf` 0.13, `getrandom` 0.4, `data-encoding` 2 (all MIT/Apache-2.0 or BSD-3-Clause/MIT) | own verification (a second source for the same rules) |
| hangar-team-protocol | copy from `79c68ca` (`vendor/`) | MIT | Wire format, keyed hashes, reservation, claims, log, E2E rules; owned by the app (step C), one source for both sides. Pinned via `git`/`rev` instead of `path`, so that uncommitted work in the app's worktree does not change the server | `path` to the worktree (development only) |
| axum | 0.8.9 | MIT | HTTP and WebSocket, required by the plan; tokio project, actively maintained | actix-web (own runtime), hyper directly (a lot of custom code) |
| tokio | 1.54 | MIT | Runtime, timers, signals; the standard in the Rust ecosystem | smol (smaller ecosystem) |
| sqlx | 0.9.0 | MIT/Apache-2.0 | SQLite (WAL), migrations (`migrate!` embeds `migrations/`); required by the plan; `sqlite-bundled` builds SQLite in (static binary) | rusqlite (synchronous, own pooling) |
| serde, serde_json | 1 | MIT/Apache-2.0 | JSON frames and documents, as in the app | none sensible |
| thiserror | 2 | MIT/Apache-2.0 | Error types, as in the app | by hand |
| ed25519-dalek | 2.2 | BSD-3-Clause | Verifying tickets and licenses, issuing tickets in self-hosting; `verify_strict`; dalek-cryptography, audited and widely used. Version 3.0 has been released but is young; 2.2 shares sha2 0.10 with the rest of the tree | ring (no Ed25519 import of raw keys in all variants), libsodium (C) |
| sha2 0.10, hmac 0.12, subtle 2.6 | | MIT/Apache-2.0 or BSD-3-Clause | Token hashes, HMAC for CSRF and rate limiting keys, constant-time comparison; RustCrypto | ring |
| base64 | 0.22 | MIT/Apache-2.0 | base64url without padding, strict | by hand |
| getrandom | 0.3 | MIT/Apache-2.0 | Randomness directly from the operating system for tokens and keys | rand (larger, unnecessary here) |
| futures-util | 0.3 | MIT/Apache-2.0 | `split` of the WebSocket into reading and writing | already in the tree via axum |
| tracing, tracing-subscriber | 0.1 / 0.3 | MIT | Structured JSON logging, required by the plan | log + env_logger (no JSON) |
| dotenvy | 0.15 | MIT | Reading `.env` (maintained successor of dotenv) | environment variables only |
| reqwest | 0.13 | MIT/Apache-2.0 | Fetching the website's revocation list (official mode only). Without default features, `rustls-no-provider`: no aws-lc-rs (C, cmake) in the static binary, root certificates via `rustls-platform-verifier` (system). No redirects, no proxy, 10 s timeout, 1 MiB size limit in the code; hyper is already in the tree via axum | hyper-util directly (build TLS, timeouts and the redirect ban yourself) |
| rustls | 0.23 | MIT/Apache-2.0/ISC | Installing the `ring` provider for reqwest once per process (`src/tls.rs`); already in the tree via lettre | none |
| lettre | 0.11.24 | MIT | SMTP with TLS (rustls, ring, webpki-roots, no OpenSSL in the static binary), multipart mail | own SMTP client (too much error surface) |

Tests only: `tokio-tungstenite` 0.29 (MIT, WebSocket client, same tungstenite version as axum),
`tower` 0.5 (MIT, `oneshot` against the router), `http-body-util` 0.1 (MIT).

Deliberately not used: `tower-http` (CORS, headers and limits are a few lines of custom
middleware, and no CORS is needed because the app does not use a browser), `jsonwebtoken` (JWT
brings algorithm selection and headers that are not needed here; the custom format is smaller
and free of `alg` confusion), `openmls` (plan: no MLS in version 1).

Maintenance: run `cargo update` only selectively, then `cargo test`; check security advisories
with `cargo audit` (cargo-audit 0.22.2, as of 2026-11-09: 271 dependencies, one finding).

Open finding: RUSTSEC-2026-0459 (CVE-2026-119375, medium, 6.8) in `libsqlite3-sys` 0.37.0,
which `sqlx-sqlite` 0.9.0 requires as a fixed version. The bundled SQLite before 3.54.0 can
return uninitialized memory when it opens a database together with a manipulated `-wal` file of
a different page size. The attack vector is local only: the server opens exclusively its own
file in its own volume. Anyone who can write there already controls the server. Consequence for
operations: only restore your own backups, never copy along a foreign `-wal` file
(`sqlite3 .backup` does not create one). Fix as soon as sqlx publishes a version with
`libsqlite3-sys` >= 0.39; accepted deliberately until then. Locally, `cargo audit` keeps
reporting the finding; only the CI (`.github/workflows/ci.yml`) allows exactly this ID, so that
new findings do not disappear behind a permanently red job. Remove it there with the sqlx update.
