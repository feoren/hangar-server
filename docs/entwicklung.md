# Entwicklung

Aufbau des Codes, Prüfkette, die Crates der App unter `vendor/` und offene Punkte. Für den
Betrieb siehe [betrieb.md](betrieb.md), für die Routen [http-api.md](http-api.md).

## Aufbau

```
Cargo.toml, Cargo.lock      ein Crate, Versionen fest
migrations/                 0001_relay.sql (Relay), 0002_identity.sql (Selbstbetrieb),
                            0003_magic_link_browser.sql (Anmeldelink an den Browser gebunden)
                            bis 0010_removed_device_log_index.sql (Log-Index der
                            Geräteentfernung, Frist des entfernten Geräts)
src/
  main.rs                   Befehle: serve, healthcheck, login-link, create-team, invite, teams
  lib.rs                    Zusammenbau (auch für die Tests)
  config.rs                 Umgebung/.env, Prüfung beim Start
  wire.rs                   Namen aus dem Protokoll-Crate der App (siehe unten)
  signed.rs, ticket.rs, license.rs   signierte Dokumente
  relay/                    conn (WebSocket), team (Log, Sequenz, Replay, Snapshot),
                            reservations ("first wins"), claims (Hash-Vergleich), store (SQLite)
  identity/                 auth (Tokens, Magic Link, Device Flow), teams (Einladungen, Plätze,
                            Lizenz, Tickets), api (Konto-API /api/v1 wie die Webseite),
                            account (/account/devices), pages (Browserseiten)
  mail/                     Versand (SMTP/log/none), Vorlagen, Texte in 12 Sprachen
  http/                     Router, Sicherheitsheader, Ratenbegrenzung
tests/                      relay.rs, identity.rs, account_api.rs, vectors.rs (Integrationstests)
testdata/                   Testvektoren für Tickets und Lizenzen
tools/php/verify_vectors.php  Gegenprobe der Vektoren mit PHP/libsodium
docs/                       Formate, Protokoll, Wünsche an das Protokoll-Crate, Sicherheit, Abhängigkeiten
Dockerfile, docker-compose.yml, Caddyfile, .env.example
```

### Crates der App (Protokoll und Krypto)

Zwei Crates gehören der App (MIT) und liegen als **feste, unveränderte Kopien** unter `vendor/`,
eingebunden als Pfadabhängigkeiten (Herkunft und Commit je Crate in `HERKUNFT.md`, derzeit
`79c68ca`). So baut das Image ohne Zugriff auf das App-Repository oder GitHub.

| Crate | Inhalt | Im Relay |
| --- | --- | --- |
| `hangar-team-protocol` (Schritt C) | Wire-Format, Keyed Hashes, Reservierungsbuch, Claims, Ereignislog, Wiederholungen, Hash-Kette des Logs | `src/wire.rs` reicht die Namen weiter; Regeln direkt aus dem Crate |
| `hangar-team-crypto` (Schritt E) | Geräteschlüssel, signiertes Mitgliedschafts-Log (`LogVerifier`), Epochen, Rotation, Schlüsselpakete, Prüfungen des Relays (`relay::check_wrap`, `relay::check_registered_keys`) | prüft jeden Log-Eintrag, jede Rotation, jede Geräteentfernung und jedes Schlüsselpaket, bevor gespeichert wird |

Das Relay hält und leitet keine Schlüssel ab; es prüft nur Signaturen, Rechte und Ketten. In
`vendor/` nichts von Hand ändern. Was den Crates für den Server noch fehlt:
[docs/protocol-wishes.md](protocol-wishes.md).

> **Krypto-Design ungeprüft.** Das E2E-Verfahren (Geräteschlüssel, Log, Epochen, HPKE,
> Wiederherstellung) ist ein eigenes Protokoll. Vor echten Teamdaten braucht es eine externe
> kryptografische Prüfung (siehe docs/security.md).

#### Crates aktualisieren (von Hand)

Wenn die App einen neuen Stand committet:

1. Commit-Hash im App-Repository nachsehen (Klon von https://github.com/feoren/hangar, hier
   neben diesem Repository als `../hangar`):
   `git -C ../hangar log -1 --format=%H -- crates/hangar-team-protocol crates/hangar-team-crypto`
   (Branch beachten).
2. Beide Kopien ersetzen, ohne `Cargo.lock`:
   ```sh
   rm -rf vendor/hangar-team-protocol vendor/hangar-team-crypto
   mkdir -p vendor
   git -C ../hangar archive <hash> crates/hangar-team-protocol crates/hangar-team-crypto | tar -x -C vendor --strip-components=1
   rm -f vendor/*/Cargo.lock
   ```
   Ohne Git: die Ordner `crates/hangar-team-protocol` und `crates/hangar-team-crypto` aus dem
   App-Repository nach `vendor/` kopieren und `Cargo.lock` sowie `target/` darin löschen.
3. In `vendor/*/HERKUNFT.md` Hash und Datum eintragen.
4. `cargo update -p hangar-team-protocol -p hangar-team-crypto`, dann `cargo fmt --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`.
5. Prüfen, dass die Kopien unverändert sind (`diff -r` gegen ein frisches `git archive`).
6. Brechen Tests: die Änderungsliste im README des Protokoll-Crates ("Changelog") lesen und
   `docs/protocol.md` nachziehen; dann neues Image bauen.

## Bauen und prüfen

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
php tools/php/verify_vectors.php testdata/tickets.json testdata/licenses.json
```

Rust stable (getestet mit 1.99.1), Edition 2021.

Image: `docker build -t hangar-team-server .`; für amd64 und arm64:
`docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hangar-team-server:<version> --push .`
(statisches musl-Binary, distroless, Nutzer `nonroot`).


## Offen

- Docker-Image: nach jedem neuen Stand der Crates der App die Kopien in `vendor/` erneuern (siehe
  "Crates aktualisieren (von Hand)").
- Externe Krypto-Prüfung des E2E-Verfahrens (App, Schritt E).
- Offizielle öffentliche Lizenzschlüssel beim Bau einbetten (statt nur Konfiguration), damit
  Selbstbetreiber sich keine eigenen Lizenzen ausstellen können.
- Konto löschen, Datenexport, Eigentum übertragen (Selbstbetrieb).
- Passkeys und OIDC; Merge-Queue und weitere Schritte G.
- Mehrere Knoten (Postgres, gemeinsame Ratenbegrenzung).
- arm64-Image nur beschrieben, nicht lokal gebaut.
- Rechtliche Prüfung der Lizenztexte, CLA für Beiträge, `TRADEMARKS.md` (ADR 0005).
