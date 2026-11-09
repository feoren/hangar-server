# Hangar-Teamserver

Server für die Zusammenarbeit in Hangar (Schritt D des Plans "Team service version 1", dazu
die Serverteile von C und E). Ein Rust-Binary: axum 0.8, tokio, WebSocket als einziger
Live-Kanal, SQLite im WAL-Modus über sqlx, Docker-Image mit Caddy davor.

Lizenz: [Elastic License 2.0](LICENSE). Nutzen, Ändern und Selbstbetrieb sind erlaubt; als
gehosteten Dienst für Dritte anbieten und die Lizenzprüfung umgehen sind es nicht.

## Zwei Betriebsarten

| | `IDENTITY=official` | `IDENTITY=local` (Selbstbetrieb) |
| --- | --- | --- |
| Konten, Projekte, Plätze | Webseite hangar.feoren.com | dieser Server |
| Anmeldung der App | Device Flow an der Webseite | Device Flow und Magic Link hier |
| Tickets für `hello` | stellt die Webseite aus (Ed25519, 60 s) | stellt dieser Server aus, gleiches Format |
| Relay (Live, Reservierungen, Claims, E2E-Ablage) | ja | ja, derselbe Kern |
| Einladungsmails, Lizenzprüfung | nein | ja |

Das Relay kennt nur einen Weg: ein gültiges Ticket im `hello`. Formate:
[docs/ticket-format.md](docs/ticket-format.md), [docs/license-format.md](docs/license-format.md),
Protokoll: [docs/protocol.md](docs/protocol.md), Widerrufe: [docs/revocation-format.md](docs/revocation-format.md),
Sicherheit: [docs/security.md](docs/security.md).

> Das E2E-Verfahren braucht vor jeder Freigabe eine externe kryptografische Prüfung. Der Server
> speichert und verteilt nur opake Daten; die Kryptografie liegt in der App (Schritt E).

## Aufbau

```
Cargo.toml, Cargo.lock      ein Crate, Versionen fest
migrations/                 0001_relay.sql (Relay), 0002_identity.sql (Selbstbetrieb),
                            0003_magic_link_browser.sql (Anmeldelink an den Browser gebunden)
src/
  main.rs                   Befehle: serve, healthcheck, login-link
  lib.rs                    Zusammenbau (auch für die Tests)
  config.rs                 Umgebung/.env, Prüfung beim Start
  wire.rs                   Namen aus dem Protokoll-Crate der App (siehe unten)
  signed.rs, ticket.rs, license.rs   signierte Dokumente
  relay/                    conn (WebSocket), team (Log, Sequenz, Replay, Snapshot),
                            reservations ("first wins"), claims (Hash-Vergleich), store (SQLite)
  identity/                 auth (Tokens, Magic Link, Device Flow), teams (Einladungen, Plätze,
                            Lizenz, Tickets), pages (Browserseiten)
  mail/                     Versand (SMTP/log/none), Vorlagen, Texte in 12 Sprachen
  http/                     Router, Sicherheitsheader, Ratenbegrenzung
tests/                      relay.rs, identity.rs, vectors.rs (Integrationstests)
testdata/                   Testvektoren für Tickets und Lizenzen
tools/php/verify_vectors.php  Gegenprobe der Vektoren mit PHP/libsodium
docs/                       Formate, Protokoll, Wünsche an das Protokoll-Crate, Sicherheit, Abhängigkeiten
Dockerfile, docker-compose.yml, Caddyfile, .env.example
```

### Crates der App (Protokoll und Krypto)

Zwei Crates gehören der App (MIT) und liegen als **feste, unveränderte Kopien** unter `vendor/`,
eingebunden als Pfadabhängigkeiten (Herkunft und Commit je Crate in `HERKUNFT.md`, derzeit
`b30b9d5`). So baut das Image ohne Zugriff auf das App-Repository oder GitHub.

| Crate | Inhalt | Im Relay |
| --- | --- | --- |
| `hangar-team-protocol` (Schritt C) | Wire-Format, Keyed Hashes, Reservierungsbuch, Claims, Ereignislog, Wiederholungen, Hash-Kette des Logs | `src/wire.rs` reicht die Namen weiter; Regeln direkt aus dem Crate |
| `hangar-team-crypto` (Schritt E) | Geräteschlüssel, signiertes Mitgliedschafts-Log (`LogVerifier`), Epochen, Rotation, Schlüsselpakete, Prüfungen des Relays (`relay::check_wrap`, `relay::check_registered_keys`) | prüft jeden Log-Eintrag, jede Rotation, jede Geräteentfernung und jedes Schlüsselpaket, bevor gespeichert wird |

Das Relay hält und leitet keine Schlüssel ab; es prüft nur Signaturen, Rechte und Ketten. In
`vendor/` nichts von Hand ändern. Was den Crates für den Server noch fehlt:
[docs/protocol-wishes.md](docs/protocol-wishes.md).

> **Krypto-Design ungeprüft.** Das E2E-Verfahren (Geräteschlüssel, Log, Epochen, HPKE,
> Wiederherstellung) ist ein eigenes Protokoll. Vor echten Teamdaten braucht es eine externe
> kryptografische Prüfung (siehe docs/security.md).

#### Crates aktualisieren (von Hand)

Wenn die App einen neuen Stand committet:

1. Commit-Hash im App-Repository nachsehen:
   `git -C E:/Seafile/Repository/Lokal/hangar log -1 --format=%H -- crates/hangar-team-protocol crates/hangar-team-crypto`
   (Branch beachten; derzeit `feat/agent-workflow`).
2. Beide Kopien ersetzen, ohne `Cargo.lock`:
   ```sh
   rm -rf vendor/hangar-team-protocol vendor/hangar-team-crypto
   mkdir -p vendor
   git -C E:/Seafile/Repository/Lokal/hangar archive <hash> crates/hangar-team-protocol crates/hangar-team-crypto | tar -x -C vendor --strip-components=1
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

## Betrieb (VPS oder Docker-Host)

1. `.env` aus `.env.example` anlegen: `PUBLIC_URL`, `TEAM_DOMAIN`, Schlüssel, bei
   `IDENTITY=local` auch `SERVER_SECRET` und Mail.
2. DNS von `TEAM_DOMAIN` auf den Host, Ports 80 und 443 frei.
3. `docker compose up -d --build`. Caddy holt das Zertifikat, der Teamserver lauscht nur im
   Compose-Netz.
4. Prüfen: `curl https://<domain>/health` ergibt `{"status":"ok",...}`.

- **Daten:** ein Volume `team-data` (`/data`): `hangar-team.db` (+ `-wal`, `-shm`), im
  Selbstbetrieb `ticket-signing.key`, bei `MAIL_TRANSPORT=log` der Ordner `mail/`.
- **Sicherung:** `sqlite3 /data/hangar-team.db ".backup /backup/team.db"` oder Volume-Snapshot
  bei gestopptem Container; `ticket-signing.key` mitsichern. Reservierungen, Log-Position,
  unzugestellte `notify` und gesperrte Geräte liegen in der Datenbank und überstehen Neustarts;
  Claims nicht (Clients senden sie nach `welcome` neu).
- **Migrationen** laufen beim Start automatisch (`sqlx migrate`, eingebettet).
- **Beenden:** SIGTERM schließt Live-Verbindungen mit 1012; die App verbindet sich neu.
- **Logs:** JSON auf stdout (`docker compose logs`), Feinsteuerung über `RUST_LOG`.
- **Überwachung:** `/health` von außen (Uptime-Monitor) und `HEALTHCHECK` im Image.
- **Speicher:** Begrenzung im Compose auf 512 MiB (200 Verbindungen mit bis zu 1 MiB
  Lesepuffer, docs/protocol.md); ungenutzte Teams werden nach 10 min entladen.

## Betrieb auf Strato V-Server

Für den offiziellen Dienst unter `team-hangar.feoren.com` auf einem Strato V-Server mit Docker.

### Voraussetzungen

- Debian oder Ubuntu LTS mit Docker Engine und dem Compose-Plugin (`docker compose version`).
  Installation nach der Docker-Anleitung für die Distribution (Paketquelle von Docker, nicht
  das alte `docker-compose`).
- Ports 80 und 443 (TCP, für HTTP/3 zusätzlich 443/UDP) offen: in der Strato-Firewall im
  Kundenbereich (Server-Login, Firewall/Sicherheit) **und**, falls aktiv, in `ufw`
  (`ufw allow 80/tcp`, `ufw allow 443/tcp`, `ufw allow 443/udp`). SSH nur mit Schlüssel.
  Port 8080 des Teamservers bleibt geschlossen; nur Caddy ist von außen erreichbar.
- DNS: `A` (und bei IPv6 `AAAA`) für `team-hangar.feoren.com` auf die IP des Servers. Erst
  wenn der Name auflöst, kann Caddy das Zertifikat holen.
- Von der Webseite: das Bearer-Token des Relays (`RELAY_REVOCATION_TOKEN`) und die öffentlichen
  Signaturschlüssel. Die Schlüssel liefert `https://hangar.feoren.com/api/v1/keys`; in
  `TICKET_PUBLIC_KEYS` gehören sie als `kid:base64url`, kommagetrennt. [UNVERIFIED: genaues
  Antwortformat von `/api/v1/keys`; maßgeblich ist `wiki/Team-Schnittstelle.md` der Webseite.]

### Image auf den Server bringen

Das Protokoll-Crate liegt als feste Kopie in `vendor/` (siehe "Protokoll-Crate der App"); der
Bau braucht also weder das App-Repository noch GitHub, nur crates.io für die übrigen
Abhängigkeiten.

Danach entweder das ganze Repository auf den Server kopieren (`git clone` bzw. `rsync`) und dort
bauen, oder das Image lokal bauen und übertragen:

```sh
docker build -t hangar-team-server:<version> .
docker save hangar-team-server:<version> | ssh <server> docker load
```

(im zweiten Fall in `docker-compose.yml` `build: .` entfernen und `image:` auf diesen Namen
setzen; `Caddyfile`, `docker-compose.yml` und `.env` gehören trotzdem auf den Server).

### Einrichten und starten

```sh
cp .env.example .env
chmod 600 .env
```

In `.env` mindestens:

```
PUBLIC_URL=https://team-hangar.feoren.com
TEAM_DOMAIN=team-hangar.feoren.com
IDENTITY=official
TICKET_AUDIENCE=hangar-relay
TICKET_PUBLIC_KEYS=<kid>:<base64url>[,<kid2>:<base64url>]
REVOCATION_URL=https://hangar.feoren.com/api/v1/team/revocations
RELAY_REVOCATION_TOKEN=<Token der Webseite>
TRUST_PROXY=true
LOG_FORMAT=json
```

Dann:

```sh
docker compose up -d --build     # mit vorab geladenem Image: docker compose up -d
```

### Prüfen

```sh
curl -fsS https://team-hangar.feoren.com/health           # {"status":"ok","version":"..."}
docker compose ps                                          # beide Dienste "healthy"/"running"
docker compose logs -f --tail=100 teamserver               # JSON-Zeilen, "Teamserver bereit"
```

Im Log darf keine Warnung `REVOCATION_URL fehlt` stehen; Fehler beim Abruf der Widerrufsliste
erscheinen als `Widerrufsliste nicht verarbeitet` mit wachsendem Abstand. Caddy-Probleme
(Zertifikat) zeigt `docker compose logs caddy`.

### Updates

```sh
git pull                                   # bzw. neues Image übertragen und laden
docker compose up -d --build               # baut neu, ersetzt den Container
docker image prune -f
```

Migrationen laufen beim Start. Die Verbindungen werden mit 1012 geschlossen, die App verbindet
sich mit ihrem Cursor neu.

### Sicherung des Datenvolumens

Im laufenden Betrieb mit der Online-Sicherung von SQLite (konsistent auch während Schreibungen):

```sh
docker run --rm -v hangar-team-server_team-data:/data -v /root/backup:/backup \
  keinos/sqlite3 sqlite3 /data/hangar-team.db ".backup '/backup/team-$(date +%F).db'"
```

Den Volume-Namen zeigt `docker volume ls` (Präfix ist der Verzeichnisname des Compose-Projekts).
Die Sicherung per Cron täglich ausführen und vom Server weg kopieren; nie eine einzelne
`-wal`-Datei mitkopieren (siehe RUSTSEC-2026-0459 in docs/dependencies.md). Zurückspielen:
Container stoppen, Datei als `hangar-team.db` ins Volume legen (alte `-wal`/`-shm` entfernen),
starten. [UNVERIFIED: das Hilfsimage `keinos/sqlite3` ist ein Beispiel; jedes Image mit
`sqlite3` ab 3.27 tut es.]

### Neustart-Verhalten

- `restart: unless-stopped`: Docker startet beide Dienste nach einem Absturz und nach einem
  Neustart des Servers.
- Reservierungen samt Fristen, offenen Freigabewünschen und Cooldowns, die Log-Position,
  unzugestellte `notify` und gesperrte Geräte kommen aus der Datenbank zurück. Nach dem Start
  gelten alle Halter als getrennt: ihre Fristen laufen, mit Warnung vorher.
- Clients mit Cursor am gespeicherten head machen ohne Snapshot weiter, ältere holen einen
  Snapshot. Claims senden die Apps nach `welcome` neu.
- Tickets gelten nach der Unterbrechung nicht weiter: die App holt ein neues bei der Webseite.

## Konfiguration

Alle Schlüssel mit Erklärung in [.env.example](.env.example). Die wichtigsten:

| Variable | Bedeutung |
| --- | --- |
| `IDENTITY` | `official` oder `local` |
| `PUBLIC_URL` | eigener Ursprung, Pflicht |
| `TICKET_PUBLIC_KEYS` | `kid:base64url` der Ticket-Aussteller; Pflicht bei `official` |
| `TICKET_AUDIENCE` | Pflichtwert für `aud`; leer = `hangar-relay` (official) bzw. `PUBLIC_URL` (local) |
| `LICENSE_PUBLIC_KEYS` | Schlüssel der Webseite für Lizenzdokumente (Selbstbetrieb) |
| `SERVER_SECRET` | mindestens 32 Zeichen (Selbstbetrieb) |
| `MAIL_TRANSPORT` | `smtp`, `log`, `none` |
| `TRUST_PROXY` | `true` nur hinter dem eigenen Caddy |
| `REVOCATION_URL`, `RELAY_REVOCATION_TOKEN` | offiziell: signierte Widerrufsliste der Webseite, alle 15 s ([docs/revocation-format.md](docs/revocation-format.md)) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | Vorgabe 200 und 200; Speicher etwa 2 MiB je Verbindung einplanen |

## Selbstbetrieb Schritt für Schritt

1. `IDENTITY=local`, `SERVER_SECRET`, `PUBLIC_URL`; Mail per SMTP oder `MAIL_TRANSPORT=none`.
2. Erste Person anmelden: In Hangar den Server eintragen und anmelden (Device Flow). Die Seite
   `/device` fragt nach der E-Mail-Adresse. Bei `SIGNUP=invite` und ohne Mail: auf dem Host
   `docker compose run --rm teamserver login-link admin@example.org` und den Link öffnen.
3. Team anlegen, Personen per E-Mail-Adresse einladen. Ohne Mail gibt die API den
   Einladungslink an den Admin zurück; er reicht ihn selbst weiter. Der Link gilt einmal, 7
   Tage, nur für diese Adresse.
4. Ab der vierten Person: Plätze auf hangar.feoren.com kaufen, das Lizenzdokument im Konto
   herunterladen und auf dem Server hinterlegen (`PUT /v1/license`). Plätze gelten für alle
   Teams dieses Eigentümers.

### HTTP-API (nur Selbstbetrieb)

| Methode und Pfad | Zweck |
| --- | --- |
| `POST /oauth/device_authorization` | Device Flow starten (`client_id=hangar`, optional `device_name`) |
| `POST /oauth/token` | `device_code` einlösen bzw. `refresh_token` rotieren (RFC 8628, RFC 6749) |
| `GET/POST /device` | Browserseite: Code bestätigen |
| `POST /auth/email`, `GET/POST /auth/magic/{token}` | Anmeldelink anfordern und einlösen |
| `GET /v1/me` | eigenes Konto und Teams |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}`, `POST /v1/auth/logout` | Sitzungen |
| `POST /v1/teams`, `GET/DELETE /v1/teams/{team}` | Teams |
| `PATCH/DELETE /v1/teams/{team}/members/{user}` | Rolle ändern, entfernen, austreten |
| `POST /v1/teams/{team}/invitations` | einladen (`emails`, `role`, optional `lang`) |
| `POST .../invitations/{id}/resend`, `DELETE .../invitations/{id}` | erneut senden, widerrufen |
| `POST /v1/invitations/accept`, `GET/POST /invite/{token}` | annehmen (App bzw. Browser) |
| `GET/PUT/DELETE /v1/license` | Lizenzdokument |
| `POST /v1/tickets` | Ticket für `hello` (`team`) |

Fehler: `{"error":"<code>"}` mit passendem Status (`unauthorized`, `forbidden`, `not_found`,
`invalid_request`, `rate_limited`, `seats_full`, `wrong_account`, `invalid_license`,
`license_expired`, `license_email_mismatch`, `license_in_use`).

## Offen

- Docker-Image: nach jedem neuen Stand des Protokoll-Crates die Kopie in `vendor/` erneuern (siehe
  "Protokoll-Crate aktualisieren").
- Externe Krypto-Prüfung des E2E-Verfahrens (App, Schritt E).
- Offizielle öffentliche Lizenzschlüssel beim Bau einbetten (statt nur Konfiguration), damit
  Selbstbetreiber sich keine eigenen Lizenzen ausstellen können.
- Konto löschen, Datenexport, Eigentum übertragen (Selbstbetrieb).
- Passkeys und OIDC; Merge-Queue und weitere Schritte G.
- Mehrere Knoten (Postgres, gemeinsame Ratenbegrenzung).
- arm64-Image nur beschrieben, nicht lokal gebaut.
- Rechtliche Prüfung der Lizenztexte, CLA für Beiträge, `TRADEMARKS.md` (ADR 0005).
