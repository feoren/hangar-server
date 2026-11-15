# Betrieb

Ausführliche Anleitung für den Betrieb mit Docker: allgemein, für den offiziellen Dienst auf
einem Strato V-Server und die vollständige Konfiguration. Der kurze Weg steht im
[README](../README.md).

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

Die Crates der App liegen als feste Kopie in `vendor/` (siehe [entwicklung.md](entwicklung.md)); der
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

Alle Schlüssel mit Erklärung in [.env.example](../.env.example). Die wichtigsten:

| Variable | Bedeutung |
| --- | --- |
| `IDENTITY` | `official` oder `local` |
| `PUBLIC_URL` | eigener Ursprung, Pflicht |
| `ROOT_REDIRECT` | optional: Ziel für Browseraufrufe von `/` (308), z. B. `https://hangar.feoren.com/`; leer = 404 |
| `TICKET_PUBLIC_KEYS` | `kid:base64url` der Ticket-Aussteller; Pflicht bei `official` |
| `TICKET_AUDIENCE` | Pflichtwert für `aud`; leer = `hangar-relay` (official) bzw. `PUBLIC_URL` (local) |
| `LICENSE_PUBLIC_KEYS` | Schlüssel der Webseite für Lizenzdokumente (Selbstbetrieb) |
| `SERVER_SECRET` | mindestens 32 Zeichen (Selbstbetrieb) |
| `MAIL_TRANSPORT` | `smtp`, `log`, `none` |
| `TRUST_PROXY` | `true` nur hinter dem eigenen Caddy |
| `REVOCATION_URL`, `RELAY_REVOCATION_TOKEN` | offiziell: signierte Widerrufsliste der Webseite, alle 15 s ([docs/revocation-format.md](revocation-format.md)) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | Vorgabe 200 und 200; Speicher etwa 2 MiB je Verbindung einplanen |


## Selbstbetrieb Schritt für Schritt

1. `IDENTITY=local`, `SERVER_SECRET`, `PUBLIC_URL`; Mail per SMTP oder `MAIL_TRANSPORT=none`.
2. Erste Person anmelden: In Hangar als Server-Adresse **`<PUBLIC_URL>/api/v1`** eintragen (z. B.
   `https://team.example.org/api/v1`) und anmelden (Device Flow). Unter dieser einen Basis bietet
   der Server dieselbe Konto-API wie hangar.feoren.com ([docs/account-api.md](account-api.md));
   das Ticket nennt den Live-Kanal `wss://<Host>/v1/live` selbst. Die Seite `/device` fragt nach
   der E-Mail-Adresse. Bei `SIGNUP=invite` und ohne Mail: auf dem Host
   `docker compose run --rm teamserver login-link admin@example.org` und den Link öffnen.
   Verbundene Geräte stehen unter `<PUBLIC_URL>/account/devices` (Hangar verlinkt die Seite) und
   lassen sich dort trennen.

   > **TLS ist Pflicht außerhalb des eigenen Rechners.** Hangar akzeptiert `http`/`ws` nur für
   > `127.0.0.1`, `localhost` und `[::1]`. Im LAN oder im Netz braucht der Server ein Zertifikat,
   > etwa über den mitgelieferten Caddy (`Caddyfile`, Let's Encrypt) oder Caddy mit
   > `tls internal` und der eigenen CA auf den Rechnern im LAN; `PUBLIC_URL` beginnt dann mit
   > `https://`.
3. Team anlegen und Personen einladen, am einfachsten auf dem Host (Hangar hat im Selbstbetrieb
   keinen Einladen-Knopf):

   ```sh
   docker compose run --rm teamserver create-team admin@example.org Entwicklung
   docker compose run --rm teamserver invite Entwicklung anna@example.org          # member
   docker compose run --rm teamserver invite Entwicklung ben@example.org admin
   docker compose run --rm teamserver teams                                         # Übersicht
   ```

   `create-team` legt das Konto des Eigentümers bei Bedarf an und gibt die Team-ID aus. `invite`
   nimmt Team-ID oder genauen Namen (bei gleichen Namen nur die ID) und gibt den
   Einladungslink aus; Mail geht dabei nie hinaus. Der Link gilt einmal, 7 Tage, nur für diese
   Adresse; ein neuer Aufruf erneuert ihn und macht den alten ungültig. Wer ihn öffnet und
   bestätigt, ist im Browser angemeldet und Mitglied; danach in Hangar dieselbe Serveradresse
   eintragen, Anmelden, Code bestätigen. Die Platzgrenze prüft der Server beim Annehmen.
   Was ein Skript weiterverwendet (Link, Team-ID), steht als letzte Zeile auf stdout.

   Über die API geht es weiter mit `POST /v1/teams` und `POST /v1/teams/{team}/invitations`;
   ohne Mail gibt die API den Link an den Admin zurück.
4. Ab der vierten Person: Plätze auf hangar.feoren.com kaufen, das Lizenzdokument im Konto
   herunterladen und auf dem Server hinterlegen (`PUT /v1/license`). Plätze gelten für alle
   Teams dieses Eigentümers.

