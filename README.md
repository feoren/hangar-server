# Hangar-Teamserver

[![CI](https://github.com/feoren/hangar-team-server/actions/workflows/ci.yml/badge.svg)](https://github.com/feoren/hangar-team-server/actions/workflows/ci.yml)
[![License: Elastic 2.0](https://img.shields.io/badge/license-Elastic%202.0-blue)](LICENSE)

Der Server für die Teamarbeit in [Hangar](https://github.com/feoren/hangar), der Desktop-App für
KI-Coding-Agenten. Er verbindet die Hangar-Apps eines Teams: Wer arbeitet gerade woran, wer hat
welche Aufgabe reserviert, welche Dateien ändert ein Agent, dazu Ende-zu-Ende-verschlüsselte
Notizen. Der Server sieht dabei nie Klartext, er speichert und verteilt nur verschlüsselte Daten.

> **In English:** the team server for [Hangar](https://github.com/feoren/hangar). It relays live
> presence, task reservations, file claims and end-to-end encrypted notes between teammates and
> can be self-hosted with its own accounts and invitations. One Rust binary with SQLite, shipped
> as a Docker image behind Caddy. The documentation is in German.

## Brauche ich das?

**Meistens nicht.** Hangar nutzt von Haus aus den offiziellen Dienst unter
[hangar.feoren.com](https://hangar.feoren.com), dort ist nichts einzurichten.

Diesen Server brauchst du nur, wenn dein Team einen **eigenen Server** betreiben will, etwa damit
alle Daten im eigenen Netz bleiben.

## Eigenen Server einrichten

Du brauchst einen Rechner mit Docker, einen Domainnamen, der auf ihn zeigt, und offene Ports
80 und 443. Das Zertifikat holt der mitgelieferte Caddy automatisch.

**1. Herunterladen und Einstellungen anlegen**

```sh
git clone https://github.com/feoren/hangar-team-server.git
cd hangar-team-server
cp .env.example .env
```

**2. In `.env` diese Werte setzen**

```
IDENTITY=local
PUBLIC_URL=https://team.example.org
TEAM_DOMAIN=team.example.org
SERVER_SECRET=<mindestens 32 zufällige Zeichen, z. B. von: openssl rand -base64 48>
```

Mails sind optional. Ohne Mailserver (`MAIL_TRANSPORT=none`) gibt der Server Links auf der
Kommandozeile aus.

**3. Starten und prüfen**

```sh
docker compose up -d --build
curl https://team.example.org/health      # ergibt {"status":"ok",...}
```

**4. Team anlegen und Leute einladen**

```sh
docker compose run --rm teamserver create-team du@example.org Entwicklung
docker compose run --rm teamserver invite Entwicklung anna@example.org
docker compose run --rm teamserver teams                  # Übersicht
```

`invite` gibt einen Einladungslink aus. Den schickst du der Person, er gilt einmal und 7 Tage.
Mit `admin` am Ende bekommt sie Adminrechte.

**5. In Hangar verbinden**

In Hangar als Server-Adresse `https://team.example.org/api/v1` eintragen, auf Anmelden klicken und
den Code im Browser bestätigen. Ohne Mailserver holst du dir den Anmeldelink für den Browser mit
`docker compose run --rm teamserver login-link du@example.org`.

## Gut zu wissen

- **Plätze:** Bis zu 3 Personen sind kostenlos. Für mehr kaufst du Plätze auf
  [hangar.feoren.com](https://hangar.feoren.com) und hinterlegst das Lizenzdokument auf dem Server.
- **Sicherung:** Alle Daten liegen im Docker-Volume `team-data`. Sichere es regelmäßig, wie in
  [docs/betrieb.md](docs/betrieb.md) beschrieben.
- **Updates:** `git pull` und danach `docker compose up -d --build`. Die Datenbank wird beim Start
  automatisch angepasst.
- **Nur mit HTTPS:** Außerhalb des eigenen Rechners verbindet sich Hangar nur über `https`.

## Mehr Dokumentation

| Thema | Datei |
| --- | --- |
| Betrieb ausführlich: Konfiguration, Sicherung, Neustarts, offizieller Dienst | [docs/betrieb.md](docs/betrieb.md) |
| Alle HTTP-Routen | [docs/http-api.md](docs/http-api.md) |
| Konto-API für die App | [docs/account-api.md](docs/account-api.md) |
| Protokoll des Live-Kanals | [docs/protocol.md](docs/protocol.md) |
| Sicherheit und Bedrohungsmodell | [docs/security.md](docs/security.md) |
| Code, Bauen, Tests, Crates der App | [docs/entwicklung.md](docs/entwicklung.md) |
| Alle Einstellungen mit Erklärung | [.env.example](.env.example) |

> **Hinweis:** Das Verschlüsselungsverfahren ist ein eigenes Protokoll der App und noch nicht
> extern geprüft. Vor dem Einsatz mit sensiblen Daten bitte [docs/security.md](docs/security.md)
> lesen.

## Lizenz und Sicherheit

[Elastic License 2.0](LICENSE): Nutzen, Ändern und Selbstbetrieb für das eigene Team sind erlaubt.
Nicht erlaubt ist, den Server als gehosteten Dienst für andere anzubieten oder die Platz- und
Lizenzprüfung zu umgehen.

Sicherheitslücken bitte nicht öffentlich melden, sondern wie in [SECURITY.md](SECURITY.md)
beschrieben.
