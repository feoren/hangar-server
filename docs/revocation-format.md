# Widerrufsliste (Version 1, offizieller Betrieb)

Damit entzogene Rechte nicht erst mit dem nächsten Ticket wirken, holt das Relay im
offiziellen Betrieb regelmäßig eine signierte Widerrufsliste von der Webseite. Zusammen mit
`ticket.renew` der App (etwa alle 5 Minuten) ist der Rechteentzug zweistufig.

## Abruf

```
GET <REVOCATION_URL>?after=<cursor>
Authorization: Bearer <RELAY_REVOCATION_TOKEN>
```

Offiziell: `REVOCATION_URL=https://hangar.feoren.com/api/v1/team/revocations`.

- Alle `REVOCATION_INTERVAL_SECS` (Vorgabe 15 s); bei `more: true` sofort die nächste Seite
  (höchstens 50 in einer Runde).
- `after`: der zuletzt gespeicherte Cursor (`last` der vorigen Antwort), anfangs `0`.
- Ausgehend nur an genau diese Adresse: `https://` (oder `http://` zu `localhost`/`127.0.0.1`),
  keine Weiterleitungen, kein Proxy, 10 s Zeitlimit, Antwort höchstens 1 MiB.
- Antwort `200` mit dem kompakten Dokument als Text (`text/plain`), sonst Fehler.
- Fehler und Unerreichbarkeit stoppen nichts: das Relay wiederholt mit wachsendem Abstand
  (doppelt, höchstens 5 min) und schreibt eine Warnung ins Protokoll.

## Dokument

Wie Tickets ([ticket-format.md](ticket-format.md)), Kontext `hangar-revoke-v1`:

```
document  = base64url(payload) "." base64url(Ed25519(sk, "hangar-revoke-v1." + base64url(payload)))
payload   = {"v":1,"kid":"…","aud":"hangar-relay","iat":…,"exp":iat+120,
             "after":<cursor der Anfrage>,"last":<neuer cursor>,"more":false,
             "items":[{"rid":…,"prj":…,"sub":…|null,"kind":"…","role":"…","at":…}]}
```

Geprüft mit den Ticketschlüsseln (`TICKET_PUBLIC_KEYS`, gleiche kid-Rotation):

1. Signatur, Kontext, kid.
2. `v == 1`, `aud` gleich `TICKET_AUDIENCE` (offiziell `hangar-relay`).
3. `exp > iat`, `exp - iat <= 300`, `iat <= jetzt + 30 s`, `jetzt < exp + 30 s`.
4. `after` gleich dem angefragten Cursor (keine alte Antwort erneut einspielbar).
5. Höchstens 1000 Einträge.

Ein ungültiges Dokument ändert nichts (auch nicht den Cursor).

`after`, `last`, `rid`, `prj`, `sub` dürfen Zahlen oder Text sein; das Relay vergleicht Text.
`at`: Unix-Sekunden der Änderung auf der Webseite.

## Einträge

| `kind` | Felder | Wirkung |
| --- | --- | --- |
| `member_removed` | `prj`, `sub`, `at` | Mitglied entfernt: Reservierungen frei, Claims weg, `member.removed`, Verbindungen Close 4403 |
| `seat_lost` | `prj`, `sub`, `at` | wie `member_removed`, bis ein neues Ticket mit `seat_ok` kommt |
| `role_changed` | `prj`, `sub`, `role`, `at` | neue Rolle still auf den laufenden Verbindungen, `member.role_changed`; ohne `role` Close 4401 (neues Ticket) |
| `project_deleted` | `prj`, `sub: null`, `at` | Team schließen (Close 4404), Relay-Daten löschen |

- Idempotent je `rid`: ein schon verarbeiteter Eintrag wird übersprungen (`relay_revocations_seen`,
  30 Tage). Unbekannte Arten werden protokolliert, gemerkt und übersprungen.
- Wiederzulassung: ein Ticket mit `iat` nach `at` öffnet das Team wieder (die Webseite hat die
  Person wieder aufgenommen). Ein älteres Ticket bleibt abgewiesen, auch nach der Wiederaufnahme.
- Der Cursor (`last`) liegt in `relay_revocation_cursor` und übersteht Neustarts. Die Webseite rückt
  `last` erst über Einträge vor, die älter als 60 s sind (eine kleinere id kann nach einer
  größeren festgeschrieben werden); jüngere Einträge kommen deshalb mehrmals und werden über
  `rid` übersprungen. Hält `last` an, ist `more` false.
- Untergrenze für Tickets (`relay_ticket_floors`, Migration 0006): `member_removed`, `seat_lost`
  und `role_changed` setzen sie auf `at`. Ein Ticket mit `iat` bis dahin öffnet das Team nicht
  (`hello`: `err forbidden`) und erneuert keine Verbindung (`ticket.renew`: Close 4401 bei
  Rollenänderung, 4403 bei Entfernung). Sonst holte sich ein herabgestuftes Mitglied mit einem
  vorher gehorteten, noch gültigen Ticket die alte Rolle zurück, bis zu
  `CONNECTION_MAX_AGE_SECS` lang. Die Untergrenze bleibt auch nach einer Wiederaufnahme.

## Konfiguration

| Variable | Bedeutung |
| --- | --- |
| `REVOCATION_URL` | Adresse der Liste auf der Webseite; fehlt sie, wirken entzogene Rechte erst beim nächsten Ticket (Warnung beim Start) |
| `RELAY_REVOCATION_TOKEN` | geheimes Bearer-Token des Relays bei der Webseite, mindestens 32 Zeichen |
| `REVOCATION_INTERVAL_SECS` | Abstand der Abrufe, Vorgabe 15 |

## Testdaten

`src/relay/revocation.rs` (Einheitstests) und `tests/revocation.rs` (Nachbau der Webseite) nutzen
eigene Testschlüssel. Der Testvektor der Webseite (`tests/php/fixtures/revocations-vector.json`
im Webseiten-Repository) liegt als `testdata/revocations-website.json` vor und wird in
`tests/vectors.rs` (`widerrufsliste_der_webseite`) gegen `revocation::verify` geprüft: `valid`
und `empty` werden angenommen, `expired`, `ticket_context`, `other_key` und `tampered`
abgelehnt. Ändert die Webseite den Vektor, die Datei erneut von dort kopieren.
