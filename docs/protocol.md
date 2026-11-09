# Live-Protokoll (Version 1)

Das Protokoll gehört der App: Crates `hangar-team-protocol` (Schritt C) und `hangar-team-crypto`
(Schritt E), hier als unveränderte Kopien aus Commit `b30b9d5` unter `vendor/`. Nachrichten,
Grenzen, Regeln der Reservierung, der Claims, des Logs und der E2E-Prüfungen kommen aus den
Crates; Referenz sind deren READMEs und `docs/wiki/pages/concepts/team-protocol.md` sowie
`team-crypto.md` im App-Repository. Dieses Dokument
beschreibt, wie das Relay es betreibt. Offene Wünsche an das Crate:
[protocol-wishes.md](protocol-wishes.md).

## Verbindung

- `GET /v1/live` mit WebSocket-Upgrade. Die App sendet keinen `Origin`; kommt einer, muss er
  in `ALLOWED_ORIGINS` oder gleich `PUBLIC_URL` sein, sonst 403.
- Ein Textrahmen = ein JSON-Objekt, höchstens 1 MiB (`limits::MAX_FRAME_BYTES`; größere weist
  schon der WebSocket-Leser ab). Binärrahmen: `err badRequest`.
- Der Server pingt alle 25 s; ohne jedes Lebenszeichen 60 s lang trennt er (Close 1001).
- Grenzen: `MAX_CONNECTIONS` gesamt (200) und `MAX_CONNECTIONS_PER_IP` (20) je Client-Adresse (IPv6 je /64)
  antworten vor dem Upgrade mit 503; `MAX_CONNECTIONS_PER_MEMBER` je Mitglied `err limit`;
  30 Rahmen/s je Verbindung mit Vorrat 120 (`err rateLimited` mit `retryAfterMs`); mehr als
  20 kaputte Rahmen oder abgelehnte `hello`: Close 1008.
- Ohne gültiges `hello` binnen `close::HELLO_TIMEOUT_SECS` (15 s) schließt der Server mit
  `CLOSE_HELLO_TIMEOUT` (1008); Pings allein halten keinen Verbindungsplatz.
- Höchstalter `CONNECTION_MAX_AGE_SECS` (Vorgabe 10 min) je Team ab dem letzten geprüften
  Ticket (`hello` oder `ticket.renew`); danach Close 4401 und Neuverbindung mit Cursor. Die
  kurze Vorgabe begrenzt Restrisiken (gehortete Tickets, verpasste Widerrufe), bis
  `ticket.renew` der App überall wirkt.
- Close-Codes: 1008 (`CLOSE_HELLO_TIMEOUT`), 1012 Neustart, 1013 zu langsam gelesen
  (Warteschlange 512 Rahmen voll), 4401 (`CLOSE_ROLE_CHANGED`: neues Ticket nötig), 4403
  (`CLOSE_REMOVED`: entfernt, Gerät entfernt, kein Platz, Ticket ungültig), 4404
  (`CLOSE_TEAM_DELETED`: Team gelöscht).

## Speicher je Verbindung

Jede Verbindung kann einen Rahmen bis 1 MiB im Lesepuffer halten. Schlimmster Fall also
`MAX_CONNECTIONS × 1 MiB`: mit der Vorgabe 200 sind das 200 MiB, dazu ausgehende
Warteschlangen und der Zustand der Teams. Das Compose-Limit steht deshalb auf 512 MiB. Wer
`MAX_CONNECTIONS` erhöht, erhöht das Speicherlimit im selben Verhältnis (Faustregel: 2 MiB je
Verbindung). Echte Rahmen sind meist wenige KiB; der große Fall ist ein `claim.set` mit 1000
Dateien und Detail oder ein `blob.put`.

## Rahmen

```
Client: {"v":1,"id":"<op>","team":"<team>","type":"task.reserve","body":{...}}
Server: {"v":1,"id":"<op beantwortet>","seq":12,"team":"<team>","type":"task.reserved","body":{...}}
```

- `v` wird zuerst gelesen; ältere Clients bekommen `err outdatedClient`.
- `id`: Operations-ID. Absichten mit `ClientMessage::deduplicated` (alle `task.*`, `blob.put`,
  `memberlog.append`, `key.rotate`, `key.wrap`) merkt das Relay je Absender (Mitglied und
  Gerät), Team und `id` zusammen mit dem Digest des Inhalts (`RecentOps`, 4096 je Team): dieselbe
  Absicht noch einmal bekommt die erste Antwort, eine andere unter derselben `id` `badRequest`.
- `team`: Projekt-ID der Webseite bzw. Team-ID des Selbstbetriebs, opak. Fehlt nur bei `ping`.
- Vor jeder Absicht prüft das Relay die Epoche (`ClientMessage::check_epoch`): Hashes und
  verschlüsselte Inhalte einer anderen als der aktuellen Epoche ergeben `err staleEpoch`.

## Anmelden: `hello`

Ticketprüfung: [ticket-format.md](ticket-format.md). Das Mitglied kommt aus `sub`, das Gerät aus
`hello.device`; Geräte-IDs gelten nur je Mitglied (gleiche ID bei zwei Mitgliedern sind zwei
Geräte). Eine Verbindung kann mehrere Teams anmelden, gehört aber genau einem Mitglied.

- **Nachspielen** (Cursor im Fenster): `welcome` mit der `id` des `hello`, danach die Ereignisse
  nach dem Cursor in Folge, dann live.
- **Snapshot**: `resync_required`, dann `member.joined`, `task.reserved` je Hold (dazu
  `reservation.expiring` und `task.release_requested`, wo sie gelten), `presence.update`, zuletzt
  `welcome`.
- Ein entferntes Mitglied kommt nur mit einem Ticket wieder herein, das nach der Entfernung
  ausgestellt wurde (`iat` später als der Widerruf).

## `ticket.renew`

Die App schickt etwa alle 5 Minuten ein frisches Ticket für ein angemeldetes Team. Nicht
dedupliziert. Vor dem `hello` des Teams: `err badRequest`.

- Gültig (Signatur, kid, Zeit, `aud`, einmalige `jti`, gleiches Mitglied, `seat_ok`): Rolle aus
  dem Ticket still übernehmen, `ack`, Höchstalter neu starten. Eine echte Änderung meldet
  `member.role_changed` an alle.
- `prj` eines anderen Teams: `err forbidden`, dann Close 4403.
- Ungültig, anderes Mitglied, `seat_ok: false`, schon verwendet: Close 4403.

## Rollenänderungen während einer Verbindung

Festlegung vom 2026-11-09: Ist die neue Rolle bekannt (aus `ticket.renew`, aus der
Widerrufsliste `role_changed` mit `role`, im Selbstbetrieb aus der Teamverwaltung), gilt sie
sofort und still auf allen Verbindungen des Mitglieds; das Team bekommt `member.role_changed`.
Getrennt wird nicht: da Rechte je Nachricht aus der Rolle der Verbindung geprüft werden,
scheitern Owner- und Admin-Absichten nach einer Herabstufung von selbst (`err forbidden`, etwa
beim nächsten `key.rotate`). Nur wenn eine Änderung ohne neue Rolle gemeldet wird
(`role_changed` ohne `role`), schließt das Relay mit 4401, und die App verbindet sich mit einem
neuen Ticket.

## Ereignislog

- Je Team Sequenznummern ab 1 (`EventLog`), Fenster der letzten 2048 Ereignisse im Speicher.
- Die Log-Position (`EventLog::position`: Stream und head) liegt zusammen mit dem Buch in
  `relay_team_state`. Beim Laden setzt `EventLog::resume` den Stream fort: ein Client genau am
  gespeicherten head macht ohne Snapshot weiter, ein älterer Cursor bekommt `tooOld` (das
  Fenster liegt nur im Speicher). Fehlt der Zustand oder ist er unlesbar, beginnt ein neuer
  Stream (`otherStream`, Snapshot).
- **Haltbarkeitsregel:** kein Rahmen mit `seq` verlässt das Relay, bevor eine Schreibung, deren
  head diese `seq` abdeckt, dauerhaft ist (SQLite `synchronous = FULL`). Das gilt für jedes
  geloggte Ereignis, auch solche, die das Buch nicht ändern (`member.joined`,
  `device.removed`). Sonst vergäbe ein Neustart dieselbe `seq` an ein neues Ereignis, und ein
  Client verwürfe es als Doppel. Test: `tests/persistence.rs`.
- Nach dem Zurückspielen einer Sicherung läuft der gespeicherte Stream weiter. Clients, die
  danach Ereignisse gesehen hatten, stehen vor dem head (`ahead`) und holen einen Snapshot.
- Geloggt: was `ServerMessage::loggable` nennt. Nicht geloggt: `presence.update`,
  `claim.overlap`, `key.wrapped`, `notify`, Antworten.
- Ereignisse gehen an alle Verbindungen des Teams, auch die auslösende; danach die Antwort an
  die auslösende. Gezielte Nachrichten (`ServerMessage::recipient`) gehen nur an ihren
  Empfänger.

## Reservierungen

Regeln: `ReservationBook` des Crates ("first wins" in Ankunftsreihenfolge je Team, Frist 30 min
nur offline mit Warnung 5 min vorher, Freigabewünsche mit 10 min Frist und Cooldown, `withdraw`,
`force_release` für owner/admin, Rekey mit `prev` und Frist nach einer Rotation). Ereignisse der
Zeit (`Applied::timing`) gehen auch bei abgelehnter Absicht hinaus. Präsenz zählt je Verbindung.

Nach jeder Operation speichert das Relay `ReservationBook::export()` (BookSnapshot v1) mit
der Log-Position und den verschlüsselten Notizen (`note`), die es neben dem Buch hält. Beim
Laden stellt `ReservationBook::restore(snapshot, policy, now)` alles wieder her: Holds mit
`since`, Aktivität, Warnung, offene Freigabewünsche, Cooldowns, Epoche und Rekey-Frist. Danach
gelten alle Halter als getrennt: die Frist jedes Holds läuft ab dem Neustart (mindestens die
Warnzeit), und die Ereignisse des Neustarts (`Restored::events`) gehen ins Log. Hat ein Absturz
`key.rotate` in der Datenbank schon bestätigt, das Buch aber nicht, dreht das Relay das Buch
beim Laden auf die Epoche der Datenbank.

## notify

`Notify::attention` des Crates: für `task.release_requested` und `reservation.expiring`, wenn
kein Gerät des haltenden Mitglieds im Team verbunden ist. Gezielt (nur an das Mitglied), nie
geloggt. Je Mitglied und Team bleibt nur die neueste unzugestellte (`relay_pending_notify`,
übersteht Neustarts); sie geht direkt nach dem nächsten `welcome` an alle Verbindungen des
Mitglieds und wird dann gelöscht. Im Selbstbetrieb geht zusätzlich eine Hinweismail ohne Inhalt.

## device.remove

`{holder, log}`, dedupliziert, nur mit dem signierten Eintrag `RemoveDevice` in `log`.
`LogVerifier::admit_device_remove` prüft ihn nach der Regel des Logs (jeder ein eigenes anderes
Gerät, der Owner jedes andere, ein Admin das Gerät eines Mitglieds; genau `holder`). Ohne gültigen
Eintrag oder für ein Gerät, das das Log nicht kennt: `badRequest`. Danach in einer Transaktion:
Eintrag speichern, Gerät auf die Sperrliste je Team und Holder (`relay_removed_devices`), seine
Schlüsselpakete und `device.keys` im Team löschen. Dann `ReservationBook::remove_device`,
`ClaimBoard::clear_device`, `memberlog.appended` und `device.removed` (beide geloggt),
Verbindungen des Geräts mit 4403 zu. Ein `hello` dieses Geräts wird danach abgelehnt; die App
meldet sich mit einer neuen Geräte-ID an. Ein Owner oder Admin sollte den Teamschlüssel rotieren.

## Claims

`ClaimBoard` des Crates: Hashes `{area, file}` je Datei, `sameFile` bei gleichem Datei-Hash
(mit dem verschlüsselten `detail` der Gegenseite), `sameArea` bei gleichem Bereich; nur gleiches
`repo` und gleiche Epoche, nie zwei Sitzungen desselben Holders. Claims liegen nur im Speicher
(je Team 2000 Sitzungen, je Gerät 64), bleiben nach Trennung 24 h und verfallen dann; beim
Austritt `clear_member`, beim Entfernen eines Geräts `clear_device`. Bewusst nicht gespeichert:
nach einem Neustart ist das Board leer, und jeder Client sendet `claim.set` seiner Sitzungen nach
jedem `welcome` erneut.

## E2E-Unterbau

Das Relay hält je Team einen `memberlog::LogVerifier` (hangar-team-crypto). Nach einem Neustart
baut es ihn mit `apply_all` aus den gespeicherten Einträgen neu auf. Jede Prüfung läuft auf einer
Kopie des Verifiers; erst wenn die Datenbank den Eintrag geschrieben hat, ersetzt die Kopie das
Original. Ein abgelehnter Eintrag ändert also nichts und blockiert das Log nicht: der nächste
gültige Eintrag am selben Index geht durch.

**Wirksame Rolle** ist die niedrigere aus Log-Rolle und Rolle des Tickets der Verbindung: eine
Herabstufung auf der Webseite wirkt sofort, auch wenn das Log sie noch nicht kennt.

- `device.keys` `{sign, kem, proof}`: Schlüssel und Besitznachweis je Team und Holder
  (`relay_device_keys`). Höchstens `limits::MAX_DEVICES_PER_MEMBER` (16) Geräte je Mitglied und
  `MAX_WRAPPED_KEYS` (512) je Team, sonst `limit`. `devices.get` listet sie samt Nachweis.
- `memberlog.append`: erst `relay::check_registered_keys` (jedes Gerät, das der Eintrag
  aufnimmt, trägt genau die Schlüssel, die dieser Holder über seine eigene Verbindung gesendet
  hat; sonst `forbidden`), dann `LogVerifier::admit(append, sender, ticket_role)` (Signatur des
  sendenden Geräts, Rechte je Art, Team, Index, `prev`, Gerätegrenzen). Eintrag 1 nur mit
  owner-Ticket. Rotation und Geräteentfernung über diesen Weg: `badRequest`. Nimmt der Eintrag
  Geräte heraus (Mitglied entfernt, `Admitted::removed`), werden sie in derselben Transaktion
  gesperrt und ihre Pakete gelöscht, dann `device.removed` und Close 4403. Ablehnungen antworten
  mit `LogError::code()`. `memberlog.get` antwortet mit `MemberLogEntries::page`.
- `key.rotate` `{epoch, log, wrapped}`: `e2e::check_rotate`, dann
  `LogVerifier::admit_rotation` (Eintrag gültig, seine Epoche gleich `epoch` und die nächste des
  Logs, jedes Paket an ein anderes Gerät des Logs). Eintrag, Epoche und alle Pakete in einer
  Transaktion oder nichts; dann `memberlog.appended` und `key.rotated` (geloggt, jedes Gerät mit
  nur seinem Paket aus der Rotation).
- `key.wrap`: `check_epoch`, dann `relay::check_wrap(state, ticket_role, sender, wrap,
  stored_from)`: Absender und Ziel Geräte des Logs, owner/admin für jedes andere Gerät, ein
  Mitglied nur für ein eigenes anderes (`forbidden`), unbekanntes Ziel `notFound`, je Absender,
  Ziel und Epoche ein Paket (`conflict`), höchstens `limits::MAX_KEY_PACKAGES` (4) je Ziel und
  Epoche, das der Rotation eingeschlossen (`limit`), nie ersetzt. Das Zielgerät bekommt
  `key.wrapped` (nicht geloggt). Pakete liegen je (Ziel, Epoche, Absender) mit ihrer Reihenfolge.
- `key.get`: alle gespeicherten Pakete des eigenen Geräts für die Epoche in `ack.keys`, in
  Reihenfolge des Eintreffens; keines: `notFound`. Das Gerät probiert jedes gegen die
  Festlegung (Commitment) der Epoche.

## Widerrufsliste (offizieller Betrieb)

[revocation-format.md](revocation-format.md): das Relay holt alle 15 s signierte Widerrufe der
Webseite und wendet sie auf laufende Verbindungen an.

## Fehlercodes

`conflict`, `limit`, `forbidden`, `rateLimited`, `outdatedClient`, `staleEpoch`, `badRequest`,
`notFound`. Fehlertexte enthalten nie Inhalte des Rahmens.

## HTTP neben dem Live-Kanal

- `GET /health`: `{"status":"ok","version":...}` oder 503.
- Nur Selbstbetrieb: Anmeldung, Teams, Einladungen, Lizenz, Tickets, siehe README.
