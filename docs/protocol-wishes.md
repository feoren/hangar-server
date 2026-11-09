# Wünsche an das Protokoll-Crate der App

Für die App-Sitzung, die `hangar-team-protocol` und `hangar-team-crypto` pflegt. Der
Teamserver nutzt beide als unveränderte Kopien aus `79c68ca` (`vendor/`, siehe README);
`src/wire.rs` reicht nur noch Namen weiter. Die früheren Wünsche (E2E-Nachrichten, `member.role_changed`,
`offline`, `ticket.renew`, Close-Codes, Rechte-Helfer, `key.wrapped`, Holder in `WrappedKey`) hat
das Crate umgesetzt. Nach b30b9d5 offen gebliebene Fragen, mit der App-Sitzung am 2026-11-09
entschieden:

- **Rotation mit unvollständigen Paketen:** bleibt erlaubt. Eine Pflicht zur Vollständigkeit
  ließe ein defektes oder böswilliges Geräteschlüssel jede Rotation blockieren. Geräte ohne
  Paket bekommen es später per `key.wrap` von owner/admin oder einem Gerät desselben Mitglieds;
  die App meldet `Rotation::failed` der Person, die rotiert hat.
- **Gesperrte Geräte nach `RemoveMember`:** die Sperre bleibt dauerhaft. Bei Wiederaufnahme legt
  die App immer eine neue Geräteidentität (neue ID, neue Schlüssel) an; eine aufgehobene Sperre
  würde alte, womöglich verlorene Geräte wieder hereinlassen. Auf 4403 verwirft die App die
  Teamidentität dieses Projekts.

Aus dem Interop-Lauf mit der App (2026-11-09):

- **Übergabe (`task.release_answer` mit `accept`) und Notiz:** erledigt. Die neue Reservierung
  trägt `note: None`, gesendet wie gespeichert, also auch im Snapshot. Die Notiz des Wunsches
  ist eine `ReleaseRequestNote` des Anfragenden; als `task.reserved.note` öffnete die App sie als
  `ReservationNote` mit dem Halter als Absender, und der Signaturkontext passte nicht. Der neue
  Halter sendet seine eigene Notiz danach per `task.reserve` (das Relay meldet sie mit
  `task.reserved`). Damit ist auch der Wunsch "Übergabe mit Notiz des neuen Halters" erledigt.
- **`task.release_requested.requester` als vollständiger Holder:** offen. Heute nur `MemberId`;
  die App liefert die Protokollfelder später im Crate.

Frühere Wünsche (Verlauf, umgesetzt):

Stand 525a8c7: Wünsche 1 bis 5 unten sind umgesetzt (export/restore, `EventLog::position`,
`notify` mit Empfänger, `CLOSE_TEAM_DELETED`, `device.remove`, Beschreibung von
`CLOSE_ROLE_CHANGED`) und im Relay angeschlossen. Der Text bleibt als Verlauf.

## 1. Reservierungen über einen Neustart

`ReservationBook` hat keine Möglichkeit, gespeicherte Holds wiederherzustellen (kein `serde`,
kein `restore`). Der Server speichert je gehaltener Aufgabe nur Halter, Epoche und Notiz und
reserviert sie beim Laden neu (`Intent::Reserve` zur aktuellen Epoche). Folgen: `since` und die
Frist beginnen neu, offene Freigabewünsche, Cooldowns und Holds einer älteren Epoche
(Rekey-Frist) gehen verloren. Damit Clients keinem veralteten Zustand trauen, beginnt jedes
Laden einen neuen `stream` (Snapshot statt Nachspielen).

Wunsch: `ReservationBook::export()` und `ReservationBook::restore(...)` (oder `Serialize`/
`Deserialize` für `Reservation`), damit ein Neustart nichts verliert; dann kann der Server auch
`EventLog::resume` mit gespeichertem `head` nutzen.

## 2. `notify`

`Notify` hat keinen Empfänger. Ein geloggtes Ereignis geht an alle Geräte des Teams, gemeint ist
aber nur der Halter. Der Server erzeugt `notify` deshalb noch nicht (im Selbstbetrieb geht eine
Hinweismail ohne Inhalt). Wunsch: ein Feld `member` (Empfänger) oder eine gezielte, nicht
geloggte Variante wie `key.wrapped`.

## 3. Close-Code für ein gelöschtes Team

Der Server schließt bei gelöschtem Team (`project_deleted` der Widerrufsliste, Selbstbetrieb)
mit 4404. Das Crate kennt den Code nicht. Wunsch: `CLOSE_TEAM_DELETED = 4404` im Modul `close`.

## 4. Gerät entfernen

`ReservationBook::remove_device` und `ClaimBoard::clear_device` sind angeschlossen
(`Relay::remove_device`), aber keine Nachricht entfernt ein Gerät. Wunsch: festlegen, woraus das
Relay das erfährt (eigene Absicht `device.remove` für owner/admin, oder die Widerrufsliste der
Webseite mit einer Art `device_removed`).

## 5. Rollenwechsel ohne Trennung

Festlegung des Koordinators (2026-11-09): Rollenänderungen gelten auf der laufenden Verbindung
still, aus `ticket.renew` und aus der Widerrufsliste (`role_changed` mit `role`);
`member.role_changed` meldet sie. 4401 (`CLOSE_ROLE_CHANGED`) nur, wenn die neue Rolle unbekannt
ist. Bitte die Beschreibung von `CLOSE_ROLE_CHANGED` im Crate daran angleichen.
