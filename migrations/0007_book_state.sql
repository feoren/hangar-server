-- Dauerhafter Zustand eines Teams für den Neustart (Protokoll-Crate 525a8c7):
-- book      `ReservationBook::export()` als JSON (BookSnapshot v1), nach jeder Operation
-- position  `EventLog::position()` ({"stream":..,"seq":..}); in derselben Schreibung wie `book`,
--           und kein Rahmen mit `seq` verlässt das Relay, bevor sie ihn abdeckt
-- notes     verschlüsselte Notizen gehaltener Aufgaben und offener Freigabewünsche (das Buch
--           kennt sie nicht): {"holds":{task:Sealed},"requests":{task:Sealed}}
-- Claims werden bewusst nicht gespeichert: Clients senden `claim.set` nach jedem `welcome` neu.
CREATE TABLE relay_team_state (
    team_id     TEXT    PRIMARY KEY REFERENCES relay_teams (id) ON DELETE CASCADE,
    book        TEXT    NOT NULL,
    position    TEXT    NOT NULL,
    notes       TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Die frühere Ablage einzelner Holds (Halter, Epoche, Notiz) ersetzt `relay_team_state`. Noch
-- nicht ausgeliefert; vorhandene Zeilen gehen bewusst verloren.
DROP TABLE relay_reservations;

-- `notify` je Mitglied und Team: nur die neueste unzugestellte, zugestellt nach dem nächsten
-- `welcome` eines Geräts des Mitglieds und dann gelöscht.
CREATE TABLE relay_pending_notify (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member      TEXT    NOT NULL,
    notify      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, member)
) STRICT, WITHOUT ROWID;

-- Mit `device.remove` aus dem Team entfernte Geräte (Holder = Mitglied und Gerät). Ein `hello`
-- dieses Geräts wird danach abgelehnt; die App meldet sich mit einer neuen Geräte-ID an.
CREATE TABLE relay_removed_devices (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    removed_at  INTEGER NOT NULL,
    by_member   TEXT    NOT NULL,
    PRIMARY KEY (team_id, member, device)
) STRICT, WITHOUT ROWID;
