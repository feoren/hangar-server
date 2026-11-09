-- Widerrufsliste der Webseite (offizieller Betrieb): das Relay holt sie alle 15 s ab.
-- relay_revocation_cursor: der zuletzt verarbeitete Cursor (`last` der Antwort), genau eine Zeile.
-- relay_revocations_seen: verarbeitete Widerrufs-IDs (`rid`), damit eine Wiederholung nichts
-- doppelt anwendet; nach 30 Tagen aufgeräumt.
CREATE TABLE relay_revocation_cursor (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    cursor      TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE relay_revocations_seen (
    rid         TEXT    PRIMARY KEY,
    seen_at     INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX relay_revocations_seen_at ON relay_revocations_seen (seen_at);
