-- Relay-Kern: Zustand, den der Server für die Live-Verbindung dauerhaft braucht.
-- Inhalte liegen nur verschlüsselt vor (opake base64url-Texte); Kennungen sind opak.
-- Zeiten: Unix-Millisekunden (UTC), außer relay_used_tickets.exp (Sekunden wie im Ticket).

-- Ein Team = Projekt der Webseite (offizieller Betrieb) bzw. Team des Selbstbetriebs.
-- stream: Kennung dieser Log-Inkarnation; nach einem Zurückspielen einer Sicherung neu
-- vergeben (Befehl rotate-streams), damit Clients keinen fremden Sequenznummern trauen.
CREATE TABLE relay_teams (
    id          TEXT    PRIMARY KEY,
    stream      TEXT    NOT NULL,
    head        INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0),
    epoch       INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    blob_bytes  INTEGER NOT NULL DEFAULT 0 CHECK (blob_bytes >= 0),
    created_at  INTEGER NOT NULL
) STRICT;

-- Mitglieder, wie die Tickets sie nennen. removed_at: aus dem Team entfernt (Selbstbetrieb).
CREATE TABLE relay_members (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member      TEXT    NOT NULL,
    role        TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    removed_at  INTEGER,
    PRIMARY KEY (team_id, member)
) STRICT, WITHOUT ROWID;

-- Geräte gehören genau einem Mitglied (kontoweit, nicht je Team). Öffentliche Schlüssel nur
-- als base64url-Text; der Server prüft nur die Länge.
CREATE TABLE relay_devices (
    device      TEXT    PRIMARY KEY,
    member      TEXT    NOT NULL,
    sign_key    TEXT,
    kem_key     TEXT,
    keys_at     INTEGER,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
) STRICT;
-- Geräteliste eines Teams: Join über member.
CREATE INDEX relay_devices_member ON relay_devices (member);

-- Gehaltene Reservierungen (Eintrag als JSON des Zustands); frei heißt: keine Zeile.
CREATE TABLE relay_reservations (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    task        TEXT    NOT NULL,
    data        TEXT    NOT NULL,
    PRIMARY KEY (team_id, task)
) STRICT, WITHOUT ROWID;

-- Verbrauchte Ticket-IDs bis zum Ablauf des Tickets (plus Uhrenabweichung).
CREATE TABLE relay_used_tickets (
    jti         TEXT    PRIMARY KEY,
    exp         INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX relay_used_tickets_exp ON relay_used_tickets (exp);

-- Verschlüsselte Ablage (Entscheidungen, Aufgaben, geteilte Transkripte).
CREATE TABLE relay_blobs (
    id          TEXT    PRIMARY KEY,
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('decision', 'task', 'transcript')),
    epoch       INTEGER NOT NULL,
    data        TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;
-- Aufräumen je Team und Alter (Aufbewahrungsfrist der Transkripte).
CREATE INDEX relay_blobs_team_kind_created ON relay_blobs (team_id, kind, created_at);

-- Signiertes, verkettetes Mitgliedschafts-Log (Schritt E). Der Server prüft nur die Kette:
-- idx lückenlos ab 1, prev = hash des Vorgängers. hash = SHA-256 der Eintragsbytes (Hex).
CREATE TABLE relay_member_log (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL CHECK (idx >= 1),
    hash        TEXT    NOT NULL,
    entry       TEXT    NOT NULL,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, idx)
) STRICT, WITHOUT ROWID;

-- Epochen des Teamschlüssels und die je Gerät verpackten Schlüssel (opake HPKE-Ausgaben).
CREATE TABLE relay_epochs (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE relay_key_packages (
    team_id     TEXT    NOT NULL,
    epoch       INTEGER NOT NULL,
    device      TEXT    NOT NULL,
    data        TEXT    NOT NULL,
    by_device   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, epoch, device),
    FOREIGN KEY (team_id, epoch) REFERENCES relay_epochs (team_id, epoch) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
