-- Eigene Identität für den Selbstbetrieb (IDENTITY=local). Im offiziellen Betrieb bleiben
-- diese Tabellen leer: Konten, Projekte und Plätze verwaltet dort die Webseite.
-- Zeiten: Unix-Sekunden (UTC). Tokens nur als SHA-256 (Hex).

CREATE TABLE users (
    id          TEXT    PRIMARY KEY,
    email       TEXT    NOT NULL UNIQUE,
    lang        TEXT    NOT NULL DEFAULT 'en',
    created_at  INTEGER NOT NULL
) STRICT;

-- Eine Anmeldung: kind app = Hangar über den Device Flow, browser = Seiten des Servers.
CREATE TABLE auth_sessions (
    id            TEXT    PRIMARY KEY,
    user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind          TEXT    NOT NULL CHECK (kind IN ('app', 'browser')),
    label         TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER
) STRICT;
CREATE INDEX auth_sessions_user ON auth_sessions (user_id);

-- Zugriffs-, Erneuerungs- und Browser-Tokens. used_at bei refresh: schon gegen ein neues Paar
-- getauscht; ein zweiter Tausch widerruft die ganze Sitzung (Erkennung gestohlener Tokens).
CREATE TABLE auth_tokens (
    hash        TEXT    PRIMARY KEY,
    session_id  TEXT    NOT NULL REFERENCES auth_sessions (id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('access', 'refresh', 'browser')),
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
) STRICT, WITHOUT ROWID;
CREATE INDEX auth_tokens_session ON auth_tokens (session_id);
CREATE INDEX auth_tokens_expires ON auth_tokens (expires_at);

-- Anmeldelinks per Mail; return_to nur aus einer festen Liste von Pfaden.
CREATE TABLE magic_links (
    hash        TEXT    PRIMARY KEY,
    email       TEXT    NOT NULL,
    return_to   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
) STRICT, WITHOUT ROWID;
CREATE INDEX magic_links_expires ON magic_links (expires_at);

-- OAuth 2.0 Device Authorization Grant (RFC 8628).
CREATE TABLE device_codes (
    hash          TEXT    PRIMARY KEY,
    user_code     TEXT    NOT NULL UNIQUE,
    label         TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    interval_s    INTEGER NOT NULL,
    last_poll_at  INTEGER,
    status        TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'used')),
    user_id       TEXT    REFERENCES users (id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX device_codes_expires ON device_codes (expires_at);

-- Teams des Selbstbetriebs. Ein Konto mit Teams wird nicht gelöscht, solange es Eigentümer ist
-- (RESTRICT): erst Teams löschen oder übertragen.
CREATE TABLE teams (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    owner_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at  INTEGER NOT NULL
) STRICT;
-- Platzzählung je Eigentümer.
CREATE INDEX teams_owner ON teams (owner_id);

CREATE TABLE team_members (
    team_id     TEXT    NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role        TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (team_id, user_id)
) STRICT, WITHOUT ROWID;
-- Teams einer Person.
CREATE INDEX team_members_user ON team_members (user_id);

-- Einladungen nur an eine E-Mail-Adresse; je Team und Adresse höchstens eine offene.
CREATE TABLE invitations (
    id            TEXT    PRIMARY KEY,
    team_id       TEXT    NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    email         TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'member')),
    token_hash    TEXT    NOT NULL UNIQUE,
    invited_by    TEXT    REFERENCES users (id) ON DELETE SET NULL,
    lang          TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    sent_count    INTEGER NOT NULL DEFAULT 1,
    last_sent_at  INTEGER NOT NULL,
    accepted_at   INTEGER,
    accepted_by   TEXT    REFERENCES users (id) ON DELETE SET NULL,
    revoked_at    INTEGER
) STRICT;
CREATE UNIQUE INDEX invitations_open ON invitations (team_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Hinterlegtes Lizenzdokument je Konto (Plätze je Konto). lid eindeutig: eine Lizenz gilt auf
-- einem Server nur für ein Konto.
CREATE TABLE licenses (
    user_id      TEXT    PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    lid          TEXT    NOT NULL UNIQUE,
    document     TEXT    NOT NULL,
    uploaded_at  INTEGER NOT NULL
) STRICT;

-- Drosselung der Hinweismails ("Etwas braucht deine Aufmerksamkeit").
CREATE TABLE mail_throttle (
    user_id     TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    team_id     TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    sent_at     INTEGER NOT NULL,
    PRIMARY KEY (user_id, team_id, kind)
) STRICT, WITHOUT ROWID;
