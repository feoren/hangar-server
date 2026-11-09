-- Untergrenze für Tickets je Mitglied und Team (Sicherheitsprüfung 2026-11-09): ein Ticket mit
-- `iat` bis `floor_ms` stammt von vor einer Entfernung oder Rollenänderung und trägt womöglich
-- eine Rolle oder einen Zugang, den die Webseite (oder der Selbstbetrieb) inzwischen entzogen
-- hat. Es öffnet das Team nicht mehr (`hello`) und erneuert keine Verbindung (`ticket.renew`);
-- die App holt ein neues Ticket. Die Zeile bleibt auch nach einer Wiederaufnahme (anders als
-- `relay_members.removed_at`), damit ein gehortetes altes Ticket nicht wieder gilt.
CREATE TABLE relay_ticket_floors (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member      TEXT    NOT NULL,
    floor_ms    INTEGER NOT NULL,
    PRIMARY KEY (team_id, member)
) STRICT, WITHOUT ROWID;
