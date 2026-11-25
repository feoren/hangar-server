-- A holder that proved possession once on protocol version 3 is never served on an older
-- version again: a stolen ticket with its device id cannot fall back to the unproven rules.
CREATE TABLE IF NOT EXISTS relay_device_proofs (
    team_id    TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member     TEXT    NOT NULL,
    device     TEXT    NOT NULL,
    proven_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, member, device)
) STRICT;
