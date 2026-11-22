-- The team's notes key ring (protocol version 2, `notes.keys.set`, ADR 0006 phase 2 of the app):
-- one opaque record per team, only the newest one is kept.
-- version   counted up per team from 1 with every stored write; the `base` the next write must
--           name (compare and set, otherwise `conflict`)
-- by_*      the device that wrote it (the record's signature must verify for it in the app)
-- epoch     the epoch the content is sealed under (the current one at the time of the write)
-- content   the sealed key ring, at most `MAX_INLINE_CIPHERTEXT_LEN`; the relay cannot read it
-- The record goes with the team (ON DELETE CASCADE); removing a member or a device leaves it, the
-- next rotation re-seals it.
CREATE TABLE IF NOT EXISTS relay_notes_keys (
    team_id     TEXT    PRIMARY KEY REFERENCES relay_teams (id) ON DELETE CASCADE,
    version     INTEGER NOT NULL CHECK (version >= 1),
    by_member   TEXT    NOT NULL,
    by_device   TEXT    NOT NULL,
    epoch       INTEGER NOT NULL CHECK (epoch >= 0),
    content     TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
