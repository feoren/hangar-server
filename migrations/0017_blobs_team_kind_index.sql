-- Pages of `blob.list` (protocol version 4): a team's blobs of one kind in storage order. An
-- index on (team_id, kind) carries the rowid as its last key, so the page reads in rowid order
-- without sorting.
CREATE INDEX IF NOT EXISTS relay_blobs_team_kind_row ON relay_blobs (team_id, kind);
