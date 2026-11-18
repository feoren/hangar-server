-- Hourly purge of old transcripts (`store::purge`): finds them by kind and age. The index
-- from 0001 starts with team_id and cannot serve this query, so it scanned the whole table
-- (including the encrypted data) under the write lock.
CREATE INDEX IF NOT EXISTS relay_blobs_kind_created ON relay_blobs (kind, created_at);
