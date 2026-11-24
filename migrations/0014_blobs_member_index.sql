-- Blob bytes per member over all teams: one account can be in many teams (a project on the
-- website is cheap), so besides the quota per team there is one per member (`put_blob`).
CREATE INDEX relay_blobs_member ON relay_blobs (member);
