-- The newest issue time (`iat`) seen per license ID: a document of the same license that is
-- older than one already stored is refused, so an owner cannot go back to a document with more
-- seats after the website issued a smaller one (downgrade). Rows stay when the license is
-- removed or replaced by another ID.
CREATE TABLE license_floors (
    lid  TEXT    PRIMARY KEY,
    iat  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
