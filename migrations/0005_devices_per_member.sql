-- Geräte-IDs wählt der Client; eindeutig sind sie nur je Mitglied (Protokoll-Crate 2e36889:
-- WrappedKey und KeyWrapped nennen den vollen Holder). Geräte und Schlüsselpakete werden deshalb
-- nach (Mitglied, Gerät) geführt statt nach der Geräte-ID allein. Bestehende Zeilen bleiben.

CREATE TABLE relay_devices_new (
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    sign_key    TEXT,
    kem_key     TEXT,
    keys_at     INTEGER,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (member, device)
) STRICT, WITHOUT ROWID;
INSERT INTO relay_devices_new (member, device, sign_key, kem_key, keys_at, created_at, last_seen)
    SELECT member, device, sign_key, kem_key, keys_at, created_at, last_seen FROM relay_devices;
DROP TABLE relay_devices;
ALTER TABLE relay_devices_new RENAME TO relay_devices;

-- Schlüsselpakete je Epoche und Holder. Das Mitglied eines alten Pakets ist das, dem das
-- Gerät damals gehörte (vor dieser Migration war die Geräte-ID kontoweit eindeutig).
CREATE TABLE relay_key_packages_new (
    team_id     TEXT    NOT NULL,
    epoch       INTEGER NOT NULL,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    data        TEXT    NOT NULL,
    by_member   TEXT    NOT NULL,
    by_device   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (team_id, epoch, member, device),
    FOREIGN KEY (team_id, epoch) REFERENCES relay_epochs (team_id, epoch) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
INSERT INTO relay_key_packages_new (team_id, epoch, member, device, data, by_member, by_device, created_at)
    SELECT p.team_id, p.epoch, d.member, p.device, p.data, '', p.by_device, p.created_at
    FROM relay_key_packages p JOIN relay_devices d ON d.device = p.device;
DROP TABLE relay_key_packages;
ALTER TABLE relay_key_packages_new RENAME TO relay_key_packages;
