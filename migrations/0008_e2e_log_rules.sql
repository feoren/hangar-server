-- Regeln aus hangar-team-crypto (Commit b30b9d5): das Relay prüft das Mitgliedschafts-Log selbst.
--
-- relay_device_keys: `device.keys` je Team. Der Besitznachweis (`proof`) bindet Team und Holder,
-- also gelten Schlüssel und Nachweis je Team, nicht kontoweit. `relay::check_registered_keys`
-- vergleicht neue Log-Einträge mit diesen Schlüsseln; `devices` listet sie samt Nachweis.
CREATE TABLE relay_device_keys (
    team_id     TEXT    NOT NULL REFERENCES relay_teams (id) ON DELETE CASCADE,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    sign_key    TEXT    NOT NULL,
    kem_key     TEXT    NOT NULL,
    proof       TEXT    NOT NULL,
    keys_at     INTEGER NOT NULL,
    PRIMARY KEY (team_id, member, device)
) STRICT, WITHOUT ROWID;
-- Die alten, kontoweiten Schlüssel in relay_devices hatten keinen Nachweis; sie werden nicht
-- übernommen (die App sendet `device.keys` nach jedem `welcome` neu).

-- Schlüsselpakete: höchstens eines je Absender, Ziel und Epoche, bis zu MAX_KEY_PACKAGES (4) je
-- Ziel und Epoche, nie ersetzt. `seq` hält die Reihenfolge des Eintreffens (`stored_from`).
CREATE TABLE relay_key_packages_new (
    team_id     TEXT    NOT NULL,
    epoch       INTEGER NOT NULL,
    member      TEXT    NOT NULL,
    device      TEXT    NOT NULL,
    by_member   TEXT    NOT NULL,
    by_device   TEXT    NOT NULL,
    data        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    PRIMARY KEY (team_id, epoch, member, device, by_member, by_device),
    FOREIGN KEY (team_id, epoch) REFERENCES relay_epochs (team_id, epoch) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
INSERT INTO relay_key_packages_new (team_id, epoch, member, device, by_member, by_device, data, created_at, seq)
    SELECT team_id, epoch, member, device, by_member, by_device, data, created_at, created_at
    FROM relay_key_packages;
DROP TABLE relay_key_packages;
ALTER TABLE relay_key_packages_new RENAME TO relay_key_packages;
-- Pakete eines Ziels in einer Epoche, in Reihenfolge des Eintreffens.
CREATE INDEX relay_key_packages_target ON relay_key_packages (team_id, epoch, member, device, seq);
