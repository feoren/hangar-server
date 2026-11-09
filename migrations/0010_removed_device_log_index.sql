-- Index des Log-Eintrags, der ein Gerät aus dem Team nahm (`device.remove` oder Mitglied
-- entfernt). Ein entferntes Gerät darf das Mitgliedschafts-Log noch genau bis zu diesem Eintrag
-- lesen (`memberlog.get` in der Frist nach `device.removed` oder nach einem `hello` des
-- gesperrten Geräts), damit die App ihre Entfernung am signierten Eintrag prüfen kann; spätere
-- Einträge (neue Mitglieder, Geräte, Epochen) bekommt es nicht.
-- Ältere Zeilen bleiben NULL; dann gilt der letzte Eintrag mit created_at <= removed_at (beide
-- schreibt dieselbe Transaktion mit demselben Zeitstempel).
ALTER TABLE relay_removed_devices ADD COLUMN log_index INTEGER;
