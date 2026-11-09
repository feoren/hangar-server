-- Konto-API unter /api/v1 (gleich der Webseite): die App meldet neben dem Gerätenamen ihre
-- Plattform (z. B. "windows"). Gespeichert für die Bestätigungsseite /device und die Liste
-- /account/devices; nur geprüfte Werte ([A-Za-z0-9 ._-], höchstens 40 Zeichen), sonst NULL.
-- Keine personenbezogenen Daten über den Gerätenamen hinaus, der schon gespeichert wird.
ALTER TABLE device_codes ADD COLUMN platform TEXT;
ALTER TABLE auth_sessions ADD COLUMN platform TEXT;
