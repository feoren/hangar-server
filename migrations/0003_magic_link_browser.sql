-- Anmeldelinks an den Browser binden, der sie angefordert hat (gegen Phishing mit fremden
-- Gerätecodes): browser_hash = SHA-256 (Hex) eines Zufallswerts, den nur dieser Browser als
-- Cookie trägt. Der Rücksprung auf /device?code=... gilt nur im selben Browser; sonst führt der
-- Link auf /device, und der Code wird von Hand eingegeben. NULL: Link ohne Browserbindung
-- (Befehl login-link).
ALTER TABLE magic_links ADD COLUMN browser_hash TEXT;
