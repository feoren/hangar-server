-- Accounts created through an invitation link that went to the inviter instead of a mailbox
-- (no mail transport): holding that link proves nothing about the address, the inviter may
-- have opened it first. The first sign-in with a real proof (magic link or `login-link` from
-- the operator) ends every session started before it and clears the mark.
ALTER TABLE users ADD COLUMN unproven INTEGER NOT NULL DEFAULT 0 CHECK (unproven IN (0, 1));
