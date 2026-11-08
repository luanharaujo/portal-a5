-- Face ID asked by a tab page itself (POST /<tab>/_passkey/verify, no portal screen around it).
-- It opens only this session's command windows (admin actions and actions with their own
-- `passkey` window); it never makes the session strong for the account pages or sensitive actions,
-- which keep using passkey_at (the portal's own Face ID).
ALTER TABLE sessions ADD COLUMN command_passkey_at TEXT;
-- The tab that check was made in: it counts only for that tab's commands.
ALTER TABLE sessions ADD COLUMN command_passkey_tab TEXT;
