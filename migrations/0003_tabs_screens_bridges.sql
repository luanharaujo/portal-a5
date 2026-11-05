-- Stage 2: fixed screens, Face ID entry into a tab, machine bridges.

-- 'person' signs in through WhatsApp; 'screen' is a fixed display (TV, monitor) that only
-- signs in by pairing. Screen rows get a non-numeric placeholder phone ('screen:<random>'),
-- which normalizePhone can never produce, so no WhatsApp message ever matches one.
ALTER TABLE people ADD COLUMN kind TEXT NOT NULL DEFAULT 'person';

-- A passkey check can be asked for a purpose: 'entry:<tab>' grants one entry into that tab.
ALTER TABLE passkey_challenges ADD COLUMN purpose TEXT;

-- 'device' (new admin device) or 'bridge' (a machine bridge reconnecting too often).
ALTER TABLE device_alerts ADD COLUMN kind TEXT NOT NULL DEFAULT 'device';

-- The screen shows a short code; a strong admin types it (or scans the QR) and picks the
-- screen account; the screen polls with its secret and gets a long session once.
CREATE TABLE screen_pairings (
  id INTEGER PRIMARY KEY,
  code_hash TEXT NOT NULL,
  secret_hash TEXT NOT NULL UNIQUE,
  label TEXT,                        -- browser/OS of the screen asking
  ip TEXT,
  place TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'approved', 'used', 'refused')),
  person_id INTEGER,                 -- the screen account chosen by the admin
  approved_by INTEGER,
  approved_at TEXT
);
CREATE INDEX screen_pairings_code ON screen_pairings (code_hash, expires_at);
CREATE INDEX screen_pairings_expires ON screen_pairings (expires_at);

-- Face ID on every entry: a passkey check made for 'entry:<tab>' leaves a grant
-- (used_at NULL, valid 60 s); the next navigation into the tab burns it (used_at set), and
-- requests inside the tab are accepted while used_at is recent enough.
CREATE TABLE tab_entries (
  id INTEGER PRIMARY KEY,
  session_id INTEGER NOT NULL,
  tab TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX tab_entries_session ON tab_entries (session_id, tab, used_at);
CREATE INDEX tab_entries_granted ON tab_entries (granted_at);

-- One key per machine bridge, bound to one tab. Only the SHA-256 of the key is stored.
CREATE TABLE machine_keys (
  id INTEGER PRIMARY KEY,
  tab TEXT NOT NULL,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_by INTEGER,
  last_used_at TEXT,
  last_ip TEXT,
  revoked_at TEXT
);
CREATE INDEX machine_keys_tab ON machine_keys (tab, revoked_at);

-- bridge alerts go to every admin
CREATE INDEX groups_admin ON groups (is_admin);
