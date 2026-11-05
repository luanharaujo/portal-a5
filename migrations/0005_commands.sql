-- Stage 3: commands to the house, Shortcuts keys, the portal brake.

-- One key per device and shortcut (or set of actions). Only the SHA-256 of the key is stored.
-- scope: JSON array of "<tab>/<action>". The key acts as person_id and loses every action the
-- person loses (group change, block) at the next use.
CREATE TABLE shortcut_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_session INTEGER,
  last_used_at TEXT,
  last_ip TEXT,
  last_place TEXT,                   -- city / ASN of the last use
  seen_places TEXT NOT NULL DEFAULT '[]', -- JSON "city|ASn" seen so far (last 20); a new one warns the admins
  revoked_at TEXT
);
CREATE INDEX shortcut_keys_person ON shortcut_keys (person_id, revoked_at);

-- One row per command the portal handed to a tab. id is the UUID the bridge sees.
-- gap_key: set when the action has a minimum interval (per device, for example).
CREATE TABLE commands (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  tab TEXT NOT NULL,
  action TEXT NOT NULL,
  params TEXT,
  credential TEXT NOT NULL,          -- 'browser' | 'screen' | 'shortcut'
  person_id INTEGER,
  session_id INTEGER,
  shortcut_id INTEGER,
  gap_key TEXT,
  status TEXT NOT NULL,              -- 'sent' | 'done' | 'failed' | 'queued' | 'offline' | 'refused' | 'timeout'
  finished_at TEXT
);
CREATE INDEX commands_gap ON commands (tab, gap_key, at);
CREATE INDEX commands_at ON commands (at);

-- Portal-wide switches. 'commands_off' = the brake: every command is refused until an admin
-- with a fresh passkey turns commands back on.
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by INTEGER
);

-- A non-admin browser session sends commands only 24 h after sign-in, or once an admin
-- with a fresh passkey lets it (a borrowed WhatsApp sign-in cannot act at once).
ALTER TABLE sessions ADD COLUMN commands_ok_at TEXT;
