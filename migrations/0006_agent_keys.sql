-- Agent keys (pa5_adm_): a house agent lists and tidies screens, devices and machine keys, and
-- prepares changes that give access (pair a screen, move a screen to another group, unblock it).
-- It never approves anything: each of those waits for an admin's Face ID. Only the SHA-256 of
-- the key is stored.
CREATE TABLE agent_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_by INTEGER,
  last_used_at TEXT,
  last_ip TEXT,
  revoked_at TEXT
);
CREATE INDEX agent_keys_created ON agent_keys (id, revoked_at);

-- What an agent asks and an admin approves with Face ID.
--   pair    a screen (new account, or an existing one) signs in through a one-use link the
--           agent opens on that screen; the screen must open it from the agent's own address
--   screen  an existing screen account changes group and/or is unblocked
CREATE TABLE agent_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pair', 'screen')),
  screen_id INTEGER,                 -- existing screen account
  screen_name TEXT,                  -- new screen account, created on approval
  group_id TEXT,                     -- non-admin group the screen ends up in (NULL: keep it)
  unblock INTEGER NOT NULL DEFAULT 0,
  pairing_id INTEGER,
  next_path TEXT,                    -- where the screen goes once paired
  agent_ip TEXT,
  at_home INTEGER NOT NULL DEFAULT 0, -- agent_ip matched a live machine key's address when asked
  state TEXT NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'approved', 'refused', 'cancelled')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_by INTEGER,
  decided_at TEXT
);
CREATE INDEX agent_requests_state ON agent_requests (state, expires_at);
CREATE INDEX agent_requests_agent ON agent_requests (agent_id, state);

-- An agent pairing has no typed code: its ticket (in the link) is swapped for the usual poll
-- secret when the screen opens the link.
ALTER TABLE screen_pairings ADD COLUMN request_id INTEGER;
ALTER TABLE screen_pairings ADD COLUMN ticket_hash TEXT;
ALTER TABLE screen_pairings ADD COLUMN claimed_at TEXT;
CREATE INDEX screen_pairings_ticket ON screen_pairings (ticket_hash);

CREATE INDEX people_kind ON people (kind);

-- "home" = the last address of a live machine (bridge) key
CREATE INDEX machine_keys_live ON machine_keys (revoked_at, last_ip);

-- Private screens of the owner (a bedroom monitor, a desk monitor): their own tabs, never admin.
-- Tabs are set from the account page, like any group.
INSERT OR IGNORE INTO groups (id, name, tabs, is_admin) VALUES ('owner-screens', 'Owner screens', '[]', 0);
