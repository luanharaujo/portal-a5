-- Every query in src/ hits one of these indexes. Free-plan D1 caps rows read per day,
-- so a full scan on a hot path is a real outage risk.

CREATE TABLE groups (
  id TEXT PRIMARY KEY,               -- 'owner', 'residents', ...
  name TEXT NOT NULL,
  tabs TEXT NOT NULL DEFAULT '[]',   -- JSON array of tab names; "*" = every tab
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO groups (id, name, tabs, is_admin) VALUES
  ('owner', 'Dono', '["*"]', 1),
  ('residents', 'Moradores', '["energia"]', 0);

CREATE TABLE people (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,        -- digits only, country code first
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  created_by INTEGER
);

CREATE TABLE person_groups (
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (person_id, group_id)
);
CREATE INDEX person_groups_group ON person_groups (group_id);

-- One row per signed-in browser / home-screen app. Only the SHA-256 of the cookie value is stored.
-- WhatsApp gives a weak session; a passkey on the device makes it strong (passkey_at).
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'browser',
  label TEXT,
  ip TEXT,
  place TEXT,                        -- city / ASN at sign-in
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  passkey_at TEXT                    -- last successful passkey check on this session
);
CREATE INDEX sessions_person ON sessions (person_id, last_used_at);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- "New device signed in as an admin" banner. Lives apart from sessions so revoking the
-- session (or the session expiring) never makes the warning disappear.
CREATE TABLE device_alerts (
  id INTEGER PRIMARY KEY,
  person_id INTEGER NOT NULL,
  session_id INTEGER NOT NULL,
  label TEXT,
  place TEXT,
  created_at TEXT NOT NULL,
  ack_at TEXT,
  ack_session_id INTEGER
);
CREATE INDEX device_alerts_person ON device_alerts (person_id, ack_at);

-- A strong admin invites another admin to add a first passkey from a weak session.
CREATE TABLE passkey_invites (
  id INTEGER PRIMARY KEY,
  person_id INTEGER NOT NULL,
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX passkey_invites_person ON passkey_invites (person_id, expires_at);

CREATE TABLE passkeys (
  id INTEGER PRIMARY KEY,
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE, -- base64url
  public_key TEXT NOT NULL,           -- SPKI, base64url (ES256)
  sign_count INTEGER NOT NULL DEFAULT 0,
  label TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX passkeys_person ON passkeys (person_id);

CREATE TABLE passkey_challenges (
  id INTEGER PRIMARY KEY,
  session_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('create', 'get')),
  challenge TEXT NOT NULL,           -- base64url, single use
  expires_at TEXT NOT NULL
);
CREATE INDEX passkey_challenges_session ON passkey_challenges (session_id, kind);
CREATE INDEX passkey_challenges_expires ON passkey_challenges (expires_at);

-- Inverted WhatsApp login: the person SENDS the code. code_hash and secret_hash are SHA-256.
CREATE TABLE login_codes (
  id INTEGER PRIMARY KEY,
  code_hash TEXT NOT NULL,
  secret_hash TEXT NOT NULL UNIQUE,
  typed_phone TEXT NOT NULL,         -- number typed on the page; the sender must match it
  label TEXT,                        -- device that asked for the code
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  confirmed_at TEXT,
  confirmed_person_id INTEGER,
  state TEXT NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'confirmed', 'pending', 'used', 'refused'))
);
CREATE INDEX login_codes_code ON login_codes (code_hash, expires_at);
CREATE INDEX login_codes_typed ON login_codes (typed_phone, state);
CREATE INDEX login_codes_expires ON login_codes (expires_at);

-- Code sent from a number other than the one typed, or from an unknown number:
-- nobody is signed in until the owner approves.
CREATE TABLE link_requests (
  id INTEGER PRIMARY KEY,
  code_id INTEGER NOT NULL UNIQUE,
  typed_phone TEXT NOT NULL,
  sender_phone TEXT NOT NULL,
  sender_person_id INTEGER,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'refused', 'expired')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by INTEGER
);
CREATE INDEX link_requests_state ON link_requests (state, expires_at);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  person_id INTEGER,
  session_id INTEGER,
  strength TEXT,                     -- 'weak' | 'strong' | 'robot'
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT,
  place TEXT
);
CREATE INDEX audit_person ON audit (person_id, id);

CREATE TABLE rate_limits (
  bucket TEXT NOT NULL,
  hour TEXT NOT NULL,                -- 'YYYY-MM-DDTHH'
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, hour)
);
CREATE INDEX rate_limits_hour ON rate_limits (hour);
