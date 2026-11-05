-- Session ids must never be reused: rows keyed by session id (tab entries, passkey challenges,
-- sockets held by tabs) would otherwise carry over to a new session that got an old id.
-- SQLite only guarantees that with AUTOINCREMENT, which needs the table rebuilt.

CREATE TABLE sessions_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'browser',
  label TEXT,
  ip TEXT,
  place TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  passkey_at TEXT
);
INSERT INTO sessions_new (id, person_id, token_hash, kind, label, ip, place, created_at, last_used_at, expires_at, passkey_at)
  SELECT id, person_id, token_hash, kind, label, ip, place, created_at, last_used_at, expires_at, passkey_at FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX sessions_person ON sessions (person_id, last_used_at);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- Rows left behind by sessions deleted before this migration.
DELETE FROM tab_entries WHERE session_id NOT IN (SELECT id FROM sessions);
DELETE FROM passkey_challenges WHERE session_id NOT IN (SELECT id FROM sessions);
