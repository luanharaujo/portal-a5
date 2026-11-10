-- Read keys ("pa5_ler_"): a program of the owner group (an agent on the Mac) reads one tab's data
-- path, GET only, with no session (docs/READ_KEYS.md). Only the hash stays. No end date (owner's
-- call, 10/11): every admin is warned when a key is used more than 30 times in a day or from a
-- second IP address in the same day (use_day*, calendar day in UTC-3).
CREATE TABLE read_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  tab TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_session INTEGER,
  last_used_at TEXT,
  last_ip TEXT,
  last_place TEXT,
  seen_places TEXT NOT NULL DEFAULT '[]', -- JSON "city|ASn" seen so far (last 20); a new one warns the admins
  use_day TEXT,                       -- YYYY-MM-DD (UTC-3) of the counters below
  use_day_n INTEGER NOT NULL DEFAULT 0,
  use_day_ips TEXT NOT NULL DEFAULT '[]', -- JSON IP addresses seen that day
  revoked_at TEXT
);
CREATE INDEX read_keys_person ON read_keys (person_id, revoked_at);
