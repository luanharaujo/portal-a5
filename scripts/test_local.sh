#!/usr/bin/env bash
# End-to-end test against `wrangler dev` with a throwaway local D1 and fake secrets.
# Usage: bash scripts/test_local.sh  (port 8941 on 127.0.0.1 unless PORT is set)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-8941}"
STATE="$(mktemp -d)"
LOG="$STATE/wrangler.log"
VARS="$STATE/test.vars"

# fake values only; real ones never touch disk
printf 'ROBOT_LOGIN_KEY=pa5_robo_test_%s\nOWNER_PHONE=5561900000001\n' "$(openssl rand -hex 32)" > "$VARS"
KEY="$(sed -n 's/^ROBOT_LOGIN_KEY=//p' "$VARS")"

# The portal plus a fake tab worker bound as several tabs (test/fake_tab), written through the
# same generator as a deploy. tab-a: session entry, screens allowed. tab-b: Face ID on entry.
# tab-slow and tab-odd: badges that are slow or malformed. The portal must drop conta (a
# reserved name), tab-bad (an unknown key), tab-nopolicy (no policy written out) and tab-badcmd
# (one malformed command). tab-a carries the commands of the stage 3 tests.
node scripts/test_commands.mjs >/dev/null || { node scripts/test_commands.mjs | grep -v "^ok"; exit 1; }
echo "ok   unit checks of src/commands.ts"
TESTCFG=".wrangler.test.toml"
cat > "$STATE/tabs.json" <<'EOF2'
{
  "tab-a": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "label": "Tab A", "icon": "bolt",
            "allow": ["screen-wake-lock"], "entry": "session", "credentials": ["browser", "screen", "machine"],
            "commands": {
              "tv": {"level": "common", "params": {"mode": {"enum": ["on", "off", "globo"]}}, "perHour": 5, "screens": true, "returns": ["state"]},
              "ac": {"level": "common", "params": {"unit": {"enum": ["a", "b"]}}, "gap": {"seconds": 180, "by": "unit"}},
              "light": {"level": "common", "perHour": 100},
              "slow": {"level": "common"},
              "boom": {"level": "common"},
              "presence": {"level": "admin", "params": {"state": {"enum": ["out", "home"]}}, "perHour": 30},
              "wipe": {"level": "sensitive"},
              "limit": {"level": "common", "passkey": "5m", "params": {"on": {"bool": true}, "top": {"int": [10, 60]}}, "perHour": 30,
                        "screens": false, "shortcut": false, "returns": ["state"]},
              "note": {"level": "common", "keyWriteOnly": true}
            }},
  "tab-b": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "label": "Tab B", "icon": "mic",
            "allow": ["microphone", "screen-wake-lock"], "entry": "passkey", "entryHours": 4,
            "credentials": ["browser", "machine"], "serviceWorker": false, "readKey": {"paths": ["/echo", "/audit"], "perHour": 8},
            "commands": {"ping": {"level": "common"},
              "jot": {"level": "common", "keyWriteOnly": true, "params": {"cents": {"int": [1, 1000]}}, "perHour": 30, "screens": false, "shortcut": true}}},
  "tab-badcmd": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "allow": [], "entry": "session", "credentials": ["browser"],
            "commands": {"tv": {"level": "common"}, "rm": {"level": "root"}}},
  "tab-slow": {"service": "portal-a5-fake-tab", "entrypoint": "SlowTab", "allow": [], "entry": "session", "credentials": ["browser"]},
  "tab-odd": {"service": "portal-a5-fake-tab", "entrypoint": "OddTab", "label": "Odd", "allow": [], "entry": "session", "credentials": ["browser"]},
  "conta": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "allow": [], "entry": "session", "credentials": ["browser"]},
  "tab-bad": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "allow": [], "entry": "session", "credentials": ["browser"], "camera": true},
  "tab-nopolicy": {"service": "portal-a5-fake-tab", "entrypoint": "FakeTab", "label": "No policy"}
}
EOF2
python3 scripts/make_config.py "$STATE/tabs.json" > "$TESTCFG" 2>/dev/null
grep -q '^TABS = "{\\"tab-a' "$TESTCFG" || { echo "FAIL could not write the test config"; exit 1; }

npx wrangler d1 migrations apply portal_a5 --local --persist-to "$STATE" >/dev/null
# residents see the first test tab (a fresh database gives them none)
npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --command "UPDATE groups SET tabs = '[\"tab-a\"]' WHERE id = 'residents'" >/dev/null
npx wrangler dev -c "$TESTCFG" -c test/fake_tab/wrangler.toml --local --ip 127.0.0.1 --port "$PORT" --persist-to "$STATE" --env-file "$VARS" >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true; rm -rf "$STATE" "$TESTCFG"' EXIT
for _ in $(seq 60); do curl -sf -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.5; done

STATE="$STATE" BASE="http://127.0.0.1:$PORT" ROBO_KEY="$KEY" OWNER=5561900000001 node scripts/test_local.mjs

# an admin new-device warning survives the revocation of that session
left="$(npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --json --command \
  "SELECT COUNT(*) AS n FROM device_alerts a LEFT JOIN sessions s ON s.id = a.session_id WHERE a.ack_at IS NULL AND s.id IS NULL" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["results"][0]["n"])')"
[ "$left" -ge 1 ] && echo "ok   alert kept after its session was revoked" || { echo "FAIL alert vanished with its session"; exit 1; }

# no rows left behind by deleted sessions, and session ids come from AUTOINCREMENT
orph="$(npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --json --command \
  "SELECT (SELECT COUNT(*) FROM tab_entries WHERE session_id NOT IN (SELECT id FROM sessions)) + (SELECT COUNT(*) FROM passkey_challenges WHERE session_id NOT IN (SELECT id FROM sessions)) AS n" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["results"][0]["n"])')"
[ "$orph" = 0 ] && echo "ok   no tab entries or challenges left by deleted sessions" || { echo "FAIL $orph rows left by deleted sessions"; exit 1; }
seq="$(npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --json --command \
  "SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'sessions' AND sql LIKE '%AUTOINCREMENT%'" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["results"][0]["n"])')"
[ "$seq" = 1 ] && echo "ok   sessions use AUTOINCREMENT" || { echo "FAIL sessions without AUTOINCREMENT"; exit 1; }

# every hot query must use an index
for q in \
  "SELECT * FROM login_codes WHERE code_hash = 'x' AND expires_at > 'y'" \
  "SELECT * FROM login_codes WHERE secret_hash = 'x'" \
  "UPDATE login_codes SET expires_at = 'x' WHERE typed_phone = 'p' AND state = 'waiting' AND expires_at > 'y'" \
  "DELETE FROM login_codes WHERE expires_at < 'x'" \
  "SELECT s.id FROM sessions s JOIN people p ON p.id = s.person_id WHERE s.token_hash = 'x' AND s.expires_at > 'y'" \
  "SELECT id FROM sessions WHERE person_id = 1 ORDER BY last_used_at DESC" \
  "SELECT g.* FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE pg.person_id = 1" \
  "SELECT * FROM people WHERE phone = 'x'" \
  "SELECT COUNT(*) FROM link_requests WHERE state = 'pending' AND expires_at > 'x'" \
  "DELETE FROM passkey_challenges WHERE session_id = 1 AND kind = 'get' AND expires_at > 'x'" \
  "SELECT credential_id FROM passkeys WHERE person_id = 1" \
  "DELETE FROM rate_limits WHERE hour < 'x'" \
  "SELECT id FROM device_alerts WHERE person_id = 1 AND ack_at IS NULL" \
  "SELECT * FROM screen_pairings WHERE secret_hash = 'x'" \
  "SELECT * FROM screen_pairings WHERE code_hash = 'x' AND expires_at > 'y' AND state = 'waiting'" \
  "DELETE FROM screen_pairings WHERE expires_at < 'x'" \
  "SELECT id FROM sessions WHERE person_id = 1" \
  "DELETE FROM tab_entries WHERE session_id = 1" \
  "DELETE FROM passkey_challenges WHERE session_id = 1" \
  "SELECT person_id FROM person_groups WHERE group_id = 'g'" \
  "UPDATE tab_entries SET used_at = 'x' WHERE session_id = 1 AND tab = 'j' AND used_at IS NULL AND granted_at > 'y'" \
  "SELECT used_at FROM tab_entries WHERE session_id = 1 AND tab = 'j' AND used_at > 'x' ORDER BY used_at DESC LIMIT 1" \
  "DELETE FROM tab_entries WHERE granted_at < 'x'" \
  "SELECT id, tab, label, revoked_at FROM machine_keys WHERE key_hash = 'x'" \
  "SELECT n FROM rate_limits WHERE bucket = 'b' AND hour = 'h'" \
  "SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1" \
  "SELECT id, label, revoked_at FROM agent_keys WHERE key_hash = 'x'" \
  "SELECT COUNT(*) AS n FROM agent_requests WHERE agent_id = 1 AND state = 'waiting' AND expires_at > 'x'" \
  "SELECT id FROM agent_requests WHERE state = 'waiting' AND expires_at > 'x' ORDER BY id LIMIT 20" \
  "SELECT r.* FROM agent_requests r LEFT JOIN agent_keys k ON k.id = r.agent_id LEFT JOIN screen_pairings p ON p.id = r.pairing_id LEFT JOIN people s ON s.id = r.screen_id LEFT JOIN groups g ON g.id = r.group_id WHERE r.id = 1 AND r.state = 'waiting' AND r.expires_at > 'x'" \
  "SELECT r.id FROM agent_requests r LEFT JOIN screen_pairings p ON p.id = r.pairing_id WHERE r.agent_id = 1 ORDER BY r.id DESC LIMIT 20" \
  "SELECT p.id FROM screen_pairings p JOIN agent_requests r ON r.id = p.request_id LEFT JOIN people s ON s.id = r.screen_id WHERE p.ticket_hash = 'x'" \
  "SELECT id, name FROM people WHERE kind = 'screen' ORDER BY id" \
  "SELECT s.id FROM sessions s JOIN people p ON p.id = s.person_id WHERE p.kind = 'screen' AND s.expires_at > 'x'" \
  "SELECT pg.person_id, pg.group_id FROM person_groups pg JOIN people p ON p.id = pg.person_id WHERE p.kind = 'screen'" \
  "UPDATE agent_requests SET state = 'cancelled' WHERE agent_id = 1 AND state = 'waiting'" \
  "SELECT last_ip FROM machine_keys WHERE revoked_at IS NULL AND last_ip IS NOT NULL LIMIT 50"; do
  plan="$(npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --json --command "EXPLAIN QUERY PLAN $q" 2>/dev/null)"
  if echo "$plan" | grep -E '"detail": *"SCAN [a-z_]+"' | grep -vq 'USING'; then echo "FAIL full scan: $q"; echo "$plan"; exit 1; fi
done
echo "index check: ok"
