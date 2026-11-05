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

# The portal plus a fake tab worker bound as tabs: energia, jarvis, lento (slow badge),
# torto (bad badge) and conta (a reserved name the portal must ignore). The config is
# wrangler.toml with the tab bindings added, written next to it so relative paths still work.
TESTCFG=".wrangler.test.toml"
sed 's/^TABS = .*/TABS = "{\\"energia\\":\\"TAB_ENERGIA\\",\\"jarvis\\":\\"TAB_JARVIS\\",\\"lento\\":\\"TAB_LENTO\\",\\"torto\\":\\"TAB_TORTO\\",\\"conta\\":\\"TAB_ENERGIA\\"}"/' wrangler.toml > "$TESTCFG"
cat >> "$TESTCFG" <<'EOF2'

[[services]]
binding = "TAB_ENERGIA"
service = "portal-a5-fake-tab"
entrypoint = "FakeTab"

[[services]]
binding = "TAB_JARVIS"
service = "portal-a5-fake-tab"
entrypoint = "FakeTab"

[[services]]
binding = "TAB_LENTO"
service = "portal-a5-fake-tab"
entrypoint = "SlowTab"

[[services]]
binding = "TAB_TORTO"
service = "portal-a5-fake-tab"
entrypoint = "OddTab"
EOF2
grep -q '^TABS = "{\\"energia' "$TESTCFG" || { echo "FAIL could not write the test config"; exit 1; }

npx wrangler d1 migrations apply portal_a5 --local --persist-to "$STATE" >/dev/null
npx wrangler dev -c "$TESTCFG" -c test/fake_tab/wrangler.toml --local --ip 127.0.0.1 --port "$PORT" --persist-to "$STATE" --env-file "$VARS" >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true; rm -rf "$STATE" "$TESTCFG"' EXIT
for _ in $(seq 60); do curl -sf -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.5; done

BASE="http://127.0.0.1:$PORT" ROBO_KEY="$KEY" OWNER=5561900000001 node scripts/test_local.mjs

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
  "SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1"; do
  plan="$(npx wrangler d1 execute portal_a5 --local --persist-to "$STATE" --json --command "EXPLAIN QUERY PLAN $q" 2>/dev/null)"
  if echo "$plan" | grep -E '"detail": *"SCAN [a-z_]+"' | grep -vq 'USING'; then echo "FAIL full scan: $q"; echo "$plan"; exit 1; fi
done
echo "index check: ok"
