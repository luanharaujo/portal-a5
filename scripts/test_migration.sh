#!/usr/bin/env bash
# Checks the session-table rebuild (migration 0004, then the later ones) on a throwaway local D1 that looks like
# production before it: one owner, one live session, one passkey.
#   1. the migration is all-or-nothing: a copy of it that fails on its last line leaves the old
#      table untouched;
#   2. the real migration keeps the owner's session (the same cookie still signs in, same id)
#      and the passkey, and new sessions get ids that are never reused.
# Usage: bash scripts/test_migration.sh  (port 8943 on 127.0.0.1 unless PORT is set)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-8943}"
WORK="$(mktemp -d)"
trap 'kill ${PID:-0} 2>/dev/null || true; wait ${PID:-0} 2>/dev/null || true; rm -rf "$WORK"' EXIT
OWNER=5561900000001
TOKEN="migration_test_token_$(openssl rand -hex 24)"
HASH="$(printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1)"
fail() { echo "FAIL $*"; exit 1; }
q() { # q <dir> <sql> -> first column of the first row
  npx wrangler d1 execute portal_a5 --local --persist-to "$1" --json --command "$2" 2>/dev/null \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)[0]["results"]; print(list(r[0].values())[0] if r else "")'
}

# a config whose migrations dir holds only what we choose
mkcfg() { # mkcfg <dir> <migrations dir>
  sed -e "s|^migrations_dir = .*|migrations_dir = \"$2\"|" -e 's|^main = "src/index.ts"|main = "'"$PWD"'/src/index.ts"|' \
      -e 's|^directory = "./public"|directory = "'"$PWD"'/public"|' wrangler.toml > "$1/wrangler.toml"
}

seed() { # seed <state dir> <config>: migrations 0001-0003 + owner, session, passkey
  npx wrangler d1 migrations apply portal_a5 --local --persist-to "$1" -c "$2" >/dev/null
  npx wrangler d1 execute portal_a5 --local --persist-to "$1" -c "$2" --command "
    INSERT INTO people (id, name, phone, status) VALUES (1, 'Owner', '$OWNER', 'active');
    INSERT INTO person_groups (person_id, group_id) VALUES (1, 'owner');
    INSERT INTO sessions (id, person_id, token_hash, kind, label, created_at, last_used_at, expires_at, passkey_at)
      VALUES (7, 1, '$HASH', 'browser', 'iPhone · Safari', '2026-11-05T12:08:00.000Z', '2026-11-05T12:08:00.000Z', '2027-05-04T12:08:00.000Z', '2026-11-05T12:10:00.000Z');
    INSERT INTO passkeys (person_id, credential_id, public_key, sign_count, label, created_at)
      VALUES (1, 'cred-test', 'pk-test', 3, 'iPhone', '2026-11-05T12:10:00.000Z');
    INSERT INTO tab_entries (session_id, tab, granted_at) VALUES (99, 'tab-b', '2026-11-05T12:00:00.000Z');" >/dev/null
}

# --- 1. all-or-nothing
A="$WORK/a"; mkdir -p "$A/m" "$A/state"
cp migrations/0001_*.sql migrations/0002_*.sql migrations/0003_*.sql "$A/m/"
mkcfg "$A" "$A/m"
seed "$A/state" "$A/wrangler.toml"
{ cat migrations/0004_*.sql; echo "SELECT no_such_column FROM sessions;"; } > "$A/m/0004_broken.sql"
if npx wrangler d1 migrations apply portal_a5 --local --persist-to "$A/state" -c "$A/wrangler.toml" >"$A/out.txt" 2>&1; then
  fail "broken migration was applied"
fi
grep -q no_such_column "$A/out.txt" || { cat "$A/out.txt"; fail "the broken migration failed for another reason"; }
[ "$(q "$A/state" "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sessions_new'")" = 0 ] || fail "half-applied migration left sessions_new"
[ "$(q "$A/state" "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sessions' AND sql LIKE '%AUTOINCREMENT%'")" = 0 ] || fail "half-applied migration changed sessions"
[ "$(q "$A/state" "SELECT token_hash FROM sessions WHERE id = 7")" = "$HASH" ] || fail "session lost after a failed migration"
[ "$(q "$A/state" "SELECT COUNT(*) FROM tab_entries")" = 1 ] || fail "failed migration deleted rows"
[ "$(q "$A/state" "SELECT COUNT(*) FROM d1_migrations WHERE name LIKE '0004%'")" = 0 ] || fail "failed migration recorded as applied"
echo "ok   a failing 0004 rolls back completely"

# --- 2. the real migration keeps the owner's session and passkey
B="$WORK/b"; mkdir -p "$B/m" "$B/state"
cp migrations/0001_*.sql migrations/0002_*.sql migrations/0003_*.sql "$B/m/"
mkcfg "$B" "$B/m"
seed "$B/state" "$B/wrangler.toml"
cp migrations/0004_*.sql "$B/m/"
npx wrangler d1 migrations apply portal_a5 --local --persist-to "$B/state" -c "$B/wrangler.toml" >/dev/null
[ "$(q "$B/state" "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sessions' AND sql LIKE '%AUTOINCREMENT%'")" = 1 ] || fail "sessions without AUTOINCREMENT"
[ "$(q "$B/state" "SELECT COUNT(*) FROM passkeys WHERE person_id = 1 AND credential_id = 'cred-test' AND sign_count = 3")" = 1 ] || fail "passkey lost"
[ "$(q "$B/state" "SELECT passkey_at FROM sessions WHERE id = 7")" = "2026-11-05T12:10:00.000Z" ] || fail "session fields changed"
[ "$(q "$B/state" "SELECT COUNT(*) FROM tab_entries")" = 0 ] || fail "orphan tab entry kept"
echo "ok   session row and passkey kept by 0004; orphan rows removed"

# the migrations after 0004 (commands, Shortcuts keys) go on top before the worker starts
for f in migrations/*.sql; do case "$(basename "$f")" in 000[1-4]_*) ;; *) cp "$f" "$B/m/" ;; esac; done
npx wrangler d1 migrations apply portal_a5 --local --persist-to "$B/state" -c "$B/wrangler.toml" >/dev/null
[ "$(q "$B/state" "SELECT COUNT(*) FROM sessions WHERE id = 7 AND commands_ok_at IS NULL")" = 1 ] || fail "session lost by the later migrations"
echo "ok   later migrations keep the session"

printf 'ROBOT_LOGIN_KEY=pa5_robo_test_%s\nOWNER_PHONE=%s\n' "$(openssl rand -hex 32)" "$OWNER" > "$B/test.vars"
npx wrangler dev -c "$B/wrangler.toml" --local --ip 127.0.0.1 --port "$PORT" --persist-to "$B/state" --env-file "$B/test.vars" >"$B/wrangler.log" 2>&1 &
PID=$!
for _ in $(seq 60); do curl -sf -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.5; done
ME="$(curl -s "http://127.0.0.1:$PORT/api/me" -H "Cookie: __Host-a5s=$TOKEN")"
echo "$ME" | python3 -c 'import json,sys; m=json.load(sys.stdin); assert m["session_id"]==7 and m["admin"] and m["passkeys"]==1, m' \
  || fail "the owner's cookie no longer signs in after 0004: $ME"
echo "ok   the same cookie signs in after 0004 (session 7, admin, 1 passkey)"
npx wrangler d1 execute portal_a5 --local --persist-to "$B/state" -c "$B/wrangler.toml" --command \
  "DELETE FROM sessions WHERE id = 7; INSERT INTO sessions (person_id, token_hash, created_at, last_used_at, expires_at) VALUES (1, 'x', 'a', 'a', 'z');" >/dev/null
[ "$(q "$B/state" "SELECT id FROM sessions WHERE token_hash = 'x'")" = 8 ] || fail "a deleted session id was reused"
echo "ok   after deleting session 7 the next session gets 8, not 7"
echo "migration check: ok"
