#!/usr/bin/env bash
# Deploys portal-a5 with an API token scoped to the portal's own Cloudflare account.
# Never uses `wrangler login`: the OAuth session on this machine may belong to another account.
#
# Keychain items (macOS, generic passwords; service names below):
#   portal-a5-cloudflare          API token (Workers Scripts: Edit + D1: Edit, this account only)
#   portal-a5-cloudflare-conta    account id
#   portal-a5-robo-login          ROBO_LOGIN_CHAVE ("pa5_robo_" + 32 random bytes)
#   portal-a5-dono-telefone       OWNER_PHONE (digits, country code first)
# Secrets go to wrangler through stdin only: never arguments, never files.
set -euo pipefail
cd "$(dirname "$0")/.."

kc() { security find-generic-password -s "$1" -w 2>/dev/null || { echo "missing Keychain item: $1" >&2; exit 1; }; }

export CLOUDFLARE_API_TOKEN="$(kc portal-a5-cloudflare)"
export CLOUDFLARE_ACCOUNT_ID="$(kc portal-a5-cloudflare-conta)"
# keep wrangler away from any OAuth login stored in the user's global config
export XDG_CONFIG_HOME="$(mktemp -d)"
trap 'rm -rf "$XDG_CONFIG_HOME"' EXIT

# 1. the token must be valid and see exactly this one account
api() { curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4/$1"; }
api user/tokens/verify | grep -q '"status":"active"' || { echo "token not active" >&2; exit 1; }
accounts="$(api 'accounts?per_page=50' | python3 -c 'import json,sys; print(" ".join(a["id"] for a in json.load(sys.stdin)["result"]))')"
[ "$accounts" = "$CLOUDFLARE_ACCOUNT_ID" ] || { echo "token sees accounts [$accounts], expected only the portal account" >&2; exit 1; }

# 2. D1 database (created on first run); its id never goes into git
db_id() { npx wrangler d1 list --json | python3 -c 'import json,sys; print(next((d["uuid"] for d in json.load(sys.stdin) if d["name"]=="portal_a5"), ""))'; }
DB_ID="$(db_id)"
if [ -z "$DB_ID" ]; then npx wrangler d1 create portal_a5 >/dev/null; DB_ID="$(db_id)"; fi
[ -n "$DB_ID" ] || { echo "could not find or create D1 portal_a5" >&2; exit 1; }

# 3. deploy config = wrangler.toml + real ids (git-ignored)
CFG=.wrangler.deploy.toml
python3 - "$DB_ID" "$CLOUDFLARE_ACCOUNT_ID" > "$CFG" <<'PY'
import sys, re
db, acct = sys.argv[1], sys.argv[2]
s = open('wrangler.toml').read()
s = s.replace('database_id = "00000000-0000-0000-0000-000000000000"', f'database_id = "{db}"')
s = re.sub(r'^(main = .*)$', rf'\1\naccount_id = "{acct}"', s, count=1, flags=re.M)
assert f'database_id = "{db}"' in s and 'account_id' in s
print(s)
PY

npx tsc --noEmit
npx wrangler d1 migrations apply portal_a5 --remote -c "$CFG"
npx wrangler deploy -c "$CFG"

# 4. secrets through stdin
kc portal-a5-robo-login | grep -q '^pa5_robo_' || { echo "robot key must start with pa5_robo_" >&2; exit 1; }
kc portal-a5-robo-login | npx wrangler secret put ROBO_LOGIN_CHAVE -c "$CFG" >/dev/null
kc portal-a5-dono-telefone | npx wrangler secret put OWNER_PHONE -c "$CFG" >/dev/null
echo "deployed: portal-a5 (account and D1 ids kept out of git)"
