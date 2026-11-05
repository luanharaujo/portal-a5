#!/usr/bin/env bash
# Deploys portal-a5 with an API token scoped to the portal's own Cloudflare account.
# Never uses `wrangler login`: the OAuth session on this machine may belong to another account.
#
# Keychain items (macOS, generic passwords; service names below):
#   portal-a5-cloudflare          API token (Workers Scripts: Edit + D1: Edit, this account only)
#   portal-a5-robot-key          ROBOT_LOGIN_KEY ("pa5_robo_" + 32 random bytes)
#   portal-a5-owner-phone       OWNER_PHONE (digits, country code first)
# The account id (not a secret, but kept out of git) comes from CLOUDFLARE_ACCOUNT_ID or from
# the git-ignored file .deploy.local (a line CLOUDFLARE_ACCOUNT_ID=<id>).
# Secrets go to wrangler through stdin only: never arguments, never files.
set -euo pipefail
cd "$(dirname "$0")/.."

# Only committed code goes out: refuse a dirty tree, and remember which commit was published.
git diff --quiet && git diff --cached --quiet && [ -z "$(git status --porcelain --untracked-files=normal)" ] \
  || { echo "working tree is not clean; commit first" >&2; exit 1; }
COMMIT="$(git rev-parse HEAD)"

kc() { security find-generic-password -s "$1" -w 2>/dev/null || { echo "missing Keychain item: $1" >&2; exit 1; }; }

export CLOUDFLARE_API_TOKEN="$(kc portal-a5-cloudflare)"
if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ] && [ -f .deploy.local ]; then
  CLOUDFLARE_ACCOUNT_ID="$(sed -n 's/^CLOUDFLARE_ACCOUNT_ID=//p' .deploy.local)"
fi
[[ "${CLOUDFLARE_ACCOUNT_ID:-}" =~ ^[0-9a-f]{32}$ ]] || { echo "set CLOUDFLARE_ACCOUNT_ID (env or .deploy.local)" >&2; exit 1; }
export CLOUDFLARE_ACCOUNT_ID
# keep wrangler away from any OAuth login stored in the user's global config
export XDG_CONFIG_HOME="$(mktemp -d)"
trap 'rm -rf "$XDG_CONFIG_HOME"' EXIT

# 1. the token must be valid and see exactly this one account
api() { curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4/$1"; }
# account-owned token: verified under the account, not under /user
api "accounts/$CLOUDFLARE_ACCOUNT_ID/tokens/verify" | grep -q '"status":"active"' || { echo "token not active for this account" >&2; exit 1; }
accounts="$(api 'accounts?per_page=50' | python3 -c 'import json,sys; print(" ".join(a["id"] for a in json.load(sys.stdin)["result"]))')"
[ "$accounts" = "$CLOUDFLARE_ACCOUNT_ID" ] || { echo "token sees accounts [$accounts], expected only the portal account" >&2; exit 1; }

# 2. D1 database (created on first run); its id never goes into git
db_id() { npx wrangler d1 list --json | python3 -c 'import json,sys; print(next((d["uuid"] for d in json.load(sys.stdin) if d["name"]=="portal_a5"), ""))'; }
DB_ID="$(db_id)"
if [ -z "$DB_ID" ]; then npx wrangler d1 create portal_a5 >/dev/null; DB_ID="$(db_id)"; fi
[ -n "$DB_ID" ] || { echo "could not find or create D1 portal_a5" >&2; exit 1; }

# 3. deploy config = wrangler.toml + real ids + the tabs (all git-ignored). Tabs come from
# .tabs.local.json (see tabs.example.json): one service binding each, and the TABS variable the
# worker validates. No file = no tabs.
CFG=.wrangler.deploy.toml
python3 scripts/make_config.py .tabs.local.json "$DB_ID" "$CLOUDFLARE_ACCOUNT_ID" > "$CFG"

npx tsc --noEmit

# 3b. pages: public/ copied to .deploy/public with a content version on every script and
# stylesheet URL in index.html, so the iOS Home Screen app never runs an old file kept under the
# same URL (scripts/build_assets.py). The list of versioned files is checked after the deploy.
mkdir -p .deploy
python3 scripts/build_assets.py public .deploy/public > .deploy/assets.txt
sed -i '' 's|^directory = "./public"$|directory = "./.deploy/public"|' "$CFG"
grep -q '^directory = "./.deploy/public"$' "$CFG" || { echo "could not point assets to the build" >&2; exit 1; }

# 4. backup of the remote D1 before any migration. It holds personal data (names, numbers):
# outside the repository, folder 700, file 600, never printed. The last 5 are kept; older ones
# go to the macOS Trash. No backup, no deploy.
BACKUPS="$HOME/Library/Application Support/portal-a5/backups"
mkdir -p "$BACKUPS" && chmod 700 "$BACKUPS"
BACKUP="$BACKUPS/portal_a5_$(date -u +%Y%m%dT%H%M%SZ)_${COMMIT:0:7}.sql"
( umask 077; npx wrangler d1 export portal_a5 --remote --output "$BACKUP" -c "$CFG" >/dev/null 2>&1 ) \
  || { echo "D1 backup failed; nothing deployed" >&2; exit 1; }
[ -s "$BACKUP" ] && grep -q 'CREATE TABLE' "$BACKUP" || { echo "D1 backup is empty; nothing deployed" >&2; exit 1; }
chmod 600 "$BACKUP"
echo "D1 backup: $BACKUP"
ls -1t "$BACKUPS"/portal_a5_*.sql | tail -n +6 | while IFS= read -r old; do /usr/bin/trash "$old"; done

npx wrangler d1 migrations apply portal_a5 --remote -c "$CFG"
npx wrangler deploy -c "$CFG" | tee .deploy/last_deploy.txt
URL="$(grep -oE 'https://[a-z0-9.-]+\.workers\.dev' .deploy/last_deploy.txt | head -1)"
VERSION="$(sed -n 's/.*Current Version ID: *//p' .deploy/last_deploy.txt | head -1)"
[ -n "$URL" ] && [ -n "$VERSION" ] || { echo "deploy output without URL or version" >&2; exit 1; }

# 5. secrets through stdin
kc portal-a5-robot-key | grep -q '^pa5_robo_' || { echo "robot key must start with pa5_robo_" >&2; exit 1; }
kc portal-a5-robot-key | npx wrangler secret put ROBOT_LOGIN_KEY -c "$CFG" >/dev/null
kc portal-a5-owner-phone | npx wrangler secret put OWNER_PHONE -c "$CFG" >/dev/null
printf '%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$COMMIT" "$VERSION" >> .deploy/deployed.log

# 6. live only when the public page, fetched without cache, names the new files and each one
# served is byte for byte the new one (the edge may take a few seconds)
live() {
  local html path v got
  html="$(curl -fsS -H 'Cache-Control: no-cache' "$URL/?fresh=$RANDOM")" || return 1
  while read -r path v; do
    grep -qF "$path?v=$v" <<<"$html" || return 1
    got="$(curl -fsS -H 'Cache-Control: no-cache' "$URL$path?v=$v" | shasum -a 256 | cut -c1-12)" || return 1
    [ "$got" = "$v" ] || return 1
  done < .deploy/assets.txt
}
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do live && break; sleep 5; done
live || { echo "DEPLOYED BUT NOT CONFIRMED: the public page still serves other files ($VERSION at $COMMIT)" >&2; exit 1; }
echo "live: portal-a5 at $COMMIT, version $VERSION; page and $(wc -l < .deploy/assets.txt | tr -d ' ') scripts/stylesheets checked without cache"
echo "if a phone still shows the old page: close the Home Screen app (swipe it away) and open it again"
