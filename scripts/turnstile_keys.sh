#!/usr/bin/env bash
# Stores the keys of the Turnstile widget used by sign-in and screen pairing:
#   the secret key in the macOS Keychain (portal-a5-turnstile-secret),
#   the site key in the git-ignored .deploy.local (TURNSTILE_SITEKEY=...).
# Create the widget first: Cloudflare dashboard > Turnstile > Add widget, hostname of the
# portal, mode "Managed". Usage: bash scripts/turnstile_keys.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(git rev-parse --git-dir)" = "$(git rev-parse --git-common-dir)" ] \
  || { echo "run from the main checkout, where deploys happen" >&2; exit 1; }

read -r -p "Site key (public): " sitekey
read -r -s -p "Secret key (hidden): " secret; echo
shape='^0x[A-Za-z0-9_-]{16,100}$'
[[ "$sitekey" =~ $shape ]] || { echo "that does not look like a site key (it starts with 0x)" >&2; exit 1; }
[[ "$secret" =~ $shape ]] || { echo "that does not look like a secret key (it starts with 0x)" >&2; exit 1; }
[ "$sitekey" != "$secret" ] || { echo "the two keys are equal" >&2; exit 1; }

# asked with a made-up token: a good secret complains about the token only
answer="$(printf '%s' "$secret" | curl -sS --max-time 20 --data-urlencode secret@- --data-urlencode response=setup-check https://challenges.cloudflare.com/turnstile/v0/siteverify)"
grep -q 'invalid-input-response' <<<"$answer" && ! grep -q 'invalid-input-secret' <<<"$answer" \
  || { echo "Turnstile does not accept that secret; nothing saved" >&2; exit 1; }

# through stdin, so the secret never shows up in the process list
printf 'add-generic-password -U -a "%s" -s portal-a5-turnstile-secret -w "%s"\n' "$USER" "$secret" | security -i >/dev/null
[ "$(security find-generic-password -s portal-a5-turnstile-secret -w)" = "$secret" ] || { echo "could not save to the Keychain" >&2; exit 1; }

touch .deploy.local
kept="$(grep -v '^TURNSTILE_SITEKEY=' .deploy.local || true)"
printf '%s\nTURNSTILE_SITEKEY=%s\n' "$kept" "$sitekey" | sed '/^$/d' > .deploy.local
echo "saved: secret key in the Keychain, site key in .deploy.local"
