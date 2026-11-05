#!/usr/bin/env bash
# Portal A5 client for a house agent (docs/AGENT_KEYS.md). The pa5_adm_ key lives in the macOS
# Keychain and never goes on a command line, in the environment or in a log: it reaches curl
# through a config read from stdin.
#
#   agent.sh save-key                         key from the clipboard into the Keychain, clipboard cleared
#   agent.sh get me|screens|devices|machines|groups|requests|audit
#   agent.sh pair "<name>" [group] [next]     new screen account; prints the link to open on the screen
#   agent.sh repair <screen id> [group] [next]  pair an existing screen account again
#   agent.sh move <screen id> <group>         change a screen's group (owner approves)
#   agent.sh unblock <screen id> [group]      unblock a screen (owner approves)
#   agent.sh rename screens|devices|machines <id> "<name>"
#   agent.sh revoke devices|machines <id>
#   agent.sh cancel <request id>
#
# PORTAL_A5_URL = the portal's https origin. PORTAL_A5_KEYCHAIN = Keychain service name
# (default portal-a5-agent-key). PORTAL_A5_KEY_FILE: read the key from a file instead (tests).
set -euo pipefail
SERVICE="${PORTAL_A5_KEYCHAIN:-portal-a5-agent-key}"

die() { echo "agent.sh: $*" >&2; exit 2; }

if [ "${1:-}" = save-key ]; then
  key="$(pbpaste)"
  [[ "$key" =~ ^pa5_adm_[A-Za-z0-9_-]{43}$ ]] || die "the clipboard does not hold a pa5_adm_ key"
  # security -i reads the command from stdin, so the key is never an argument of a process
  printf 'add-generic-password -U -s %s -a %s -w %s\n' "$SERVICE" "$USER" "$key" | security -i >/dev/null
  pbcopy </dev/null
  unset key
  echo "saved in the Keychain as $SERVICE; clipboard cleared"
  exit 0
fi

BASE="${PORTAL_A5_URL:-}"
[[ "$BASE" =~ ^https://[a-z0-9.-]+$|^http://127\.0\.0\.1:[0-9]+$ ]] || die "set PORTAL_A5_URL to the portal origin"

call() { # call METHOD PATH [JSON]
  local key
  if [ -n "${PORTAL_A5_KEY_FILE:-}" ]; then key="$(cat "$PORTAL_A5_KEY_FILE")" # tests only
  else key="$(security find-generic-password -s "$SERVICE" -w 2>/dev/null)" || die "no key in the Keychain ($SERVICE): run save-key"; fi
  {
    printf 'header = "Authorization: Bearer %s"\n' "$key"
    [ -n "${3:-}" ] && printf 'header = "Content-Type: application/json"\n'
    true
  } | if [ -n "${3:-}" ]; then
    curl -sS -K - -X "$1" --data-binary "$3" -w '\n%{http_code}\n' "$BASE$2"
  else
    curl -sS -K - -X "$1" -w '\n%{http_code}\n' "$BASE$2"
  fi | python3 -c '
import json, sys
lines = sys.stdin.read().rstrip("\n").split("\n")
status, text = int(lines[-1]), "\n".join(lines[:-1])
try: print(json.dumps(json.loads(text), ensure_ascii=False, indent=1))
except ValueError: print(text)
sys.exit(0 if status < 400 else 1)'
}

jsonof() { python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps({a[i]: json.loads(a[i+1]) for i in range(0, len(a), 2) if a[i+1] != "null"}))' "$@"; }
str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]) if sys.argv[1] else "null")' "${1:-}"; }

case "${1:-}" in
  get) [[ "${2:-}" =~ ^(me|screens|devices|machines|groups|requests|audit)$ ]] || die "get what?"; call GET "/_agent/$2" ;;
  pair) [ -n "${2:-}" ] || die "pair needs a name"
    call POST /_agent/requests "$(jsonof kind '"pair"' name "$(str "$2")" group "$(str "${3:-}")" next "$(str "${4:-}")")" ;;
  repair) [[ "${2:-}" =~ ^[0-9]+$ ]] || die "repair needs a screen id"
    call POST /_agent/requests "$(jsonof kind '"pair"' screen "$2" group "$(str "${3:-}")" next "$(str "${4:-}")")" ;;
  move) [[ "${2:-}" =~ ^[0-9]+$ && -n "${3:-}" ]] || die "move needs a screen id and a group"
    call POST /_agent/requests "$(jsonof kind '"screen"' screen "$2" group "$(str "$3")")" ;;
  unblock) [[ "${2:-}" =~ ^[0-9]+$ ]] || die "unblock needs a screen id"
    call POST /_agent/requests "$(jsonof kind '"screen"' screen "$2" group "$(str "${3:-}")" unblock true)" ;;
  rename) [[ "${2:-}" =~ ^(screens|devices|machines)$ && "${3:-}" =~ ^[0-9]+$ && -n "${4:-}" ]] || die "rename screens|devices|machines <id> <name>"
    call POST "/_agent/$2/$3" "$(jsonof name "$(str "$4")")" ;;
  revoke) [[ "${2:-}" =~ ^(devices|machines)$ && "${3:-}" =~ ^[0-9]+$ ]] || die "revoke devices|machines <id>"
    call DELETE "/_agent/$2/$3" ;;
  cancel) [[ "${2:-}" =~ ^[0-9]+$ ]] || die "cancel <request id>"; call DELETE "/_agent/requests/$2" ;;
  *) sed -n '5,15p' "$0"; exit 2 ;;
esac
