# House agents (`pa5_adm_` keys)

A house agent (a script or an AI agent on a machine at home) can look after screens, devices and machine keys without anyone clicking through the account page. It can prepare anything that gives access, but it can never grant it: an admin approves each of those with one Face ID, from wherever they are.

## The key

- Created by an admin with a fresh passkey check, on the account page (Agents). Shown once; the portal keeps only its SHA-256.
- Sent as `Authorization: Bearer pa5_adm_...` to `/_agent/*` only. It opens no `/api/*` route, no tab and no bridge.
- Revoked from the same card. Revoking also cancels whatever that key left waiting.
- Every call is limited (600 an hour per key, 30 refusals an hour per address) and every write is in the audit log with strength `agent`. A key used from a new address warns every admin on the account page.
- `scripts/agent.sh save-key` moves a key from the clipboard into the macOS Keychain and clears the clipboard; the script then reads it from there for every call, never from the command line.

## What the key can do alone

| Route | |
|---|---|
| `GET /_agent/me` | the key's own label |
| `GET /_agent/screens` | screen accounts with their groups and live sessions |
| `GET /_agent/devices` | every live session, admins flagged; place only on screen rows |
| `GET /_agent/machines` | machine (bridge) keys, never the key itself |
| `GET /_agent/groups` | groups and their tabs |
| `GET /_agent/requests` | this key's last 20 requests and their state |
| `GET /_agent/audit?before=` | the audit log, numbers always masked; address and place only on rows by an agent, a screen or a machine |
| `POST /_agent/screens/<id>` `{name}` | rename a screen account |
| `POST /_agent/devices/<id>` `{name}` | rename a session that is not an admin's |
| `POST /_agent/machines/<id>` `{name}` | rename a machine key |
| `DELETE /_agent/devices/<id>` | disconnect a screen session, or a resident's session unused for 30 days |
| `DELETE /_agent/machines/<id>` | revoke a machine key |
| `DELETE /_agent/requests/<id>` | cancel one of its own waiting requests |

It cannot create keys of any kind, add or change people, change a group's tabs, approve sign-in requests, touch an admin's sessions, or approve its own requests.

## What waits for an admin

`POST /_agent/requests` (at most 5 open per key, 20 an hour):

- `{"kind": "pair", "name": "...", "group": "...", "next": "/tab/..."}` (group required) pairs a new screen account; `{"kind": "pair", "screen": <id>, ...}` pairs an existing one again (its old session goes). Valid 15 minutes.
- `{"kind": "screen", "screen": <id>, "group": "...", "unblock": true}` moves a screen to another group and/or unblocks it. Valid 12 hours.

**Home only.** A request is accepted only when the agent calls from home, and approved only while that still holds. Home is the last address of a live machine (bridge) key: the same IPv4 address, or the same IPv6 /64. A stolen agent key used from elsewhere gets `409 not_at_home` (`AGENT_HOME=warn` lets it through, flagged in red on the approval page).

`group` must be a non-admin group; a screen account is never an admin. A blocked screen comes back only through a request that says it unblocks (for a pairing, the portal sets that itself and the approval page shows it).

The answer has `approve_url` (`/conta/?agent_request=<id>`), for the admin, and for a pairing `screen_url` (`/#screen_ticket=<ticket>`, in the fragment so it never reaches a server log), a one-use link for the screen:

1. The agent opens `screen_url` on the screen. The page swaps the ticket for a poll secret (`POST /api/pair/claim`) and removes it from the address bar. The screen must open it from the agent's network or from home; otherwise it is refused (`AGENT_PAIR_OTHER_IP=warn` turns that into a warning on the approval page).
2. The agent sends `approve_url` to the admin (a notification, a message).
3. The admin's page shows who asked, the screen's browser and address, the group and whether it unblocks. The button runs a passkey check with purpose `agent:<id>`; that check is the approval, and it is only offered once the screen has opened its link. Refusing needs no Face ID.
4. The screen's next poll gets its 1-year session and goes to `next`.

Nothing is created before the approval: a new screen account exists only once approved.
