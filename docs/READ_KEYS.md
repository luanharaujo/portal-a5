# Read keys (`pa5_ler_` keys)

A program of the owner (an agent on the Mac, for example) reads one tab's data on its own: `GET` on a path the tab's configuration names, nothing else. It never changes anything, never runs a command and never reaches a portal API.

## The key

- Created on the account page (Shortcuts → Read keys) by a session in the `owner` group with a fresh passkey check, for one tab. Shown once; the portal keeps only its SHA-256.
- Sent as `Authorization: Bearer pa5_ler_...`. Any request carrying one is answered by the read-key handler alone, whatever its path, and the session cookie is ignored.
- Accepted only on `GET /<tab><path>` where `<path>` is in the tab's `readKey.paths`. Anything else with a valid key is `403 read_key_scope`: another method, another path of the tab, `/_cmd`, `/_passkey`, sockets, another tab, `/api/*` (see as included) and the account page. A wrong, revoked or unknown key is `401 bad_key` (30 refusals an hour per address, then `429`).
- The holder must still be active and in the `owner` group at each use; otherwise `401`.
- No end date (owner's call, 10/11). Revoked from the same card, by any session of the owner, without Face ID; it stops at once.

## Limits and warnings

- `readKey.dayAlert` is the day's warning threshold (default 30).
- `readKey.perHour` uses per key (at most 60), then `429 too_many_attempts`.
- Every admin gets a warning on the account page when a key is used:
  - for the first time from a city or network it never used (`read_key_place`);
  - more than `dayAlert` times in one day, 30 by default (`read_key_day`, once a day);
  - from a second IP address in the same day (`read_key_ip`, at each new address that day).
  The day is the calendar day in UTC-3.
- Every use is in the audit log as `read_key_used` (strength `read_key`, key id, path, answer status, uses that day); refusals as `read_key_refused` with the reason. The key itself never is.

## What the tab sees

`handle(request, identity)` with:

```ts
{ credential: 'read_key', read_key: <key id>, person: <owner id>, name, groups,
  session: null, machine: null, shortcut: null, strong: false,
  entered_at: null, entry_until: null, admin_until: null, actions: [], passkey_until: {} }
```

No `Authorization` and no cookie reach the tab. The tab must:

- accept `credential: 'read_key'` only on the paths it configured, and only for `GET` (the portal already refuses the rest; check again);
- give it nothing that needs a passkey entry beyond that data, and no write permission (for example, no "can classify");
- send `X-Tab-Audit` on each answer if it wants its own row (stored with `read_key` in the detail).

## Configuration

In `.tabs.local.json`, per tab:

```json
"readKey": { "paths": ["/_data"], "perHour": 30, "dayAlert": 30 }
```

`dayAlert` (30 to 1000, default 30) is the daily use above which `read_key_day` warns the admins; raise it only for a program that sweeps on a schedule (security review first).

Paths are exact (`/[a-z0-9_-]` segments, at most 5 paths, never `/_cmd` or `/_passkey`). A tab without `readKey` takes no read keys. A deploy that adds a path or raises `perHour` counts as loosening (`PORTAL_A5_CONFIG_REMOVE=1`).
