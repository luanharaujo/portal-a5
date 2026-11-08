# Commands

How a person, a fixed screen or an Apple Shortcuts key asks a tab to do something in the house, and what the tab must do with it. Read `TABS.md` first; this adds stage 3 to it. Portal side: `src/commands.ts` (catalog, parameters, levels) and `src/index.ts` (routes, keys, limits, audit).

## 1. Path of a command

```
page button ──POST /<tab>/_cmd/<action>──┐
                                         ├─ portal: who, level, action, params, limits, brake, audit
Shortcuts ──POST /_cmd/<tab>/<action>────┘        │
                                                  │ command(cmd, identity)   (RPC, waits up to 8 s)
                                                  ▼
                                    tab ── Durable Object ── {"t":"cmd",...} ──▶ machine bridge
                                                  ▲                                   │ checks again,
                                                  └──────── {"t":"result",...} ◀──────┘ runs or refuses
```

The tab never takes a command any other way. `handle()` and page sockets must not run anything in the house; a command that did not come through `command()` was not checked by the portal.

## 2. The catalog (per tab, in the TABS configuration)

Each tab lists its actions under `commands`. The list lives in the deploy configuration, next to the tab's binding, not in this repository.

```json
"commands": {
  "tv_off":   {"level": "common", "perHour": 20, "screens": true},
  "screen":   {"level": "admin",  "params": {"mode": {"enum": ["on", "off"]}}},
  "presence": {"level": "admin",  "params": {"state": {"enum": ["out", "home"]}}, "perHour": 30},
  "ac":       {"level": "common", "params": {"unit": {"enum": ["a", "b"]}, "power": {"bool": true}},
               "perHour": 10, "gap": {"seconds": 180, "by": "unit"}, "returns": ["power"]}
}
```

| Field | Meaning | Default |
|---|---|---|
| `level` | `common`, `admin` or `sensitive` (section 3) | required |
| `params` | up to 4; each is `{"enum": [...]}` (up to 16 values, `^[a-z0-9][a-z0-9_.-]{0,39}$`), `{"int": [min, max]}` or `{"bool": true}`. All are required. There is no string type: free text never reaches the house | none |
| `perHour` | per caller (person or key) per hour, 1 to 120 | 20 |
| `gap` | `{"seconds", "key"?, "by"?}`: minimum time between two runs for everyone; `key` lets actions share one interval, `by` makes it per value of one parameter | none |
| `screens` | fixed screens may send it (`common` only) | false |
| `shortcut` | may go in a Shortcuts key (never `sensitive`) | true |
| `returns` | result fields the caller gets back (strings up to 80, numbers, booleans) | none |
| `passkey` | `"<n>m"` (1 to 60): on top of the level, a passkey check on this very browser session within that time, for anyone who runs it, admins included (section 3). Only on `common` or `admin`; never for screens or keys (`screens: true` or `shortcut: true` next to it drops the action) | none |

Prefer absolute states (`on`/`off`) to a toggle: a command repeated or arriving twice then does no harm. A reading (is the TV on?) is never a command: it goes in the tab's `state`, where the tab decides who sees it.

Action names: `^[a-z][a-z0-9_]{0,39}$`, at most 40 per tab. A malformed action is dropped (it never turns into a looser one). An unknown field drops the action.

## 3. Levels

| Level | Browser | Fixed screen | Shortcuts key |
|---|---|---|---|
| `common` | anyone with the tab (since 08/11 a new non-admin device acts at once; each new resident sign-in is an alert to the admins) | only with `screens: true` | if in the key's scope |
| `admin` | admin group, with a passkey check within `ADMIN_COMMAND_PASSKEY` on this very session (`ADMIN_COMMAND_PASSKEY` in wrangler.toml: `12h`, one Face ID a day; `<n>m`/`<n>h`, or `session`; missing or malformed = 5 minutes). Shortcuts keys need no Face ID: the key is the proof | never | admin's key, if in scope |
| `sensitive` | admin with a passkey check in the last 5 minutes | never | never |

### Actions with their own passkey window (`passkey`)

For something every resident may do but only with Face ID each time (the TV volume limiter):

```json
"tv_limit": {"level": "common", "passkey": "5m", "params": {"on": {"bool": true}, "max": {"int": [10, 60]}},
             "perHour": 30, "screens": false, "shortcut": false, "returns": ["on", "max"]}
```

- Browser sessions only, anyone with the tab. The check must be on this session within the window; the admin window (`ADMIN_COMMAND_PASSKEY`) does not count. Everything else still applies (device hold, brake, limits).
- `identity.actions` lists it for every browser session with the tab, open or not; never for a screen or a key.
- `identity.passkey_until`: `{"<action>": "<ISO>"}` for each such action whose window is open on this session; an action missing from it means "ask Face ID first". `{}` for screens and keys.
- Refused with 403 `passkey_missing` when the person has no passkey at all (no `step_up`: an admin must invite them, account page > People), else 403 `passkey_required` with `step_up`.
- Residents get a passkey only with an invite (README), one invite per passkey.
- "See as": the window counts as open (`passkey_until` shows a full window from now) and the command comes back simulated, like any rehearsal.

On top of the level, the person's groups must still give the tab, at the moment of the command (a key loses an action as soon as its person loses it). Data that only an admin may see (presence) goes in `admin` actions, never `common`.

`identity.actions` (TABS.md section 2) lists the actions this identity may run in the tab, so a page shows only the buttons that can work. For an admin's browser session it includes the `admin` actions even while the Face ID window is closed (`admin_until` null): the page shows them and asks for Face ID before sending, and their admin-only readings (presence) are shown too. Never `sensitive` ones without the check, never for a screen, a key or "see as". It is a hint for the page; the portal checks again on every command. `identity.admin_until` says when this session's window for `admin` actions closes (ISO), or null when it is not open (no recent check, not an admin, a fixed screen, "see as"); a page can ask for Face ID before the tap instead of after a refusal.

### Face ID for an owner's command

A tab page cannot run WebAuthn (its CSP). It sends the person to the portal, full page:

`/?step_up=<tab>&purpose=command&next=<path>` (`next` must start with `/<tab>/`; a `#` in it comes back intact)

The portal page asks for Face ID with the purpose `command:<tab>` (browser sessions, not while seeing as: 403 `admin_only`). The tab must exist, be open to the person and have an action with `passkey` (anyone) or an `admin` or `sensitive` one (admins only); a non-admin on a tab without `passkey` actions gets 403 `admin_only`, anything else 400 `bad_purpose`. A person without a passkey gets 409 `no_passkey` and the page says to ask for an invite. The check sets the session's passkey time, which opens the `admin` window (and, for 5 minutes, `sensitive`), audits `command_passkey_ok` with the tab as target and goes back to `next`. "Not now" goes back too. Nothing is resent on the way back: the person taps the command again. A page command refused with `passkey_required` carries that address as `step_up` (`next` = `/<tab>/`) for an admin's browser session, and for anyone's when the action has `passkey`.

### Face ID asked by the tab page itself (preferred)

The page asks Face ID on the tap, with only the system sheet: no portal page, no navigation. Two routes under the tab's own path (the tab CSP already allows them; the portal answers them, the tab Worker never sees them). Both are `POST` with `Origin` = the portal and `X-Portal: 1`, and pass the same gate as any tab request (session, groups, `credentials`, Face ID on entry if the tab has it).

- `POST /<tab>/_passkey/options`, body `{}`: `{challenge, rpId, allowCredentials, userVerification: "required", timeout}` (base64url ids, 5 minutes). Same rules as the step-up above: 403 `admin_only`, 400 `bad_purpose`, 409 `no_passkey`. The tab comes from the path, so a page only ever gets a challenge for its own tab. Asking again replaces the tab's previous one.
- `POST /<tab>/_passkey/verify`, body `{id, clientDataJSON, authenticatorData, signature}` (base64url): `{ok: true, passkey_until, admin_until}` (the fields of the identity, so the page updates without reloading). It only takes this tab's own challenge (anything else: 400 `challenge_expired`); 400 `unknown_passkey` or a WebAuthn error code (audited `passkey_failed`). Audits `command_passkey_ok`, detail `{via: "tab"}`.

This check opens only the session's command windows (`admin` actions and actions with `passkey`), and only for commands of that same tab. It never makes the session strong: `identity.strong`, `sensitive` actions, other tabs and the account pages still need the portal's own Face ID. Audited with strength `tab_passkey`. Its challenge (`tabcmd:<tab>`, one per tab) lives beside the portal's own: prefetching never drops a Face ID waiting on a portal page, and the portal never accepts a tab's challenge.

Safari on iOS wants `navigator.credentials.get` straight from the tap (a fetch or await in between may lose the gesture). Fetch the options before the tap (when the control shows, again every 4 minutes and when the page becomes visible), call `get` synchronously in the tap handler, then verify, then send the command. Options serve once: fetch new ones after any `get`. On `NotAllowedError` (cancelled) show nothing; just fetch new options. Fall back to `step_up` only when the options fail in an unexpected way.

## 4. Routes

### From a tab page

```
POST /<tab>/_cmd/<action>
Origin: <portal>      X-Portal: 1      Content-Type: application/json
{"params": {...}}
```

Inside the tab's own path, so the tab's CSP lets the page call it. Same session, origin and entry rules as any request into the tab (TABS.md section 3), then the checks below. Any other method answers 405. The portal answers it itself; the tab's `handle()` never sees `/_cmd/`.

### From Shortcuts

```
POST /_cmd/<tab>/<action>
Authorization: Bearer pa5_atl_<43 chars>
Content-Type: application/json
{"params": {...}}
```

No cookie, no session. Browsers cannot send this from another site: `Authorization` needs a CORS preflight, and the portal answers no CORS. The key never opens a page, a socket, `/api/*` or anything that reads.

### Answer (both)

```json
{"id": "<uuid>", "status": "done", "ok": true, "result": {"power": true}}
```

| HTTP | status | Meaning |
|---|---|---|
| 200 | `done` | the bridge ran it |
| 202 | `queued` / `sent` | handed over; the bridge did not answer within the wait (it may still run until `expires_at`, never after) |
| 409 | `refused` | the tab or the bridge refused it (`error` says why) |
| 502 | `failed` | the bridge tried and failed |
| 503 | `offline` | no bridge connected |

Refusals before the tab: 404 `unknown_action` (or `not_found` for a tab that does not exist); 400 `bad_params`, `unknown_param`, `missing_param`, `bad_param`; 401 `bad_key`; 403 `no_tab_access`, `admin_only`, `passkey_required`, `passkey_missing`, `not_for_screens`, `not_for_shortcuts`, `out_of_scope`; 429 `too_many_commands`, `too_soon` (with `retry_after` in seconds), `too_many_attempts`; 503 `commands_off`.

## 5. Shortcuts keys

- Created on the account page by an admin, with a passkey check in the last 5 minutes. One key per device and shortcut (or small set of actions): `label` says which ("iPhone · TV off"). Scope: up to 12 `<tab>/<action>` entries, each existing, allowed in keys and not above the creator's level.
- `pa5_atl_` + 32 random bytes (base64url), shown once. Only the SHA-256 is stored.
- Each use records time, IP and place (city/ASN) on the key; the list shows them. A key used from a city or network it was never used from warns every admin on the account page (`shortcut_new_place`); the first use counts as new.
- 30 commands an hour per key, on top of each action's `perHour`. Failed key checks are capped per IP (30/h) and audited as `shortcut_refused`.
- Revoked with one tap from any session of its owner, weak or strong (taking access away never needs Face ID).
- A key never reads anything: the answer carries only the action's `returns`.
- A shortcut holding a key is never shared; the signed file stays out of synced folders beyond what is needed.

## 6. The brake

`commands_off` on the account page (admins): with it on, every command is refused (503 `commands_off`) and audited. Turning it on needs any admin session; turning commands back on needs a passkey check. It sits in front of the tab, so it also stops a page or key that still works. Bridges keep their own local brake, which wins even if the portal says otherwise.

## 7. Limits

| Where | What |
|---|---|
| portal, per key | 30/h |
| portal, per caller and action | `perHour` |
| portal, per action (and parameter value) | `gap.seconds` between runs, for everyone |
| portal, per tab | 300/h in total |
| tab and bridge | their own, at least as tight (for example, TV 20/h; each air conditioner 3 min apart and 10/h) |

The bridge must hold its limits even when the portal and the tab are compromised. The portal's `gap` is checked before the command is stored, so two calls at the same instant can both pass it; the bridge's own interval is the real guarantee.

## 8. What the tab implements

```ts
interface Command {
  id: string          // UUID made by the portal, unique
  action: string      // in the catalog
  params: Record<string, string | number | boolean>   // exactly the declared ones, already checked
  expires_at: string  // ISO, created + 60 s
}
interface CommandAnswer {
  status: 'done' | 'failed' | 'queued' | 'offline' | 'refused'
  result?: Record<string, unknown>   // only `returns` fields reach the caller
  error?: string                     // ^[a-z][a-z0-9_]{0,39}$
}
async command(cmd: Command, identity: PortalIdentity): Promise<CommandAnswer>
```

- Check `identity.actions.includes(cmd.action)` and the parameters again against the tab's own list; refuse anything else with `refused`.
- Send `{"t":"cmd","id","action","params","expires_at"}` to the bridge (TABS.md section 6). Wait at most 6 s for `{"t":"result","id","ok"}`; then answer `queued`. No bridge connected: `offline` (or `queued` if the tab keeps it until `expires_at` and re-sends on `hello`).
- Never re-send after `expires_at`. Keep the ids you have seen for 24 h and refuse a repeated one.
- The bridge: closed dictionary action → function with its parameter schema; no shell, URL or free text; refuses repeated or expired ids; obeys its local brake; keeps its own limits.
- Audit: the portal stores every command (`command` with tab, action, parameters, caller, credential, key, status). The tab keeps its own log of what the bridge did.

`identity.credential` is `browser`, `screen` or `shortcut` here (never `machine`). For a key, `identity.shortcut` is the key id and `identity.session` is null.

## 9. Audit

One line per command: action `command`, target `<tab>/<action>`, detail `{id, params, credential, shortcut?, status, error?}`. Refusals before the tab are audited as `command_refused` with the reason. Key events: `shortcut_key_created`, `shortcut_key_revoked`, `shortcut_refused`, `shortcut_new_place`. Brake: `commands_off`, `commands_on`. Device release: `device_commands_allowed`. The audit list is admin only.

## Rehearsal ("see as")

While an admin sees the portal as a non-admin group, a page command goes through the same checks a resident meets (catalog, params, group, level, the brake) and then stops: the tab's `command()` is never called, nothing is written to `commands`, and the answer is `200 {"id": "<uuid>", "status": "done", "ok": true, "simulated": true}`. It has its own hourly limit (120), so it never spends the real ones. Audit: `command` with `simulated: true` and `view_as`.
