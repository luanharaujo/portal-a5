# Tab contract

How a tab plugs into the portal. Written for whoever builds a tab. The portal side lives in `src/tabs.ts` (policy and header rules) and `src/index.ts` (router, screens, bridges).

## 1. Shape of a tab

A tab is a private Worker:

```toml
workers_dev = false
preview_urls = false
# no routes
```

It exports a `WorkerEntrypoint` class, and its default `fetch` answers 404 to everything. The portal binds that class with one service binding:

```toml
# portal wrangler.toml
[[services]]
binding = "TAB_NOTES"
service = "portal-a5-notes"
entrypoint = "NotesTab"
```

plus `TABS = '{"notes":"TAB_NOTES"}'`. The order of `TABS` is the order of the tab selector (section 9). A tab can't be named `api`, `robo`, `conta`, `locale` or `vendor` (the portal ignores such a binding). Through that single binding the portal calls these:

| Call | When | Identity |
|---|---|---|
| `handle(request, identity)` (RPC) | every plain request and answer under `/<tab>/*`, including streamed bodies | typed argument |
| `fetch(request)` | only WebSocket upgrades: live pages and machine bridges | `X-A5-Identity` request header, set by the portal: base64url of the UTF-8 JSON (names may hold emoji, which a raw header cannot carry) |
| `revoke(ref)` (RPC, optional but expected) | a session, screen or machine key was revoked, or a person blocked | `ref = {session?, machine?, person?}`; close every socket opened with that credential |
| `badge(identity)` (RPC, optional) | `GET /api/tabs`, for a person with more than one tab | typed argument; answers `{count}` (section 9) |

`fetch` exists only because a 101 answer cannot cross an RPC call. The entrypoint's `fetch` is reachable only through a service binding; the public address stays off. The tab's `fetch` answers 401 when `X-A5-Identity` is missing or does not decode to JSON, 404 to anything that is not an upgrade, and never passes the header on.

Decoding: `JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(h.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))))`.

## 2. Identity

```ts
interface PortalIdentity {
  credential: 'browser' | 'screen' | 'machine' | 'shortcut'
  person: number | null      // null for machines
  name: string               // person or screen name, or the machine key label
  groups: string[]           // empty for machines
  session: number | null     // browser or screen session id; null for machines
  machine: number | null     // machine key id; only for machines
  strong: boolean            // passkey checked on this session in the last 5 minutes
  entered_at: string | null  // tabs with entry 'passkey': when this session entered with Face ID
  entry_until: string | null // ...and when that entry ends
  actions: string[]          // stage 3 (commands); empty for now
}
```

- `browser`: a person signed in through WhatsApp (weak) or with a fresh passkey (strong).
- `screen`: a fixed display paired by code (section 5). Always in `residents`, never admin, never strong.
- `machine`: a house bridge (section 6). No person, no groups.
- `shortcut`: reserved for Shortcuts keys (`pa5_atl_`), not built yet.

The tab trusts this object and nothing in the request that claims to be identity. A tab may still apply its own rules on top (for example, only the owner group).

## 3. What the portal does on every tab request

Before the call:
- session cookie checked; signed out: navigation gets 302 to `/?next=/<tab>/...`, anything else 401 `signed_out`;
- group must include the tab (`*` = all), and the tab policy must accept the credential (section 4), else 403 `no_tab_access`;
- non-GET needs `Origin` equal to the portal origin and `X-Portal: 1` (403 otherwise). GET must never change state;
- WebSocket upgrades from pages also need that exact `Origin` (cross-site socket hijacking);
- a tab whose policy says `serviceWorker: false` gets 403 on a request with `Service-Worker: script`;
- removed from the request: `Cookie`, `Authorization`, every `X-Portal-*` and `X-A5-*` (the portal then sets its own `X-A5-Identity` on upgrades).

After the call:
- removed from the answer: `Set-Cookie`, `Clear-Site-Data`, `Service-Worker-Allowed`, `Refresh`, `X-Tab-Audit`, every `Access-Control-*`;
- set on the answer, overwriting whatever the tab sent: a CSP bound to the tab's path, `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, HSTS and the tab's `Permissions-Policy`. The CSP:

  ```
  default-src 'self';
  script-src https://<portal>/<tab>/ https://<portal>/_shell/tabs.js https://<portal>/locale/pt-BR.js;
  style-src 'self'; img-src 'self' data:;
  connect-src https://<portal>/<tab>/ wss://<portal>/<tab>/ https://<portal>/api/tabs;
  object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action https://<portal>/<tab>/
  ```

  A tab page cannot run inline script, and cannot load scripts from, fetch from or post to anything outside its own path (no other `/api/*`, no other tab). The only exceptions are the shared selector's two files and the read-only `GET /api/tabs` (section 9); a source without a trailing slash matches that exact path only. Navigating to the portal (a link, `location.href = step_up`) is fine;
- a 101 goes back with no tab headers at all.

So a tab page: scripts and styles in files under its own path, `textContent` for every value, no inline handlers, no cookies, no CORS.

## 4. Policy per tab (decided by the portal)

One line per tab in `TAB_POLICY` (`src/tabs.ts`):

| Field | Meaning | Default |
|---|---|---|
| `allow` | browser features the tab's pages may use (`microphone`, `screen-wake-lock`, ...) | none |
| `entry` | `session`: a session with access is enough; `passkey`: Face ID on every entry | `session` |
| `entryHours` | with `passkey`: how long requests inside the tab are accepted after an entry | 0 |
| `credentials` | which of `browser`, `screen`, `machine` may reach the tab | browser, machine |
| `serviceWorker` | `false` refuses service worker registration | true |

`Permissions-Policy` lists camera, microphone, geolocation, screen-wake-lock, display-capture, usb, serial, bluetooth, hid and payment as `()` everywhere except what the tab is allowed, which gets `(self)`. Several of these default to `self` when left out, so they are always written down. A tab that needs a new feature asks the portal; it cannot add it itself.

### Face ID on entry

For a tab with `entry: 'passkey'`:

1. A navigation into the tab (`Sec-Fetch-Mode: navigate`) without a fresh grant gets 302 to `/?step_up=<tab>&next=<path>`.
2. The portal page shows "confirm with Face ID", runs a passkey check with `purpose: "entry:<tab>"` and navigates back to `next`.
3. The check leaves a single-use grant valid for 60 s. The next navigation burns it, the tab is served, and `identity.entered_at` is set.
4. Any other request inside the tab (API, assets, streams, sockets) is accepted while the last entry is younger than `entryHours`; otherwise 401 `{"error":"entry_required","step_up":"/?step_up=<tab>&next=/<tab>/"}`. The page sends the person to `step_up`.
5. Reloading the page is a new entry and asks Face ID again. A passkey check done for anything else (an admin action) never counts as an entry.

The tab does not need its own "entered" bookkeeping; `entered_at`/`entry_until` are the answer. If it keeps one as a second barrier, it must be keyed so that a new session never inherits it (the portal never reuses a session id, but do not rely on that alone). A page socket opened inside the entry must be closed at `entry_until`. The portal refuses service worker registration for such a tab (a cached page would skip the entry check).

## 5. Fixed screens

A TV or monitor gets its own account, kind `screen`, in `residents`:

1. The screen opens `/?screen=1&next=/<tab>/` (or taps the pairing link on the sign-in page). It gets a 6-character code (`ABC-DEF`, 5 minutes, single use) and a QR for `/?pair=ABCDEF`.
2. The owner, on the phone, on the admin page, in the screens card, types the code or scans the QR, sees which browser, place and IP is asking, and picks an existing screen account or names a new one. Approving is an admin write: passkey in the last 5 minutes. A request from another IP than the approving phone is refused (`PAIR_OTHER_IP = "refuse"`: a screen is paired on the same network as the phone), with a clear message and an audit line `screen_pair_refused`. `"warn"` only shows a red warning.
3. The screen's poll gets a session cookie for 365 days, renewed on use, if it picks up the approval before the code's expiry + 5 minutes. Only the hash is stored. A screen account holds one session; pairing it again ends the old one (and calls `revoke`).
4. The session shows up in the list of all devices and is revoked there. Each pairing is audited (`screen_paired`, `screen_signed_in`).

Tabs see `credential: 'screen'` and decide which commands, if any, a screen may send.

## 6. House bridges

One mechanism for every machine: an outgoing WebSocket to the portal, authenticated by the portal, handed to the tab's `fetch`, then held by the tab's Durable Object with the Hibernation API.

```
GET wss://<portal>/_bridge/<tab>
Upgrade: websocket
X-A5-Machine-Key: pa5_maq_<43 chars>
```

- Keys are created by the owner on the admin page, in the house bridges card (passkey required), one per machine and tab, shown once, stored as SHA-256. Put it in the machine's Keychain.
- The portal checks the key against the tab in the path. A key for another tab, revoked, malformed, or missing: 401 and an audit line `bridge_refused`. A cookie alone never opens a bridge. Failures per IP are capped (30/h).
- On success: audit `bridge_connected`; more than 3 connections of the same key in an hour, or a key connecting from an IP other than its last one (`bridge_new_ip`), shows a warning to every admin; more than 120 in an hour is refused.
- The tab receives the upgrade with `identity.credential === 'machine'` and `identity.machine` set. It must accept bridge sockets only with that credential, and keep one bridge per machine (a new one closes the old with code 4000).
- Revoking a key calls `revoke({machine})`, and the tab closes that socket.

A tab may keep its own key check in a header of its own (for example `X-Notes-Bridge-Key`) as a second barrier; the portal passes headers that are not `X-A5-*`/`X-Portal-*`/`Cookie`/`Authorization`.

### Why not SSE for bridges and screens

Server-Sent Events keep a Durable Object awake for as long as the stream is open. The free plan gives 13,000 GB-s of Durable Object time a day, and one object awake for 24 hours uses about 10,800. A bridge and a TV are connected all day. A hibernated WebSocket costs nothing while idle, and the automatic ping/pong does not wake the object. SSE through `handle` still works (streamed bodies pass), but only for pages that are open for a short while.

### Message envelope (bridge ↔ Durable Object)

JSON text frames. Every tab uses these names; payload fields are the tab's.

```
machine → cloud
  {"t":"hello","v":1}                                  right after connecting; cloud answers {"t":"hello","v":1} and re-sends live commands
  {"t":"state", ...}                                   the machine's current data (each tab caps how often)
  {"t":"result","id":"<uuid>","ok":true|false, ...}    final answer to one command
  "ping"                                               answered "pong" by the runtime without waking the object
cloud → machine
  {"t":"cmd","id":"<uuid>","action":"<name>","params":{...},"expires_at":"<ISO>"}
  {"t":"state_ack", ...}                               informative, after each state: counts only, never commands
```

The machine sends `hello` as its first message, and so does a page socket. In local `workerd`, a socket that never sent a message did not get a close started by the server when it passed portal → tab → Durable Object, so a `revoke` test with a silent socket looks broken locally. Check revocation against production when a tab goes live.

Rules for commands:
- `id` unique (UUID), `expires_at` = creation + 60 s. The cloud never re-sends an expired command; on `hello` it re-sends only live ones.
- The bridge refuses an `id` it has seen (keeps them 24 h) and anything past `expires_at`. It never runs a command later than that.
- The bridge has no generic function: a closed dictionary action → function with a parameter schema, nothing that runs a shell, a URL or free text.
- Rate limits on both sides, per action and per device, and a local brake the bridge obeys even if the cloud says otherwise.

## 6b. Sockets and revocation (all tabs)

Every socket the tab accepts (page or bridge) stores `credential`, `session`, `person`, `machine` and `entry_until` from the identity in its attachment (`serializeAttachment`). The tab closes it:
- on `revoke(ref)` when any of `ref.session`, `ref.machine`, `ref.person` matches. The portal calls `revoke({person})` also when that person's groups change or their group loses the tab: close the person's page sockets; the next request goes through the portal again, which decides;
- at `entry_until`, for tabs with entry `passkey` (an alarm, or a check on every message);
- one bridge per machine: a new one closes the old with code 4000.

## 7. Audit from a tab

The tab reports what a person did by adding one header to its answer (plain or 101):

```
X-Tab-Audit: {"action":"note_saved","target":"note:42","detail":{"size":120}}
```

- `action`: `^[a-z][a-z0-9_]{0,39}$`; `target`: string up to 120; `detail`: object; no other keys; header up to 4 KB.
- The portal stores it as `<tab>.<action>` with the person, session, strength, IP and place it already knows, plus `credential` (and `machine`) in the detail, then removes the header.
- A malformed header is stored as `<tab>.invalid_audit` with no content.

The tab never says who did it: the portal fills that in. Events with no request behind them (a bridge result arriving later) stay in the tab's own log.

## 8. Checklist for a new tab

- `workers_dev = false`, `preview_urls = false`, no route, default `fetch` = 404, checked once against production (the tab's `*.workers.dev` must not answer).
- `WorkerEntrypoint` with `handle`, `fetch` (upgrades only) and `revoke`.
- Pages: files only, no inline script or style, `textContent`.
- Sockets: Hibernation API; one bridge per machine; check `identity.credential`.
- Commands: section 6 rules, and a security review of the tab and its bridge before they are switched on.
- Ask the portal for its policy line (features, entry, credentials) and binding.
- Title marked with `data-a5-tabs` and the selector's files loaded (section 9); `badge` if something waits for people there.

## 9. Tab selector and pending counts

There is no home page. `/` opens the last tab used on that device (`localStorage` key `a5.lastTab`), else the first tab the person can open, else the account page. Every tab's title is the way to the other tabs.

### In the tab page

```html
<link rel="stylesheet" href="/_shell/tabs.css">
<script src="/locale/pt-BR.js" defer></script>
<script src="/_shell/tabs.js" defer></script>
...
<h1><button type="button" data-a5-tabs>Painel de Energia da Casa</button></h1>
```

- The script asks `GET /api/tabs?current=<tab>`, adds an SVG arrow and the dot to the marked title and turns it into a menu button. With no selector (fixed screens, signed out, any error) the title stays a plain title, and `tabs.css` keeps a marked `<button>` looking like the title around it.
- The list opens on tap, click, Enter, Space or arrow down; closes on Esc, a tap outside or the title again. Arrow keys, Home and End move, Enter or Space picks (TV remotes and keyboards: nothing needs hover). Focus stays in the list while it is open. Picking is a full page navigation (`location.assign`), never an iframe, and records `a5.lastTab`. The tab page also records itself on load.
- Counts come back when the page loads, when the list opens and when the page becomes visible again (`visibilitychange`). No polling.
- `locale/pt-BR.js` sets `window.T` and `window.A5_TEXT`; the selector reads `A5_TEXT` only, so a tab may keep its own `T` (load the locale before the tab's scripts).
- Colors: dark by default (`--a5t-*` tokens in `tabs.css`); a tab may override the tokens. The portal's own pages map them to the device theme.

### `GET /api/tabs`

Session required (401 otherwise), GET only, `Cache-Control: no-store`.

```json
{
  "selector": true,
  "current": "energia",
  "tabs": [
    {"id": "energia", "path": "/energia/", "badge": null, "entry": "session"},
    {"id": "jarvis", "path": "/jarvis/", "badge": 2, "entry": "passkey"}
  ],
  "account": {"id": "conta", "path": "/conta/"}
}
```

- `tabs`: the tabs this session can open (group and the tab's `credentials` policy, the same rule as `/<tab>/*`), in `TABS` order. Tab names come from the locale by `id`.
- `selector` is `false` for a fixed screen (`credential: 'screen'`): plain title, no counts.
- `current` is the `current` query echoed back only when it is `conta` or a listed tab.
- `entry: "passkey"` shows "Face ID" next to the tab in the list.

### `badge(identity)` (optional)

```ts
async badge(identity: PortalIdentity): Promise<{ count: number }>
```

- How many things wait for this person in the tab (for example, decisions waiting for an answer). The tab decides what counts. Only the number leaves the tab, never the content.
- Called only for a browser session with more than one tab, for each of its tabs. Never for a fixed screen or a person with a single tab.
- The identity is the person's, with `entered_at` and `entry_until` null: a passkey tab's count shows without Face ID, its content stays behind the entry.
- The portal waits 300 ms at most, then shows no number. Anything but a non-negative integer is no number; above 99 is shown as 99 (the dot itself shows `9+` above 9). The answer is kept per person and tab for 60 seconds in the portal's isolate.
- The dot next to the title is the sum of the other tabs' counts; inside the list each tab shows its own.

### The account tab

`/conta/` is a portal page (portal CSP, device theme): my devices, people and groups, screens, bridges, audit, sign out. It is always the last entry of the list, after a line, and its title carries the same selector.

