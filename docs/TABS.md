# Tab contract

How a tab plugs into the portal. Written for whoever builds a tab. The portal side lives in `src/tabs.ts` (policy and header rules) and `src/index.ts` (router, screens, bridges).

## 0. House rules (every page, no exceptions)

These hold for every page served under the portal, a first mockup included. A page that breaks one does not go live. The portal's maintainer checks each new tab and each visible change before it goes live; new rules are added here.

- **H1. Never a dead end.** Every screen and state of a page (inner screens, sheets, empty, error, loading) has pull to refresh and one visible tap back to the tab list. The standard way is section 9: the title marked `data-a5-tabs` plus `/_shell/tabs.css` and `/_shell/tabs.js`, which bring both. Never hide or replace the title on an inner screen.
- **H2. Face ID straight away.** When something needs Face ID, the Apple prompt is the first thing the person sees: no "use Face ID" button, no confirm screen, no detour through another page first. Inside a tab, fetch the options before the tap and call `navigator.credentials.get` in the tap that asked for the action (COMMANDS.md). On a page whose only job is the check, call it on load (Safari allows one call without a gesture per navigation) and keep a button only as the fallback after a cancel.
- **H3. Fast.** As fast as the energy and controls tabs: first paint from one round trip, files under `?v=` with long cache, scripts `defer`, nothing external, no chained requests before drawing.
- **H4. Fewest taps.** The common path takes the fewest taps possible; no confirmation for what can be undone; sensible defaults filled in.

## 1. Shape of a tab

A tab is a private Worker:

```toml
workers_dev = false
preview_urls = false
# no routes
```

It exports a `WorkerEntrypoint` class, and its default `fetch` answers 404 to everything. The portal binds that class with one service binding:

```toml
# generated at deploy time
[[services]]
binding = "TAB_NOTES"
service = "portal-a5-notes"
entrypoint = "NotesTab"
```

Which tabs exist, and each one's policy, label and icon, live outside the code: in `.tabs.local.json` on the deploying machine (git-ignored; format in `tabs.example.json`). `scripts/deploy.sh` turns it into the bindings above plus the `TABS` variable of the portal Worker, which the portal validates on start (`parseTabs` in `src/tabs.ts`). Nobody can change it from the web. The order of the file is the order of the tab selector (section 9). A tab can't be named `api`, `robo`, `conta`, `locale` or `vendor`. Through that single binding the portal calls these:

| Call | When | Identity |
|---|---|---|
| `handle(request, identity)` (RPC) | every plain request and answer under `/<tab>/*`, including streamed bodies | typed argument |
| `fetch(request)` | only WebSocket upgrades: live pages and machine bridges | `X-A5-Identity` request header, set by the portal: base64url of the UTF-8 JSON (names may hold emoji, which a raw header cannot carry) |
| `revoke(ref)` (RPC, optional but expected) | a session, screen or machine key was revoked, or a person blocked | `ref = {session?, machine?, person?}`; close every socket opened with that credential |
| `badge(identity)` (RPC, optional) | `GET /api/tabs`, for a person with more than one tab | typed argument; answers `{count}` (section 9) |
| `command(cmd, identity)` (RPC, optional) | a page button or a Shortcuts key sent a command the portal checked | typed argument; see `COMMANDS.md` |

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
  shortcut: number | null    // Shortcuts key id; only for shortcuts
  actions: string[]          // commands this identity may send in the tab (COMMANDS.md)
  admin_until: string | null // when this session's window for admin commands closes, or null (COMMANDS.md)
  passkey_until: Record<string, string> // actions with their own `passkey` window that are open on this
                             // browser session: action -> when it closes (ISO); {} otherwise (COMMANDS.md)
}
```

- `browser`: a person signed in through WhatsApp (weak) or with a fresh passkey (strong).
- `screen`: a fixed display paired by code (section 5). Always in `residents`, never admin, never strong.
- `machine`: a house bridge (section 6). No person, no groups.
- `shortcut`: an Apple Shortcuts key (`pa5_atl_`). Reaches only `command()`, never `handle()`, `fetch()` or `badge()` (COMMANDS.md).

The tab trusts this object and nothing in the request that claims to be identity. A tab may still apply its own rules on top (for example, only the owner group).

## 3. What the portal does on every tab request

Before the call:
- session cookie checked; signed out: navigation gets 302 to `/?next=<path and query>` (query dropped above 512 characters), anything else 401 `signed_out`;
- group must include the tab (`*` = all), and the tab policy must accept the credential (section 4), else 403 `no_tab_access`;
- non-GET needs `Origin` equal to the portal origin and `X-Portal: 1` (403 otherwise). GET must never change state;
- `/<tab>/_cmd/*` is the portal's: commands from the tab's pages, answered by the portal and handed to `command()` only after its checks. It never reaches `handle()`;
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

One entry per tab in the tab configuration (section 1):

```json
{
  "notes": {
    "service": "portal-a5-notes", "entrypoint": "NotesTab",
    "label": "Notes", "icon": "grid",
    "allow": ["screen-wake-lock"], "entry": "session", "credentials": ["browser", "screen", "machine"]
  }
}
```

| Field | Meaning | Required |
|---|---|---|
| `service`, `entrypoint` | the tab Worker and its `WorkerEntrypoint` class (used by the deploy only) | yes |
| `allow` | browser features the tab's pages may use (`microphone`, `screen-wake-lock`, ...); `[]` for none | yes |
| `entry` | `session`: a session with access is enough; `passkey`: Face ID on every entry | yes |
| `entryHours` | with `passkey`: how long requests inside the tab are accepted after an entry, more than 0 and at most 24 | with `passkey` |
| `credentials` | which of `browser`, `screen`, `machine` may reach the tab, at least one | yes |
| `serviceWorker` | `false` refuses service worker registration; always `false` with `passkey` | no (true) |
| `label` | the tab's name in the selector (up to 40 characters) | no (the tab id) |
| `hint` | the second line under the name in the selector (up to 40 characters) | no (none; "Face ID" for a passkey tab) |
| `icon` | one of the selector's drawings: `bolt`, `power`, `mic`, `terminal`, `coin`, `grid`; it also picks the tile's color | no (a gray tile) |
| `commands` | the actions the tab takes, with level, parameters and limits (`COMMANDS.md` section 2); one malformed action drops the tab | no (none) |

Fail closed: there is no default policy. A tab whose entry misses `allow`, `entry` or `credentials`, has an unknown key or a value out of range is not bound at all (its path answers 404) and the portal logs `tab config refused`. After a deploy, check `GET /api/tabs` (a passkey tab must say `"entry": "passkey"`).

`Permissions-Policy` lists camera, microphone, geolocation, screen-wake-lock, display-capture, usb, serial, bluetooth, hid and payment as `()` everywhere except what the tab is allowed, which gets `(self)`. Several of these default to `self` when left out, so they are always written down. A tab that needs a new feature asks the portal; it cannot add it itself.

### Face ID on entry

For a tab with `entry: 'passkey'`:

1. A navigation into the tab (`Sec-Fetch-Mode: navigate`) without a fresh grant, and outside the entry window of this session (step 5), gets the portal's Face ID page **in place**: 200 at the same address (`no-store`, the portal's own CSP), built from `public/entry.html`. It holds nothing of the tab (the tab's `handle` is not called): the house drawing, the title marked `data-a5-tabs` (so the tab list and pull to refresh work, house rule H1), and a fresh challenge for `entry:<tab>` in `<script type="application/json" id="a5-entry">`.
2. `/_shell/entry.js` opens the Face ID prompt on load, with no tap (Safari allows one call without a gesture per navigation), verifies with `POST /api/passkey/get/verify` and reloads the same address. After a cancel it fetches new options (`POST /api/passkey/get/options`, `purpose: "entry:<tab>"`) and shows one button that calls the prompt straight from the tap. A session that is not a browser session with a passkey, or is seeing as another group, still gets 302 to the portal's step-up page `/?step_up=<tab>&next=<path and query>`, which also opens the prompt on load. That page stays for older links.
3. The check leaves a single-use grant valid for 60 s. The next navigation burns it, the tab is served, and `identity.entered_at` is set.
4. Any other request inside the tab (API, assets, streams, sockets) is accepted while the last entry is younger than `entryHours`; otherwise 401 `{"error":"entry_required","step_up":"/<tab>/"}`. The page sends the person to `step_up` (a navigation to the tab itself, which asks the Face ID in place).
5. Reloading the page, or coming back to the tab from the selector, within min(`entryHours`, 15 minutes) of the last entry on this same session serves the tab without a new Face ID; `entered_at` and `entry_until` stay those of that entry (the window never moves or grows). After it, a navigation asks Face ID again. Another session (another device, or after signing in again) needs its own entry. A passkey check done for anything else (an admin action) never counts as an entry.

The tab does not need its own "entered" bookkeeping; `entered_at`/`entry_until` are the answer. If it keeps one as a second barrier, it must be keyed so that a new session never inherits it (the portal never reuses a session id, but do not rely on that alone). A page socket opened inside the entry must be closed at `entry_until`. The portal refuses service worker registration for such a tab (a cached page would skip the entry check).

## 5. Fixed screens

A TV or monitor gets its own account, kind `screen`, in `residents`:

1. The screen opens `/?screen=1&next=/<tab>/` (URL-encoded; a query is kept, e.g. `next=%2F<tab>%2F%3Fview%3Dlandscape`) (or taps the pairing link on the sign-in page). It gets a 6-character code (`ABC-DEF`, 5 minutes, single use) and a QR for `/?pair=ABCDEF`.
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
- Title marked with `data-a5-tabs`, the selector's files and the home-screen app lines in `<head>` (section 9); `badge` if something waits for people there.
- The house rules of section 0, checked by the portal's maintainer before going live.

## 9. Tab selector and pending counts

There is no home page. `/` opens the last tab used on that device (`localStorage` key `a5.lastTab`), else the first tab the person can open, else the account page. Every tab's title is the way to the other tabs.

### In the tab page

```html
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-180.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Portal A5">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0d1117">
<link rel="apple-touch-startup-image" media="(device-width: 393px) and (device-height: 852px) and (-webkit-device-pixel-ratio: 3) and (orientation: portrait)" href="/splash/splash-1179x2556.png">
<!-- ...one line per iPhone size: copy all ten from the portal's public/index.html -->
<link rel="stylesheet" href="/_shell/tabs.css">
<script src="/locale/pt-BR.js" defer></script>
<script src="/_shell/tabs.js" defer></script>
...
<h1><button type="button" data-a5-tabs>Notes</button></h1>
```

- The first nine lines make the whole portal one home-screen app (one manifest, scope `/`, same icon and name). Without them, a page saved to the iPhone home screen from inside a tab gets no icon. The files live on the portal; the tab CSP's `default-src 'self'` already allows them. With `black-translucent` the page runs under the status bar: pad the top with `env(safe-area-inset-top)`. The `apple-touch-startup-image` lines (ten, in the portal's `public/index.html`) give the iPhone app its launch screen, the house at night; without them a home-screen launch from the tab starts on a blank page.
- The script asks `GET /api/tabs?current=<tab>`, adds an SVG arrow and the dot to the marked title and turns it into a menu button. With no selector (fixed screens, signed out, any error) the title stays a plain title, and `tabs.css` keeps a marked `<button>` looking like the title around it.
- The list opens on tap, click, Enter, Space or arrow down; closes on Esc, a tap outside or the title again. Arrow keys, Home and End move, Enter or Space picks (TV remotes and keyboards: nothing needs hover). Focus stays in the list while it is open. Picking is a full page navigation (`location.assign`), never an iframe, and records `a5.lastTab`. The tab page also records itself on load.
- Counts come back when the page loads, when the list opens and when the page becomes visible again (`visibilitychange`). No polling.
- `locale/pt-BR.js` sets `window.T` and `window.A5_TEXT`; the selector reads `A5_TEXT` only, so a tab may keep its own `T` (load the locale before the tab's scripts).
- Colors: dark by default (`--a5t-*` tokens in `tabs.css`); a tab may override the tokens. The portal's own pages map them to the device theme.

### Pull to refresh (every tab, from the shell)

The home-screen app has no reload button, so `tabs.js` reloads the page when a signed-in person drags it down at the top (past 80 px, with a "pull/release to refresh" pill). Nothing to do in the tab. It starts only when the selector is on (never on a fixed screen), on touch only (a TV remote never starts it), with one finger (pinch zoom is left alone), only at the top of the page and of the box under the finger, and never while the tab list, a `<dialog open>`, an `aria-modal="true"` element, an element marked `data-a5-sheet` (not `hidden`) or a text field is open. Mark your sheets with `data-a5-sheet`. A tab with its own pull to refresh sets `<html data-a5-pull="own">` and the shell stays out. Texts: `A5_TEXT.shell.pull`.

### "See as" (admins)

An admin's list also offers "see as <group>" (`A5_TEXT.shell.seeAs`) for every non-admin group, above the line before Conta. Picking one sends `POST /api/tabs {"view_as": "<group>"}` and, from then on, that session (that device only) is that group and no admin: `/api/tabs`, `/<tab>/*`, the identity every tab gets (`groups`, `actions` with the group's level), commands and the account pages. Nothing to change in a tab: it shows exactly what that group sees. The title carries a "seeing as ..." mark (`seeingAs`) and the list starts with "back to owner mode" (`backToOwner`, sends `{"view_as": null}`). Going in asks for nothing (the mode only takes power away). Coming back asks for Face ID made after going in: turning the mode on clears the session's last check, and `{"view_as": null}` answers 403 `passkey_required` without a fresh one. A tab page cannot run that check (its CSP), so the selector's "back to owner mode" opens `/conta/?owner=1&next=<this page>`, which asks for Face ID and then comes back. No counts while it is on. Audit: `view_as_on` and `view_as_off`, target the group, and every other audit row written while it is on carries `view_as` in its detail.

It is also a rehearsal with a made-up resident (`A5_TEXT.rehearsal.name`): the identity a tab gets has `rehearsal: true` (show that name instead of `name` if the tab shows one), and a command sent from it passes every check a resident meets and then stops at the portal: nothing reaches `command()`, the answer is `200 {"id", "status": "done", "ok": true, "simulated": true}` and the audit row has `simulated: true`. A tab that sees `simulated` says nothing was sent (`A5_TEXT.rehearsal.nothingSent` is there for that). Every page of it shows a yellow bar on top (`.a5-rehearsal`, `<html data-a5-rehearsal>`, `--a5-bar` is its height, 42 px): `tabs.js` draws it on a tab page, `app.js` on the portal's own pages. The bar is fixed over the top of the page: a tab moves its own top down while it is on, for example `html[data-a5-rehearsal] .my-header { padding-top: calc(env(safe-area-inset-top) + var(--a5-bar)) }`. While it is on, the list shows only "back to owner mode", that group's tabs and Conta. The list also has a rehearsal row (the made-up name, flask icon) that turns on "see as" the residents and starts from the signed-out pages. Signing out of the rehearsal happens on the portal page only: it draws the signed-out pages (sign in, message, waiting for approval, screen pairing) with made-up data and calls none of the sign-in, pairing or passkey routes; `POST /api/logout` answers 403 `view_as_active` while the mode is on, so the owner's session never drops.

"See as" is a view, not a security boundary: the page still runs with the admin's own session, and any script on it can turn the mode off. Never use it to try out a tab you do not trust.

### `GET /api/tabs`

Session required (401 otherwise), GET only, `Cache-Control: no-store`.

```json
{
  "selector": true,
  "current": "notes",
  "tabs": [
    {"id": "notes", "path": "/notes/", "label": "Notes", "hint": null, "icon": "grid", "badge": null, "entry": "session"},
    {"id": "voice", "path": "/voice/", "label": "Voice", "hint": "talk to the house", "icon": "mic", "badge": 2, "entry": "passkey"}
  ],
  "who": {"name": "Owner", "group": "owner"},
  "account": {"id": "conta", "path": "/conta/"},
  "view_as": null,
  "view_options": [{"id": "residents", "name": "Residents"}]
}
```

- `who`: the header line of the list, the session's own name and group id (an admin group first); `name` is null while seeing as someone else; null for a fixed screen. Nothing about anyone else.
- `view_as`: the group this session is seen as (`{id, name}`), or null. `view_options`: the groups an admin can see the portal as (empty for everyone else).
- `POST /api/tabs` with `{"view_as": "<group>" | null}` (same origin, `X-Portal: 1`) turns "see as" on or off and answers the new list. Admin browser sessions only (403); an admin group is refused (400 `view_as_admin_group`).

- `tabs`: the tabs this session can open (group and the tab's `credentials` policy, the same rule as `/<tab>/*`), in configuration order, with the configured `label`, `hint` and `icon` (or null). The account's name comes from the locale.
- `selector` is `false` for a fixed screen (`credential: 'screen'`): plain title, no counts.
- `current` is the `current` query echoed back only when it is `conta` or a listed tab.
- `entry: "passkey"` shows "Face ID" next to the tab in the list.

### `badge(identity)` (optional)

```ts
async badge(identity: PortalIdentity): Promise<{ count: number }>
```

- How many things wait for this person in the tab (for example, decisions waiting for an answer). The tab decides what counts. Only the number leaves the tab, never the content.
- Called only for a browser session with more than one tab, for each of its tabs. Never for a fixed screen, a person with a single tab or an admin seeing as another group.
- The identity is the person's, with `strong` false (a count is never an action) and `entered_at` and `entry_until` null: a passkey tab's count shows without Face ID, its content stays behind the entry.
- The portal waits 300 ms at most, then shows no number. Anything but a non-negative integer is no number; above 99 is shown as 99 (the dot itself shows `9+` above 9). The answer is kept per person and tab for 60 seconds in the portal's isolate.
- The dot next to the title is the sum of the other tabs' counts; inside the list each tab shows its own.

### The account tab

`/conta/` is a portal page (portal CSP, device theme): my devices, people and groups, screens, bridges, audit, sign out. It is always the last entry of the list, after a line, and its title carries the same selector.

