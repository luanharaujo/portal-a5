// What the portal enforces on each tab. The contract is written up in docs/TABS.md.
//
// A tab is a private worker. Its service binding (with `entrypoint` set to the tab's
// WorkerEntrypoint class) carries two calls:
//   handle(request, identity)  every plain request/response, over RPC
//   fetch(request)             only WebSocket upgrades (bridges and live pages); the identity
//                              travels in the X-A5-Identity header the portal sets
//   revoke(ref)                optional; the portal calls it when a session, screen or machine
//                              key is revoked, so the tab closes that credential's sockets
//   badge(identity)            optional; how many things wait for this person in the tab
//                              ({count}), shown next to the tab selector. Only the number leaves.
//   command(cmd, identity)     optional; one checked command for the house (docs/COMMANDS.md)

import { type Catalog, type Command, hasText, parseCatalogStrict } from './commands'

export type Credential = 'browser' | 'screen' | 'machine' | 'shortcut' | 'read_key'

export interface PortalIdentity {
  credential: Credential
  person: number | null      // null for machines
  name: string               // person or screen name, or the machine key label
  groups: string[]           // empty for machines
  session: number | null     // browser or screen session id; null for machines and shortcuts
  machine: number | null     // machine key id; only for machines
  shortcut: number | null    // Shortcuts key id; only for shortcuts
  read_key?: number          // read key id (docs/READ_KEYS.md); only for credential 'read_key'
  strong: boolean            // passkey checked on this session in the last 5 minutes
  entered_at: string | null  // tabs with entry 'passkey': when this session entered with Face ID
  entry_until: string | null // ...and when that entry ends: close this session's sockets then
  actions: string[]          // commands this identity may send in the tab (docs/COMMANDS.md)
  admin_until: string | null // admin commands from this browser session need no new Face ID until
                             // then (ADMIN_COMMAND_PASSKEY window); null = ask (docs/COMMANDS.md)
  passkey_until: Record<string, string> // actions with their own `passkey` window: action -> when
                             // the window on this browser session closes (ISO); absent = ask Face ID first
  rehearsal?: true          // an admin rehearsing as a resident ("see as"): commands come back
                             // simulated; show the made-up resident (T.rehearsal.name), not name
}

export interface RevokeRef { session?: number; machine?: number; person?: number }

export interface TabService {
  handle(req: Request, who: PortalIdentity): Promise<Response>
  fetch(req: Request): Promise<Response>
  revoke?(ref: RevokeRef): Promise<void>
  badge?(who: PortalIdentity): Promise<{ count: number }>
  command?(cmd: Command, who: PortalIdentity): Promise<unknown>
}

// Names a tab can never take: portal pages and routes living at /<name>/.
export const RESERVED_TABS = ['api', 'robo', 'conta', 'locale', 'vendor']

// The shared tab selector every tab page may load. These exact files (and /api/tabs) are the
// only portal paths a tab page may script from or connect to.
export const SHELL_SCRIPTS = ['/_shell/tabs.js', '/locale/pt-BR.js']
export const SHELL_API = '/api/tabs'

// What the portal enforces for one tab. Set per tab in the TABS configuration (see parseTabs).
export interface TabPolicy {
  // browser features this tab's pages may use (everything else stays off)
  allow: string[]
  // 'session': a signed-in session with access is enough.
  // 'passkey': every navigation into the tab needs a passkey check done for that entry;
  //            requests inside the tab need an entry from the last `entryHours`.
  entry: 'session' | 'passkey'
  entryHours: number
  credentials: Credential[]
  // false: requests registering a service worker (Service-Worker: script) are refused
  serviceWorker: boolean
}

const CLOSED_POLICY: TabPolicy = { allow: [], entry: 'passkey', entryHours: 0, credentials: [], serviceWorker: false }

// Drawings the selector knows (public/_shell/tabs.js). A tab picks one by name.
export const TAB_ICONS = ['bolt', 'power', 'mic', 'terminal', 'coin', 'grid']

// One tab as configured outside the code: the binding, how the selector shows it, and its policy.
export interface TabConfig extends TabPolicy {
  binding: string
  label: string | null
  hint: string | null       // second line under the name in the selector
  icon: string | null
  // actions the tab takes (docs/COMMANDS.md); empty = the tab takes no commands
  commands: Catalog
  // GET paths a read key may fetch (docs/READ_KEYS.md); null = the tab takes no read keys
  readKey: ReadKeyPolicy | null
}

export interface ReadKeyPolicy { paths: string[]; perHour: number; dayAlert: number }
export const READ_KEY_DAY_ALERT_DEFAULT = 30
export const READ_KEY_DAY_ALERT_MAX = 1000
export const READ_KEY_MAX_PER_HOUR = 60

// The TABS variable is generated at deploy time from a file kept out of git (scripts/deploy.sh):
//   {"<tab>": {"binding": "TAB_X", "label": "...", "icon": "bolt", "allow": [...], "entry": "session",
//              "entryHours": 0, "credentials": ["browser"], "serviceWorker": true}}
// Fail closed: allow, entry and credentials must be written out for every tab (no default policy),
// and anything that does not validate drops the whole tab, logged. A dropped tab answers 404.
export function parseTabs(raw: string | undefined): Record<string, TabConfig> {
  let all: unknown
  try { all = JSON.parse(raw || '{}') } catch { console.error('TABS is not JSON'); return {} }
  if (!all || typeof all !== 'object' || Array.isArray(all)) return {}
  const out: Record<string, TabConfig> = {}
  for (const [tab, v] of Object.entries(all as Record<string, unknown>)) {
    const c = validTab(tab, v)
    if (c) out[tab] = c
    else console.error('tab config refused', tab)
  }
  return out
}

const CREDENTIALS: Credential[] = ['browser', 'screen', 'machine']
const isList = (v: unknown, ok: string[]) => Array.isArray(v) && v.every((x) => typeof x === 'string' && ok.includes(x))

function validTab(tab: string, v: unknown): TabConfig | null {
  if (!/^[a-z][a-z0-9-]{0,30}$/.test(tab) || RESERVED_TABS.includes(tab)) return null
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null
  const o = v as Record<string, unknown>
  const known = ['binding', 'label', 'hint', 'icon', 'allow', 'entry', 'entryHours', 'credentials', 'serviceWorker', 'commands', 'readKey', 'textParams']
  if (Object.keys(o).some((k) => !known.includes(k))) return null
  if (typeof o.binding !== 'string' || !/^[A-Z][A-Z0-9_]{0,40}$/.test(o.binding)) return null
  if (o.label != null && (typeof o.label !== 'string' || !o.label.trim() || o.label.length > 40 || /[\u0000-\u001f<>]/.test(o.label))) return null
  if (o.hint != null && (typeof o.hint !== 'string' || !o.hint.trim() || o.hint.length > 40 || /[\u0000-\u001f<>]/.test(o.hint))) return null
  if (o.icon != null && (typeof o.icon !== 'string' || !TAB_ICONS.includes(o.icon))) return null
  if (!isList(o.allow, FEATURES)) return null
  if (o.entry !== 'session' && o.entry !== 'passkey') return null
  if (!isList(o.credentials, CREDENTIALS) || !(o.credentials as string[]).length) return null
  if (o.serviceWorker != null && typeof o.serviceWorker !== 'boolean') return null
  const entry = o.entry as TabPolicy['entry']
  const hours = o.entryHours ?? 0
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours < 0 || hours > 24) return null
  if (entry === 'passkey' && hours <= 0) return null
  // one malformed action refuses the whole tab, like any other bad field
  const commands = parseCatalogStrict(o.commands ?? {})
  if (!commands) return null
  if (o.textParams != null && typeof o.textParams !== 'boolean') return null
  if (Object.values(commands).some(hasText) && o.textParams !== true) return null
  const readKey = o.readKey == null ? null : parseReadKey(o.readKey)
  if (o.readKey != null && !readKey) return null
  return {
    binding: o.binding, label: (o.label as string | undefined)?.trim() ?? null, hint: (o.hint as string | undefined)?.trim() ?? null, icon: (o.icon as string | undefined) ?? null,
    allow: [...new Set(o.allow as string[])],
    entry,
    entryHours: entry === 'passkey' ? hours : 0,
    credentials: [...new Set(o.credentials as Credential[])],
    // a cached page would skip the Face ID check on entry
    serviceWorker: entry === 'passkey' ? false : ((o.serviceWorker as boolean | undefined) ?? true),
    commands,
    readKey,
  }
}

// {"paths": ["/_data"], "perHour": 30}: exact paths under /<tab>, never the portal's own
// (_cmd, _passkey), at most 5, and an hourly limit per key (1 to READ_KEY_MAX_PER_HOUR).
function parseReadKey(v: unknown): ReadKeyPolicy | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null
  const o = v as Record<string, unknown>
  if (Object.keys(o).some((k) => !['paths', 'perHour', 'dayAlert'].includes(k))) return null
  if (!Array.isArray(o.paths) || !o.paths.length || o.paths.length > 5) return null
  for (const p of o.paths)
    if (typeof p !== 'string' || !/^(\/[a-z0-9_-]{1,40}){1,4}$/.test(p) || /^\/_(cmd|passkey)(\/|$)/.test(p)) return null
  const n = o.perHour
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > READ_KEY_MAX_PER_HOUR) return null
  // the daily use that warns the admins (a key read by a program that sweeps every few minutes needs more)
  const d = o.dayAlert ?? READ_KEY_DAY_ALERT_DEFAULT
  if (typeof d !== 'number' || !Number.isInteger(d) || d < READ_KEY_DAY_ALERT_DEFAULT || d > READ_KEY_DAY_ALERT_MAX) return null
  return { paths: [...new Set(o.paths as string[])], perHour: n, dayAlert: d }
}

// The configuration arrives in pieces (TABS, TABS_2, ... up to TABS_9) because Cloudflare caps
// each text variable at about 5 KB; scripts/make_config.py splits it and this joins it back.
export function tabsText(env: object): string | undefined {
  const v = env as Record<string, unknown>
  if (typeof v.TABS !== 'string') return undefined
  let s = v.TABS
  for (let n = 2; n <= 9 && typeof v['TABS_' + n] === 'string'; n++) s += v['TABS_' + n] as string
  return s
}

// The router reads the configuration once per isolate (re-parsed only if the variable changes).
let loadedRaw: string | undefined
let loaded: Record<string, TabConfig> = {}
export function tabsConfig(raw: string | undefined): Record<string, TabConfig> {
  if (raw !== loadedRaw) { loaded = parseTabs(raw); loadedRaw = raw }
  return loaded
}

export const policyOf = (tab: string): TabPolicy => {
  const c = loaded[tab]
  // a tab that is not configured is never routed (no binding); this answer only keeps callers simple
  return c ? { allow: c.allow, entry: c.entry, entryHours: c.entryHours, credentials: c.credentials, serviceWorker: c.serviceWorker } : { ...CLOSED_POLICY }
}

// Features a page could ask for. Listed as () unless the tab allows them, because several
// (microphone, camera, screen-wake-lock) default to 'self' when the header leaves them out.
const FEATURES = ['camera', 'microphone', 'geolocation', 'screen-wake-lock', 'display-capture', 'usb', 'serial', 'bluetooth', 'hid', 'payment']

export function permissionsPolicy(allow: string[] = []): string {
  return [
    ...FEATURES.map((f) => `${f}=${allow.includes(f) ? '(self)' : '()'}`),
    'publickey-credentials-get=(self)', 'publickey-credentials-create=(self)',
  ].join(', ')
}

// Response headers a tab can never send: they would reach past its own path on a shared origin.
const DROP_FROM_TAB = ['set-cookie', 'clear-site-data', 'service-worker-allowed', 'x-tab-audit', 'refresh']

// A tab's pages may load scripts, connect and post only under the tab's own path, so a script
// in one tab cannot call the portal API (/api/*) or another tab with the person's cookie.
// The one exception is the shared selector: two exact script files and the read-only
// GET /api/tabs (a source without a trailing slash matches that path only).
export function tabCsp(origin: string, tab: string): string {
  const base = `${origin}/${tab}/`
  const ws = `${origin.replace(/^http/, 'ws')}/${tab}/`
  const shell = SHELL_SCRIPTS.map((p) => origin + p).join(' ')
  return `default-src 'self'; script-src ${base} ${shell}; style-src 'self'; img-src 'self' data:; connect-src ${base} ${ws} ${origin}${SHELL_API}; ` +
    `object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action ${base}`
}

// origin null: an error answer (API headers, CSP default-src 'none').
export function sanitizeTabHeaders(h: Headers, pageHeaders: Record<string, string>, tab: string, origin: string | null) {
  for (const k of [...h.keys()]) {
    const l = k.toLowerCase()
    if (DROP_FROM_TAB.includes(l) || l.startsWith('access-control-')) h.delete(k)
  }
  for (const [k, v] of Object.entries(pageHeaders)) h.set(k, v)
  if (origin) h.set('Content-Security-Policy', tabCsp(origin, tab))
  h.set('Permissions-Policy', permissionsPolicy(policyOf(tab).allow))
}

// Request headers a tab never sees: the session cookie, client auth, and anything that looks
// like a portal header (a client could forge those).
export function stripRequestHeaders(src: Headers): Headers {
  const h = new Headers(src)
  for (const k of [...h.keys()]) {
    const l = k.toLowerCase()
    if (l === 'cookie' || l === 'authorization' || l.startsWith('x-portal') || l.startsWith('x-a5-')) h.delete(k)
  }
  return h
}

// X-Tab-Audit: {"action": "turn_on", "target": "ac:living", "detail": {...}}. The portal fills
// who, when, from where and the credential; the tab only says what happened.
export type TabAudit = { action: string; target: string | null; detail: unknown } | 'invalid' | null

export function readTabAudit(h: Headers): TabAudit {
  const raw = h.get('X-Tab-Audit')
  if (raw == null) return null
  if (raw.length > 4096) return 'invalid'
  let v: unknown
  try { v = JSON.parse(raw) } catch { return 'invalid' }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'invalid'
  const o = v as Record<string, unknown>
  if (Object.keys(o).some((k) => !['action', 'target', 'detail'].includes(k))) return 'invalid'
  if (typeof o.action !== 'string' || !/^[a-z][a-z0-9_]{0,39}$/.test(o.action)) return 'invalid'
  if (o.target != null && (typeof o.target !== 'string' || o.target.length > 120)) return 'invalid'
  if (o.detail != null && (typeof o.detail !== 'object' || Array.isArray(o.detail))) return 'invalid'
  return { action: o.action, target: (o.target as string | undefined) ?? null, detail: o.detail ?? null }
}

export function isNavigation(req: Request): boolean {
  if (req.method !== 'GET') return false
  const mode = req.headers.get('Sec-Fetch-Mode')
  if (mode) return mode === 'navigate'
  return (req.headers.get('Accept') ?? '').includes('text/html')
}

export const isUpgrade = (req: Request) => (req.headers.get('Upgrade') ?? '').toLowerCase() === 'websocket'
