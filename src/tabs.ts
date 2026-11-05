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

export type Credential = 'browser' | 'screen' | 'machine' | 'shortcut'

export interface PortalIdentity {
  credential: Credential
  person: number | null      // null for machines
  name: string               // person or screen name, or the machine key label
  groups: string[]           // empty for machines
  session: number | null     // browser or screen session id; null for machines
  machine: number | null     // machine key id; only for machines
  strong: boolean            // passkey checked on this session in the last 5 minutes
  entered_at: string | null  // tabs with entry 'passkey': when this session entered with Face ID
  entry_until: string | null // ...and when that entry ends: close this session's sockets then
  actions: string[]          // reserved for stage 3 (commands); empty for now
}

export interface RevokeRef { session?: number; machine?: number; person?: number }

export interface TabService {
  handle(req: Request, who: PortalIdentity): Promise<Response>
  fetch(req: Request): Promise<Response>
  revoke?(ref: RevokeRef): Promise<void>
  badge?(who: PortalIdentity): Promise<{ count: number }>
}

// Names a tab can never take: portal pages and routes living at /<name>/.
export const RESERVED_TABS = ['api', 'robo', 'conta', 'locale', 'vendor']

// The shared tab selector every tab page may load. These exact files (and /api/tabs) are the
// only portal paths a tab page may script from or connect to.
export const SHELL_SCRIPTS = ['/_shell/tabs.js', '/locale/pt-BR.js']
export const SHELL_API = '/api/tabs'

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

const DEFAULT_POLICY: TabPolicy = { allow: [], entry: 'session', entryHours: 0, credentials: ['browser', 'machine'], serviceWorker: true }

export const TAB_POLICY: Record<string, Partial<TabPolicy>> = {
  // fixed screens show the energy panel and keep the display awake
  energia: { allow: ['screen-wake-lock'], credentials: ['browser', 'screen', 'machine'] },
  // voice conversation; Face ID on every entry, free inside
  jarvis: { allow: ['microphone', 'screen-wake-lock'], entry: 'passkey', entryHours: 4, credentials: ['browser', 'machine'], serviceWorker: false },
}

export const policyOf = (tab: string): TabPolicy => ({ ...DEFAULT_POLICY, ...(TAB_POLICY[tab] ?? {}) })

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
