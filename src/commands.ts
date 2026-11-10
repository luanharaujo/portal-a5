// Commands: what a person, a fixed screen or a Shortcuts key may ask a tab to do in the house.
// The contract is written up in docs/COMMANDS.md.
//
// Each tab declares its actions in the TABS configuration (`commands`). The portal checks the
// action, every parameter, the level and its own rate limits before the tab ever sees the call;
// the tab's machine bridge checks all of it again against its own closed list.
// There is no free text, except one narrow door: a `text` parameter, only on keyWriteOnly actions of a
// tab whose configuration says `textParams: true` (a tab that keeps the text as data, with no bridge
// that runs anything). The value is checked here for size and control characters and never leaves
// the tab: the audit and the commands table keep its length only.

export type Level = 'common' | 'admin' | 'sensitive'

export type ParamSpec =
  | { enum: string[] }
  | { int: [number, number] }
  | { bool: true }
  | { text: number }

export interface CommandSpec {
  level: Level
  params: Record<string, ParamSpec>
  // per caller (person or Shortcuts key) per hour, on the portal side
  perHour: number
  // minimum time between two runs of this action (or of every action sharing `gap.key`),
  // for everyone, optionally per value of one parameter (for example, per air conditioner)
  gap: { seconds: number; key: string; by: string | null } | null
  // fixed screens may send it (common level only)
  screens: boolean
  // may be put in a Shortcuts key (never for 'sensitive')
  shortcut: boolean
  // result fields the caller gets back (strings, numbers, booleans only)
  returns: string[]
  // browser only: a passkey check on this very session within this many ms, for anyone who runs it
  // (owner's rule for the TV volume limiter, 08/11: Face ID every time, residents too). Never for
  // fixed screens or Shortcuts keys.
  passkey: number | null
  // the one way a Shortcuts key reaches a tab with Face ID on entry: write-only, alone in its key,
  // answered with {ok, id} only. Off unless the catalog says true; no effect on a tab without
  // Face ID on entry, other than the trimmed answer to a key.
  keyWriteOnly: boolean
  // only opens the tab's own Face ID window (`passkey`): the tab checks identity.passkey_until on its
  // own routes; /_cmd refuses it before the tab is called
  windowOnly: boolean
}

export type Catalog = Record<string, CommandSpec>

export const ACTION_RE = /^[a-z][a-z0-9_]{0,39}$/
const PARAM_RE = /^[a-z][a-z0-9_]{0,23}$/
const ENUM_RE = /^[a-z0-9][a-z0-9_.-]{0,39}$/
const MAX_ACTIONS = 40
const MAX_PARAMS = 4
const MAX_ENUM = 16
export const TEXT_MAX = 4000
const MAX_RETURNS = 8
const DEFAULT_PER_HOUR = 20
const MAX_PER_HOUR = 120
const BAD = ['__proto__', 'constructor', 'prototype']

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
const own = (o: Record<string, unknown>) => Object.keys(o).filter((k) => !BAD.includes(k))

function parseParam(v: unknown): ParamSpec | null {
  if (!isObj(v)) return null
  const keys = Object.keys(v)
  if (keys.length !== 1) return null
  if (Array.isArray(v.enum)) {
    const e = v.enum
    if (!e.length || e.length > MAX_ENUM || !e.every((x) => typeof x === 'string' && ENUM_RE.test(x))) return null
    return { enum: [...new Set(e as string[])] }
  }
  if (Array.isArray(v.int)) {
    const [a, b] = v.int as unknown[]
    if (v.int.length !== 2 || !Number.isSafeInteger(a) || !Number.isSafeInteger(b) || (a as number) > (b as number)) return null
    return { int: [a as number, b as number] }
  }
  if (v.bool === true) return { bool: true }
  if (typeof v.text === 'number' && Number.isSafeInteger(v.text) && v.text >= 1 && v.text <= TEXT_MAX) return { text: v.text }
  return null
}

export const hasText = (spec: CommandSpec) => Object.values(spec.params).some((p) => 'text' in p)

// What the audit and the commands table keep of a call: text values become their length.
export function redactParams(spec: CommandSpec, params: Record<string, string | number | boolean>): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {}
  for (const [k, v] of Object.entries(params)) out[k] = spec.params[k] && 'text' in spec.params[k] && typeof v === 'string' ? `[text:${[...v].length}]` : v
  return out
}

// One action from the configuration. Anything malformed drops the action (never a looser one).
function parseSpec(v: unknown): CommandSpec | null {
  if (!isObj(v)) return null
  const allowed = ['level', 'params', 'perHour', 'gap', 'screens', 'shortcut', 'returns', 'passkey', 'keyWriteOnly', 'windowOnly']
  if (Object.keys(v).some((k) => !allowed.includes(k))) return null
  if (v.level !== 'common' && v.level !== 'admin' && v.level !== 'sensitive') return null
  const level = v.level as Level

  const params: Record<string, ParamSpec> = Object.create(null)
  if (v.params != null) {
    if (!isObj(v.params) || Object.keys(v.params).length > MAX_PARAMS) return null
    for (const k of Object.keys(v.params)) {
      if (!PARAM_RE.test(k) || BAD.includes(k)) return null
      const p = parseParam(v.params[k])
      if (!p) return null
      params[k] = p
    }
  }

  let perHour = DEFAULT_PER_HOUR
  if (v.perHour != null) {
    if (!Number.isSafeInteger(v.perHour) || (v.perHour as number) < 1 || (v.perHour as number) > MAX_PER_HOUR) return null
    perHour = v.perHour as number
  }

  let gap: CommandSpec['gap'] = null
  if (v.gap != null) {
    const g = v.gap
    if (!isObj(g) || Object.keys(g).some((k) => !['seconds', 'key', 'by'].includes(k))) return null
    if (!Number.isSafeInteger(g.seconds) || (g.seconds as number) < 1 || (g.seconds as number) > 86400) return null
    if (g.key != null && (typeof g.key !== 'string' || !ACTION_RE.test(g.key))) return null
    if (g.by != null && (typeof g.by !== 'string' || !(g.by in params))) return null
    gap = { seconds: g.seconds as number, key: (g.key as string | undefined) ?? '', by: (g.by as string | undefined) ?? null }
  }

  if (v.screens != null && typeof v.screens !== 'boolean') return null
  if (v.shortcut != null && typeof v.shortcut !== 'boolean') return null
  if (v.keyWriteOnly != null && typeof v.keyWriteOnly !== 'boolean') return null
  // a write-only key action that could not go in a key, or that also reads back or reaches a screen,
  // is a contradiction: the action is dropped
  if (v.keyWriteOnly === true &&
    (v.shortcut === false || level === 'sensitive' || v.passkey != null || v.screens === true || v.returns != null)) return null

  // free text only in a write-only action (the key answers {ok, id}; nothing reads it back)
  if (Object.values(params).some((p) => 'text' in p) && v.keyWriteOnly !== true) return null
  if (v.windowOnly != null && (v.windowOnly !== true || v.passkey == null || v.keyWriteOnly === true)) return null

  // "<n>m", 1 to 60 minutes, on common or admin actions; it rules out screens and keys, so asking
  // for either next to it is a contradiction and drops the action
  let passkey: number | null = null
  if (v.passkey != null) {
    const pm = typeof v.passkey === 'string' ? /^([1-9]\d?)m$/.exec(v.passkey) : null
    if (!pm || Number(pm[1]) > 60 || level === 'sensitive') return null
    if (v.screens === true || v.shortcut === true) return null
    passkey = Number(pm[1]) * 60e3
  }
  const screens = v.screens === true && level === 'common' && !passkey
  const shortcut = v.shortcut !== false && level !== 'sensitive' && !passkey

  let returns: string[] = []
  if (v.returns != null) {
    if (!Array.isArray(v.returns) || v.returns.length > MAX_RETURNS) return null
    if (!v.returns.every((r) => typeof r === 'string' && PARAM_RE.test(r) && !BAD.includes(r))) return null
    returns = [...new Set(v.returns as string[])]
  }
  return { level, params, perHour, gap, screens, shortcut, returns, passkey, keyWriteOnly: v.keyWriteOnly === true, windowOnly: v.windowOnly === true }
}

// The `commands` field of one tab. A bad action is dropped; a bad catalog is empty.
// The router uses parseCatalogStrict (below), which refuses the whole catalog instead.
export function parseCatalog(v: unknown): Catalog {
  const out: Catalog = Object.create(null)
  if (!isObj(v)) return out
  const names = own(v).filter((n) => ACTION_RE.test(n)).slice(0, MAX_ACTIONS)
  for (const n of names) {
    const s = parseSpec(v[n])
    if (s) {
      if (s.gap && !s.gap.key) s.gap.key = n
      out[n] = s
    }
  }
  return out
}

// Exactly the declared parameters, each of the declared type. Returns a clean copy, or the
// error code. Nothing the caller sent beyond the declared names reaches the tab.
export function checkParams(spec: CommandSpec, raw: unknown): { params: Record<string, string | number | boolean> } | { error: string } {
  const input = raw == null ? {} : raw
  if (!isObj(input)) return { error: 'bad_params' }
  const names = Object.keys(spec.params)
  if (Object.keys(input).some((k) => !names.includes(k))) return { error: 'unknown_param' }
  const params: Record<string, string | number | boolean> = Object.create(null)
  for (const n of names) {
    const p = spec.params[n]
    const val = input[n]
    if (val === undefined) return { error: 'missing_param' }
    if ('enum' in p) {
      if (typeof val !== 'string' || !p.enum.includes(val)) return { error: 'bad_param' }
    } else if ('text' in p) {
      // letters, digits and punctuation; line breaks and tabs are fine, other control characters are not
      if (typeof val !== 'string' || [...val].length > p.text || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u2028\u2029]/.test(val) || /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(val)) return { error: 'bad_param' }
    } else if ('int' in p) {
      if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < p.int[0] || val > p.int[1]) return { error: 'bad_param' }
    } else if (typeof val !== 'boolean') return { error: 'bad_param' }
    params[n] = val
  }
  return { params }
}

// Fail closed: null unless every entry is a valid action (the tab is then not switched on).
export function parseCatalogStrict(v: unknown): Catalog | null {
  if (!isObj(v)) return null
  const keys = Object.keys(v)
  if (keys.length > MAX_ACTIONS) return null
  const c = parseCatalog(v)
  return keys.length === Object.keys(c).length ? c : null
}

// What the portal hands the tab's command() (docs/COMMANDS.md section 8).
export interface Command {
  id: string
  action: string
  params: Record<string, string | number | boolean>
  expires_at: string
}

export const gapKeyOf = (spec: CommandSpec, params: Record<string, unknown>): string | null =>
  spec.gap ? (spec.gap.by ? `${spec.gap.key}:${String(params[spec.gap.by])}` : spec.gap.key) : null

// Who is asking, as far as levels go.
export interface Caller {
  credential: 'browser' | 'screen' | 'shortcut'
  admin: boolean           // in an admin group (never true for a screen)
  strong: boolean          // browser: passkey checked in the last 5 minutes
  adminFresh: boolean      // browser: passkey checked within the window for admin actions
                           // (ADMIN_COMMAND_PASSKEY in wrangler.toml: '12h'; '<n>m'/'<n>h' or 'session')
  scope: string[] | null   // shortcut: "<tab>/<action>" entries of the key
  entryPasskey?: boolean   // shortcut: the tab asks Face ID on entry (only keyWriteOnly actions, from a one-action key)
  passkeyAt?: string | null // browser: this session's last passkey check (for actions with `passkey`)
  rehearsal?: boolean      // browser: an admin seeing as another group (nothing reaches the house)
}

// Is the action's own passkey window (spec.passkey) open on this browser session? A rehearsal
// counts as open: its commands never reach the tab, and the owner cannot do a Face ID while seeing as.
export function passkeyWindowOk(spec: CommandSpec, c: Caller, nowMs = Date.now()): boolean {
  if (!spec.passkey) return true
  if (c.credential !== 'browser') return false
  if (c.rehearsal) return true
  const at = c.passkeyAt ? Date.parse(c.passkeyAt) : NaN
  return Number.isFinite(at) && at <= nowMs + 60e3 && nowMs - at < spec.passkey
}

// identity.passkey_until: action -> when its window closes (ISO), only for actions with `passkey`
// whose window is open on this session. A rehearsal shows them open for a full window from now.
export function passkeyUntil(catalog: Catalog, c: Caller, nowMs = Date.now()): Record<string, string> {
  const out: Record<string, string> = {}
  if (c.credential !== 'browser') return out
  for (const [a, spec] of Object.entries(catalog)) {
    if (!spec.passkey || !passkeyWindowOk(spec, c, nowMs)) continue
    const from = c.rehearsal ? nowMs : Date.parse(c.passkeyAt!)
    out[a] = new Date(from + spec.passkey).toISOString()
  }
  return out
}

// Was this session's last passkey check recent enough for an 'admin' command from a browser?
// setting: '<n>m' / '<n>h' or 'session' (once on that session). wrangler.toml sets '12h' (one
// Face ID a day). Missing or malformed falls back to 5 minutes, the safe side.
export const ADMIN_WINDOW_DEFAULT = '5m'
export function adminWindowOk(passkeyAt: string | null, setting: string | undefined, nowMs = Date.now()): boolean {
  if (!passkeyAt) return false
  const at = Date.parse(passkeyAt)
  if (!Number.isFinite(at)) return false
  const v = setting ?? ADMIN_WINDOW_DEFAULT
  if (v === 'session') return true
  const m = /^(\d{1,4})(m|h)$/.exec(v) ?? /^(\d{1,4})(m|h)$/.exec(ADMIN_WINDOW_DEFAULT)!
  return nowMs - at < Number(m[1]) * (m[2] === 'h' ? 3600e3 : 60e3)
}

// When that window closes (ISO), or null when it is not open. Same rule as adminWindowOk;
// 'session' never closes while the session lives, so it answers a far date.
export function adminWindowUntil(passkeyAt: string | null, setting: string | undefined, nowMs = Date.now()): string | null {
  if (!adminWindowOk(passkeyAt, setting, nowMs)) return null
  const v = setting ?? ADMIN_WINDOW_DEFAULT
  if (v === 'session') return '9999-12-31T00:00:00.000Z'
  const m = /^(\d{1,4})(m|h)$/.exec(v) ?? /^(\d{1,4})(m|h)$/.exec(ADMIN_WINDOW_DEFAULT)!
  return new Date(Date.parse(passkeyAt!) + Number(m[1]) * (m[2] === 'h' ? 3600e3 : 60e3)).toISOString()
}

// Why a caller cannot run an action, or null. The tab access itself (group) is checked before.
export function refusal(tab: string, action: string, spec: CommandSpec, c: Caller): string | null {
  if (c.credential === 'shortcut') {
    if (!spec.shortcut || spec.level === 'sensitive') return 'not_for_shortcuts'
    if (c.entryPasskey && !spec.keyWriteOnly) return 'not_for_shortcuts'
    if (!c.scope?.includes(`${tab}/${action}`)) return 'out_of_scope'
    if (c.entryPasskey && c.scope.length !== 1) return 'out_of_scope'
    if (spec.level === 'admin' && !c.admin) return 'admin_only'
    return null
  }
  if (c.credential === 'screen') return spec.level === 'common' && spec.screens ? null : 'not_for_screens'
  if (spec.level !== 'common' && !c.admin) return 'admin_only'
  if (spec.level === 'admin' && !(c.adminFresh || c.strong)) return 'passkey_required'
  if (spec.level === 'sensitive' && !c.strong) return 'passkey_required'
  return passkeyWindowOk(spec, c) ? null : 'passkey_required'
}

// The actions this caller may run in the tab (sent to the tab as identity.actions). An admin's browser session also
// gets its `admin` actions while the Face ID window is closed (owner's decision, 07/11): the page shows them and asks
// for Face ID before sending (admin_until); the command itself is still refused with passkey_required until then.
export const allowedActions = (tab: string, catalog: Catalog, c: Caller): string[] =>
  Object.keys(catalog).filter((a) => {
    const why = refusal(tab, a, catalog[a], c)
    if (why === null) return true
    if (why !== 'passkey_required' || c.credential !== 'browser') return false
    // the page shows it and asks for Face ID before sending
    return (catalog[a].level === 'admin' && c.admin) || (catalog[a].level === 'common' && !!catalog[a].passkey)
  })

// Only the declared result fields, and only plain values.
export function pickReturns(spec: CommandSpec, result: unknown): Record<string, string | number | boolean> | null {
  if (!spec.returns.length || !isObj(result)) return null
  const out: Record<string, string | number | boolean> = {}
  for (const k of spec.returns) {
    const v = result[k]
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v
    else if (typeof v === 'boolean') out[k] = v
    else if (typeof v === 'string') out[k] = v.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 80)
  }
  return Object.keys(out).length ? out : null
}

// What a tab answers to command(). Anything else counts as 'failed'.
export type CommandStatus = 'done' | 'failed' | 'queued' | 'offline' | 'refused'
export interface CommandAnswer { status: CommandStatus; result?: unknown; error?: string }

export function readAnswer(v: unknown): CommandAnswer {
  if (!isObj(v)) return { status: 'failed', error: 'bad_answer' }
  const s = v.status
  if (s !== 'done' && s !== 'failed' && s !== 'queued' && s !== 'offline' && s !== 'refused') return { status: 'failed', error: 'bad_answer' }
  const error = typeof v.error === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(v.error) ? v.error : undefined
  return { status: s, result: v.result, error }
}

// Shortcuts keys: "pa5_atl_" + 32 random bytes in base64url (43 characters).
export const SHORTCUT_KEY_PREFIX = 'pa5_atl_'
export const isShortcutKeyShape = (k: string) => /^pa5_atl_[A-Za-z0-9_-]{43}$/.test(k)

// Scope of a new key: "<tab>/<action>" entries that exist and may go in a key. In a tab with Face
// ID on entry (passkeyTabs) only a keyWriteOnly action may, and it must be the key's only entry.
export function checkScope(raw: unknown, catalogs: Record<string, Catalog>, admin: boolean, passkeyTabs: Set<string> = new Set()): string[] | null {
  if (!Array.isArray(raw) || !raw.length || raw.length > 12) return null
  const out: string[] = []
  // a key holding a text action is the Mac's: only write-only actions of that one tab next to it
  const tabsIn = new Set<string>()
  for (const e of raw) if (typeof e === 'string') tabsIn.add(e.split('/')[0])
  for (const e of raw) {
    if (typeof e !== 'string') return null
    const m = /^([a-z][a-z0-9-]{0,30})\/([a-z][a-z0-9_]{0,39})$/.exec(e)
    if (!m) return null
    const spec = catalogs[m[1]]?.[m[2]]
    if (!spec || !spec.shortcut || spec.level === 'sensitive') return null
    if (spec.level === 'admin' && !admin) return null
    if (hasText(spec) && (tabsIn.size !== 1 || raw.some((x) => !catalogs[m[1]]?.[String(x).split('/')[1]]?.keyWriteOnly))) return null
    if (passkeyTabs.has(m[1]) && (!spec.keyWriteOnly || new Set(raw).size !== 1)) return null
    if (!out.includes(e)) out.push(e)
  }
  return out
}
