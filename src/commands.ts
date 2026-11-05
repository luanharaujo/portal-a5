// Commands: what a person, a fixed screen or a Shortcuts key may ask a tab to do in the house.
// The contract is written up in docs/COMMANDS.md.
//
// Each tab declares its actions in the TABS configuration (`commands`). The portal checks the
// action, every parameter, the level and its own rate limits before the tab ever sees the call;
// the tab's machine bridge checks all of it again against its own closed list.
// There is no free text anywhere: a parameter is an enum, a bounded integer or a boolean.

export type Level = 'common' | 'admin' | 'sensitive'

export type ParamSpec =
  | { enum: string[] }
  | { int: [number, number] }
  | { bool: true }

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
}

export type Catalog = Record<string, CommandSpec>

export const ACTION_RE = /^[a-z][a-z0-9_]{0,39}$/
const PARAM_RE = /^[a-z][a-z0-9_]{0,23}$/
const ENUM_RE = /^[a-z0-9][a-z0-9_.-]{0,39}$/
const MAX_ACTIONS = 40
const MAX_PARAMS = 4
const MAX_ENUM = 16
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
  return null
}

// One action from the configuration. Anything malformed drops the action (never a looser one).
function parseSpec(v: unknown): CommandSpec | null {
  if (!isObj(v)) return null
  const allowed = ['level', 'params', 'perHour', 'gap', 'screens', 'shortcut', 'returns']
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
  const screens = v.screens === true && level === 'common'
  const shortcut = v.shortcut !== false && level !== 'sensitive'

  let returns: string[] = []
  if (v.returns != null) {
    if (!Array.isArray(v.returns) || v.returns.length > MAX_RETURNS) return null
    if (!v.returns.every((r) => typeof r === 'string' && PARAM_RE.test(r) && !BAD.includes(r))) return null
    returns = [...new Set(v.returns as string[])]
  }
  return { level, params, perHour, gap, screens, shortcut, returns }
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

// Why a caller cannot run an action, or null. The tab access itself (group) is checked before.
export function refusal(tab: string, action: string, spec: CommandSpec, c: Caller): string | null {
  if (c.credential === 'shortcut') {
    if (!spec.shortcut || spec.level === 'sensitive') return 'not_for_shortcuts'
    if (!c.scope?.includes(`${tab}/${action}`)) return 'out_of_scope'
    if (spec.level === 'admin' && !c.admin) return 'admin_only'
    return null
  }
  if (c.credential === 'screen') return spec.level === 'common' && spec.screens ? null : 'not_for_screens'
  if (spec.level === 'common') return null
  if (!c.admin) return 'admin_only'
  if (spec.level === 'admin') return c.adminFresh || c.strong ? null : 'passkey_required'
  return c.strong ? null : 'passkey_required'
}

// The actions this caller may run in the tab (sent to the tab as identity.actions).
export const allowedActions = (tab: string, catalog: Catalog, c: Caller): string[] =>
  Object.keys(catalog).filter((a) => refusal(tab, a, catalog[a], c) === null)

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

// Scope of a new key: "<tab>/<action>" entries that exist and may go in a key.
export function checkScope(raw: unknown, catalogs: Record<string, Catalog>, admin: boolean): string[] | null {
  if (!Array.isArray(raw) || !raw.length || raw.length > 12) return null
  const out: string[] = []
  for (const e of raw) {
    if (typeof e !== 'string') return null
    const m = /^([a-z][a-z0-9-]{0,30})\/([a-z][a-z0-9_]{0,39})$/.exec(e)
    if (!m) return null
    const spec = catalogs[m[1]]?.[m[2]]
    if (!spec || !spec.shortcut || spec.level === 'sensitive') return null
    if (spec.level === 'admin' && !admin) return null
    if (!out.includes(e)) out.push(e)
  }
  return out
}
