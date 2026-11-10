// Portal worker: WhatsApp sign-in, passkeys, devices, groups, and a router that hands each
// tab (/<tab>/*) to a private worker over RPC.
//
// Trust levels:
//   weak session    signed in through WhatsApp. Can read; can revoke its own devices.
//   strong session  the same session after a passkey check (Face ID / Touch ID).
//                   Every admin write needs a passkey check from the last 5 minutes.

import { WebAuthnError, b64url, verifyAssertion, verifyRegistration } from './webauthn'
import {
  type PortalIdentity, type RevokeRef, type TabPolicy, type TabService, isNavigation, isUpgrade, permissionsPolicy,
  policyOf, readTabAudit, sanitizeTabHeaders, stripRequestHeaders, tabsConfig,
} from './tabs'
import {
  type Caller, type Catalog, SHORTCUT_KEY_PREFIX, adminWindowOk, adminWindowUntil, allowedActions, passkeyUntil, checkParams, checkScope, gapKeyOf,
  isShortcutKeyShape, pickReturns, readAnswer, refusal,
} from './commands'

export type { PortalIdentity } from './tabs'

export interface Env {
  DB: D1Database
  ASSETS: Fetcher
  ROBOT_LOGIN_KEY: string
  OWNER_PHONE: string
  TABS?: string
  // 'refuse' (default): a screen whose request came from another IP than the approving admin
  // cannot be approved; 'warn': only a red warning.
  PAIR_OTHER_IP?: string
  // how recent this session's passkey check must be for an 'admin' command from a browser:
  // '<n>m' or '<n>h', or 'session'; wrangler.toml sets '12h'. Missing or malformed = 5 minutes.
  ADMIN_COMMAND_PASSKEY?: string
  // 'refuse' (default): a screen opening an agent's pairing link from another IP than the agent
  // called from is turned away; 'warn': only shown on the approval page.
  AGENT_PAIR_OTHER_IP?: string
  // 'refuse' (default): an agent request (and its approval) only counts when the agent calls from
  // home, the last address of a live machine key; 'warn': allowed, flagged in red to the admin.
  AGENT_HOME?: string
  [binding: string]: unknown
}

const CODE_MINUTES = 10
const SESSION_DAYS = 180
const SCREEN_DAYS = 365
const PAIR_MINUTES = 5
const PAIR_PICKUP_GRACE_MS = 5 * 60e3 // an approved pairing can be picked up until expires_at + 5 min
const ENTRY_GRANT_MS = 60e3
const BADGE_TIMEOUT_MS = 300
const BADGE_CACHE_MS = 60e3
const ACCOUNT_PATH = '/conta/'
const MACHINE_KEY_PREFIX = 'pa5_maq_'
const AGENT_KEY_PREFIX = 'pa5_adm_'
const AGENT_PAIR_MINUTES = 15
const AGENT_PENDING_MAX = 5
const BRIDGE_ALERT_PER_HOUR = 3 // more reconnections than this in an hour warns the admins
const BRIDGE_MAX_PER_HOUR = 120
const SESSION_TOUCH_MS = 5 * 60e3
const PASSKEY_FRESH_MS = 5 * 60e3
const CHALLENGE_MS = 5 * 60e3
const MAX_DEVICES = 3 // non-admin; admins have no cap
const PENDING_MAX = 20
const PENDING_DAYS = 7
const LIMITS = {
  startPerIp: 20, startPerNumber: 5, statusPerIp: 900,
  robotPerSender: 3, robotTotal: 30, // per hour
  pairPerIp: 10, bridgeFailPerIp: 30,
  agentFailPerIp: 30, agentPerHour: 600, agentPairPerHour: 20, claimPerIp: 30,
}
const COOKIE = '__Host-a5s'
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789' // no 0/O/1/I/L
// The reader matches this exact phrase, so it is part of the protocol, not UI text.
const LOGIN_PHRASE = 'Entrar no Portal A5: '
// commands sent while an admin rehearses as a resident ("see as"): nothing leaves the portal
const REHEARSAL_COMMANDS_PER_HOUR = 120
const ROBOT_KEY_PREFIX = 'pa5_robo_'
const OWNER_GROUP = 'owner'
// groups made only for screens: a tab whose policy takes no screen credential can't be put there
const SCREEN_GROUPS = new Set(['owner-screens'])
// commands (docs/COMMANDS.md)
const COMMAND_TTL_MS = 60e3
const COMMAND_WAIT_MS = 8e3
const SHORTCUT_PER_HOUR = 30
const SHORTCUT_FAIL_PER_IP = 30
const TAB_COMMANDS_PER_HOUR = 300
const MAX_SHORTCUT_KEYS = 30

const HTML_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
const PAGE_HEADERS: Record<string, string> = {
  'Content-Security-Policy': HTML_CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': permissionsPolicy(),
  'Strict-Transport-Security': 'max-age=31536000',
  'X-Frame-Options': 'DENY',
}
const API_HEADERS: Record<string, string> = {
  ...PAGE_HEADERS,
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cache-Control': 'no-store',
}

type Row = Record<string, unknown>
interface Person { id: number; name: string; phone: string; status: string; kind?: string }
interface Group { id: string; name: string; tabs: string; is_admin: number }
interface Who {
  entryUsedAt?: string | null
  person: Person; sessionId: number; sessionCreatedAt: string; kind: 'browser' | 'screen'; groups: Group[]; admin: boolean; tabs: Set<string>
  passkeyAt: string | null; refreshCookie: string | null; commandsOkAt: string | null
  // Face ID made by a tab page itself (/<tab>/_passkey/verify): command windows only, never strong
  commandPasskeyAt: string | null; commandPasskeyTab: string | null
  // "see as": an admin session shown as one non-admin group. groups, admin and tabs above are
  // then that group's; realAdmin keeps what the person really is (only to leave the mode).
  realAdmin: boolean; viewAs: { id: string; name: string } | null
}

class HttpError extends Error {
  // message is a stable error code; the page turns it into text for people
  constructor(public status: number, message: string, public extra: Row = {}) { super(message) }
}

// ------------------------------------------------------------------ small helpers
const now = () => new Date().toISOString()
const inMs = (ms: number) => new Date(Date.now() + ms).toISOString()

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

const randomToken = (bytes = 32) => b64url(crypto.getRandomValues(new Uint8Array(bytes)))

function newCode(): string {
  const b = crypto.getRandomValues(new Uint8Array(4))
  return 'A5-' + [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join('')
}

// Constant-time comparison: hash both sides, then compare fixed-length digests.
async function sameSecret(a: string, b: string): Promise<boolean> {
  if (!a || !b) return false
  const [x, y] = await Promise.all([sha256(a), sha256(b)])
  let diff = 0
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i)
  return diff === 0
}

// Digits only, country code first. Brazilian mobiles are stored with the 9th digit, since
// WhatsApp ids for older numbers often drop it.
export function normalizePhone(raw: unknown): string | null {
  let d = String(raw ?? '').replace(/@.*$/, '').replace(/\D/g, '')
  if (!d) return null
  if (d.length === 10 || d.length === 11) d = '55' + d
  if (d.startsWith('55') && d.length === 12 && /[6-9]/.test(d[4])) d = d.slice(0, 4) + '9' + d.slice(4)
  if (d.length < 10 || d.length > 15) return null
  return d
}

function text(v: unknown, max: number): string | null {
  const s = String(v ?? '').replace(/[\u0000-\u001f\u007f<>]/g, ' ').trim()
  return s ? s.slice(0, max) : null
}

function deviceLabel(ua: string | null, mode: unknown): string {
  const u = ua ?? ''
  const os = /iPhone/.test(u) ? 'iPhone' : /iPad/.test(u) ? 'iPad' : /Android/.test(u) ? 'Android'
    : /Macintosh|Mac OS X/.test(u) ? 'Mac' : /Windows/.test(u) ? 'Windows' : /Linux/.test(u) ? 'Linux' : 'device'
  const br = /Edg\//.test(u) ? 'Edge' : /Firefox\//.test(u) ? 'Firefox' : /CriOS|Chrome\//.test(u) ? 'Chrome'
    : /Safari\//.test(u) ? 'Safari' : 'browser'
  return mode === 'app' ? `${os} · app` : `${os} · ${br}`
}

const clientIp = (req: Request) => req.headers.get('CF-Connecting-IP') ?? 'local'

function place(req: Request): string | null {
  const cf = (req as unknown as { cf?: Row }).cf
  if (!cf) return null
  const bits = [cf.city, cf.region, cf.asn ? `AS${cf.asn}` : null, cf.asOrganization].filter(Boolean).map(String)
  return bits.length ? bits.join(', ').slice(0, 120) : null
}

function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...API_HEADERS, ...extra },
  })
}

async function body(req: Request): Promise<Row> {
  const raw = await req.text()
  if (raw.length > 16_384) throw new HttpError(413, 'too_large')
  try {
    const b = JSON.parse(raw || '{}')
    return b && typeof b === 'object' && !Array.isArray(b) ? (b as Row) : {}
  } catch {
    throw new HttpError(400, 'bad_json')
  }
}

function cookieValue(req: Request, name: string): string | null {
  const h = req.headers.get('Cookie') ?? ''
  for (const part of h.split(';')) {
    const i = part.indexOf('=')
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim()
  }
  return null
}

// Lax, not Strict: a link from WhatsApp or a shortcut must arrive signed in.
const sessionDays = (kind: string) => (kind === 'screen' ? SCREEN_DAYS : SESSION_DAYS)
const sessionCookie = (token: string, kind = 'browser') =>
  `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${sessionDays(kind) * 86400}`
const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`

const strength = (who: Who | null) => (who ? (fresh(who) ? 'strong' : 'weak') : null)
const fresh = (who: Who) => !!who.passkeyAt && Date.now() - Date.parse(who.passkeyAt) < PASSKEY_FRESH_MS
// "strong" as told to tabs, commands and the page: only an admin's (08/11: everyone may
// have a passkey now, and a resident's Face ID only opens the `passkey` windows of the catalog)
const strongAdmin = (who: Who) => who.admin && fresh(who)

async function audit(env: Env, req: Request | null, a: { who?: Who | null; person?: number | null; strength?: string | null; action: string; target?: string | null; detail?: unknown }) {
  // anything done while seeing as another group says so in its audit row
  const view = a.who?.viewAs?.id
  if (view) a = { ...a, detail: a.detail != null && typeof a.detail === 'object' && !Array.isArray(a.detail) ? { ...a.detail, view_as: view } : { value: a.detail ?? null, view_as: view } }
  await env.DB.prepare('INSERT INTO audit (at, person_id, session_id, strength, action, target, detail, ip, place) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(now(), a.person ?? a.who?.person.id ?? null, a.who?.sessionId ?? null, a.strength ?? strength(a.who ?? null), a.action,
      a.target ?? null, a.detail == null ? null : JSON.stringify(a.detail).slice(0, 2000),
      req ? clientIp(req) : null, req ? place(req) : null)
    .run()
}

// Fixed-window counter keyed by `window` (default: the hour). False once over `max`.
async function underLimit(env: Env, bucket: string, max: number, window = now().slice(0, 13)): Promise<boolean> {
  const r = await env.DB.prepare(
    'INSERT INTO rate_limits (bucket, hour, n) VALUES (?, ?, 1) ON CONFLICT (bucket, hour) DO UPDATE SET n = n + 1 RETURNING n',
  ).bind(bucket, window).first<{ n: number }>()
  return (r?.n ?? 0) <= max
}

// Every non-GET request must come from this exact origin and carry X-Portal: 1
// (a header a cross-site form cannot set). GET never changes state.
function requireSameOrigin(req: Request, url: URL) {
  if (req.method === 'GET' || req.method === 'HEAD') return
  if (req.headers.get('Origin') !== url.origin) throw new HttpError(403, 'bad_origin')
  if (req.headers.get('X-Portal') !== '1') throw new HttpError(403, 'missing_x_portal')
}

// ------------------------------------------------------------------ people and groups
async function groupsOf(env: Env, personId: number): Promise<Group[]> {
  const r = await env.DB.prepare(
    'SELECT g.* FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE pg.person_id = ?',
  ).bind(personId).all<Group>()
  return r.results
}

function tabsOf(groups: Group[]): Set<string> {
  const s = new Set<string>()
  for (const g of groups) {
    try { for (const t of JSON.parse(g.tabs) as string[]) s.add(String(t)) } catch { /* bad JSON = no tabs */ }
  }
  return s
}

const personByPhone = (env: Env, phone: string) => env.DB.prepare('SELECT * FROM people WHERE phone = ?').bind(phone).first<Person>()

// The owner bootstraps on first sign-in: their number is a secret, never a row in a migration.
async function ensureOwner(env: Env, phone: string): Promise<Person | null> {
  const owner = normalizePhone(env.OWNER_PHONE)
  if (!owner || owner !== phone) return null
  const p = await env.DB.prepare(
    `INSERT INTO people (name, phone, status) VALUES ('Owner', ?, 'active')
     ON CONFLICT (phone) DO UPDATE SET status = 'active' RETURNING *`,
  ).bind(phone).first<Person>()
  await env.DB.prepare('INSERT OR IGNORE INTO person_groups (person_id, group_id) VALUES (?, ?)').bind(p!.id, OWNER_GROUP).run()
  return p
}

// ------------------------------------------------------------------ sessions
// One D1 round trip per request (about 150 ms from Brazil to the database): the session, the
// person, their groups, the "see as" group and, for a tab with Face ID on entry, the last entry
// all come back in one query. Same checks as before, only fewer trips.
async function currentSession(req: Request, env: Env, entryTab: string | null = null): Promise<Who | null> {
  const token = cookieValue(req, COOKIE)
  if (!token || token.length < 40) return null
  const entryHours = entryTab ? policyOf(entryTab).entryHours : 0
  const s = await env.DB.prepare(
    `SELECT s.id AS sid, s.kind AS skind, s.created_at AS screated, s.last_used_at, s.passkey_at, s.command_passkey_at, s.command_passkey_tab, s.commands_ok_at, s.view_as, p.*,
       (SELECT json_group_array(json_object('id', g.id, 'name', g.name, 'tabs', g.tabs, 'is_admin', g.is_admin))
          FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE pg.person_id = s.person_id) AS groups_json,
       (SELECT json_object('id', v.id, 'name', v.name, 'tabs', v.tabs, 'is_admin', v.is_admin) FROM groups v WHERE v.id = s.view_as) AS view_json,
       (SELECT MAX(e.used_at) FROM tab_entries e WHERE e.session_id = s.id AND e.tab = ? AND e.used_at > ? AND e.granted_at >= s.created_at) AS entry_used_at
     FROM sessions s JOIN people p ON p.id = s.person_id
     WHERE s.token_hash = ? AND s.expires_at > ?`,
  ).bind(entryTab ?? '', inMs(-entryHours * 3600e3), await sha256(token), now()).first<Row>()
  if (!s || s.status !== 'active') return null
  const kind = s.skind === 'screen' ? 'screen' : 'browser'
  let refreshCookie: string | null = null
  if (Date.now() - Date.parse(String(s.last_used_at)) > SESSION_TOUCH_MS) {
    await env.DB.prepare('UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE id = ?')
      .bind(now(), inMs(sessionDays(kind) * 864e5), s.sid).run()
    refreshCookie = sessionCookie(token, kind)
  }
  const person: Person = { id: Number(s.id), name: String(s.name), phone: String(s.phone), status: String(s.status), kind: String(s.kind) }
  const real = parseGroups(s.groups_json)
  // a screen account is never an admin, whatever its groups say
  const realAdmin = kind === 'browser' && person.kind !== 'screen' && real.some((g) => g.is_admin)
  // "see as" only ever narrows: kept only while the person is an admin and the group is not one
  let view: Group | null = null
  if (realAdmin && s.view_as && s.view_json) {
    const g = parseGroups(`[${String(s.view_json)}]`)[0]
    if (g && !g.is_admin) view = g
  }
  const groups = view ? [view] : real
  return {
    person, sessionId: Number(s.sid), sessionCreatedAt: String(s.screated), kind, groups, admin: realAdmin && !view, tabs: tabsOf(groups),
    passkeyAt: (s.passkey_at as string | null) ?? null, refreshCookie, commandsOkAt: (s.commands_ok_at as string | null) ?? null,
    commandPasskeyAt: (s.command_passkey_at as string | null) ?? null, commandPasskeyTab: (s.command_passkey_tab as string | null) ?? null,
    realAdmin, viewAs: view ? { id: view.id, name: view.name } : null,
    entryUsedAt: entryTab ? ((s.entry_used_at as string | null) ?? null) : undefined,
  }
}

// groups as json_object rows: is_admin back to a number, tabs stays the stored JSON text
function parseGroups(raw: unknown): Group[] {
  let v: unknown
  try { v = JSON.parse(String(raw ?? '[]')) } catch { return [] }
  if (!Array.isArray(v)) return []
  return v.filter((g) => g && typeof g === 'object' && typeof g.id === 'string')
    .map((g) => ({ id: String(g.id), name: String(g.name), tabs: String(g.tabs ?? '[]'), is_admin: Number(g.is_admin) ? 1 : 0 }))
}

async function requireSession(req: Request, env: Env): Promise<Who> {
  const who = await currentSession(req, env)
  if (!who) throw new HttpError(401, 'signed_out')
  return who
}

// Admin writes: admin group + passkey checked in the last 5 minutes on this session.
function requireStrongAdmin(who: Who) {
  if (!who.admin) throw new HttpError(403, 'admin_only')
  if (!fresh(who)) throw new HttpError(403, 'passkey_required', { passkey: true })
}

// Every session delete goes through here: the rows tied to the session id go with it, and the
// tabs close its sockets. (Session ids are AUTOINCREMENT since migration 0004, so an id is never
// reused; this is the second barrier.)
async function dropSessions(env: Env, ids: number[]) {
  for (const id of ids) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id),
      env.DB.prepare('DELETE FROM tab_entries WHERE session_id = ?').bind(id),
      env.DB.prepare('DELETE FROM passkey_challenges WHERE session_id = ?').bind(id),
    ])
    await notifyTabs(env, { session: id })
  }
}

async function createSession(env: Env, req: Request, person: Person, label: string): Promise<string> {
  const groups = await groupsOf(env, person.id)
  const admin = groups.some((g) => g.is_admin)
  if (!admin) {
    // keep the newest MAX_DEVICES - 1, so the new one fits
    const old = await env.DB.prepare('SELECT id FROM sessions WHERE person_id = ? ORDER BY last_used_at DESC LIMIT -1 OFFSET ?')
      .bind(person.id, MAX_DEVICES - 1).all<{ id: number }>()
    await dropSessions(env, old.results.map((o) => o.id))
  }
  const token = randomToken(32)
  const t = now()
  const r = await env.DB.prepare(
    `INSERT INTO sessions (person_id, token_hash, kind, label, ip, place, created_at, last_used_at, expires_at)
     VALUES (?, ?, 'browser', ?, ?, ?, ?, ?, ?) RETURNING id`,
  ).bind(person.id, await sha256(token), label, clientIp(req), place(req), t, t, inMs(SESSION_DAYS * 864e5)).first<{ id: number }>()
  await env.DB.prepare(
    'INSERT INTO audit (at, person_id, session_id, strength, action, target, ip, place) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(t, person.id, r!.id, 'weak', admin ? 'login_admin' : 'login', label, clientIp(req), place(req)).run()
  if (admin)
    await env.DB.prepare('INSERT INTO device_alerts (person_id, session_id, label, place, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(person.id, r!.id, label, place(req), t).run()
  else {
    // every new resident device warns the admins at once, with a way to sign it out (08/11)
    const admins = await env.DB.prepare('SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1').all<{ person_id: number }>()
    for (const a of admins.results)
      await env.DB.prepare("INSERT INTO device_alerts (person_id, session_id, label, place, created_at, kind) VALUES (?, ?, ?, ?, ?, 'resident_login')")
        .bind(a.person_id, r!.id, `${person.name} · ${label}`, place(req), t).run()
  }
  return token
}

// ------------------------------------------------------------------ fixed screens
// The screen asks for a code and shows it (and a QR). A strong admin types the code and picks
// the screen account. The screen's poll then gets a 1-year session, renewed on use. A screen
// account has one live session: pairing again replaces the old one.
function newPairCode(): string {
  const b = crypto.getRandomValues(new Uint8Array(6))
  return [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join('')
}
const normPairCode = (v: unknown) => String(v ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12)

async function pairStart(req: Request, env: Env, url: URL) {
  if (!(await underLimit(env, `pair-ip:${clientIp(req)}`, LIMITS.pairPerIp))) throw new HttpError(429, 'too_many_attempts')
  await env.DB.prepare('DELETE FROM screen_pairings WHERE expires_at < ?').bind(inMs(-864e5)).run()
  const code = newPairCode()
  const secret = randomToken(24)
  const expires = inMs(PAIR_MINUTES * 60e3)
  await env.DB.prepare('INSERT INTO screen_pairings (code_hash, secret_hash, label, ip, place, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256(code), await sha256(secret), deviceLabel(req.headers.get('User-Agent'), null), clientIp(req), place(req), now(), expires).run()
  return json({ code: `${code.slice(0, 3)}-${code.slice(3)}`, secret, expires_at: expires, pair_url: `${url.origin}/?pair=${code}` }, 201)
}

async function pairStatus(req: Request, env: Env) {
  if (!(await underLimit(env, `status-ip:${clientIp(req)}`, LIMITS.statusPerIp))) throw new HttpError(429, 'too_many_polls')
  const b = await body(req)
  const secret = String(b.secret ?? '')
  if (secret.length < 30) throw new HttpError(400, 'missing_secret')
  const p = await env.DB.prepare('SELECT * FROM screen_pairings WHERE secret_hash = ?').bind(await sha256(secret)).first<Row>()
  if (!p) throw new HttpError(404, 'code_not_found')
  const state = String(p.state)
  if (state === 'used' || state === 'refused') return json({ status: state })
  if (state === 'waiting') return json(String(p.expires_at) < now() ? { status: 'expired' } : { status: 'waiting', expires_at: p.expires_at })
  // approved: burn it and hand out the session exactly once, if picked up in time
  if (Date.parse(String(p.expires_at)) + PAIR_PICKUP_GRACE_MS < Date.now()) {
    await env.DB.prepare(`UPDATE screen_pairings SET state = 'refused' WHERE id = ? AND state = 'approved'`).bind(p.id).run()
    return json({ status: 'expired' })
  }
  const r = await env.DB.prepare(`UPDATE screen_pairings SET state = 'used' WHERE id = ? AND state = 'approved'`).bind(p.id).run()
  if (!r.meta.changes) return json({ status: 'used' })
  const screen = await env.DB.prepare(`SELECT * FROM people WHERE id = ? AND kind = 'screen' AND status = 'active'`).bind(p.person_id).first<Person>()
  if (!screen) return json({ status: 'refused' })
  const old = await env.DB.prepare('SELECT id FROM sessions WHERE person_id = ?').bind(screen.id).all<{ id: number }>()
  const token = randomToken(32)
  const t = now()
  const s = await env.DB.prepare(
    `INSERT INTO sessions (person_id, token_hash, kind, label, ip, place, created_at, last_used_at, expires_at)
     VALUES (?, ?, 'screen', ?, ?, ?, ?, ?, ?) RETURNING id`,
  ).bind(screen.id, await sha256(token), String(p.label ?? ''), clientIp(req), place(req), t, t, inMs(SCREEN_DAYS * 864e5)).first<{ id: number }>()
  await dropSessions(env, old.results.map((o) => o.id))
  await env.DB.prepare('INSERT INTO audit (at, person_id, session_id, strength, action, target, ip, place) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(t, screen.id, s!.id, 'screen', 'screen_signed_in', String(p.label ?? ''), clientIp(req), place(req)).run()
  return json({ status: 'ok', name: screen.name }, 200, { 'Set-Cookie': sessionCookie(token, 'screen') })
}

const refuseOtherIp = (env: Env) => env.PAIR_OTHER_IP !== 'warn'

// What the admin sees before approving: who is asking and whether it came from the same
// network as the admin's phone (the "device code" scam sends a code made somewhere else).
async function pairLookup(req: Request, env: Env, url: URL) {
  const code = normPairCode(url.searchParams.get('code'))
  const p = await env.DB.prepare(`SELECT label, place, ip, created_at, expires_at FROM screen_pairings WHERE code_hash = ? AND expires_at > ? AND state = 'waiting' AND request_id IS NULL`)
    .bind(await sha256(code), now()).first<Row>()
  if (!p) throw new HttpError(404, 'pair_code_not_found')
  return { ...p, same_ip: p.ip === clientIp(req), admin_ip: clientIp(req), other_ip_refused: refuseOtherIp(env) }
}

async function pairApprove(env: Env, req: Request, who: Who) {
  const b = await body(req)
  const code = normPairCode(b.code)
  const p = await env.DB.prepare(`SELECT * FROM screen_pairings WHERE code_hash = ? AND expires_at > ? AND state = 'waiting' AND request_id IS NULL`)
    .bind(await sha256(code), now()).first<Row>()
  if (!p) throw new HttpError(404, 'pair_code_not_found')
  const sameIp = p.ip === clientIp(req)
  if (!sameIp && refuseOtherIp(env)) {
    await audit(env, req, { who, action: 'screen_pair_refused', detail: { reason: 'other_ip', ip: p.ip, label: p.label } })
    throw new HttpError(409, 'pair_other_network')
  }
  let screen: Person | null
  if (b.screen != null) {
    screen = await env.DB.prepare(`SELECT * FROM people WHERE id = ? AND kind = 'screen'`).bind(Number(b.screen)).first<Person>()
    if (!screen) throw new HttpError(404, 'screen_not_found')
    if (screen.status !== 'active') throw new HttpError(409, 'screen_blocked')
  } else {
    const name = text(b.name, 40)
    if (!name) throw new HttpError(400, 'name_required')
    screen = await env.DB.prepare(`INSERT INTO people (name, phone, status, kind, created_by) VALUES (?, ?, 'active', 'screen', ?) RETURNING *`)
      .bind(name, `screen:${randomToken(9)}`, who.person.id).first<Person>()
    await env.DB.prepare(`INSERT INTO person_groups (person_id, group_id) VALUES (?, 'residents')`).bind(screen!.id).run()
  }
  const r = await env.DB.prepare(`UPDATE screen_pairings SET state = 'approved', person_id = ?, approved_by = ?, approved_at = ? WHERE id = ? AND state = 'waiting'`)
    .bind(screen!.id, who.person.id, now(), p.id).run()
  if (!r.meta.changes) throw new HttpError(404, 'pair_code_not_found')
  await audit(env, req, { who, action: 'screen_paired', target: screen!.name, detail: { screen: screen!.id, label: p.label, place: p.place, ip: p.ip, same_ip: sameIp } })
  return { ok: true, screen: screen!.id }
}

// ------------------------------------------------------------------ machine keys (bridges)
async function listMachines(env: Env) {
  const r = await env.DB.prepare('SELECT id, tab, label, created_at, last_used_at, last_ip, revoked_at FROM machine_keys ORDER BY id DESC LIMIT 100').all<Row>()
  return r.results
}

async function addMachine(env: Env, req: Request, who: Who) {
  const b = await body(req)
  const tab = String(b.tab ?? '')
  if (!tabBindings(env)[tab]) throw new HttpError(400, 'unknown_tab')
  if (!policyOf(tab).credentials.includes('machine')) throw new HttpError(409, 'tab_takes_no_machine')
  const label = text(b.label, 40)
  if (!label) throw new HttpError(400, 'name_required')
  const key = MACHINE_KEY_PREFIX + randomToken(32)
  const r = await env.DB.prepare('INSERT INTO machine_keys (tab, label, key_hash, created_at, created_by) VALUES (?, ?, ?, ?, ?) RETURNING id')
    .bind(tab, label, await sha256(key), now(), who.person.id).first<{ id: number }>()
  await audit(env, req, { who, action: 'machine_key_created', target: `${tab}:${label}`, detail: { id: r!.id } })
  // shown once; only the hash stays
  return { id: r!.id, tab, label, key }
}

async function revokeMachine(env: Env, req: Request, who: Who, id: number) {
  const m = await env.DB.prepare('UPDATE machine_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING tab, label').bind(now(), id).first<Row>()
  if (!m) throw new HttpError(404, 'machine_not_found')
  await notifyTabs(env, { machine: id }, String(m.tab))
  await audit(env, req, { who, action: 'machine_key_revoked', target: `${m.tab}:${m.label}` })
}

// GET /_bridge/<tab> with Upgrade: websocket and X-A5-Machine-Key. The key opens one tab only.
async function bridge(req: Request, env: Env, tab: string): Promise<Response> {
  const service = tabService(env, tab)
  if (!service || !policyOf(tab).credentials.includes('machine')) throw new HttpError(404, 'not_found')
  if (req.method !== 'GET' || !isUpgrade(req)) throw new HttpError(426, 'websocket_required')
  const key = req.headers.get('X-A5-Machine-Key') ?? ''
  const refuse = async (reason: string) => {
    if (!(await underLimit(env, `bridge-fail-ip:${clientIp(req)}`, LIMITS.bridgeFailPerIp))) throw new HttpError(429, 'too_many_attempts')
    await audit(env, req, { strength: 'machine', action: 'bridge_refused', target: tab, detail: { reason } })
    throw new HttpError(401, 'bad_key')
  }
  if (!key.startsWith(MACHINE_KEY_PREFIX) || key.length < 40 || key.length > 80) return refuse('format')
  // looked up by hash (unique index); the hash itself is the constant-time part
  const m = await env.DB.prepare('SELECT id, tab, label, revoked_at, last_ip FROM machine_keys WHERE key_hash = ?').bind(await sha256(key)).first<Row>()
  if (!m) return refuse('unknown')
  if (m.revoked_at) return refuse('revoked')
  if (m.tab !== tab) return refuse('other_tab')
  const id = Number(m.id)
  const hour = now().slice(0, 13)
  if (!(await underLimit(env, `bridge:${id}`, BRIDGE_MAX_PER_HOUR, hour))) throw new HttpError(429, 'too_many_attempts')
  const n = (await env.DB.prepare('SELECT n FROM rate_limits WHERE bucket = ? AND hour = ?').bind(`bridge:${id}`, hour).first<{ n: number }>())?.n ?? 1
  await env.DB.prepare('UPDATE machine_keys SET last_used_at = ?, last_ip = ? WHERE id = ?').bind(now(), clientIp(req), id).run()
  const newIp = !!m.last_ip && m.last_ip !== clientIp(req)
  await audit(env, req, { strength: 'machine', action: newIp ? 'bridge_new_ip' : 'bridge_connected', target: `${tab}:${m.label}`, detail: { machine: id, n, ...(newIp ? { previous_ip: m.last_ip } : {}) } })
  // a new bridge replacing the old one more than 3 times in an hour, or a key used from a new
  // address: tell every admin
  if (n === BRIDGE_ALERT_PER_HOUR + 1) await alertAdmins(env, req, `${tab}:${m.label}`, 'bridge')
  if (newIp) await alertAdmins(env, req, `${tab}:${m.label}`, 'bridge_ip')
  const identity: PortalIdentity = {
    credential: 'machine', person: null, name: String(m.label), groups: [], session: null, machine: id, shortcut: null,
    strong: false, entered_at: null, entry_until: null, admin_until: null, actions: [], passkey_until: {},
  }
  return forwardSocket(env, req, service, tab, identity, null)
}

// ------------------------------------------------------------------ login (browser side)
// Same answer for known, unknown and blocked numbers: nothing here tells who is registered.
async function loginStart(req: Request, env: Env) {
  const b = await body(req)
  const phone = normalizePhone(b.phone)
  if (!phone) throw new HttpError(400, 'bad_number')
  if (!(await underLimit(env, `start-ip:${clientIp(req)}`, LIMITS.startPerIp))) throw new HttpError(429, 'too_many_attempts')
  if (!(await underLimit(env, `start-num:${phone}`, LIMITS.startPerNumber))) throw new HttpError(429, 'too_many_for_number')
  const owner = normalizePhone(env.OWNER_PHONE)
  if (!owner) throw new HttpError(503, 'not_configured')

  // housekeeping, all on indexed columns
  await env.DB.batch([
    env.DB.prepare('DELETE FROM login_codes WHERE expires_at < ?').bind(inMs(-864e5)),
    env.DB.prepare('DELETE FROM rate_limits WHERE hour < ?').bind(inMs(-3 * 3600e3).slice(0, 13)),
    env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at < ?').bind(now()),
  ])

  let code = ''
  for (let i = 0; i < 8; i++) {
    code = newCode()
    const busy = await env.DB.prepare('SELECT 1 FROM login_codes WHERE code_hash = ? AND expires_at > ?').bind(await sha256(code), now()).first()
    if (!busy) break
  }
  const secret = randomToken(24)
  const expires = inMs(CODE_MINUTES * 60e3)
  await env.DB.batch([
    // one live code per number: the previous one dies now
    env.DB.prepare(`UPDATE login_codes SET expires_at = ? WHERE typed_phone = ? AND state = 'waiting' AND expires_at > ?`).bind(now(), phone, now()),
    env.DB.prepare('INSERT INTO login_codes (code_hash, secret_hash, typed_phone, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(await sha256(code), await sha256(secret), phone, deviceLabel(req.headers.get('User-Agent'), b.mode), now(), expires),
  ])
  const message = LOGIN_PHRASE + code
  return json({ code, secret, expires_at: expires, message, wa_link: `https://wa.me/${owner}?text=${encodeURIComponent(message)}` }, 201)
}

async function loginStatus(req: Request, env: Env) {
  if (!(await underLimit(env, `status-ip:${clientIp(req)}`, LIMITS.statusPerIp))) throw new HttpError(429, 'too_many_polls')
  const b = await body(req)
  const secret = String(b.secret ?? '')
  if (secret.length < 30) throw new HttpError(400, 'missing_secret')
  const c = await env.DB.prepare('SELECT * FROM login_codes WHERE secret_hash = ?').bind(await sha256(secret)).first<Row>()
  if (!c) throw new HttpError(404, 'code_not_found')
  const state = String(c.state)
  if (state === 'used' || state === 'refused') return json({ status: state })
  if (String(c.expires_at) < now()) return json({ status: 'expired' })
  if (state === 'waiting') return json({ status: state, expires_at: c.expires_at })
  if (state === 'pending') {
    // why the owner must decide, said only from what this visitor already knows (the number typed
    // and the number they sent from): never whether some other number is registered
    const lr = await env.DB.prepare('SELECT sender_phone FROM link_requests WHERE code_id = ?').bind(c.id).first<Row>()
    return json({ status: state, expires_at: c.expires_at, why: lr && lr.sender_phone === c.typed_phone ? 'new_number' : 'other_number' })
  }
  // confirmed: burn the code and hand out the session exactly once
  const r = await env.DB.prepare(`UPDATE login_codes SET state = 'used' WHERE id = ? AND state = 'confirmed'`).bind(c.id).run()
  if (!r.meta.changes) return json({ status: 'used' })
  const p = await env.DB.prepare('SELECT * FROM people WHERE id = ?').bind(c.confirmed_person_id).first<Person>()
  if (!p || p.status !== 'active') return json({ status: 'refused' })
  const token = await createSession(env, req, p, deviceLabel(req.headers.get('User-Agent'), b.mode))
  return json({ status: 'ok', name: p.name }, 200, { 'Set-Cookie': sessionCookie(token) })
}

// ------------------------------------------------------------------ login (robot side)
// POST /robo/login. The WhatsApp reader saw the exact phrase in a private chat and reports the
// number WhatsApp proved sent it. Identity is always the sender, never the number typed.
// The key opens this route only, and a session born here is weak.
async function robotLogin(req: Request, env: Env) {
  const key = env.ROBOT_LOGIN_KEY ?? ''
  if (!key.startsWith(ROBOT_KEY_PREFIX) || key.length < 40) throw new HttpError(503, 'robot_key_not_configured')
  if (!(await sameSecret(req.headers.get('X-A5-Robot-Key') ?? '', key))) throw new HttpError(401, 'bad_key')
  const b = await body(req)
  const m = /^A5-[A-Z0-9]{4}$/.exec(String(b.code ?? '').trim().toUpperCase())
  if (!m) throw new HttpError(400, 'missing_code')
  const code = m[0]
  const sender = normalizePhone(b.phone)
  if (!sender) throw new HttpError(400, 'missing_number')
  const self = b.self_chat === true
  const owner = normalizePhone(env.OWNER_PHONE)
  if (self && sender !== owner) throw new HttpError(400, 'self_chat_not_owner')
  const msgId = text(b.msg_id, 80)

  if (!(await underLimit(env, 'robot-total', LIMITS.robotTotal))) return json({ ok: false, reason: 'total_limit' })
  if (!(await underLimit(env, `robot:${sender}`, LIMITS.robotPerSender))) return json({ ok: false, reason: 'sender_limit' })

  const c = await env.DB.prepare(`SELECT * FROM login_codes WHERE code_hash = ? AND expires_at > ? AND state IN ('waiting', 'confirmed', 'pending') ORDER BY id DESC`)
    .bind(await sha256(code), now()).first<Row>()
  const reqInfo = { msg_id: msgId, self_chat: self }
  if (!c) {
    await audit(env, req, { strength: 'robot', action: 'robot_invalid_code', detail: reqInfo })
    return json({ ok: false, reason: 'invalid_code' })
  }
  const device = { device: c.label, requested_at: c.created_at }
  if (c.state === 'confirmed') return json({ ok: true, repeated: true, ...device })
  if (c.state === 'pending') return json({ ok: false, reason: 'awaiting_owner', repeated: true, ...device })

  let person = await personByPhone(env, sender)
  if (!person) person = await ensureOwner(env, sender)

  if (person && person.status === 'blocked') {
    await env.DB.prepare(`UPDATE login_codes SET state = 'refused' WHERE id = ?`).bind(c.id).run()
    await audit(env, req, { person: person.id, strength: 'robot', action: 'robot_blocked', detail: reqInfo })
    return json({ ok: false, reason: 'blocked' })
  }

  if (person && sender === c.typed_phone) {
    // admin numbers: at most one accepted login every 10 minutes
    const admin = (await groupsOf(env, person.id)).some((g) => g.is_admin)
    if (admin && !(await underLimit(env, `robot-admin:${sender}`, 1, now().slice(0, 15))))
      return json({ ok: false, reason: 'admin_limit' })
    await env.DB.prepare(`UPDATE login_codes SET state = 'confirmed', confirmed_at = ?, confirmed_person_id = ? WHERE id = ? AND state = 'waiting'`)
      .bind(now(), person.id, c.id).run()
    await audit(env, req, { person: person.id, strength: 'robot', action: 'robot_confirmed', target: String(c.label ?? ''), detail: reqInfo })
    return json({ ok: true, ...device })
  }

  // Unknown sender, or a sender other than the number typed: nobody signs in. The owner decides.
  const pending = await env.DB.prepare(`SELECT COUNT(*) AS n FROM link_requests WHERE state = 'pending' AND expires_at > ?`).bind(now()).first<{ n: number }>()
  if ((pending?.n ?? 0) >= PENDING_MAX) {
    await env.DB.prepare(`UPDATE login_codes SET state = 'refused' WHERE id = ?`).bind(c.id).run()
    return json({ ok: false, reason: 'too_many_pending' })
  }
  await env.DB.batch([
    env.DB.prepare(`UPDATE login_codes SET state = 'pending' WHERE id = ? AND state = 'waiting'`).bind(c.id),
    env.DB.prepare(
      `INSERT INTO link_requests (code_id, typed_phone, sender_phone, sender_person_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (code_id) DO NOTHING`,
    ).bind(c.id, c.typed_phone, sender, person?.id ?? null, now(), inMs(PENDING_DAYS * 864e5)),
  ])
  await audit(env, req, { person: person?.id ?? null, strength: 'robot', action: 'robot_pending', detail: { ...reqInfo, mismatch: !!person } })
  return json({ ok: false, reason: 'awaiting_owner', ...device })
}

// ------------------------------------------------------------------ passkeys
const rpOf = (url: URL) => ({ id: url.hostname, origin: url.origin })

async function passkeyCount(env: Env, personId: number) {
  return (await env.DB.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE person_id = ?').bind(personId).first<{ n: number }>())?.n ?? 0
}

async function newChallenge(env: Env, who: Who, kind: 'create' | 'get', purpose: string | null = null) {
  const challenge = randomToken(32)
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM passkey_challenges WHERE session_id = ? AND kind = ? AND ${NOT_TAB_CHALLENGE}`).bind(who.sessionId, kind),
    env.DB.prepare('INSERT INTO passkey_challenges (session_id, kind, challenge, expires_at, purpose) VALUES (?, ?, ?, ?, ?)')
      .bind(who.sessionId, kind, challenge, inMs(CHALLENGE_MS), purpose),
  ])
  return challenge
}

// A tab page's own Face ID ('tabcmd:<tab>', /<tab>/_passkey/*) lives beside the portal's challenge:
// neither replaces nor takes the other (a tab prefetching never drops an approval waiting on the portal,
// and the portal's verify never turns a tab challenge into a strong session).
const NOT_TAB_CHALLENGE = "(purpose IS NULL OR purpose NOT LIKE 'tabcmd:%')"

async function takeChallenge(env: Env, who: Who, kind: 'create' | 'get'): Promise<{ challenge: string; purpose: string | null }> {
  const c = await env.DB.prepare(`DELETE FROM passkey_challenges WHERE session_id = ? AND kind = ? AND expires_at > ? AND ${NOT_TAB_CHALLENGE} RETURNING challenge, purpose`)
    .bind(who.sessionId, kind, now()).first<{ challenge: string; purpose: string | null }>()
  if (!c) throw new HttpError(400, 'challenge_expired')
  return c
}

// 'entry:<tab>' for a tab this session can open whose policy asks a passkey on entry;
// 'agent:<id>' for an admin approving what an agent prepared (the Face ID is the approval).
async function checkPurpose(env: Env, who: Who, raw: unknown): Promise<string | null> {
  const pm = /^agent:(\d{1,12})$/.exec(String(raw ?? ''))
  if (pm) {
    if (!who.admin) throw new HttpError(403, 'admin_only')
    await pendingAgentRequest(env, Number(pm[1]), true)
    return `agent:${Number(pm[1])}`
  }
  const cm = /^command:([a-z][a-z0-9-]{0,30})$/.exec(String(raw ?? ''))
  if (cm) return commandPurpose(env, who, cm[1])
  return entryPurpose(env, who, raw)
}

// 'command:<tab>': the Face ID a tab page asks for before an owner's command (the tab pages
// cannot run WebAuthn). It only opens the session's window for admin commands (passkey_at, as any
// passkey check does) and is audited; the tab never resends a command on its own afterwards.
// Anyone with the tab may do it when the tab has an action with its own `passkey` window; otherwise
// only an admin, for the tab's admin or sensitive actions. Never while seeing as.
function commandPurpose(env: Env, who: Who, tab: string): string {
  if (who.kind !== 'browser' || who.viewAs) throw new HttpError(403, 'admin_only')
  const catalog = catalogOf(env, tab)
  const needs = Object.values(catalog).some((c) => !!c.passkey || (who.admin && c.level !== 'common'))
  if (!needs && !who.admin) throw new HttpError(403, 'admin_only')
  if (!tabService(env, tab) || !canOpen(who, tab) || !needs) throw new HttpError(400, 'bad_purpose')
  return `command:${tab}`
}

function entryPurpose(env: Env, who: Who, raw: unknown): string | null {
  if (raw == null) return null
  const m = /^entry:([a-z][a-z0-9-]{0,30})$/.exec(String(raw))
  const tab = m?.[1]
  if (!tab || !tabService(env, tab) || policyOf(tab).entry !== 'passkey' || !canOpen(who, tab)) throw new HttpError(400, 'bad_purpose')
  return `entry:${tab}`
}

// From a weak session a passkey can be added only (a) when the portal has no passkey at all,
// once, with the owner in front of the screen, or (b) with an unexpired invite a strong admin
// created for this person. Anything else needs a fresh passkey check.
// A non-admin (resident, 08/11) adds their own (since 08/11 everyone has their own Face ID,
// no waiting; what it unlocks is still the groups and the catalog): the first one from any of their
// sessions, another only after their own Face ID on the portal (or with an invite). At most
// RESIDENT_PASSKEYS each. Every one is an alert to the admins, as is every new resident sign-in.
async function pendingInvite(env: Env, personId: number): Promise<number | null> {
  const inv = await env.DB.prepare('SELECT id FROM passkey_invites WHERE person_id = ? AND expires_at > ? AND used_at IS NULL ORDER BY id DESC')
    .bind(personId, now()).first<{ id: number }>()
  return inv?.id ?? null
}

const RESIDENT_PASSKEYS = 3

async function canAddPasskey(env: Env, who: Who): Promise<number | null> {
  if (who.kind !== 'browser' || who.viewAs || who.person.kind === 'screen') throw new HttpError(403, 'passkey_admin_only')
  if (!who.admin) {
    const count = await passkeyCount(env, who.person.id)
    if (count >= RESIDENT_PASSKEYS) throw new HttpError(409, 'passkey_limit')
    const inv = await pendingInvite(env, who.person.id)
    if (inv) return inv
    // a second key needs the person's own Face ID first (the portal's; a tab's check never counts),
    // so whoever holds a session cannot plant a key of their own beside the person's
    if (count > 0 && !fresh(who)) throw new HttpError(403, 'passkey_required', { passkey: true })
    return null
  }
  if (fresh(who)) return null
  const any = await env.DB.prepare('SELECT 1 FROM passkeys LIMIT 1').first()
  if (!any) return null
  const inv = await env.DB.prepare('SELECT id FROM passkey_invites WHERE person_id = ? AND expires_at > ? AND used_at IS NULL ORDER BY id DESC')
    .bind(who.person.id, now()).first<{ id: number }>()
  if (inv) return inv.id
  throw new HttpError(403, 'passkey_required', { passkey: true })
}

// Any person (never a fixed screen), active.
async function createInvite(env: Env, req: Request, who: Who, personId: number) {
  const target = await env.DB.prepare('SELECT kind, status FROM people WHERE id = ?').bind(personId).first<{ kind: string; status: string }>()
  if (!target) throw new HttpError(404, 'person_not_found')
  if (target.kind === 'screen' || target.status !== 'active') throw new HttpError(409, 'invite_not_allowed')
  await env.DB.prepare('INSERT INTO passkey_invites (person_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(personId, who.person.id, now(), inMs(864e5)).run()
  await audit(env, req, { who, action: 'passkey_invite', target: String(personId) })
}

async function passkeyCreateOptions(env: Env, url: URL, who: Who) {
  await canAddPasskey(env, who)
  const existing = await env.DB.prepare('SELECT credential_id FROM passkeys WHERE person_id = ?').bind(who.person.id).all<{ credential_id: string }>()
  const rp = rpOf(url)
  return {
    challenge: await newChallenge(env, who, 'create'),
    rp: { id: rp.id, name: 'Portal A5' },
    user: { id: b64url(new TextEncoder().encode(`a5-${who.person.id}`)), name: who.person.name, displayName: who.person.name },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    excludeCredentials: existing.results.map((e) => ({ type: 'public-key', id: e.credential_id })),
    timeout: CHALLENGE_MS,
    attestation: 'none',
  }
}

async function passkeyCreateVerify(req: Request, env: Env, url: URL, who: Who) {
  const invite = await canAddPasskey(env, who)
  const b = await body(req)
  const rp = rpOf(url)
  const { challenge } = await takeChallenge(env, who, 'create')
  let reg
  try {
    reg = await verifyRegistration({
      id: String(b.id ?? ''), clientDataJSON: String(b.clientDataJSON ?? ''), authenticatorData: String(b.authenticatorData ?? ''),
      publicKey: String(b.publicKey ?? ''), publicKeyAlgorithm: Number(b.publicKeyAlgorithm),
    }, { challenge, origin: rp.origin, rpId: rp.id })
  } catch (e) {
    if (e instanceof WebAuthnError) throw new HttpError(400, e.message)
    throw e
  }
  const label = text(b.label, 60) ?? deviceLabel(req.headers.get('User-Agent'), null)
  // one invite, one passkey: claim it before inserting (two devices at once cannot both use it)
  if (invite) {
    const claimed = await env.DB.prepare('UPDATE passkey_invites SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(now(), invite).run()
    if (!claimed.meta.changes) throw new HttpError(403, who.admin ? 'passkey_required' : 'passkey_invite_required', who.admin ? { passkey: true } : {})
  }
  if (!who.admin) {
    // the limit holds against two devices registering at once too
    const ins = await env.DB.prepare(`INSERT INTO passkeys (person_id, credential_id, public_key, sign_count, label, created_at)
      SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM passkeys WHERE person_id = ?) < ?`)
      .bind(who.person.id, reg.credentialId, reg.publicKey, reg.signCount, label, now(), who.person.id, RESIDENT_PASSKEYS).run()
    if (!ins.meta.changes) throw new HttpError(409, 'passkey_limit')
    // registering is not a Face ID check: it opens no window and never makes the session strong
    const age = Math.round((Date.now() - Date.parse(who.sessionCreatedAt)) / 3600e3)
    await audit(env, req, { who, action: 'passkey_added', target: label, detail: { ...(invite ? { invite } : { self: true }), session_hours: age, released: !!who.commandsOkAt } })
    await alertAdmins(env, req, `${who.person.name} · ${label}`, 'passkey')
    return { ok: true }
  }
  await env.DB.prepare('INSERT INTO passkeys (person_id, credential_id, public_key, sign_count, label, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(who.person.id, reg.credentialId, reg.publicKey, reg.signCount, label, now()).run()
  await env.DB.prepare('UPDATE sessions SET passkey_at = ? WHERE id = ?').bind(now(), who.sessionId).run()
  await audit(env, req, { who, strength: 'strong', action: 'passkey_added', target: label, detail: invite ? { invite } : null })
  return { ok: true }
}

async function passkeyGetOptions(req: Request, env: Env, url: URL, who: Who) {
  const purpose = await checkPurpose(env, who, (await body(req)).purpose)
  const creds = await env.DB.prepare('SELECT credential_id FROM passkeys WHERE person_id = ?').bind(who.person.id).all<{ credential_id: string }>()
  if (!creds.results.length) throw new HttpError(409, 'no_passkey', { no_passkey: true })
  return {
    challenge: await newChallenge(env, who, 'get', purpose),
    rpId: rpOf(url).id,
    allowCredentials: creds.results.map((c) => ({ type: 'public-key', id: c.credential_id })),
    userVerification: 'required',
    timeout: CHALLENGE_MS,
  }
}

async function passkeyGetVerify(req: Request, env: Env, url: URL, who: Who) {
  const b = await body(req)
  const rp = rpOf(url)
  const { challenge, purpose } = await takeChallenge(env, who, 'get')
  const key = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ? AND person_id = ?')
    .bind(String(b.id ?? ''), who.person.id).first<Row>()
  if (!key) throw new HttpError(400, 'unknown_passkey')
  let count
  try {
    count = await verifyAssertion(
      { clientDataJSON: String(b.clientDataJSON ?? ''), authenticatorData: String(b.authenticatorData ?? ''), signature: String(b.signature ?? '') },
      { publicKey: String(key.public_key), signCount: Number(key.sign_count) },
      { challenge, origin: rp.origin, rpId: rp.id },
    )
  } catch (e) {
    if (e instanceof WebAuthnError) {
      await audit(env, req, { who, action: 'passkey_failed', detail: { reason: e.message } })
      throw new HttpError(400, e.message)
    }
    throw e
  }
  await env.DB.batch([
    env.DB.prepare('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?').bind(count, now(), key.id),
    env.DB.prepare('UPDATE sessions SET passkey_at = ? WHERE id = ?').bind(now(), who.sessionId),
  ])
  if (purpose?.startsWith('agent:')) return approveAgentRequest(env, req, who, Number(purpose.slice(6)))
  if (purpose?.startsWith('command:')) {
    const tab = purpose.slice(8)
    await audit(env, req, { who, strength: 'strong', action: 'command_passkey_ok', target: tab })
    return { ok: true, next: `/${tab}/` }
  }
  if (purpose?.startsWith('entry:')) {
    const tab = purpose.slice(6)
    await env.DB.batch([
      env.DB.prepare('DELETE FROM tab_entries WHERE granted_at < ?').bind(inMs(-2 * 864e5)),
      env.DB.prepare('INSERT INTO tab_entries (session_id, tab, granted_at) VALUES (?, ?, ?)').bind(who.sessionId, tab, now()),
    ])
    await audit(env, req, { who, strength: 'strong', action: 'tab_entry_granted', target: tab })
    return { ok: true, next: `/${tab}/` }
  }
  await audit(env, req, { who, strength: 'strong', action: 'passkey_ok' })
  return { ok: true }
}

// Face ID asked by the tab page itself, on the tap, with only the system sheet (docs/COMMANDS.md).
// The tab comes from the path (a tab's scripts may connect only under their own path), so a page
// can only ever get a 'command:<its tab>' challenge: never an agent approval or another tab's entry.
// Same rules as the portal's step-up for commands. The check opens only command_passkey_at.
async function tabPasskeyOptions(env: Env, url: URL, who: Who, tab: string) {
  commandPurpose(env, who, tab)
  const creds = await env.DB.prepare('SELECT credential_id FROM passkeys WHERE person_id = ?').bind(who.person.id).all<{ credential_id: string }>()
  if (!creds.results.length) throw new HttpError(409, 'no_passkey', { no_passkey: true })
  const challenge = randomToken(32)
  await env.DB.batch([
    env.DB.prepare("DELETE FROM passkey_challenges WHERE session_id = ? AND kind = 'get' AND purpose = ?").bind(who.sessionId, `tabcmd:${tab}`),
    env.DB.prepare("INSERT INTO passkey_challenges (session_id, kind, challenge, expires_at, purpose) VALUES (?, 'get', ?, ?, ?)")
      .bind(who.sessionId, challenge, inMs(CHALLENGE_MS), `tabcmd:${tab}`),
  ])
  return {
    challenge,
    rpId: rpOf(url).id,
    allowCredentials: creds.results.map((c) => ({ type: 'public-key', id: c.credential_id })),
    userVerification: 'required',
    timeout: CHALLENGE_MS,
  }
}

async function tabPasskeyVerify(req: Request, env: Env, url: URL, who: Who, tab: string) {
  // the rules again: seeing as, a lost admin group or a changed catalog since the options
  commandPurpose(env, who, tab)
  const b = await body(req)
  const rp = rpOf(url)
  // only this tab's command challenge; any other pending one (the portal's own) is left alone
  const c = await env.DB.prepare("DELETE FROM passkey_challenges WHERE session_id = ? AND kind = 'get' AND purpose = ? AND expires_at > ? RETURNING challenge")
    .bind(who.sessionId, `tabcmd:${tab}`, now()).first<{ challenge: string }>()
  if (!c) throw new HttpError(400, 'challenge_expired')
  const key = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ? AND person_id = ?')
    .bind(String(b.id ?? ''), who.person.id).first<Row>()
  if (!key) throw new HttpError(400, 'unknown_passkey')
  let count
  try {
    count = await verifyAssertion(
      { clientDataJSON: String(b.clientDataJSON ?? ''), authenticatorData: String(b.authenticatorData ?? ''), signature: String(b.signature ?? '') },
      { publicKey: String(key.public_key), signCount: Number(key.sign_count) },
      { challenge: c.challenge, origin: rp.origin, rpId: rp.id },
    )
  } catch (e) {
    if (e instanceof WebAuthnError) {
      await audit(env, req, { who, action: 'passkey_failed', target: tab, detail: { reason: e.message, via: 'tab' } })
      throw new HttpError(400, e.message)
    }
    throw e
  }
  const t = now()
  await env.DB.batch([
    env.DB.prepare('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?').bind(count, t, key.id),
    env.DB.prepare('UPDATE sessions SET command_passkey_at = ?, command_passkey_tab = ? WHERE id = ?').bind(t, tab, who.sessionId),
  ])
  await audit(env, req, { who, strength: 'tab_passkey', action: 'command_passkey_ok', target: tab, detail: { via: 'tab' } })
  const after: Who = { ...who, commandPasskeyAt: t, commandPasskeyTab: tab }
  return {
    ok: true,
    passkey_until: passkeyUntil(catalogOf(env, tab), callerOf(env, after, tab)),
    admin_until: after.kind === 'browser' && after.admin ? adminWindowUntil(commandPasskeyAt(after, tab), env.ADMIN_COMMAND_PASSKEY) : null,
  }
}

// ------------------------------------------------------------------ "me"
async function alertsOf(env: Env, who: Who) {
  if (!who.admin) return []
  const r = await env.DB.prepare(
    `SELECT a.id, a.kind, a.session_id, a.label, a.place, a.created_at, s.id IS NOT NULL AS live
       FROM device_alerts a LEFT JOIN sessions s ON s.id = a.session_id
      WHERE a.person_id = ? AND a.ack_at IS NULL ORDER BY a.id`,
  ).bind(who.person.id).all<Row>()
  return r.results.map((a) => ({ ...a, live: !!a.live, current: Number(a.session_id) === who.sessionId }))
}

async function me(env: Env, who: Who) {
  // independent reads, sent together: one trip instead of up to five
  const [passkeys, invite, self, alerts, commandsOffNow] = await Promise.all([
    who.viewAs || who.kind !== 'browser' ? 0 : passkeyCount(env, who.person.id),
    !who.admin && !who.viewAs && who.kind === 'browser' ? pendingInvite(env, who.person.id) : null,
    selfPasskeyState(env, who),
    alertsOf(env, who),
    who.admin ? commandsOff(env) : undefined,
  ])
  return {
    person: { id: who.person.id, name: who.person.name },
    groups: who.groups.map((g) => ({ id: g.id, name: g.name })),
    admin: who.admin,
    view_as: who.viewAs,
    // the page shows a made-up resident then (its name lives in the locale)
    rehearsal: !!who.viewAs,
    tabs: who.tabs.has('*') ? Object.keys(tabBindings(env)) : [...who.tabs],
    all_tabs: who.admin ? Object.keys(tabBindings(env)) : [],
    screen_tabs: who.admin ? Object.keys(tabBindings(env)).filter((t) => policyOf(t).credentials.includes('screen')) : [],
    session_id: who.sessionId,
    credential: who.kind,
    strong: strongAdmin(who),
    // the made-up resident of a rehearsal has none
    passkeys,
    passkey_invite: !!invite,
    ...self,
    alerts,
    commands_off: commandsOffNow,
  }
}

// /api/me: may this session add a passkey (passkey_can_add; with a key already, the page asks the
// Face ID first). passkey_add_after stays null (no waiting since 08/11).
async function selfPasskeyState(env: Env, who: Who) {
  if (who.kind !== 'browser' || who.viewAs || who.person.kind === 'screen') return { passkey_can_add: false, passkey_add_after: null }
  if (who.admin) return { passkey_can_add: true, passkey_add_after: null }
  const count = await passkeyCount(env, who.person.id)
  if (count >= RESIDENT_PASSKEYS) return { passkey_can_add: false, passkey_add_after: null, passkey_limit: true }
  return { passkey_can_add: true, passkey_add_after: null }
}

// A person's passkeys (never the key itself), for the account page.
async function passkeysOf(env: Env, personId: number) {
  const r = await env.DB.prepare('SELECT id, label, created_at, last_used_at FROM passkeys WHERE person_id = ? ORDER BY id').bind(personId).all<Row>()
  return r.results
}

// Removing a passkey: the person's own after a fresh Face ID of the portal (so a session alone
// cannot drop the person's keys and register its own), or anyone's by a strong admin.
// Every Face ID window of that person's sessions closes with it.
async function removePasskey(env: Env, req: Request, who: Who, personId: number, id: number) {
  if (who.kind !== 'browser' || who.viewAs) throw new HttpError(403, 'view_as_active')
  if (personId !== who.person.id) requireStrongAdmin(who)
  else if (!fresh(who)) throw new HttpError(403, 'passkey_required', { passkey: true })
  const k = await env.DB.prepare('DELETE FROM passkeys WHERE id = ? AND person_id = ? RETURNING label').bind(id, personId).first<{ label: string }>()
  if (!k) throw new HttpError(404, 'passkey_not_found')
  await env.DB.prepare('UPDATE sessions SET passkey_at = NULL, command_passkey_at = NULL, command_passkey_tab = NULL WHERE person_id = ?').bind(personId).run()
  await audit(env, req, { who, action: 'passkey_removed', target: String(personId), detail: { passkey: id, label: k.label } })
}

async function myDevices(env: Env, who: Who) {
  // the made-up resident of a rehearsal has only the device in hand
  if (who.viewAs) {
    const r = await env.DB.prepare('SELECT id, kind, label, place, created_at, last_used_at FROM sessions WHERE id = ?').bind(who.sessionId).all<Row>()
    return r.results.map((s) => ({ ...s, current: true }))
  }
  const r = await env.DB.prepare('SELECT id, kind, label, place, created_at, last_used_at FROM sessions WHERE person_id = ? AND expires_at > ? ORDER BY last_used_at DESC')
    .bind(who.person.id, now()).all<Row>()
  return r.results.map((s) => ({ ...s, current: Number(s.id) === who.sessionId }))
}

async function revokeSession(env: Env, req: Request, who: Who, id: number, anyPerson: boolean) {
  const s = await env.DB.prepare('SELECT id, person_id, label FROM sessions WHERE id = ?').bind(id).first<Row>()
  if (!s || (!anyPerson && Number(s.person_id) !== who.person.id)) throw new HttpError(404, 'device_not_found')
  await dropSessions(env, [id])
  await audit(env, req, { who, action: 'device_revoked', target: `${s.person_id}:${s.label ?? ''}` })
}

async function ackAlert(env: Env, req: Request, who: Who, id: number) {
  requireStrongAdmin(who)
  const r = await env.DB.prepare('UPDATE device_alerts SET ack_at = ?, ack_session_id = ? WHERE id = ? AND person_id = ? AND ack_at IS NULL')
    .bind(now(), who.sessionId, id, who.person.id).run()
  if (!r.meta.changes) throw new HttpError(404, 'alert_not_found')
  await audit(env, req, { who, action: 'device_acknowledged', target: String(id) })
}

// ------------------------------------------------------------------ admin
// Weak admin sessions read lists with numbers masked; a passkey check shows them in full.
const mask = (v: unknown) =>
  String(v ?? '').replace(/\d{8,}/g, (d) => d.slice(0, 4) + '•'.repeat(d.length - 6) + d.slice(-2))
function masked<T extends Row>(rows: T[], who: Who, cols: string[]): T[] {
  if (fresh(who)) return rows
  return rows.map((r) => { const o: Row = { ...r }; for (const c of cols) if (o[c] != null) o[c] = mask(o[c]); return o as T })
}

async function listPeople(env: Env) {
  const people = await env.DB.prepare('SELECT id, name, phone, status, kind, created_at FROM people ORDER BY name').all<Row>()
  const links = await env.DB.prepare('SELECT person_id, group_id FROM person_groups').all<Row>()
  const devices = await env.DB.prepare('SELECT person_id, COUNT(*) AS n FROM sessions WHERE expires_at > ? GROUP BY person_id').bind(now()).all<Row>()
  return people.results.map((p) => ({
    ...p,
    phone: p.kind === 'screen' ? null : p.phone,
    groups: links.results.filter((l) => l.person_id === p.id).map((l) => l.group_id),
    devices: Number(devices.results.find((d) => d.person_id === p.id)?.n ?? 0),
  }))
}

// fail closed: a person (not a screen) never goes into a group made only for screens
function noScreenGroups(groups: unknown) {
  if (Array.isArray(groups) && groups.some((g) => SCREEN_GROUPS.has(String(g)))) throw new HttpError(409, 'group_for_screens')
}

async function setGroups(env: Env, personId: number, groups: unknown) {
  if (!Array.isArray(groups)) return
  const valid = (await env.DB.prepare('SELECT id FROM groups').all<{ id: string }>()).results.map((g) => g.id)
  const wanted = [...new Set(groups.map(String))].filter((g) => valid.includes(g))
  if (wanted.some((g) => SCREEN_GROUPS.has(g))) {
    const p = await env.DB.prepare('SELECT kind FROM people WHERE id = ?').bind(personId).first<Row>()
    if (p?.kind !== 'screen') throw new HttpError(409, 'group_for_screens')
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM person_groups WHERE person_id = ?').bind(personId),
    ...wanted.map((g) => env.DB.prepare('INSERT INTO person_groups (person_id, group_id) VALUES (?, ?)').bind(personId, g)),
  ])
}

async function guardOwner(env: Env, personId: number, change: { status?: string; groups?: unknown }) {
  // The owner can never lock themselves out from the web UI.
  const p = await env.DB.prepare('SELECT phone FROM people WHERE id = ?').bind(personId).first<Row>()
  if (!p || normalizePhone(env.OWNER_PHONE) !== p.phone) return
  if (change.status && change.status !== 'active') throw new HttpError(409, 'owner_not_blockable')
  if (Array.isArray(change.groups) && !change.groups.includes(OWNER_GROUP)) throw new HttpError(409, 'owner_keeps_group')
}

async function addPerson(env: Env, req: Request, who: Who) {
  const b = await body(req)
  const name = text(b.name, 40)
  const phone = normalizePhone(b.phone)
  if (!name || !phone) throw new HttpError(400, 'name_and_number')
  noScreenGroups(b.groups)
  const p = await env.DB.prepare(`INSERT INTO people (name, phone, status, created_by) VALUES (?, ?, 'active', ?) ON CONFLICT (phone) DO NOTHING RETURNING id`)
    .bind(name, phone, who.person.id).first<{ id: number }>()
  if (!p) throw new HttpError(409, 'number_taken')
  await setGroups(env, p.id, b.groups ?? [])
  await audit(env, req, { who, action: 'person_added', target: String(p.id), detail: { groups: b.groups } })
  return { id: p.id }
}

async function editPerson(env: Env, req: Request, who: Who, id: number) {
  const b = await body(req)
  const status = b.status == null ? undefined : String(b.status)
  if (status && !['active', 'blocked'].includes(status)) throw new HttpError(400, 'bad_status')
  await guardOwner(env, id, { status, groups: b.groups })
  const exists = await env.DB.prepare('SELECT id, kind FROM people WHERE id = ?').bind(id).first<Row>()
  if (!exists) throw new HttpError(404, 'person_not_found')
  if (exists.kind !== 'screen') noScreenGroups(b.groups)
  if (exists.kind === 'screen' && Array.isArray(b.groups)) {
    const admins = (await env.DB.prepare('SELECT id FROM groups WHERE is_admin = 1').all<{ id: string }>()).results.map((g) => g.id)
    if (b.groups.some((g) => admins.includes(String(g)))) throw new HttpError(409, 'screen_not_admin')
  }
  const name = text(b.name, 40)
  if (name) await env.DB.prepare('UPDATE people SET name = ? WHERE id = ?').bind(name, id).run()
  if (status) {
    await env.DB.prepare('UPDATE people SET status = ? WHERE id = ?').bind(status, id).run()
    if (status === 'blocked') {
      const ids = await env.DB.prepare('SELECT id FROM sessions WHERE person_id = ?').bind(id).all<{ id: number }>()
      await dropSessions(env, ids.results.map((x) => x.id))
      await notifyTabs(env, { person: id })
    }
  }
  if (b.groups !== undefined) {
    await setGroups(env, id, b.groups)
    // the tabs re-check this person's open sockets (a tab may have been taken away)
    await notifyTabs(env, { person: id })
  }
  await audit(env, req, { who, action: 'person_changed', target: String(id), detail: { name, status, groups: b.groups } })
}

async function listGroups(env: Env) {
  const r = await env.DB.prepare('SELECT id, name, tabs, is_admin FROM groups ORDER BY is_admin DESC, id').all<Row>()
  return r.results.map((g) => ({ ...g, tabs: JSON.parse(String(g.tabs)), screens_only: SCREEN_GROUPS.has(String(g.id)) }))
}

async function editGroup(env: Env, req: Request, who: Who, id: string) {
  if (id === OWNER_GROUP) throw new HttpError(409, 'owner_group_fixed')
  const b = await body(req)
  if (!Array.isArray(b.tabs)) throw new HttpError(400, 'bad_tabs')
  const tabs = [...new Set(b.tabs.map((t) => String(t).toLowerCase()).filter((t) => /^[a-z][a-z0-9-]{0,30}$/.test(t)))]
  const before = await env.DB.prepare('SELECT tabs FROM groups WHERE id = ?').bind(id).first<{ tabs: string }>()
  if (!before) throw new HttpError(404, 'group_not_found')
  // fail closed: in a screens group every tab must be one that opens on a screen
  if (SCREEN_GROUPS.has(id) && tabs.some((t) => !policyOf(t).credentials.includes('screen'))) throw new HttpError(409, 'tab_not_for_screens')
  await env.DB.prepare('UPDATE groups SET tabs = ? WHERE id = ?').bind(JSON.stringify(tabs), id).run()
  let old: string[] = []
  try { old = JSON.parse(before.tabs) } catch { /* bad JSON = no tabs */ }
  const removed = old.filter((t) => !tabs.includes(t))
  if (removed.length) {
    // members lose those tabs now: the tabs close their sockets
    const members = await env.DB.prepare('SELECT person_id FROM person_groups WHERE group_id = ?').bind(id).all<{ person_id: number }>()
    for (const m of members.results) for (const t of removed.includes('*') ? Object.keys(tabBindings(env)) : removed) await notifyTabs(env, { person: m.person_id }, t)
  }
  await audit(env, req, { who, action: 'group_changed', target: id, detail: { tabs } })
}

async function listRequests(env: Env) {
  await env.DB.prepare(`UPDATE link_requests SET state = 'expired' WHERE state = 'pending' AND expires_at < ?`).bind(now()).run()
  const r = await env.DB.prepare(
    `SELECT r.id, r.typed_phone, r.sender_phone, r.sender_person_id, s.name AS sender_known_as, r.created_at,
            c.label AS device, c.expires_at AS code_expires_at, c.state AS code_state
       FROM link_requests r LEFT JOIN people s ON s.id = r.sender_person_id LEFT JOIN login_codes c ON c.id = r.code_id
      WHERE r.state = 'pending' ORDER BY r.id`,
  ).all<Row>()
  // new_number: unknown sender who typed their own number; other_number: a known person typed another
  // number; new_other: unknown sender who typed another number
  const why = (x: Row) => x.sender_person_id ? 'other_number' : x.typed_phone === x.sender_phone ? 'new_number' : 'new_other'
  return r.results.map((x) => ({ ...x, why: why(x), code_valid: x.code_state === 'pending' && String(x.code_expires_at ?? '') > now() }))
}

// Approving signs the waiting tab in as the SENDER (the number WhatsApp proved), creating that
// person if needed. It never signs anyone in as the number that was typed.
async function resolveRequest(env: Env, req: Request, who: Who, id: number, action: 'approve' | 'refuse') {
  const r = await env.DB.prepare(`SELECT * FROM link_requests WHERE id = ? AND state = 'pending' AND expires_at > ?`).bind(id, now()).first<Row>()
  if (!r) throw new HttpError(404, 'request_not_found')
  const done = (state: string) => env.DB.prepare(`UPDATE link_requests SET state = ?, resolved_at = ?, resolved_by = ? WHERE id = ?`).bind(state, now(), who.person.id, id)
  if (action === 'refuse') {
    await env.DB.batch([done('refused'), env.DB.prepare(`UPDATE login_codes SET state = 'refused' WHERE id = ? AND state = 'pending'`).bind(r.code_id)])
    await audit(env, req, { who, action: 'request_refused', target: String(id) })
    return { state: 'refused' }
  }
  const b = await body(req)
  let person = await personByPhone(env, String(r.sender_phone))
  if (person && person.status !== 'active') throw new HttpError(409, 'number_blocked')
  // admins sign in only through the direct path (their own number typed and sent)
  if (person && (await groupsOf(env, person.id)).some((g) => g.is_admin)) throw new HttpError(409, 'admin_direct_only')
  if (!person) {
    const name = text(b.name, 40)
    if (!name) throw new HttpError(400, 'name_required')
    noScreenGroups(b.groups)
    person = await env.DB.prepare(`INSERT INTO people (name, phone, status, created_by) VALUES (?, ?, 'active', ?) RETURNING *`)
      .bind(name, r.sender_phone, who.person.id).first<Person>()
    await setGroups(env, person!.id, b.groups ?? [])
  }
  const c = await env.DB.prepare(`UPDATE login_codes SET state = 'confirmed', confirmed_at = ?, confirmed_person_id = ? WHERE id = ? AND state = 'pending' AND expires_at > ?`)
    .bind(now(), person!.id, r.code_id, now()).run()
  await done('approved').run()
  await audit(env, req, { who, action: 'request_approved', target: String(id), detail: { person: person!.id } })
  return { state: 'approved', code_valid: c.meta.changes > 0 }
}

async function listAllDevices(env: Env) {
  const r = await env.DB.prepare(
    `SELECT s.id, s.person_id, p.name, s.kind, s.label, s.place, s.created_at, s.last_used_at, s.commands_ok_at FROM sessions s JOIN people p ON p.id = s.person_id
      WHERE s.expires_at > ? ORDER BY s.last_used_at DESC LIMIT 200`,
  ).bind(now()).all<Row>()
  return r.results
}

// The params of a keyWriteOnly command in a Face ID tab (an expense, say) are the business of the
// person who sent it: another admin reading the audit sees them masked.
function hideWriteOnlyParams(env: Env, rows: Row[], who: Who): Row[] {
  return rows.map((r) => {
    if (r.action !== 'command' || r.person_id === who.person.id) return r
    const [t, a] = String(r.target ?? '').split('/')
    if (!t || !a || policyOf(t).entry !== 'passkey' || !catalogOf(env, t)[a]?.keyWriteOnly) return r
    try {
      const d = JSON.parse(String(r.detail)) as Row
      if (d.params && typeof d.params === 'object') d.params = Object.fromEntries(Object.keys(d.params as Row).map((k) => [k, '***']))
      return { ...r, detail: JSON.stringify(d) }
    } catch { return { ...r, detail: null } }
  })
}

async function listAudit(env: Env, url: URL) {
  const before = Number(url.searchParams.get('before')) || 9e15
  const r = await env.DB.prepare(
    `SELECT a.id, a.at, a.person_id, p.name, a.strength, a.action, a.target, a.detail, a.ip, a.place FROM audit a LEFT JOIN people p ON p.id = a.person_id
      WHERE a.id < ? ORDER BY a.id DESC LIMIT 100`,
  ).bind(before).all<Row>()
  return r.results
}

// ------------------------------------------------------------------ tabs
// Tab name -> binding name, from the TABS configuration (validated in tabs.ts; a tab named like a
// portal page, or with a bad policy, is dropped).
function tabBindings(env: Env): Record<string, string> {
  return Object.fromEntries(Object.entries(tabsConfig(env.TABS)).map(([t, c]) => [t, c.binding]))
}

function tabService(env: Env, tab: string): TabService | null {
  const binding = tabBindings(env)[tab]
  return binding ? ((env[binding] as TabService | undefined) ?? null) : null
}

const canOpen = (who: Who, tab: string) => who.tabs.has('*') || who.tabs.has(tab)

// Tell every tab (or one) that a credential is gone, so it closes that credential's sockets.
// Best effort: a tab without revoke() or a failing tab must not block the revocation itself.
async function notifyTabs(env: Env, ref: RevokeRef, only?: string) {
  const names = only ? [only] : Object.keys(tabBindings(env))
  await Promise.allSettled(names.map(async (t) => {
    const s = tabService(env, t)
    if (s) await s.revoke?.(ref)
  }))
}

const stepUpUrl = (tab: string, next: string) => `/?step_up=${tab}&next=${encodeURIComponent(next)}`
// where to come back after sign-in or Face ID: same path and query (a same-origin path, never a full URL)
const backTo = (url: URL) => (url.pathname + url.search).length <= 512 ? url.pathname + url.search : url.pathname

// Face ID on entry: a navigation burns a grant left by a passkey check made for this entry (60 s), or,
// with no grant, goes on inside the window of this session's last entry (a reload, or back to the tab
// from the menu: owner's request, 09/11); the window neither moves nor grows. Anything else inside the
// tab needs the same: an entry from the last entryHours. Returns when the session entered.
async function checkEntry(env: Env, req: Request, url: URL, who: Who, tab: string): Promise<string | Response> {
  if (isNavigation(req) && !isUpgrade(req)) {
    const t = now()
    const r = await env.DB.prepare('UPDATE tab_entries SET used_at = ? WHERE session_id = ? AND tab = ? AND used_at IS NULL AND granted_at > ? AND granted_at >= ?')
      .bind(t, who.sessionId, tab, inMs(-ENTRY_GRANT_MS), who.sessionCreatedAt).run()
    if (r.meta.changes) {
      await audit(env, req, { who, strength: 'strong', action: 'tab_entered', target: tab })
      return t
    }
    const prior = await lastEntry(env, who, tab)
    if (prior) return prior
    return new Response(null, { status: 302, headers: { Location: stepUpUrl(tab, backTo(url)), ...API_HEADERS } })
  }
  const prior = await lastEntry(env, who, tab)
  if (prior) return prior
  throw new HttpError(401, 'entry_required', { step_up: stepUpUrl(tab, `/${tab}/`) })
}

// This session's last entry into the tab, when still inside entryHours; null otherwise.
async function lastEntry(env: Env, who: Who, tab: string): Promise<string | null> {
  // read with the session itself (currentSession), in the same trip
  if (who.entryUsedAt !== undefined) return who.entryUsedAt ?? null
  const e = await env.DB.prepare('SELECT used_at FROM tab_entries WHERE session_id = ? AND tab = ? AND used_at > ? AND granted_at >= ? ORDER BY used_at DESC LIMIT 1')
    .bind(who.sessionId, tab, inMs(-policyOf(tab).entryHours * 3600e3), who.sessionCreatedAt).first<{ used_at: string }>()
  return e?.used_at ?? null
}

async function recordTabAudit(env: Env, req: Request, tab: string, h: Headers, who: Who | null, identity: PortalIdentity) {
  const a = readTabAudit(h)
  if (!a) return
  const ok = a !== 'invalid'
  await audit(env, req, {
    who, person: identity.person, strength: who ? strength(who) : identity.credential,
    action: ok ? `${tab}.${a.action}` : `${tab}.invalid_audit`,
    target: ok ? a.target : null,
    detail: ok ? { ...(a.detail as object ?? {}), credential: identity.credential, ...(identity.machine ? { machine: identity.machine } : {}) } : null,
  })
}

// Long-lived connection: authenticated here, then the upgrade goes to the tab's fetch() with
// the identity in X-A5-Identity. The 101 answer goes back as is, minus every header.
async function forwardSocket(env: Env, req: Request, service: TabService, tab: string, identity: PortalIdentity, who: Who | null): Promise<Response> {
  const headers = stripRequestHeaders(req.headers)
  // base64url of the UTF-8 JSON: a header value cannot carry characters above U+00FF (emoji)
  headers.set('X-A5-Identity', b64url(new TextEncoder().encode(JSON.stringify(identity))))
  const res = await service.fetch(new Request(req.url, { method: 'GET', headers }))
  await recordTabAudit(env, req, tab, res.headers, who, identity)
  if (res.status !== 101 || !res.webSocket) {
    const out = new Response(res.body, { status: res.status, headers: res.headers })
    sanitizeTabHeaders(out.headers, API_HEADERS, tab, null)
    return out
  }
  return new Response(null, { status: 101, webSocket: res.webSocket })
}

function identityOf(env: Env, tab: string, who: Who, policy: TabPolicy, enteredAt: string | null): PortalIdentity {
  return {
    credential: who.kind, person: who.person.id, name: who.person.name, groups: who.groups.map((g) => g.id),
    session: who.sessionId, machine: null, shortcut: null, strong: strongAdmin(who), entered_at: enteredAt,
    entry_until: enteredAt ? new Date(Date.parse(enteredAt) + policy.entryHours * 3600e3).toISOString() : null,
    // same rule as the commands (callerOf): only a browser session of an admin, never while seeing as
    admin_until: who.kind === 'browser' && who.admin ? adminWindowUntil(commandPasskeyAt(who, tab), env.ADMIN_COMMAND_PASSKEY) : null,
    actions: allowedActions(tab, catalogOf(env, tab), callerOf(env, who, tab)),
    passkey_until: passkeyUntil(catalogOf(env, tab), callerOf(env, who, tab)),
    ...(who.viewAs ? { rehearsal: true } : {}),
  }
}

// Tabs this session can open from a page, in the order of the TABS binding.
function visibleTabs(env: Env, who: Who): string[] {
  return Object.keys(tabBindings(env)).filter((t) => canOpen(who, t) && policyOf(t).credentials.includes(who.kind))
}

// badge(identity) answers per person, kept for a minute in this isolate (no D1 read). A tab that
// is slow, has no badge() or answers anything but an integer shows no number.
const badgeCache = new Map<string, { at: number; count: number | null }>()

async function badgeOf(env: Env, who: Who, tab: string): Promise<number | null> {
  const key = `${who.person.id}:${who.viewAs?.id ?? ''}:${tab}`
  const hit = badgeCache.get(key)
  if (hit && Date.now() - hit.at < BADGE_CACHE_MS) return hit.count
  let count: number | null = null
  const service = tabService(env, tab)
  if (service) {
    let timer: ReturnType<typeof setTimeout> | undefined
    const late = new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), BADGE_TIMEOUT_MS) })
    try {
      // no entry and never strong here: the badge is a count, never the tab's content or an action
      const r = await Promise.race([Promise.resolve(service.badge?.({ ...identityOf(env, tab, who, policyOf(tab), null), strong: false })), late])
      const n = (r as { count?: unknown } | null | undefined)?.count
      if (typeof n === 'number' && Number.isInteger(n) && n >= 0) count = Math.min(n, 99)
    } catch { /* no badge() or a failing tab: no number */ }
    if (timer !== undefined) clearTimeout(timer)
  }
  if (badgeCache.size > 500) badgeCache.clear()
  badgeCache.set(key, { at: Date.now(), count })
  return count
}

// GET /api/tabs: what the shared selector (/_shell/tabs.js) shows. The only portal API a tab page
// may call (its CSP allows this exact path), so it answers with names, paths and counts only.
async function tabsMenu(env: Env, who: Who, url: URL) {
  const tabs = visibleTabs(env, who)
  // fixed screens get no selector; the list is still there so "/" knows where to go
  const selector = who.kind === 'browser'
  // the dot only makes sense with more than one tab besides the account; none while seeing as
  // someone else (the counts would still be the admin's own)
  const withBadges = selector && tabs.length > 1 && !who.viewAs
  // badges (each tab, 300 ms at most) and the "see as" list go out together
  const [badges, viewOpts] = await Promise.all([
    withBadges ? Promise.all(tabs.map((t) => badgeOf(env, who, t))) : tabs.map(() => null),
    selector && who.realAdmin ? viewOptions(env) : [],
  ])
  const cur = url.searchParams.get('current')
  return {
    selector,
    current: cur === 'conta' || (cur && tabs.includes(cur)) ? cur : null,
    tabs: tabs.map((t, i) => {
      const c = tabsConfig(env.TABS)[t]
      return { id: t, path: `/${t}/`, label: c?.label ?? null, hint: c?.hint ?? null, icon: c?.icon ?? null, badge: badges[i], entry: policyOf(t).entry }
    }),
    // the header line of the list: this person's own name and group, nothing about anyone else;
    // no name while seeing as someone else (the page shows the made-up resident)
    who: selector ? { name: who.viewAs ? null : who.person.name, group: (who.groups.find((g) => g.is_admin) ?? who.groups[0])?.id ?? null } : null,
    account: { id: 'conta', path: ACCOUNT_PATH },
    view_as: who.viewAs,
    view_options: viewOpts,
  }
}

// Groups an admin can see the portal as: every group that is not an admin group (a few rows).
async function viewOptions(env: Env): Promise<{ id: string; name: string }[]> {
  const r = await env.DB.prepare('SELECT id, name FROM groups WHERE is_admin = 0 ORDER BY id').all<{ id: string; name: string }>()
  return r.results
}

// POST /api/tabs {"view_as": "<group>" | null}: an admin browser session shows itself as one
// non-admin group, on this device only, or comes back. It goes through /api/tabs because that is
// the one portal path the tab pages may call (their CSP), and the selector lives in them too.
// Going in asks for nothing (the mode only takes power away). Coming back asks for Face ID done
// after going in (the owner's call on the Security R1): whoever holds the phone during a rehearsal
// must not get the owner back with one touch. Never for screens or non-admins.
async function setViewAs(env: Env, req: Request, who: Who, url: URL) {
  if (who.kind !== 'browser' || !who.realAdmin) throw new HttpError(403, 'admin_only')
  const b = await body(req)
  if (!('view_as' in b)) throw new HttpError(400, 'bad_value')
  const was = who.viewAs?.id ?? null
  let next: string | null = null
  if (b.view_as !== null) {
    if (typeof b.view_as !== 'string' || !/^[a-z][a-z0-9-]{0,30}$/.test(b.view_as)) throw new HttpError(400, 'bad_value')
    const g = await env.DB.prepare('SELECT id, is_admin FROM groups WHERE id = ?').bind(b.view_as).first<Row>()
    if (!g) throw new HttpError(404, 'group_not_found')
    if (g.is_admin) throw new HttpError(400, 'view_as_admin_group')
    next = String(g.id)
  }
  // going in drops this session's Face ID, so "fresh" below can only be a check made since
  if (was && next === null && !fresh(who)) throw new HttpError(403, 'passkey_required', { passkey: true })
  if (next !== was) {
    if (!was) await env.DB.prepare('UPDATE sessions SET view_as = ?, passkey_at = NULL, command_passkey_at = NULL, command_passkey_tab = NULL WHERE id = ?').bind(next, who.sessionId).run()
    else await env.DB.prepare('UPDATE sessions SET view_as = ? WHERE id = ?').bind(next, who.sessionId).run()
    if (was) await audit(env, req, { who, action: 'view_as_off', target: was })
    if (next) await audit(env, req, { who, action: 'view_as_on', target: next })
  }
  const after = await currentSession(req, env)
  if (!after) throw new HttpError(401, 'signed_out')
  return tabsMenu(env, after, url)
}

// The account tab is a portal page: the same index.html, with the portal's own headers.
async function accountPage(req: Request, env: Env, url: URL): Promise<Response> {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'not_found')
  if (url.pathname !== ACCOUNT_PATH) return new Response(null, { status: 301, headers: { Location: ACCOUNT_PATH + url.search, ...API_HEADERS } })
  const page = await env.ASSETS.fetch(new Request(url.origin + '/', { method: req.method }))
  const out = new Response(page.body, { status: page.status, headers: page.headers })
  for (const [k, v] of Object.entries(PAGE_HEADERS)) out.headers.set(k, v)
  out.headers.set('Cache-Control', 'no-cache')
  return out
}

async function routeTab(req: Request, env: Env, url: URL, tab: string): Promise<Response | null> {
  const service = tabService(env, tab)
  if (!service) return null
  const who = await currentSession(req, env, policyOf(tab).entry === 'passkey' && !(isNavigation(req) && !isUpgrade(req)) ? tab : null)
  if (!who) {
    if (isNavigation(req)) return new Response(null, { status: 302, headers: { Location: `/?next=${encodeURIComponent(backTo(url))}`, ...API_HEADERS } })
    throw new HttpError(401, 'signed_out')
  }
  if (!canOpen(who, tab)) throw new HttpError(403, 'no_tab_access')
  const policy = policyOf(tab)
  if (!policy.credentials.includes(who.kind)) throw new HttpError(403, 'no_tab_access')
  requireSameOrigin(req, url)
  // a page socket carries the cookie, so it must come from the portal's own pages
  if (isUpgrade(req) && req.headers.get('Origin') !== url.origin) throw new HttpError(403, 'bad_origin')
  // a service worker could serve the tab's pages from cache and skip the entry check
  if (!policy.serviceWorker && req.headers.get('Service-Worker') === 'script') throw new HttpError(403, 'no_service_worker')

  let enteredAt: string | null = null
  if (policy.entry === 'passkey') {
    const e = await checkEntry(env, req, url, who, tab)
    if (e instanceof Response) return e
    enteredAt = e
  }
  // commands from the tab's own pages: answered by the portal, never handed to handle()
  const cmdPath = url.pathname.slice(tab.length + 1)
  if (cmdPath === '/_passkey' || cmdPath.startsWith('/_passkey/')) {
    if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed')
    let data: unknown
    if (cmdPath === '/_passkey/options') data = await tabPasskeyOptions(env, url, who, tab)
    else if (cmdPath === '/_passkey/verify') data = await tabPasskeyVerify(req, env, url, who, tab)
    else throw new HttpError(404, 'not_found')
    return json(data, 200, who.refreshCookie ? { 'Set-Cookie': who.refreshCookie } : {})
  }
  if (cmdPath === '/_cmd' || cmdPath.startsWith('/_cmd/')) {
    const a = /^\/_cmd\/([a-z][a-z0-9_]{0,39})$/.exec(cmdPath)
    if (!a) throw new HttpError(404, 'not_found')
    if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed')
    const res = await runCommand(env, req, tab, a[1], { who, key: null, enteredAt })
    if (who.refreshCookie) res.headers.append('Set-Cookie', who.refreshCookie)
    return res
  }

  const identity = identityOf(env, tab, who, policy, enteredAt)
  if (isUpgrade(req)) return forwardSocket(env, req, service, tab, identity, who)

  const forwarded = new Request(req.url, { method: req.method, headers: stripRequestHeaders(req.headers), body: req.body })
  const res = await service.handle(forwarded, identity)
  await recordTabAudit(env, req, tab, res.headers, who, identity)
  // A tab shares the portal's origin: it cannot set cookies or loosen the page policy.
  const out = new Response(res.body, { status: res.status, statusText: res.statusText, headers: res.headers })
  sanitizeTabHeaders(out.headers, PAGE_HEADERS, tab, url.origin)
  if (who.refreshCookie) out.headers.append('Set-Cookie', who.refreshCookie)
  return out
}

// ------------------------------------------------------------------ commands (docs/COMMANDS.md)
// The tab's actions, from its configuration (validated in tabs.ts; a bad catalog drops the tab).
const catalogOf = (env: Env, tab: string): Catalog => tabsConfig(env.TABS)[tab]?.commands ?? {}

// identity.actions and every command use the same rule: this session's own last Face ID, from the
// portal (passkey_at) or from a tab page (command_passkey_at, only for commands of that same tab).
// Only passkey_at makes it strong.
function commandPasskeyAt(who: Who, tab: string): string | null {
  const a = who.passkeyAt, b = who.commandPasskeyTab === tab ? who.commandPasskeyAt : null
  if (!a || !b) return a ?? b
  return Date.parse(b) > Date.parse(a) ? b : a
}

function callerOf(env: Env, who: Who, tab: string): Caller {
  const at = commandPasskeyAt(who, tab)
  return {
    credential: who.kind, admin: who.admin, strong: strongAdmin(who), adminFresh: adminWindowOk(at, env.ADMIN_COMMAND_PASSKEY), scope: null,
    passkeyAt: at, rehearsal: !!who.viewAs,
  }
}

interface ShortcutKey { id: number; person: Person; groups: Group[]; admin: boolean; tabs: Set<string>; label: string; scope: string[] }

async function commandsOff(env: Env): Promise<boolean> {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key = 'commands_off'").first<{ value: string }>()
  return r?.value === '1'
}

const COMMAND_HTTP: Record<string, number> = { done: 200, queued: 202, sent: 202, refused: 409, failed: 502, offline: 503 }

// Every command, from a page or a Shortcuts key, goes through here. Order: action, parameters,
// tab access, level, device, brake, limits, interval; only then the tab is called.
async function runCommand(env: Env, req: Request, tab: string, action: string,
  c: { who: Who | null; key: ShortcutKey | null; enteredAt: string | null }): Promise<Response> {
  const service = tabService(env, tab)
  if (!service) throw new HttpError(404, 'not_found')
  const credential = c.key ? 'shortcut' : c.who!.kind
  const person = c.key ? c.key.person : c.who!.person
  const actor = c.key
    ? { person: person.id, strength: 'shortcut' }
    : { who: c.who }
  const target = `${tab}/${action}`
  const refuse = async (status: number, code: string, extra: Row = {}): Promise<never> => {
    await audit(env, req, { ...actor, action: 'command_refused', target, detail: { reason: code, credential, ...(c.key ? { shortcut: c.key.id } : {}) } })
    throw new HttpError(status, code, extra)
  }

  const spec = catalogOf(env, tab)[action]
  if (!spec) return refuse(404, 'unknown_action')
  const b = await body(req)
  if (Object.keys(b).some((k) => k !== 'params')) return refuse(400, 'bad_params')
  const p = checkParams(spec, b.params)
  if ('error' in p) return refuse(400, p.error)

  const policy = policyOf(tab)
  const groupsOk = c.key ? (c.key.tabs.has('*') || c.key.tabs.has(tab)) : canOpen(c.who!, tab)
  if (!groupsOk) return refuse(403, 'no_tab_access')
  // a key never stands in for Face ID on entry: in such a tab it may only run an action the catalog
  // marks keyWriteOnly, from a key holding that one action (refusal), and it reads nothing back
  const entryPasskey = policy.entry === 'passkey'
  if (c.key && entryPasskey && !spec.keyWriteOnly) return refuse(403, 'not_for_shortcuts')
  const caller: Caller = c.key
    ? { credential: 'shortcut', admin: c.key.admin, strong: false, adminFresh: false, scope: c.key.scope, entryPasskey }
    : callerOf(env, c.who!, tab)
  const why = refusal(tab, action, spec, caller)
  // an action with its own passkey window, for anyone: a person with no passkey at all is told so
  // (an admin invites them from the account page) instead of being sent to a Face ID that cannot work
  if (why === 'passkey_required' && spec.passkey && c.who?.kind === 'browser' &&
    !(await env.DB.prepare('SELECT 1 FROM passkeys WHERE person_id = ? LIMIT 1').bind(person.id).first())) {
    return refuse(403, 'passkey_missing')
  }
  // a page: where the portal asks the Face ID (the tab page cannot), coming back to the tab
  if (why === 'passkey_required' && c.who?.kind === 'browser' && !c.who.viewAs && (c.who.admin || spec.passkey)) {
    return refuse(403, why, { step_up: `/?step_up=${tab}&purpose=command&next=${encodeURIComponent(`/${tab}/`)}` })
  }
  if (why) return refuse(403, why)
  // (the 24 h hold on a new resident device, was dropped on 08/11: a person
  // the owner put in a group acts at once; every new resident sign-in is an alert to the admins instead)
  if (await commandsOff(env)) return refuse(503, 'commands_off')

  // "see as" is a rehearsal: the command passes every check a resident would meet, then nothing
  // goes to the tab or the house. It has its own hourly limit, so it never spends the real ones.
  if (c.who?.viewAs) {
    if (!(await underLimit(env, `cmd-rehearsal:p${person.id}`, REHEARSAL_COMMANDS_PER_HOUR))) return refuse(429, 'too_many_commands')
    const id = crypto.randomUUID()
    await audit(env, req, { ...actor, action: 'command', target, detail: { id, params: p.params, credential, status: 'done', simulated: true } })
    return json({ id, status: 'done', ok: true, simulated: true }, 200)
  }

  const callerId = c.key ? `k${c.key.id}` : `p${person.id}`
  if (c.key && !(await underLimit(env, `cmd-key:${c.key.id}`, SHORTCUT_PER_HOUR))) return refuse(429, 'too_many_commands')
  if (!(await underLimit(env, `cmd:${target}:${callerId}`, spec.perHour))) return refuse(429, 'too_many_commands')
  if (!(await underLimit(env, `cmd-tab:${tab}`, TAB_COMMANDS_PER_HOUR))) return refuse(429, 'too_many_commands')
  const gapKey = gapKeyOf(spec, p.params)
  if (gapKey && spec.gap) {
    const last = await env.DB.prepare(
      "SELECT at FROM commands WHERE tab = ? AND gap_key = ? AND at > ? AND status IN ('sent', 'queued', 'done') ORDER BY at DESC LIMIT 1",
    ).bind(tab, gapKey, inMs(-spec.gap.seconds * 1e3)).first<{ at: string }>()
    if (last) {
      const wait = Math.max(1, Math.ceil((Date.parse(last.at) + spec.gap.seconds * 1e3 - Date.now()) / 1e3))
      return refuse(429, 'too_soon', { retry_after: wait })
    }
  }

  const id = crypto.randomUUID()
  const at = now()
  const cmd = { id, action, params: { ...p.params }, expires_at: inMs(COMMAND_TTL_MS) }
  await env.DB.prepare(
    `INSERT INTO commands (id, at, tab, action, params, credential, person_id, session_id, shortcut_id, gap_key, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent')`,
  ).bind(id, at, tab, action, JSON.stringify(cmd.params), credential, person.id, c.who?.sessionId ?? null, c.key?.id ?? null, gapKey).run()

  const identity: PortalIdentity = c.key
    ? {
      credential: 'shortcut', person: person.id, name: person.name, groups: c.key.groups.map((g) => g.id), session: null,
      machine: null, shortcut: c.key.id, strong: false, entered_at: null, entry_until: null, admin_until: null,
      actions: entryPasskey ? [action] : allowedActions(tab, catalogOf(env, tab), caller), passkey_until: {},
    }
    : identityOf(env, tab, c.who!, policy, c.enteredAt)

  let status: string
  let result: unknown
  let error: string | undefined
  if (typeof service.command !== 'function') {
    status = 'failed'; error = 'tab_takes_no_commands'
  } else {
    let timer: ReturnType<typeof setTimeout> | undefined
    const late = new Promise<'late'>((resolve) => { timer = setTimeout(() => resolve('late'), COMMAND_WAIT_MS) })
    try {
      const r = await Promise.race([service.command(cmd, identity), late])
      if (r === 'late') status = 'sent'
      else ({ status, result, error } = readAnswer(r))
    } catch {
      status = 'failed'; error = 'tab_error'
    }
    if (timer !== undefined) clearTimeout(timer)
  }
  await env.DB.prepare('UPDATE commands SET status = ?, finished_at = ? WHERE id = ?').bind(status, now(), id).run()
  await audit(env, req, {
    ...actor, action: 'command', target,
    detail: { id, params: cmd.params, credential, status, ...(error ? { error } : {}), ...(c.key ? { shortcut: c.key.id } : {}) },
  })
  // a key on a write-only action gets {ok, id} and nothing else (no result, no error from the tab)
  if (c.key && spec.keyWriteOnly) return json({ ok: status === 'done', id }, COMMAND_HTTP[status] ?? 502)
  const out: Row = { id, status, ok: status === 'done' }
  const ret = pickReturns(spec, result)
  if (ret) out.result = ret
  if (error) out.error = error
  return json(out, COMMAND_HTTP[status] ?? 502)
}

// City and network of a request, the unit for "never seen from here".
function placeKey(req: Request): string {
  const cf = (req as unknown as { cf?: Row }).cf
  return `${String(cf?.city ?? '?')}|AS${String(cf?.asn ?? '?')}`.slice(0, 120)
}

// A warning on every admin's account page (device_alerts, session 0 = not a session).
async function alertAdmins(env: Env, req: Request, label: string, kind: string) {
  const admins = await env.DB.prepare('SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1').all<{ person_id: number }>()
  for (const a of admins.results)
    await env.DB.prepare('INSERT INTO device_alerts (person_id, session_id, label, place, created_at, kind) VALUES (?, 0, ?, ?, ?, ?)')
      .bind(a.person_id, label, `${clientIp(req)}${place(req) ? ', ' + place(req) : ''}`, now(), kind).run()
}

// POST /_cmd/<tab>/<action> with Authorization: Bearer pa5_atl_... (Apple Shortcuts). No cookie,
// no session; a browser on another site cannot send it (Authorization needs a CORS preflight,
// and the portal answers none).
async function shortcutCommand(req: Request, env: Env, tab: string, action: string): Promise<Response> {
  if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed')
  // the key is checked before anything about the tab, so no key, no hint of which tabs exist
  const raw = /^Bearer (\S+)$/.exec(req.headers.get('Authorization') ?? '')?.[1] ?? ''
  const refuse = async (reason: string, person: number | null = null): Promise<never> => {
    if (!(await underLimit(env, `atl-fail-ip:${clientIp(req)}`, SHORTCUT_FAIL_PER_IP))) throw new HttpError(429, 'too_many_attempts')
    await audit(env, req, { person, strength: 'shortcut', action: 'shortcut_refused', target: `${tab}/${action}`, detail: { reason } })
    throw new HttpError(401, 'bad_key')
  }
  if (!isShortcutKeyShape(raw)) return refuse('format')
  // looked up by hash (unique index); the hash is the constant-time part
  const k = await env.DB.prepare(
    `SELECT k.id, k.label, k.scope, k.revoked_at, k.seen_places, p.id AS pid, p.name, p.phone, p.status, p.kind
       FROM shortcut_keys k JOIN people p ON p.id = k.person_id WHERE k.key_hash = ?`,
  ).bind(await sha256(raw)).first<Row>()
  if (!k) return refuse('unknown')
  if (k.revoked_at) return refuse('revoked', Number(k.pid))
  if (k.status !== 'active' || k.kind === 'screen') return refuse('person_blocked', Number(k.pid))
  // a key used from a city/network it never used before warns every admin
  const where = placeKey(req)
  let seen: string[] = []
  try { seen = (JSON.parse(String(k.seen_places)) as unknown[]).filter((x): x is string => typeof x === 'string') } catch { /* none */ }
  const newPlace = !seen.includes(where)
  if (newPlace) seen = [...seen, where].slice(-20)
  await env.DB.prepare('UPDATE shortcut_keys SET last_used_at = ?, last_ip = ?, last_place = ?, seen_places = ? WHERE id = ?')
    .bind(now(), clientIp(req), place(req), JSON.stringify(seen), k.id).run()
  if (newPlace) {
    await audit(env, req, { person: Number(k.pid), strength: 'shortcut', action: 'shortcut_new_place', target: String(k.label), detail: { shortcut: Number(k.id) } })
    await alertAdmins(env, req, String(k.label), 'shortcut_place')
  }
  const person: Person = { id: Number(k.pid), name: String(k.name), phone: String(k.phone), status: String(k.status) }
  const groups = await groupsOf(env, person.id)
  let scope: string[] = []
  try { scope = (JSON.parse(String(k.scope)) as unknown[]).filter((x): x is string => typeof x === 'string') } catch { /* no scope */ }
  const key: ShortcutKey = {
    id: Number(k.id), person, groups, admin: groups.some((g) => g.is_admin), tabs: tabsOf(groups), label: String(k.label), scope,
  }
  return runCommand(env, req, tab, action, { who: null, key, enteredAt: null })
}

// Actions an admin may put in a key: actions allowed in keys; in a tab with Face ID on entry, only
// keyWriteOnly ones, each alone in its key (checkScope with keyPasskeyTabs).
function keyCatalogs(env: Env, who: Who): Record<string, Catalog> {
  const out: Record<string, Catalog> = {}
  for (const t of Object.keys(tabBindings(env))) if (canOpen(who, t)) out[t] = catalogOf(env, t)
  return out
}
const keyPasskeyTabs = (env: Env) => new Set(Object.keys(tabBindings(env)).filter((t) => policyOf(t).entry === 'passkey'))

async function listShortcutKeys(env: Env, who: Who) {
  if (!who.admin) throw new HttpError(403, 'admin_only')
  const keys = await env.DB.prepare(
    'SELECT id, label, scope, created_at, last_used_at, last_ip, last_place, revoked_at FROM shortcut_keys WHERE person_id = ? ORDER BY id DESC LIMIT 100',
  ).bind(who.person.id).all<Row>()
  const available: { tab: string; action: string; level: string }[] = []
  for (const [t, cat] of Object.entries(keyCatalogs(env, who)))
    for (const [a, s] of Object.entries(cat)) if (checkScope([`${t}/${a}`], { [t]: cat }, who.admin, keyPasskeyTabs(env))) available.push({ tab: t, action: a, level: s.level })
  return {
    keys: keys.results.map((k) => ({ ...k, scope: (() => { try { return JSON.parse(String(k.scope)) } catch { return [] } })() })),
    available,
  }
}

async function addShortcutKey(env: Env, req: Request, who: Who) {
  requireStrongAdmin(who)
  const b = await body(req)
  const label = text(b.label, 60)
  if (!label) throw new HttpError(400, 'name_required')
  const scope = checkScope(b.scope, keyCatalogs(env, who), who.admin, keyPasskeyTabs(env))
  if (!scope) throw new HttpError(400, 'bad_scope')
  const live = await env.DB.prepare('SELECT COUNT(*) AS n FROM shortcut_keys WHERE person_id = ? AND revoked_at IS NULL').bind(who.person.id).first<{ n: number }>()
  if ((live?.n ?? 0) >= MAX_SHORTCUT_KEYS) throw new HttpError(409, 'too_many_keys')
  const key = SHORTCUT_KEY_PREFIX + randomToken(32)
  const r = await env.DB.prepare(
    'INSERT INTO shortcut_keys (person_id, label, key_hash, scope, created_at, created_session) VALUES (?, ?, ?, ?, ?, ?) RETURNING id',
  ).bind(who.person.id, label, await sha256(key), JSON.stringify(scope), now(), who.sessionId).first<{ id: number }>()
  await audit(env, req, { who, action: 'shortcut_key_created', target: label, detail: { id: r!.id, scope } })
  // shown once; only the hash stays
  return { id: r!.id, label, scope, key }
}

// Taking access away never needs Face ID: any session of the key's owner revokes it.
async function revokeShortcutKey(env: Env, req: Request, who: Who, id: number) {
  const k = await env.DB.prepare('UPDATE shortcut_keys SET revoked_at = ? WHERE id = ? AND person_id = ? AND revoked_at IS NULL RETURNING label')
    .bind(now(), id, who.person.id).first<{ label: string }>()
  if (!k) throw new HttpError(404, 'key_not_found')
  await audit(env, req, { who, action: 'shortcut_key_revoked', target: k.label, detail: { id } })
}

// The brake: any admin session stops commands; turning them back on needs a passkey check.
async function setBrake(env: Env, req: Request, who: Who) {
  if (!who.admin) throw new HttpError(403, 'admin_only')
  const b = await body(req)
  if (typeof b.off !== 'boolean') throw new HttpError(400, 'bad_value')
  if (!b.off) requireStrongAdmin(who)
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('commands_off', ?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
  ).bind(b.off ? '1' : '0', now(), who.person.id).run()
  await audit(env, req, { who, action: b.off ? 'commands_off' : 'commands_on' })
  return { ok: true, commands_off: b.off }
}

// An admin lets a new non-admin device send commands before its 24 hours.
async function allowDeviceCommands(env: Env, req: Request, who: Who, id: number) {
  const s = await env.DB.prepare('UPDATE sessions SET commands_ok_at = ? WHERE id = ? AND expires_at > ? RETURNING person_id, label')
    .bind(now(), id, now()).first<Row>()
  if (!s) throw new HttpError(404, 'device_not_found')
  await audit(env, req, { who, action: 'device_commands_allowed', target: `${s.person_id}:${s.label ?? ''}` })
}

// ------------------------------------------------------------------ house agents (pa5_adm_)
// An agent key reads screens, devices, machine keys, groups and the audit log; renames screens,
// devices and machine keys; disconnects non-admin devices and revokes machine keys. Anything
// that gives access (pairing a screen, moving it to another group, unblocking it) is only
// PREPARED by the agent: it waits in agent_requests until an admin approves it with Face ID.
// The key never approves, never creates keys, never touches people, groups or admin sessions.
interface Agent { id: number; label: string }

const agentPairOtherIpRefused = (env: Env) => env.AGENT_PAIR_OTHER_IP !== 'warn'
const agentHomeRequired = (env: Env) => env.AGENT_HOME !== 'warn'

// One network: the same IPv4 address, or the same IPv6 /64.
function ipv6Prefix64(ip: string): string | null {
  if (!ip.includes(':') || ip.includes('.')) return null
  const [head, tail = ''] = ip.toLowerCase().split('::')
  const h = head ? head.split(':') : []
  const t = ip.includes('::') ? (tail ? tail.split(':') : []) : []
  const parts = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t]
  if (parts.length !== 8 || parts.some((p) => !/^[0-9a-f]{1,4}$/.test(p))) return null
  return parts.slice(0, 4).map((p) => p.replace(/^0+(?=.)/, '')).join(':')
}
export function sameNetwork(a: unknown, b: unknown): boolean {
  if (!a || !b) return false
  const x = String(a), y = String(b)
  const px = ipv6Prefix64(x), py = ipv6Prefix64(y)
  return px || py ? px !== null && px === py : x === y
}

// "Home" is wherever a live house bridge (a machine key nobody revoked) last connected from.
async function atHome(env: Env, ip: unknown): Promise<boolean> {
  const r = await env.DB.prepare('SELECT last_ip FROM machine_keys WHERE revoked_at IS NULL AND last_ip IS NOT NULL LIMIT 50').all<{ last_ip: string }>()
  return r.results.some((m) => sameNetwork(m.last_ip, ip))
}

async function agentOf(req: Request, env: Env): Promise<Agent> {
  const h = req.headers.get('Authorization') ?? ''
  const key = h.startsWith('Bearer ') ? h.slice(7).trim() : ''
  const refuse = async (reason: string): Promise<never> => {
    if (!(await underLimit(env, `agent-fail-ip:${clientIp(req)}`, LIMITS.agentFailPerIp))) throw new HttpError(429, 'too_many_attempts')
    await audit(env, req, { strength: 'agent', action: 'agent_refused', detail: { reason } })
    throw new HttpError(401, 'bad_key')
  }
  if (!key.startsWith(AGENT_KEY_PREFIX) || key.length < 40 || key.length > 80) return refuse('format')
  const a = await env.DB.prepare('SELECT id, label, revoked_at, last_ip, last_used_at FROM agent_keys WHERE key_hash = ?').bind(await sha256(key)).first<Row>()
  if (!a) return refuse('unknown')
  if (a.revoked_at) return refuse('revoked')
  const id = Number(a.id)
  if (!(await underLimit(env, `agent:${id}`, LIMITS.agentPerHour))) throw new HttpError(429, 'too_many_attempts')
  const ip = clientIp(req)
  if (a.last_ip !== ip || !a.last_used_at || Date.now() - Date.parse(String(a.last_used_at)) > SESSION_TOUCH_MS)
    await env.DB.prepare('UPDATE agent_keys SET last_used_at = ?, last_ip = ? WHERE id = ?').bind(now(), ip, id).run()
  if (a.last_ip && a.last_ip !== ip) {
    // the key turned up somewhere new: every admin sees it on the account page
    await audit(env, req, { strength: 'agent', action: 'agent_new_ip', target: String(a.label), detail: { agent: id, previous_ip: a.last_ip } })
    await alertAdmins(env, req, String(a.label), 'agent_ip')
  }
  return { id, label: String(a.label) }
}

const agentAudit = (env: Env, req: Request, agent: Agent, action: string, target: string | null, detail: Row = {}) =>
  audit(env, req, { strength: 'agent', action, target, detail: { agent: agent.id, agent_label: agent.label, ...detail } })

// a same-origin path into a tab, query allowed: what a screen opens once paired
function safeNext(v: unknown): string | null {
  if (v == null || v === '') return null
  const s = String(v)
  if (s.length > 200 || s.includes('//') || s.includes('\\') || !/^\/[a-z][a-z0-9-]{0,30}(\/[A-Za-z0-9._~\/?=&%-]*)?$/.test(s)) throw new HttpError(400, 'bad_next')
  return s
}

async function nonAdminGroup(env: Env, v: unknown): Promise<string | null> {
  if (v == null || v === '') return null
  const g = await env.DB.prepare('SELECT id, is_admin FROM groups WHERE id = ?').bind(String(v)).first<Row>()
  if (!g) throw new HttpError(404, 'group_not_found')
  if (g.is_admin) throw new HttpError(409, 'screen_not_admin')
  return String(g.id)
}

const screenById = (env: Env, id: unknown) =>
  env.DB.prepare(`SELECT * FROM people WHERE id = ? AND kind = 'screen'`).bind(Number(id)).first<Person>()

async function agentRequestCreate(env: Env, req: Request, url: URL, agent: Agent) {
  const b = await body(req)
  const kind = String(b.kind ?? '')
  if (kind !== 'pair' && kind !== 'screen') throw new HttpError(400, 'bad_kind')
  const open = await env.DB.prepare(`SELECT COUNT(*) AS n FROM agent_requests WHERE agent_id = ? AND state = 'waiting' AND expires_at > ?`)
    .bind(agent.id, now()).first<{ n: number }>()
  if ((open?.n ?? 0) >= AGENT_PENDING_MAX) throw new HttpError(429, 'too_many_pending')

  const group = await nonAdminGroup(env, b.group)
  // a new or re-paired screen always says which group it lands in (never a silent default)
  if (kind === 'pair' && !group) throw new HttpError(400, 'group_required')
  const home = await atHome(env, clientIp(req))
  if (!home) {
    await agentAudit(env, req, agent, 'agent_request_not_home', null, { kind })
    if (agentHomeRequired(env)) throw new HttpError(409, 'not_at_home')
  }
  let screen: Person | null = null
  let name: string | null = null
  if (b.screen != null) {
    screen = await screenById(env, b.screen)
    if (!screen) throw new HttpError(404, 'screen_not_found')
  } else if (kind === 'pair') {
    name = text(b.name, 40)
    if (!name) throw new HttpError(400, 'name_required')
  } else throw new HttpError(400, 'screen_required')
  // a blocked screen comes back only through an approval that says so
  const unblock = screen?.status === 'blocked' ? 1 : 0
  if (kind === 'screen' && !unblock && !group) throw new HttpError(400, 'nothing_to_change')
  if (kind === 'screen' && b.unblock !== true && unblock) throw new HttpError(409, 'screen_blocked')
  const next = kind === 'pair' ? safeNext(b.next) : null

  // counts requests actually created (refusals are already capped by the key's hourly limit)
  if (!(await underLimit(env, `agent-req:${agent.id}`, LIMITS.agentPairPerHour))) throw new HttpError(429, 'too_many_attempts')
  const t = now()
  const expires = inMs((kind === 'pair' ? AGENT_PAIR_MINUTES : 12 * 60) * 60e3)
  const r = await env.DB.prepare(
    `INSERT INTO agent_requests (agent_id, kind, screen_id, screen_name, group_id, unblock, next_path, agent_ip, at_home, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
  ).bind(agent.id, kind, screen?.id ?? null, name, group, unblock, next, clientIp(req), home ? 1 : 0, t, expires).first<{ id: number }>()
  const out: Row = {
    id: r!.id, kind, screen: screen?.id ?? null, name: screen?.name ?? name, group, unblock: !!unblock, expires_at: expires,
    approve_url: `${url.origin}${ACCOUNT_PATH}?agent_request=${r!.id}`,
  }
  if (kind === 'pair') {
    // no typed code: code and poll secret are random until the screen opens the link
    const ticket = randomToken(24)
    const p = await env.DB.prepare(
      `INSERT INTO screen_pairings (code_hash, secret_hash, created_at, expires_at, request_id, ticket_hash) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
    ).bind(await sha256(randomToken(24)), await sha256(randomToken(24)), t, expires, r!.id, await sha256(ticket)).first<{ id: number }>()
    await env.DB.prepare('UPDATE agent_requests SET pairing_id = ? WHERE id = ?').bind(p!.id, r!.id).run()
    // in the fragment: never sent to the server, so never in an edge log
    out.screen_url = `${url.origin}/#screen_ticket=${ticket}`
  }
  await agentAudit(env, req, agent, `agent_${kind}_prepared`, String(out.name), { request: r!.id, screen: out.screen, group, unblock: !!unblock, at_home: home })
  return out
}

// A request still open; for approval a pairing must already have been opened on the screen,
// so the admin sees which browser is asking.
async function pendingAgentRequest(env: Env, id: number, forApproval = false): Promise<Row> {
  const r = await env.DB.prepare(
    `SELECT r.*, k.label AS agent_label, p.claimed_at, p.label AS screen_label, p.ip AS screen_ip, p.place AS screen_place,
            s.name AS screen_current_name, s.status AS screen_status, g.name AS group_name
       FROM agent_requests r LEFT JOIN agent_keys k ON k.id = r.agent_id LEFT JOIN screen_pairings p ON p.id = r.pairing_id
       LEFT JOIN people s ON s.id = r.screen_id LEFT JOIN groups g ON g.id = r.group_id
      WHERE r.id = ? AND r.state = 'waiting' AND r.expires_at > ?`,
  ).bind(id, now()).first<Row>()
  if (!r) throw new HttpError(404, 'request_not_found')
  if (forApproval && r.kind === 'pair' && !r.claimed_at) throw new HttpError(409, 'pair_not_claimed')
  return r
}

// What the approval page shows. No key material, no ticket.
function agentRequestView(r: Row) {
  const screenGroups = r.screen_groups as string[] | undefined
  return {
    id: r.id, kind: r.kind, agent: r.agent_label ?? null, agent_ip: r.agent_ip, created_at: r.created_at, expires_at: r.expires_at,
    name: r.screen_current_name ?? r.screen_name, existing: r.screen_id != null, blocked: r.screen_status === 'blocked',
    unblock: !!r.unblock, group: r.group_id ?? null, current_groups: screenGroups ?? [], at_home: !!r.at_home,
    claimed: !!r.claimed_at, screen_label: r.screen_label ?? null, screen_ip: r.screen_ip ?? null, screen_place: r.screen_place ?? null,
    same_ip: r.claimed_at ? sameNetwork(r.screen_ip, r.agent_ip) : null,
  }
}

async function adminAgentRequest(env: Env, id: number) {
  const r = await pendingAgentRequest(env, id)
  if (r.screen_id) r.screen_groups = (await groupsOf(env, Number(r.screen_id))).map((g) => g.id)
  return agentRequestView(r)
}

async function adminAgentRequests(env: Env) {
  const r = await env.DB.prepare(`SELECT id FROM agent_requests WHERE state = 'waiting' AND expires_at > ? ORDER BY id LIMIT 20`).bind(now()).all<{ id: number }>()
  return Promise.all(r.results.map((x) => adminAgentRequest(env, x.id)))
}

// The Face ID that called this IS the approval (passkey purpose 'agent:<id>').
async function approveAgentRequest(env: Env, req: Request, who: Who, id: number) {
  if (!who.admin) throw new HttpError(403, 'admin_only')
  const r = await pendingAgentRequest(env, id, true)
  // the group is checked again: it may have become an admin group since
  const group = await nonAdminGroup(env, r.group_id)
  if (r.kind === 'pair' && !group) throw new HttpError(400, 'group_required')
  // home again: the bridge may have moved or been revoked since the request
  if (!(await atHome(env, r.agent_ip))) {
    await audit(env, req, { who, action: 'agent_request_not_home', target: String(id) })
    if (agentHomeRequired(env)) throw new HttpError(409, 'not_at_home')
  }
  let screen: Person | null
  if (r.screen_id) {
    screen = await screenById(env, r.screen_id)
    if (!screen) throw new HttpError(404, 'screen_not_found')
    if (screen.status === 'blocked' && !r.unblock) throw new HttpError(409, 'screen_blocked')
  } else screen = null
  const done = await env.DB.prepare(`UPDATE agent_requests SET state = 'approved', decided_by = ?, decided_at = ? WHERE id = ? AND state = 'waiting'`)
    .bind(who.person.id, now(), id).run()
  if (!done.meta.changes) throw new HttpError(404, 'request_not_found')
  if (!screen) {
    screen = await env.DB.prepare(`INSERT INTO people (name, phone, status, kind, created_by) VALUES (?, ?, 'active', 'screen', ?) RETURNING *`)
      .bind(String(r.screen_name), `screen:${randomToken(9)}`, who.person.id).first<Person>()
  }
  if (r.unblock) await env.DB.prepare(`UPDATE people SET status = 'active' WHERE id = ? AND kind = 'screen'`).bind(screen!.id).run()
  if (group) {
    await setGroups(env, screen!.id, [group])
    await notifyTabs(env, { person: screen!.id })
  }
  if (r.kind === 'pair') {
    await env.DB.prepare(`UPDATE screen_pairings SET state = 'approved', person_id = ?, approved_by = ?, approved_at = ? WHERE id = ? AND state = 'waiting'`)
      .bind(screen!.id, who.person.id, now(), r.pairing_id).run()
  }
  await audit(env, req, {
    who, strength: 'strong', action: r.kind === 'pair' ? 'screen_paired' : 'screen_changed', target: screen!.name,
    detail: { via: 'agent', request: id, agent: r.agent_id, screen: screen!.id, group, unblock: !!r.unblock,
      ...(r.kind === 'pair' ? { label: r.screen_label, place: r.screen_place, ip: r.screen_ip, agent_ip: r.agent_ip } : {}) },
  })
  return { ok: true, screen: screen!.id, name: screen!.name }
}

async function refuseAgentRequest(env: Env, req: Request, who: Who | null, id: number, agent: Agent | null = null) {
  const r = await env.DB.prepare(`UPDATE agent_requests SET state = ?, decided_by = ?, decided_at = ? WHERE id = ? AND state = 'waiting'${agent ? ' AND agent_id = ?' : ''} RETURNING pairing_id, screen_name, screen_id`)
    .bind(...[agent ? 'cancelled' : 'refused', who?.person.id ?? null, now(), id, ...(agent ? [agent.id] : [])]).first<Row>()
  if (!r) throw new HttpError(404, 'request_not_found')
  if (r.pairing_id) await env.DB.prepare(`UPDATE screen_pairings SET state = 'refused' WHERE id = ? AND state = 'waiting'`).bind(r.pairing_id).run()
  if (agent) await agentAudit(env, req, agent, 'agent_request_cancelled', String(id))
  else await audit(env, req, { who, action: 'agent_request_refused', target: String(id) })
}

// POST /api/pair/claim from the screen: the one-use ticket from the agent's link becomes the poll
// secret. Only from the address the agent called from (the house), and only once.
async function pairClaim(req: Request, env: Env) {
  if (!(await underLimit(env, `claim-ip:${clientIp(req)}`, LIMITS.claimPerIp))) throw new HttpError(429, 'too_many_attempts')
  const ticket = String((await body(req)).ticket ?? '')
  if (ticket.length < 30 || ticket.length > 64) throw new HttpError(400, 'missing_secret')
  const p = await env.DB.prepare(
    `SELECT p.id, p.claimed_at, p.state, p.expires_at, r.id AS rid, r.agent_ip, r.next_path, r.screen_name, s.name AS screen_current_name
       FROM screen_pairings p JOIN agent_requests r ON r.id = p.request_id LEFT JOIN people s ON s.id = r.screen_id
      WHERE p.ticket_hash = ?`,
  ).bind(await sha256(ticket)).first<Row>()
  if (!p || p.claimed_at || p.state !== 'waiting') throw new HttpError(404, 'ticket_used')
  if (String(p.expires_at) < now()) throw new HttpError(410, 'pair_expired')
  if (!sameNetwork(p.agent_ip, clientIp(req)) && !(await atHome(env, clientIp(req)))) {
    await audit(env, req, { strength: 'screen', action: 'agent_pair_claim_other_ip', detail: { request: p.rid, agent_ip: p.agent_ip } })
    if (agentPairOtherIpRefused(env)) throw new HttpError(409, 'claim_other_network')
  }
  const secret = randomToken(24)
  const r = await env.DB.prepare(`UPDATE screen_pairings SET secret_hash = ?, claimed_at = ?, label = ?, ip = ?, place = ? WHERE id = ? AND claimed_at IS NULL AND state = 'waiting'`)
    .bind(await sha256(secret), now(), deviceLabel(req.headers.get('User-Agent'), null), clientIp(req), place(req), p.id).run()
  if (!r.meta.changes) throw new HttpError(404, 'ticket_used')
  await audit(env, req, { strength: 'screen', action: 'agent_pair_claimed', target: String(p.screen_current_name ?? p.screen_name), detail: { request: p.rid } })
  return json({ secret, name: p.screen_current_name ?? p.screen_name, expires_at: p.expires_at, next: p.next_path ?? null })
}

// --- agent reads
async function agentScreens(env: Env) {
  const people = await env.DB.prepare(`SELECT id, name, status, created_at FROM people WHERE kind = 'screen' ORDER BY id`).all<Row>()
  const sessions = await env.DB.prepare(
    `SELECT s.id, s.person_id, s.label, s.place, s.created_at, s.last_used_at FROM sessions s JOIN people p ON p.id = s.person_id
      WHERE p.kind = 'screen' AND s.expires_at > ?`,
  ).bind(now()).all<Row>()
  const links = await env.DB.prepare(`SELECT pg.person_id, pg.group_id FROM person_groups pg JOIN people p ON p.id = pg.person_id WHERE p.kind = 'screen'`).all<Row>()
  return people.results.map((p) => ({
    ...p,
    groups: links.results.filter((l) => l.person_id === p.id).map((l) => l.group_id),
    sessions: sessions.results.filter((s) => s.person_id === p.id).map(({ person_id: _, ...s }) => s),
  }))
}

async function adminPeopleIds(env: Env): Promise<Set<number>> {
  const r = await env.DB.prepare(`SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1`).all<{ person_id: number }>()
  return new Set(r.results.map((x) => Number(x.person_id)))
}

// where a person's phone has been is not the agent's business: place only on screen rows
async function agentDevices(env: Env) {
  const admins = await adminPeopleIds(env)
  return (await listAllDevices(env)).map((d) => ({ ...d, place: d.kind === 'screen' ? d.place : null, admin: admins.has(Number(d.person_id)) }))
}

// audit rows for an agent: address and place only where the actor is an agent, a screen or a machine
const AGENT_AUDIT_PLACES = new Set(['agent', 'screen', 'machine'])

async function agentRequestsOf(env: Env, agent: Agent) {
  const r = await env.DB.prepare(
    `SELECT r.id, r.kind, r.screen_id, r.screen_name, r.group_id, r.unblock, r.state, r.created_at, r.expires_at, r.decided_at, p.claimed_at
       FROM agent_requests r LEFT JOIN screen_pairings p ON p.id = r.pairing_id WHERE r.agent_id = ? ORDER BY r.id DESC LIMIT 20`,
  ).bind(agent.id).all<Row>()
  return r.results.map((x) => ({ ...x, unblock: !!x.unblock, state: x.state === 'waiting' && String(x.expires_at) < now() ? 'expired' : x.state }))
}

// an admin's own devices stay theirs: the agent cannot sign the owner out or rename their phone
async function nonAdminSession(env: Env, id: number): Promise<Row> {
  const s = await env.DB.prepare('SELECT s.id, s.person_id, s.label, s.kind, s.last_used_at FROM sessions s WHERE s.id = ?').bind(id).first<Row>()
  if (!s) throw new HttpError(404, 'device_not_found')
  if ((await adminPeopleIds(env)).has(Number(s.person_id))) throw new HttpError(403, 'admin_device')
  return s
}
const RESIDENT_IDLE_DAYS = 30

async function handleAgent(req: Request, env: Env, url: URL): Promise<Response> {
  const agent = await agentOf(req, env)
  const path = url.pathname
  const m = req.method
  let mm: RegExpMatchArray | null
  if (m === 'GET') {
    if (path === '/_agent/me') return json({ id: agent.id, label: agent.label })
    if (path === '/_agent/screens') return json(await agentScreens(env))
    if (path === '/_agent/devices') return json(await agentDevices(env))
    if (path === '/_agent/machines') return json(await listMachines(env))
    if (path === '/_agent/groups') return json(await listGroups(env))
    if (path === '/_agent/requests') return json(await agentRequestsOf(env, agent))
    // phones and anything that looks like one stay masked for an agent, always
    if (path === '/_agent/audit') return json((await listAudit(env, url)).map((a) => {
      const keep = AGENT_AUDIT_PLACES.has(String(a.strength))
      const detail = a.detail == null ? null : keep ? String(a.detail) : String(a.detail).replace(/"(ip|previous_ip|agent_ip|place)":"[^"]*"/g, '"$1":null')
      return { ...a, ip: keep ? a.ip : null, place: keep ? a.place : null, target: a.target == null ? null : mask(a.target), detail: detail == null ? null : mask(detail) }
    }))
    throw new HttpError(404, 'not_found')
  }
  if (path === '/_agent/requests' && m === 'POST') return json(await agentRequestCreate(env, req, url, agent), 201)
  if ((mm = path.match(/^\/_agent\/requests\/(\d+)$/)) && m === 'DELETE') {
    await refuseAgentRequest(env, req, null, Number(mm[1]), agent)
    return json({ ok: true })
  }
  if ((mm = path.match(/^\/_agent\/(screens|devices|machines)\/(\d+)$/)) && m === 'POST') {
    const id = Number(mm[2])
    const name = text((await body(req)).name, 40)
    if (!name) throw new HttpError(400, 'name_required')
    let before: Row | null
    if (mm[1] === 'screens') {
      before = await env.DB.prepare(`SELECT name FROM people WHERE id = ? AND kind = 'screen'`).bind(id).first<Row>()
      if (!before) throw new HttpError(404, 'screen_not_found')
      await env.DB.prepare(`UPDATE people SET name = ? WHERE id = ? AND kind = 'screen'`).bind(name, id).run()
    } else if (mm[1] === 'devices') {
      before = await nonAdminSession(env, id)
      await env.DB.prepare('UPDATE sessions SET label = ? WHERE id = ?').bind(name, id).run()
    } else {
      before = await env.DB.prepare('SELECT label FROM machine_keys WHERE id = ?').bind(id).first<Row>()
      if (!before) throw new HttpError(404, 'machine_not_found')
      await env.DB.prepare('UPDATE machine_keys SET label = ? WHERE id = ?').bind(name, id).run()
    }
    await agentAudit(env, req, agent, `agent_renamed_${mm[1].slice(0, -1)}`, name, { id, before: before.name ?? before.label ?? null })
    return json({ ok: true })
  }
  if ((mm = path.match(/^\/_agent\/devices\/(\d+)$/)) && m === 'DELETE') {
    const s = await nonAdminSession(env, Number(mm[1]))
    // screens: any time; a resident's phone: only one left unused for a month (the old phone case)
    if (s.kind !== 'screen' && Date.now() - Date.parse(String(s.last_used_at)) < RESIDENT_IDLE_DAYS * 864e5) throw new HttpError(403, 'device_in_use')
    await dropSessions(env, [Number(s.id)])
    await agentAudit(env, req, agent, 'device_revoked', `${s.person_id}:${s.label ?? ''}`)
    return json({ ok: true })
  }
  if ((mm = path.match(/^\/_agent\/machines\/(\d+)$/)) && m === 'DELETE') {
    const k = await env.DB.prepare('UPDATE machine_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING tab, label').bind(now(), Number(mm[1])).first<Row>()
    if (!k) throw new HttpError(404, 'machine_not_found')
    await notifyTabs(env, { machine: Number(mm[1]) }, String(k.tab))
    await agentAudit(env, req, agent, 'machine_key_revoked', `${k.tab}:${k.label}`)
    return json({ ok: true })
  }
  throw new HttpError(404, 'not_found')
}

// --- agent keys, managed by a strong admin from the account page
async function listAgentKeys(env: Env) {
  const r = await env.DB.prepare('SELECT id, label, created_at, last_used_at, last_ip, revoked_at FROM agent_keys ORDER BY id DESC LIMIT 50').all<Row>()
  return r.results
}

async function addAgentKey(env: Env, req: Request, who: Who) {
  const label = text((await body(req)).label, 40)
  if (!label) throw new HttpError(400, 'name_required')
  const key = AGENT_KEY_PREFIX + randomToken(32)
  const r = await env.DB.prepare('INSERT INTO agent_keys (label, key_hash, created_at, created_by) VALUES (?, ?, ?, ?) RETURNING id')
    .bind(label, await sha256(key), now(), who.person.id).first<{ id: number }>()
  await audit(env, req, { who, action: 'agent_key_created', target: label, detail: { id: r!.id } })
  // shown once; only the hash stays
  return { id: r!.id, label, key }
}

async function revokeAgentKey(env: Env, req: Request, who: Who, id: number) {
  const k = await env.DB.prepare('UPDATE agent_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING label').bind(now(), id).first<Row>()
  if (!k) throw new HttpError(404, 'agent_not_found')
  // what it left waiting dies with it, links included
  const open = await env.DB.prepare(`UPDATE agent_requests SET state = 'cancelled', decided_at = ? WHERE agent_id = ? AND state = 'waiting' RETURNING pairing_id`)
    .bind(now(), id).all<{ pairing_id: number | null }>()
  for (const r of open.results)
    if (r.pairing_id) await env.DB.prepare(`UPDATE screen_pairings SET state = 'refused' WHERE id = ? AND state = 'waiting'`).bind(r.pairing_id).run()
  await audit(env, req, { who, action: 'agent_key_revoked', target: String(k.label) })
}

// ------------------------------------------------------------------ router
async function handle(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url)
  const path = url.pathname
  const m = req.method

  if (path === '/robo/login' && m === 'POST') return robotLogin(req, env)
  if (path.startsWith('/robo/')) throw new HttpError(404, 'not_found')
  let mb: RegExpMatchArray | null
  if ((mb = path.match(/^\/_bridge\/([a-z][a-z0-9-]{0,30})$/))) return bridge(req, env, mb[1])
  if (path.startsWith('/_bridge')) throw new HttpError(404, 'not_found')
  if ((mb = path.match(/^\/_cmd\/([a-z][a-z0-9-]{0,30})\/([a-z][a-z0-9_]{0,39})$/))) return shortcutCommand(req, env, mb[1], mb[2])
  if (path.startsWith('/_cmd')) throw new HttpError(404, 'not_found')
  if (path.startsWith('/_agent/')) return handleAgent(req, env, url)

  if (path.startsWith('/api/')) {
    requireSameOrigin(req, url)
    if (path === '/api/login/start' && m === 'POST') return loginStart(req, env)
    if (path === '/api/login/status' && m === 'POST') return loginStatus(req, env)
    if (path === '/api/pair/start' && m === 'POST') return pairStart(req, env, url)
    if (path === '/api/pair/status' && m === 'POST') return pairStatus(req, env)
    if (path === '/api/pair/claim' && m === 'POST') return pairClaim(req, env)
    if (path === '/api/logout' && m === 'POST') {
      const who = await currentSession(req, env)
      // a rehearsal signs out only on the page (app.js): the owner's real session never drops here,
      // unless the page says so in words ({"real": true}: the way out when Face ID cannot bring
      // the owner back). Signing out only takes power away.
      if (who?.viewAs && (await body(req)).real !== true) throw new HttpError(403, 'view_as_active')
      if (who) {
        await dropSessions(env, [who.sessionId])
        await audit(env, req, { who, action: 'logout' })
      }
      return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() })
    }

    const who = await requireSession(req, env)
    const extra: Record<string, string> = who.refreshCookie ? { 'Set-Cookie': who.refreshCookie } : {}
    const out = (data: unknown) => json(data, 200, extra)
    let mm: RegExpMatchArray | null

    if (path === '/api/me' && m === 'GET') return out(await me(env, who))
    if (path === '/api/tabs' && m === 'GET') return out(await tabsMenu(env, who, url))
    if (path === '/api/tabs' && m === 'POST') return out(await setViewAs(env, req, who, url))
    if (path === '/api/me/devices' && m === 'GET') return out(await myDevices(env, who))
    if ((mm = path.match(/^\/api\/me\/devices\/(\d+)$/)) && m === 'DELETE') {
      // an admin weak session must not be able to kick the owner's real devices out
      if (who.realAdmin && Number(mm[1]) !== who.sessionId) {
        // seeing as a resident never skips the admin's own rule: come back first
        if (who.viewAs) throw new HttpError(403, 'view_as_active')
        requireStrongAdmin(who)
      }
      await revokeSession(env, req, who, Number(mm[1]), false)
      return out({ ok: true })
    }
    if (path === '/api/me/passkeys' && m === 'GET') return out(who.viewAs || who.kind !== 'browser' ? [] : await passkeysOf(env, who.person.id))
    if ((mm = path.match(/^\/api\/me\/passkeys\/(\d+)$/)) && m === 'DELETE') {
      await removePasskey(env, req, who, who.person.id, Number(mm[1]))
      return out({ ok: true })
    }
    if (path === '/api/me/shortcuts' && m === 'GET') return out(await listShortcutKeys(env, who))
    if (path === '/api/me/shortcuts' && m === 'POST') return out(await addShortcutKey(env, req, who))
    if ((mm = path.match(/^\/api\/me\/shortcuts\/(\d+)$/)) && m === 'DELETE') {
      await revokeShortcutKey(env, req, who, Number(mm[1]))
      return out({ ok: true })
    }
    if ((mm = path.match(/^\/api\/me\/alerts\/(\d+)\/ack$/)) && m === 'POST') {
      await ackAlert(env, req, who, Number(mm[1]))
      return out({ ok: true })
    }
    if (path === '/api/passkey/create/options' && m === 'POST') return out(await passkeyCreateOptions(env, url, who))
    if (path === '/api/passkey/create/verify' && m === 'POST') return out(await passkeyCreateVerify(req, env, url, who))
    if (path === '/api/passkey/get/options' && m === 'POST') return out(await passkeyGetOptions(req, env, url, who))
    if (path === '/api/passkey/get/verify' && m === 'POST') return out(await passkeyGetVerify(req, env, url, who))

    if (path.startsWith('/api/admin/')) {
      if (!who.admin) throw new HttpError(403, 'admin_only')
      // reads: any admin session
      if (m === 'GET') {
        if (path === '/api/admin/people') return out(masked(await listPeople(env), who, ['phone']))
        if (path === '/api/admin/groups') return out(await listGroups(env))
        if (path === '/api/admin/requests') return out(masked(await listRequests(env), who, ['typed_phone', 'sender_phone']))
        if (path === '/api/admin/devices') return out(await listAllDevices(env))
        if ((mm = path.match(/^\/api\/admin\/people\/(\d+)\/passkeys$/))) return out(await passkeysOf(env, Number(mm[1])))
        if (path === '/api/admin/audit') return out(masked(hideWriteOnlyParams(env, await listAudit(env, url), who), who, ['detail']))
        if (path === '/api/admin/pair') return out(await pairLookup(req, env, url))
        if (path === '/api/admin/machines') return out(await listMachines(env))
        if (path === '/api/admin/agents') return out(await listAgentKeys(env))
        if (path === '/api/admin/agent-requests') return out(await adminAgentRequests(env))
        if ((mm = path.match(/^\/api\/admin\/agent-requests\/(\d+)$/))) return out(await adminAgentRequest(env, Number(mm[1])))
        throw new HttpError(404, 'not_found')
      }
      // the brake: stopping commands takes any admin session (setBrake asks a passkey to restart)
      if (path === '/api/admin/commands' && m === 'POST') return out(await setBrake(env, req, who))
      // refusing what an agent asked gives nobody access: any admin session
      if ((mm = path.match(/^\/api\/admin\/agent-requests\/(\d+)\/refuse$/)) && m === 'POST') {
        await refuseAgentRequest(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
      // writes: passkey in the last 5 minutes
      requireStrongAdmin(who)
      if (path === '/api/admin/people' && m === 'POST') return out(await addPerson(env, req, who))
      if ((mm = path.match(/^\/api\/admin\/people\/(\d+)$/)) && m === 'POST') {
        await editPerson(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/people\/(\d+)\/passkeys\/(\d+)$/)) && m === 'DELETE') {
        await removePasskey(env, req, who, Number(mm[1]), Number(mm[2]))
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/people\/(\d+)\/passkey-invite$/)) && m === 'POST') {
        await createInvite(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/groups\/([a-z][a-z0-9-]{0,30})$/)) && m === 'POST') {
        await editGroup(env, req, who, mm[1])
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/requests\/(\d+)\/(approve|refuse)$/)) && m === 'POST')
        return out(await resolveRequest(env, req, who, Number(mm[1]), mm[2] as 'approve' | 'refuse'))
      if ((mm = path.match(/^\/api\/admin\/devices\/(\d+)$/)) && m === 'DELETE') {
        await revokeSession(env, req, who, Number(mm[1]), true)
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/devices\/(\d+)\/commands$/)) && m === 'POST') {
        await allowDeviceCommands(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
      if (path === '/api/admin/pair' && m === 'POST') return out(await pairApprove(env, req, who))
      if (path === '/api/admin/machines' && m === 'POST') return out(await addMachine(env, req, who))
      if (path === '/api/admin/agents' && m === 'POST') return out(await addAgentKey(env, req, who))
      if ((mm = path.match(/^\/api\/admin\/agents\/(\d+)$/)) && m === 'DELETE') {
        await revokeAgentKey(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
      if ((mm = path.match(/^\/api\/admin\/machines\/(\d+)$/)) && m === 'DELETE') {
        await revokeMachine(env, req, who, Number(mm[1]))
        return out({ ok: true })
      }
    }
    throw new HttpError(404, 'not_found')
  }

  if (path === ACCOUNT_PATH || path === '/conta') return accountPage(req, env, url)

  const tab = /^\/([a-z][a-z0-9-]{0,30})(\/|$)/.exec(path)?.[1]
  if (tab) {
    const r = await routeTab(req, env, url, tab)
    if (r) return r
  }
  return new Response('not_found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...API_HEADERS } })
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    tabsConfig(env.TABS) // policyOf() reads what this loads
    try {
      return await handle(req, env)
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, ...e.extra }, e.status)
      console.error('unhandled', e instanceof Error ? e.message : String(e))
      return json({ error: 'internal' }, 500)
    }
  },
} satisfies ExportedHandler<Env>
