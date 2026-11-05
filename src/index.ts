// Portal worker: WhatsApp sign-in, passkeys, devices, groups, and a router that hands each
// tab (/<tab>/*) to a private worker over RPC.
//
// Trust levels:
//   weak session    signed in through WhatsApp. Can read; can revoke its own devices.
//   strong session  the same session after a passkey check (Face ID / Touch ID).
//                   Every admin write needs a passkey check from the last 5 minutes.

import { WebAuthnError, b64url, verifyAssertion, verifyRegistration } from './webauthn'
import {
  RESERVED_TABS, type PortalIdentity, type RevokeRef, type TabPolicy, type TabService, isNavigation, isUpgrade, permissionsPolicy,
  policyOf, readTabAudit, sanitizeTabHeaders, stripRequestHeaders,
} from './tabs'

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
}
const COOKIE = '__Host-a5s'
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789' // no 0/O/1/I/L
// The reader matches this exact phrase, so it is part of the protocol, not UI text.
const LOGIN_PHRASE = 'Entrar no Portal A5: '
const ROBOT_KEY_PREFIX = 'pa5_robo_'
const OWNER_GROUP = 'owner'

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
  person: Person; sessionId: number; sessionCreatedAt: string; kind: 'browser' | 'screen'; groups: Group[]; admin: boolean; tabs: Set<string>
  passkeyAt: string | null; refreshCookie: string | null
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

async function audit(env: Env, req: Request | null, a: { who?: Who | null; person?: number | null; strength?: string | null; action: string; target?: string | null; detail?: unknown }) {
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
async function currentSession(req: Request, env: Env): Promise<Who | null> {
  const token = cookieValue(req, COOKIE)
  if (!token || token.length < 40) return null
  const s = await env.DB.prepare(
    `SELECT s.id AS sid, s.kind AS skind, s.created_at AS screated, s.last_used_at, s.passkey_at, p.* FROM sessions s JOIN people p ON p.id = s.person_id
     WHERE s.token_hash = ? AND s.expires_at > ?`,
  ).bind(await sha256(token), now()).first<Row>()
  if (!s || s.status !== 'active') return null
  const kind = s.skind === 'screen' ? 'screen' : 'browser'
  let refreshCookie: string | null = null
  if (Date.now() - Date.parse(String(s.last_used_at)) > SESSION_TOUCH_MS) {
    await env.DB.prepare('UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE id = ?')
      .bind(now(), inMs(sessionDays(kind) * 864e5), s.sid).run()
    refreshCookie = sessionCookie(token, kind)
  }
  const person: Person = { id: Number(s.id), name: String(s.name), phone: String(s.phone), status: String(s.status), kind: String(s.kind) }
  const groups = await groupsOf(env, person.id)
  // a screen account is never an admin, whatever its groups say
  const admin = kind === 'browser' && person.kind !== 'screen' && groups.some((g) => g.is_admin)
  return {
    person, sessionId: Number(s.sid), sessionCreatedAt: String(s.screated), kind, groups, admin, tabs: tabsOf(groups),
    passkeyAt: (s.passkey_at as string | null) ?? null, refreshCookie,
  }
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
  const p = await env.DB.prepare(`SELECT label, place, ip, created_at, expires_at FROM screen_pairings WHERE code_hash = ? AND expires_at > ? AND state = 'waiting'`)
    .bind(await sha256(code), now()).first<Row>()
  if (!p) throw new HttpError(404, 'pair_code_not_found')
  return { ...p, same_ip: p.ip === clientIp(req), admin_ip: clientIp(req), other_ip_refused: refuseOtherIp(env) }
}

async function pairApprove(env: Env, req: Request, who: Who) {
  const b = await body(req)
  const code = normPairCode(b.code)
  const p = await env.DB.prepare(`SELECT * FROM screen_pairings WHERE code_hash = ? AND expires_at > ? AND state = 'waiting'`)
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
  const alertAdmins = async (kind: string) => {
    const admins = await env.DB.prepare(`SELECT pg.person_id FROM person_groups pg JOIN groups g ON g.id = pg.group_id WHERE g.is_admin = 1`).all<{ person_id: number }>()
    for (const a of admins.results)
      await env.DB.prepare(`INSERT INTO device_alerts (person_id, session_id, label, place, created_at, kind) VALUES (?, 0, ?, ?, ?, ?)`)
        .bind(a.person_id, `${tab}:${m.label}`, `${clientIp(req)}${place(req) ? ', ' + place(req) : ''}`, now(), kind).run()
  }
  // a new bridge replacing the old one more than 3 times in an hour, or a key used from a new
  // address: tell every admin
  if (n === BRIDGE_ALERT_PER_HOUR + 1) await alertAdmins('bridge')
  if (newIp) await alertAdmins('bridge_ip')
  const identity: PortalIdentity = {
    credential: 'machine', person: null, name: String(m.label), groups: [], session: null, machine: id,
    strong: false, entered_at: null, entry_until: null, actions: [],
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
  if (state === 'waiting' || state === 'pending') return json({ status: state, expires_at: c.expires_at })
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
    env.DB.prepare('DELETE FROM passkey_challenges WHERE session_id = ? AND kind = ?').bind(who.sessionId, kind),
    env.DB.prepare('INSERT INTO passkey_challenges (session_id, kind, challenge, expires_at, purpose) VALUES (?, ?, ?, ?, ?)')
      .bind(who.sessionId, kind, challenge, inMs(CHALLENGE_MS), purpose),
  ])
  return challenge
}

async function takeChallenge(env: Env, who: Who, kind: 'create' | 'get'): Promise<{ challenge: string; purpose: string | null }> {
  const c = await env.DB.prepare('DELETE FROM passkey_challenges WHERE session_id = ? AND kind = ? AND expires_at > ? RETURNING challenge, purpose')
    .bind(who.sessionId, kind, now()).first<{ challenge: string; purpose: string | null }>()
  if (!c) throw new HttpError(400, 'challenge_expired')
  return c
}

// 'entry:<tab>' for a tab this session can open whose policy asks a passkey on entry.
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
async function canAddPasskey(env: Env, who: Who): Promise<number | null> {
  if (!who.admin) throw new HttpError(403, 'passkey_admin_only')
  if (fresh(who)) return null
  const any = await env.DB.prepare('SELECT 1 FROM passkeys LIMIT 1').first()
  if (!any) return null
  const inv = await env.DB.prepare('SELECT id FROM passkey_invites WHERE person_id = ? AND expires_at > ? AND used_at IS NULL ORDER BY id DESC')
    .bind(who.person.id, now()).first<{ id: number }>()
  if (inv) return inv.id
  throw new HttpError(403, 'passkey_required', { passkey: true })
}

async function createInvite(env: Env, req: Request, who: Who, personId: number) {
  const target = (await groupsOf(env, personId)).some((g) => g.is_admin)
  if (!target) throw new HttpError(409, 'invite_admin_only')
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
  await env.DB.prepare('INSERT INTO passkeys (person_id, credential_id, public_key, sign_count, label, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(who.person.id, reg.credentialId, reg.publicKey, reg.signCount, label, now()).run()
  await env.DB.prepare('UPDATE sessions SET passkey_at = ? WHERE id = ?').bind(now(), who.sessionId).run()
  if (invite) await env.DB.prepare('UPDATE passkey_invites SET used_at = ? WHERE id = ?').bind(now(), invite).run()
  await audit(env, req, { who, strength: 'strong', action: 'passkey_added', target: label, detail: invite ? { invite } : null })
  return { ok: true }
}

async function passkeyGetOptions(req: Request, env: Env, url: URL, who: Who) {
  const purpose = entryPurpose(env, who, (await body(req)).purpose)
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
  return {
    person: { id: who.person.id, name: who.person.name },
    groups: who.groups.map((g) => ({ id: g.id, name: g.name })),
    admin: who.admin,
    tabs: who.tabs.has('*') ? Object.keys(tabBindings(env)) : [...who.tabs],
    all_tabs: who.admin ? Object.keys(tabBindings(env)) : [],
    session_id: who.sessionId,
    credential: who.kind,
    strong: fresh(who),
    passkeys: who.admin ? await passkeyCount(env, who.person.id) : 0,
    alerts: await alertsOf(env, who),
  }
}

async function myDevices(env: Env, who: Who) {
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

async function setGroups(env: Env, personId: number, groups: unknown) {
  if (!Array.isArray(groups)) return
  const valid = (await env.DB.prepare('SELECT id FROM groups').all<{ id: string }>()).results.map((g) => g.id)
  const wanted = [...new Set(groups.map(String))].filter((g) => valid.includes(g))
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
  return r.results.map((g) => ({ ...g, tabs: JSON.parse(String(g.tabs)) }))
}

async function editGroup(env: Env, req: Request, who: Who, id: string) {
  if (id === OWNER_GROUP) throw new HttpError(409, 'owner_group_fixed')
  const b = await body(req)
  if (!Array.isArray(b.tabs)) throw new HttpError(400, 'bad_tabs')
  const tabs = [...new Set(b.tabs.map((t) => String(t).toLowerCase()).filter((t) => /^[a-z][a-z0-9-]{0,30}$/.test(t)))]
  const before = await env.DB.prepare('SELECT tabs FROM groups WHERE id = ?').bind(id).first<{ tabs: string }>()
  if (!before) throw new HttpError(404, 'group_not_found')
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
  return r.results.map((x) => ({ ...x, code_valid: x.code_state === 'pending' && String(x.code_expires_at ?? '') > now() }))
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
    `SELECT s.id, s.person_id, p.name, s.kind, s.label, s.place, s.created_at, s.last_used_at FROM sessions s JOIN people p ON p.id = s.person_id
      WHERE s.expires_at > ? ORDER BY s.last_used_at DESC LIMIT 200`,
  ).bind(now()).all<Row>()
  return r.results
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
function tabBindings(env: Env): Record<string, string> {
  let all: Record<string, string>
  try { all = JSON.parse(env.TABS || '{}') } catch { return {} }
  // a tab named like a portal page would never be reached; drop it instead of half-serving it
  return Object.fromEntries(Object.entries(all).filter(([t]) => /^[a-z][a-z0-9-]{0,30}$/.test(t) && !RESERVED_TABS.includes(t)))
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

// Face ID on entry: a navigation burns a grant left by a passkey check made for this entry (60 s); anything
// else inside the tab needs an entry from the last entryHours. Returns when the session entered.
async function checkEntry(env: Env, req: Request, url: URL, who: Who, tab: string): Promise<string | Response> {
  const policy = policyOf(tab)
  if (isNavigation(req) && !isUpgrade(req)) {
    const t = now()
    const r = await env.DB.prepare('UPDATE tab_entries SET used_at = ? WHERE session_id = ? AND tab = ? AND used_at IS NULL AND granted_at > ? AND granted_at >= ?')
      .bind(t, who.sessionId, tab, inMs(-ENTRY_GRANT_MS), who.sessionCreatedAt).run()
    if (r.meta.changes) {
      await audit(env, req, { who, strength: 'strong', action: 'tab_entered', target: tab })
      return t
    }
    return new Response(null, { status: 302, headers: { Location: stepUpUrl(tab, url.pathname), ...API_HEADERS } })
  }
  const e = await env.DB.prepare('SELECT used_at FROM tab_entries WHERE session_id = ? AND tab = ? AND used_at > ? AND granted_at >= ? ORDER BY used_at DESC LIMIT 1')
    .bind(who.sessionId, tab, inMs(-policy.entryHours * 3600e3), who.sessionCreatedAt).first<{ used_at: string }>()
  if (e) return e.used_at
  throw new HttpError(401, 'entry_required', { step_up: stepUpUrl(tab, `/${tab}/`) })
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

function identityOf(who: Who, policy: TabPolicy, enteredAt: string | null): PortalIdentity {
  return {
    credential: who.kind, person: who.person.id, name: who.person.name, groups: who.groups.map((g) => g.id),
    session: who.sessionId, machine: null, strong: fresh(who), entered_at: enteredAt,
    entry_until: enteredAt ? new Date(Date.parse(enteredAt) + policy.entryHours * 3600e3).toISOString() : null, actions: [],
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
  const key = `${who.person.id}:${tab}`
  const hit = badgeCache.get(key)
  if (hit && Date.now() - hit.at < BADGE_CACHE_MS) return hit.count
  let count: number | null = null
  const service = tabService(env, tab)
  if (service) {
    let timer: ReturnType<typeof setTimeout> | undefined
    const late = new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), BADGE_TIMEOUT_MS) })
    try {
      // no entry and never strong here: the badge is a count, never the tab's content or an action
      const r = await Promise.race([Promise.resolve(service.badge?.({ ...identityOf(who, policyOf(tab), null), strong: false })), late])
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
  // the dot only makes sense with more than one tab besides the account
  const withBadges = selector && tabs.length > 1
  const badges = withBadges ? await Promise.all(tabs.map((t) => badgeOf(env, who, t))) : tabs.map(() => null)
  const cur = url.searchParams.get('current')
  return {
    selector,
    current: cur === 'conta' || (cur && tabs.includes(cur)) ? cur : null,
    tabs: tabs.map((t, i) => ({ id: t, path: `/${t}/`, badge: badges[i], entry: policyOf(t).entry })),
    account: { id: 'conta', path: ACCOUNT_PATH },
  }
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
  const who = await currentSession(req, env)
  if (!who) {
    if (isNavigation(req)) return new Response(null, { status: 302, headers: { Location: `/?next=${encodeURIComponent(url.pathname)}`, ...API_HEADERS } })
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
  const identity = identityOf(who, policy, enteredAt)
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

  if (path.startsWith('/api/')) {
    requireSameOrigin(req, url)
    if (path === '/api/login/start' && m === 'POST') return loginStart(req, env)
    if (path === '/api/login/status' && m === 'POST') return loginStatus(req, env)
    if (path === '/api/pair/start' && m === 'POST') return pairStart(req, env, url)
    if (path === '/api/pair/status' && m === 'POST') return pairStatus(req, env)
    if (path === '/api/logout' && m === 'POST') {
      const who = await currentSession(req, env)
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
    if (path === '/api/me/devices' && m === 'GET') return out(await myDevices(env, who))
    if ((mm = path.match(/^\/api\/me\/devices\/(\d+)$/)) && m === 'DELETE') {
      // an admin weak session must not be able to kick the owner's real devices out
      if (who.admin && Number(mm[1]) !== who.sessionId) requireStrongAdmin(who)
      await revokeSession(env, req, who, Number(mm[1]), false)
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
        if (path === '/api/admin/audit') return out(masked(await listAudit(env, url), who, ['detail']))
        if (path === '/api/admin/pair') return out(await pairLookup(req, env, url))
        if (path === '/api/admin/machines') return out(await listMachines(env))
        throw new HttpError(404, 'not_found')
      }
      // writes: passkey in the last 5 minutes
      requireStrongAdmin(who)
      if (path === '/api/admin/people' && m === 'POST') return out(await addPerson(env, req, who))
      if ((mm = path.match(/^\/api\/admin\/people\/(\d+)$/)) && m === 'POST') {
        await editPerson(env, req, who, Number(mm[1]))
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
      if (path === '/api/admin/pair' && m === 'POST') return out(await pairApprove(env, req, who))
      if (path === '/api/admin/machines' && m === 'POST') return out(await addMachine(env, req, who))
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
    try {
      return await handle(req, env)
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, ...e.extra }, e.status)
      console.error('unhandled', e instanceof Error ? e.message : String(e))
      return json({ error: 'internal' }, 500)
    }
  },
} satisfies ExportedHandler<Env>
