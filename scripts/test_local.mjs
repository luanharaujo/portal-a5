// Drives the whole sign-in flow against a local `wrangler dev`, including a fake WhatsApp
// reader (POST /robo/login) and a software passkey. Run through scripts/test_local.sh.
import { webcrypto as wc } from 'node:crypto'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import { agentPairChecks, browserChecks } from './test_browser.mjs'

const BASE = process.env.BASE
const ROBO_KEY = process.env.ROBO_KEY
const OWNER = process.env.OWNER
const RP_ID = new URL(BASE).hostname
const RESIDENT = '5561900000002'
const STRANGER = '5561900000003'

let failures = 0
function check(name, cond, extra) {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${!cond && extra !== undefined ? ' -> ' + JSON.stringify(extra) : ''}`)
  if (!cond) failures++
}

// --- tiny client with its own cookie jar
function client() {
  let cookie = ''
  return {
    async req(method, path, body, headers = {}) {
      const h = Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined))
      if (cookie) h.Cookie = cookie
      if (method !== 'GET' && !('Origin' in headers)) h.Origin = BASE
      if (method !== 'GET' && !('X-Portal' in headers)) h['X-Portal'] = '1'
      if (body !== undefined) h['Content-Type'] = 'application/json'
      const r = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
      const sc = r.headers.get('set-cookie')
      if (sc) {
        const m = /__Host-a5s=([^;]*)/.exec(sc)
        if (m) cookie = m[1] ? `__Host-a5s=${m[1]}` : ''
      }
      const text = await r.text()
      let data
      try { data = JSON.parse(text) } catch { data = text }
      return { status: r.status, data, headers: r.headers, setCookie: sc }
    },
    get cookie() { return cookie },
  }
}

const robot = (body, key = ROBO_KEY, path = '/robo/login') =>
  fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-A5-Robot-Key': key }, body: JSON.stringify(body) })
    .then(async (r) => ({ status: r.status, data: await r.json().catch(() => null) }))

async function signIn(c, typed, sender, self = false) {
  const s = await c.req('POST', '/api/login/start', { phone: typed })
  const code = /A5-[A-Z0-9]{4}/.exec(s.data.message)[0]
  const r = await robot({ code, phone: sender, msg_id: 'test-' + Math.random(), self_chat: self })
  const st = await c.req('POST', '/api/login/status', { secret: s.data.secret })
  return { start: s, robot: r, status: st, code }
}

// --- software passkey (ES256)
const b64u = (b) => Buffer.from(b).toString('base64url')
const sha = async (b) => new Uint8Array(await wc.subtle.digest('SHA-256', b))
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]) }
  const body = Buffer.concat([int(Buffer.from(raw.slice(0, 32))), int(Buffer.from(raw.slice(32)))])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}
async function makeAuthenticator() {
  const keys = await wc.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const credId = wc.getRandomValues(new Uint8Array(16))
  let counter = 0
  return {
    id: b64u(credId),
    async create(opts) {
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: opts.challenge, origin: BASE }))
      const authData = Buffer.concat([Buffer.from(await sha(Buffer.from(RP_ID))), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16), Buffer.from([0, 16]), Buffer.from(credId)])
      return {
        id: b64u(credId), clientDataJSON: b64u(clientData), authenticatorData: b64u(authData),
        publicKey: b64u(await wc.subtle.exportKey('spki', keys.publicKey)), publicKeyAlgorithm: -7,
      }
    },
    async get(opts, { origin = BASE, uv = true } = {}) {
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: opts.challenge, origin }))
      const flags = uv ? 0x05 : 0x01
      const authData = Buffer.concat([Buffer.from(await sha(Buffer.from(RP_ID))), Buffer.from([flags]), Buffer.from([0, 0, 0, counter])])
      const signed = Buffer.concat([authData, Buffer.from(await sha(clientData))])
      const sig = new Uint8Array(await wc.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, signed))
      return { id: b64u(credId), clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(rawToDer(sig)) }
    },
  }
}

// ------------------------------------------------------------------ tests
const anon = client()
const home = await anon.req('GET', '/')
check('page served', home.status === 200 && String(home.data).includes('Portal A5'))
check('page CSP', (home.headers.get('content-security-policy') || '').includes("script-src 'self'"), home.headers.get('content-security-policy'))
check('page Permissions-Policy', (home.headers.get('permissions-policy') || '').includes('publickey-credentials-get=(self)'))

check('POST without Origin = 403', (await anon.req('POST', '/api/login/start', { phone: OWNER }, { Origin: undefined })).status === 403)
check('POST from other origin = 403', (await anon.req('POST', '/api/login/start', { phone: OWNER }, { Origin: 'https://evil.example' })).status === 403)
check('POST without X-Portal = 403', (await anon.req('POST', '/api/login/start', { phone: OWNER }, { 'X-Portal': undefined })).status === 403)
check('/api/me signed out = 401', (await anon.req('GET', '/api/me')).status === 401)

// same answer for known and unknown numbers
const known = await anon.req('POST', '/api/login/start', { phone: OWNER })
const unknown = await anon.req('POST', '/api/login/start', { phone: '5511988887777' })
check('start: same shape for known and unknown', known.status === 201 && unknown.status === 201 &&
  JSON.stringify(Object.keys(known.data).sort()) === JSON.stringify(Object.keys(unknown.data).sort()), [known.data, unknown.data])
check('start: exact phrase', /^Entrar no Portal A5: A5-[A-Z2-9]{4}$/.test(known.data.message), known.data.message)
check('status waiting', (await anon.req('POST', '/api/login/status', { secret: known.data.secret })).data.status === 'waiting')

// robot key boundaries
const code0 = /A5-[A-Z0-9]{4}/.exec(known.data.message)[0]
check('robot wrong key = 401', (await robot({ code: code0, phone: OWNER }, 'pa5_robo_wrong')).status === 401)
check('robot key on other /robo route = 404', (await robot({}, ROBO_KEY, '/robo/caixa')).status === 404)
check('robot key on /api = 401/403', [401, 403].includes((await fetch(BASE + '/api/me', { headers: { 'X-A5-Robot-Key': ROBO_KEY } })).status))
check('self_chat with other number = 400', (await robot({ code: code0, phone: RESIDENT, self_chat: true })).status === 400)

// owner signs in (self chat)
const owner = client()
const o = await signIn(owner, OWNER, OWNER, true)
check('owner robot ok', o.robot.data?.ok === true, o.robot.data)
check('robot reply names the device', typeof o.robot.data?.device === 'string')
check('owner status ok + cookie', o.status.data.status === 'ok' && /__Host-a5s=.{40,}; Path=\/; HttpOnly; Secure; SameSite=Lax/.test(o.status.setCookie || ''), o.status.setCookie)
check('code is single use', (await owner.req('POST', '/api/login/status', { secret: o.start.data.secret })).data.status === 'used')
let me = (await owner.req('GET', '/api/me')).data
check('owner is admin, weak', me.admin === true && me.strong === false, me)
check('new-device alert shown', me.alerts?.length === 1, me.alerts)

// a second owner login inside 10 minutes is refused by the worker
const o2 = await signIn(client(), OWNER, OWNER, true)
check('owner 1 per 10 min', o2.robot.data?.reason === 'admin_limit', o2.robot.data)

// weak session: reads yes, writes no
check('weak admin read ok', (await owner.req('GET', '/api/admin/people')).status === 200)
const w = await owner.req('POST', '/api/admin/people', { name: 'Resident', phone: RESIDENT, groups: ['residents'] })
check('weak admin write = 403 passkey', w.status === 403 && w.data.passkey === true, w)
check('ack alert needs passkey', (await owner.req('POST', `/api/me/alerts/${me.alerts[0].id}/ack`, {})).status === 403)
check('get options without passkey = 409', (await owner.req('POST', '/api/passkey/get/options', {})).status === 409)

// first passkey (bootstrap from a weak session)
const auth = await makeAuthenticator()
const co = await owner.req('POST', '/api/passkey/create/options', {})
check('create options', co.status === 200 && co.data.rp.id === RP_ID, co.data)
const cv = await owner.req('POST', '/api/passkey/create/verify', await auth.create(co.data))
check('passkey registered', cv.status === 200, cv.data)
me = (await owner.req('GET', '/api/me')).data
check('session strong after registering', me.strong === true && me.passkeys === 1, me)

// strong: writes ok
const add = await owner.req('POST', '/api/admin/people', { name: '<img src=x onerror=alert(1)>', phone: RESIDENT, groups: ['residents'] })
check('strong write ok', add.status === 200, add.data)
const people = (await owner.req('GET', '/api/admin/people')).data
const res = people.find((p) => p.phone === RESIDENT)
check('name stored without markup', res && !/[<>]/.test(res.name), res)
check('ack alert with passkey', (await owner.req('POST', `/api/me/alerts/${me.alerts[0].id}/ack`, {})).status === 200)

// second passkey needs a fresh check: a fresh check works, a replayed or bad one does not
const go = await owner.req('POST', '/api/passkey/get/options', {})
const assertion = await auth.get(go.data)
check('passkey check ok', (await owner.req('POST', '/api/passkey/get/verify', assertion)).status === 200)
check('challenge single use', (await owner.req('POST', '/api/passkey/get/verify', assertion)).status === 400)
const go2 = await owner.req('POST', '/api/passkey/get/options', {})
check('wrong origin rejected', (await owner.req('POST', '/api/passkey/get/verify', await auth.get(go2.data, { origin: 'https://evil.example' }))).status === 400)
const go3 = await owner.req('POST', '/api/passkey/get/options', {})
check('no user verification rejected', (await owner.req('POST', '/api/passkey/get/verify', await auth.get(go3.data, { uv: false }))).status === 400)

// second admin: no first passkey from a weak session once the portal has one; an invite opens it
const ADMIN2 = '5561900000004'
check('owner adds a second admin', (await owner.req('POST', '/api/admin/people', { name: 'Admin2', phone: ADMIN2, groups: ['owner'] })).status === 200)
const admin2 = client()
const a2 = await signIn(admin2, ADMIN2, ADMIN2)
check('second admin signed in (weak)', a2.status.data.status === 'ok', a2.status.data)
check('weak admin: no passkey once the portal has one', (await admin2.req('POST', '/api/passkey/create/options', {})).status === 403)
const kick = await admin2.req('DELETE', `/api/me/devices/${me.session_id}`)
check('weak admin: revoking another device needs a passkey', kick.status === 403 && kick.data.passkey === true, kick)
check('weak admin sees masked numbers', (await admin2.req('GET', '/api/admin/people')).data.every((p) => p.phone.includes('•')))
const a2id = (await owner.req('GET', '/api/admin/people')).data.find((p) => p.phone === ADMIN2).id
check('strong admin sees full numbers', !!a2id)
check('owner invites second admin', (await owner.req('POST', `/api/admin/people/${a2id}/passkey-invite`, {})).status === 200)
const auth2 = await makeAuthenticator()
const co2 = await admin2.req('POST', '/api/passkey/create/options', {})
check('invite opens passkey options', co2.status === 200, co2.data)
check('invited admin registers passkey', (await admin2.req('POST', '/api/passkey/create/verify', await auth2.create(co2.data))).status === 200)
const a2sid = (await admin2.req('GET', '/api/me')).data.session_id

// a pending request whose sender is an admin can never be approved
const trick = client()
const tr = await signIn(trick, RESIDENT, OWNER)
check('admin number sending someone else\'s code -> pending', tr.robot.data?.reason === 'awaiting_owner', tr.robot.data)
const trReq = (await owner.req('GET', '/api/admin/requests')).data.find((x) => x.sender_phone === OWNER)
const trAp = await owner.req('POST', `/api/admin/requests/${trReq.id}/approve`, {})
check('approving an admin sender = 409', trAp.status === 409 && trAp.data.error === 'admin_direct_only', trAp)
check('refuse it', (await owner.req('POST', `/api/admin/requests/${trReq.id}/refuse`, {})).status === 200)

// the owner revokes the second admin's session; its warning must stay (checked in the shell script)
check('owner revokes the second admin device', (await owner.req('DELETE', `/api/admin/devices/${a2sid}`)).status === 200)

// resident: sees only their tab, no admin
const resident = client()
const r1 = await signIn(resident, RESIDENT, RESIDENT)
check('resident ok', r1.status.data.status === 'ok', [r1.robot.data, r1.status.data])
const rme = (await resident.req('GET', '/api/me')).data
check('resident tabs = tab-a, not admin', rme.admin === false && rme.tabs.join() === 'tab-a', rme)
check('resident admin read = 403', (await resident.req('GET', '/api/admin/people')).status === 403)
check('resident cannot register passkey', (await resident.req('POST', '/api/passkey/create/options', {})).status === 403)

// someone else sends the resident's code: nobody signs in until the owner approves
const victimTab = client()
const mm = await signIn(victimTab, RESIDENT, STRANGER)
check('mismatch -> pending', mm.robot.data?.reason === 'awaiting_owner' && mm.status.data.status === 'pending', [mm.robot.data, mm.status.data])
check('pending tab has no cookie', !victimTab.cookie)
const reqs = (await owner.req('GET', '/api/admin/requests')).data
const pend = reqs.find((x) => x.sender_phone === STRANGER)
check('request listed with sender number', !!pend && pend.typed_phone === RESIDENT, reqs)
const ap = await owner.req('POST', `/api/admin/requests/${pend.id}/approve`, { name: 'Visitor', groups: ['residents'] })
check('approve ok', ap.status === 200 && ap.data.code_valid === true, ap.data)
const after = await victimTab.req('POST', '/api/login/status', { secret: mm.start.data.secret })
check('approved tab signs in as the SENDER', after.data.status === 'ok' && after.data.name === 'Visitor', after.data)

// sender rate limit: 3 per hour
const spam = client()
let last
for (let i = 0; i < 4; i++) last = await signIn(spam, '5561900000009', '5561900000009')
check('robot 3/h per sender', last.robot.data?.reason === 'sender_limit', last.robot.data)

// revoke own device; the revoked cookie stops working
const resDevices = (await resident.req('GET', '/api/me/devices')).data
check('my devices lists current', resDevices.some((d) => d.current))
const second = client()
await signIn(second, RESIDENT, RESIDENT)
const sid = (await second.req('GET', '/api/me')).data.session_id
check('resident revokes other device', (await resident.req('DELETE', `/api/me/devices/${sid}`)).status === 200)
check('revoked session = 401', (await second.req('GET', '/api/me')).status === 401)
check('resident cannot revoke owner device', (await resident.req('DELETE', `/api/me/devices/${me.session_id}`)).status === 404)

// owner cannot lock themselves out
const ownerId = people.find((p) => p.phone === OWNER).id
check('owner cannot be blocked', (await owner.req('POST', `/api/admin/people/${ownerId}`, { status: 'blocked' })).status === 409)

// tabs: none configured yet
check('unknown tab = 404', (await owner.req('GET', '/nothing/')).status === 404)

// audit has the trail
const auditRows = (await owner.req('GET', '/api/admin/audit')).data
const actions = new Set(auditRows.map((a) => a.action))
for (const a of ['login_admin', 'passkey_added', 'passkey_ok', 'person_added', 'request_approved', 'device_revoked', 'robot_pending'])
  check(`audit has ${a}`, actions.has(a))
check('audit marks strength', auditRows.some((a) => a.strength === 'strong') && auditRows.some((a) => a.strength === 'weak'))

// ------------------------------------------------------------------ stage 2: tabs, screens, bridges
// Two tabs are bound to a fake tab worker (test/fake_tab): tab-a (residents) and tab-b
// (owner only, Face ID on every entry). The fake tab echoes what it receives.
const NAV = { 'Sec-Fetch-Mode': 'navigate', Accept: 'text/html' }
const CORS = { 'Sec-Fetch-Mode': 'cors', Accept: 'application/json' }
const WS_BASE = BASE.replace(/^http/, 'ws')
const residentId = (await owner.req('GET', '/api/admin/people')).data.find((p) => p.phone === RESIDENT).id
const ownerCsp = home.headers.get('content-security-policy')

function openWs(path, headers) {
  return new Promise((resolve) => {
    const ws = new WebSocket(WS_BASE + path, { headers })
    const t = setTimeout(() => { try { ws.close() } catch {} ; resolve({ ok: false, error: 'timeout' }) }, 5000)
    ws.onmessage = (e) => { clearTimeout(t); ws.close(); resolve({ ok: true, data: JSON.parse(String(e.data)) }) }
    ws.onerror = () => { clearTimeout(t); resolve({ ok: false, error: 'refused' }) }
  })
}
// Raw GET through node:http: fetch() forces Sec-Fetch-Mode: cors and refuses Upgrade, so
// browser navigations and socket handshakes are sent by hand.
function rawGet(path, headers) {
  return new Promise((resolve, reject) => {
    const r = http.request(BASE + path, { method: 'GET', headers })
    r.on('response', (res) => {
      let body = ''
      res.on('data', (d) => { body += d })
      res.on('end', () => {
        let data
        try { data = JSON.parse(body) } catch { data = body }
        resolve({ status: res.statusCode, headers: new Headers(Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)])), data, setCookie: res.headers['set-cookie']?.join(', ') })
      })
    })
    r.on('upgrade', (res, socket) => { socket.destroy(); resolve({ status: 101, headers: new Headers(), data: null }) })
    r.on('error', reject)
    r.end()
  })
}
const upgradeStatus = async (path, headers) => (await rawGet(path, { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': Buffer.from(wc.getRandomValues(new Uint8Array(16))).toString('base64'), ...headers })).status
const navigate = (c, path) => rawGet(path, { ...NAV, ...(c.cookie ? { Cookie: c.cookie } : {}) })
const tabRevoked = async () => (await resident.req('GET', '/tab-a/revoked', undefined, CORS)).data

// signed out
check('tab signed out: navigation redirects to sign-in', (await navigate(anon, '/tab-a/')).headers.get('location') === '/?next=%2Ftab-a%2F')
check('tab signed out: next keeps the query', (await navigate(anon, '/tab-a/?view=landscape')).headers.get('location') === '/?next=%2Ftab-a%2F%3Fview%3Dlandscape')
check('tab signed out: overlong query falls back to the path', (await navigate(anon, '/tab-a/?x=' + 'a'.repeat(600))).headers.get('location') === '/?next=%2Ftab-a%2F')
check('tab signed out: fetch = 401', (await anon.req('GET', '/tab-a/echo', undefined, CORS)).status === 401)

// identity and request headers
const echo = await resident.req('GET', '/tab-a/echo', undefined, {
  ...CORS, 'X-Portal-Person': 'owner', 'X-A5-Identity': '{"person":1,"groups":["owner"]}', Authorization: 'Bearer x', 'X-A5-Machine-Key': 'pa5_maq_fake',
})
const id = echo.data.identity
check('tab gets identity from the portal', echo.status === 200 && id.credential === 'browser' && id.person === residentId &&
  id.groups.join() === 'residents' && id.strong === false && id.machine === null && Array.isArray(id.actions), echo.data)
const fh = echo.data.headers || {}
check('forged portal headers never reach the tab', !('x-portal-person' in fh) && !('x-a5-identity' in fh) && !('x-a5-machine-key' in fh), fh)
check('tab never sees Cookie or Authorization', !('cookie' in fh) && !('authorization' in fh), fh)

const bad = (await navigate(resident, '/tab-a/html'))
check('Set-Cookie from the tab removed', !/stolen/.test(bad.setCookie || ''), bad.setCookie)
check('tab cannot send Clear-Site-Data, Service-Worker-Allowed or CORS', !bad.headers.get('clear-site-data') && !bad.headers.get('service-worker-allowed') &&
  ![...bad.headers.keys()].some((k) => k.startsWith('access-control-')))
const tabCspE = bad.headers.get('content-security-policy') || ''
check('portal CSP replaces the tab CSP (inline script blocked)', tabCspE.includes(`script-src ${BASE}/tab-a/ ${BASE}/_shell/tabs.js ${BASE}/locale/pt-BR.js;`) && !/unsafe-inline|\*/.test(tabCspE) && tabCspE.includes("frame-ancestors 'none'"), tabCspE)
check('tab CSP: connect only under the tab path plus /api/tabs; form-action only the tab', tabCspE.includes(`connect-src ${BASE}/tab-a/ ${WS_BASE}/tab-a/ ${BASE}/api/tabs;`) && tabCspE.includes(`form-action ${BASE}/tab-a/`), tabCspE)
const cspPart = (csp, d) => (csp.split(';').map((x) => x.trim()).find((x) => x.startsWith(d + ' ')) || '').split(' ').slice(1)
check('tab CSP: the only portal scripts are the two shell files', cspPart(tabCspE, 'script-src').join() === [`${BASE}/tab-a/`, `${BASE}/_shell/tabs.js`, `${BASE}/locale/pt-BR.js`].join(), cspPart(tabCspE, 'script-src'))
check('tab CSP: the only portal API is /api/tabs (no /api/ prefix, no self)', cspPart(tabCspE, 'connect-src').join() === [`${BASE}/tab-a/`, `${WS_BASE}/tab-a/`, `${BASE}/api/tabs`].join(), cspPart(tabCspE, 'connect-src'))
check('portal pages keep the portal CSP', ownerCsp.includes("script-src 'self'") && !ownerCsp.includes('/tab-a/'), ownerCsp)
check('tab page keeps nosniff and DENY', bad.headers.get('x-content-type-options') === 'nosniff' && bad.headers.get('x-frame-options') === 'DENY')
const ppE = bad.headers.get('permissions-policy') || ''
check('tab-a: wake lock on, microphone off', ppE.includes('screen-wake-lock=(self)') && ppE.includes('microphone=()') && ppE.includes('camera=()'), ppE)
const ppHome = home.headers.get('permissions-policy') || ''
check('portal pages: microphone and wake lock off', ppHome.includes('microphone=()') && ppHome.includes('screen-wake-lock=()'), ppHome)

// writes to a tab follow the portal's CSRF rule
check('tab POST without X-Portal = 403', (await resident.req('POST', '/tab-a/echo', { a: 1 }, { 'X-Portal': undefined })).status === 403)
check('tab POST from other origin = 403', (await resident.req('POST', '/tab-a/echo', { a: 1 }, { Origin: 'https://evil.example' })).status === 403)
const post = await resident.req('POST', '/tab-a/echo', { a: 1 })
check('tab POST body reaches the tab', post.status === 200 && post.data.body === '{"a":1}', post.data)
check('tab streams pass through', (await resident.req('GET', '/tab-a/stream', undefined, CORS)).data === 'data: one\n\n')

// no tab in the group
check('resident on tab-b = 403', (await resident.req('GET', '/tab-b/echo', undefined, CORS)).status === 403)
check('resident navigating to tab-b = 403', (await navigate(resident, '/tab-b/')).status === 403)

// audit through X-Tab-Audit
const au = await resident.req('GET', '/tab-a/audit', undefined, CORS)
check('X-Tab-Audit stripped from the answer', au.status === 200 && !au.headers.get('x-tab-audit'))
await resident.req('GET', '/tab-a/badaudit', undefined, CORS)
let rows = (await owner.req('GET', '/api/admin/audit')).data
const tabRow = rows.find((a) => a.action === 'tab-a.turn_on')
check('tab audit recorded with the portal\'s person', tabRow && tabRow.person_id === residentId && tabRow.target === 'ac:living' && /"credential":"browser"/.test(tabRow.detail), tabRow)
check('malformed tab audit recorded as invalid', rows.some((a) => a.action === 'tab-a.invalid_audit' && a.person_id === residentId))

// Face ID on every entry into tab-b
const nav1 = (await navigate(owner, '/tab-b/'))
check('tab-b entry without Face ID -> step-up page', nav1.status === 302 && nav1.headers.get('location') === '/?step_up=tab-b&next=%2Ftab-b%2F', [nav1.status, nav1.headers.get('location')])
check('tab-b step-up next keeps the query', (await navigate(owner, '/tab-b/?v=1')).headers.get('location') === '/?step_up=tab-b&next=%2Ftab-b%2F%3Fv%3D1')
const in1 = await owner.req('GET', '/tab-b/echo', undefined, CORS)
check('tab-b request without entry = 401 entry_required', in1.status === 401 && in1.data.error === 'entry_required' && in1.data.step_up, in1.data)
check('tab-b socket without entry = 401', (await upgradeStatus('/tab-b/live', { Cookie: owner.cookie, Origin: BASE })) === 401)
// a passkey check without the entry purpose does not open the tab
const plain = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(plain.data))
check('plain passkey check is not an entry', (await navigate(owner, '/tab-b/')).status === 302)
check('entry purpose for a session-only tab = 400', (await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:tab-a' })).status === 400)
check('entry purpose for an unknown tab = 400', (await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:nothing' })).status === 400)
check('resident cannot ask a tab-b entry', (await resident.req('POST', '/api/passkey/get/options', { purpose: 'entry:tab-b' })).status === 400)
const eo = await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:tab-b' })
const ev = await owner.req('POST', '/api/passkey/get/verify', await auth.get(eo.data))
check('entry passkey ok', ev.status === 200 && ev.data.next === '/tab-b/', ev.data)
const nav2 = (await navigate(owner, '/tab-b/'))
check('tab-b entry after Face ID = 200 with entered_at', nav2.status === 200 && !!nav2.data.identity.entered_at && nav2.data.identity.strong === true, nav2.data)
check('identity says when the entry ends (4 h)', Date.parse(nav2.data.identity.entry_until) - Date.parse(nav2.data.identity.entered_at) === 4 * 3600e3, nav2.data.identity)
check('tab-b refuses a service worker', (await owner.req('GET', '/tab-b/sw.js', undefined, { ...CORS, 'Service-Worker': 'script' })).status === 403)
check('tab-a allows a service worker', (await resident.req('GET', '/tab-a/sw.js', undefined, { ...CORS, 'Service-Worker': 'script' })).status === 200)
const ppJ = nav2.headers.get('permissions-policy') || ''
check('tab-b: microphone and wake lock on, camera off', ppJ.includes('microphone=(self)') && ppJ.includes('screen-wake-lock=(self)') && ppJ.includes('camera=()'), ppJ)
check('tab-b inside: requests free after entry', (await owner.req('GET', '/tab-b/echo', undefined, CORS)).status === 200)
check('tab-b: the grant is single use (reload asks again)', (await navigate(owner, '/tab-b/')).status === 302)
const jws = await openWs('/tab-b/live', { Cookie: owner.cookie, Origin: BASE })
check('tab-b socket after entry carries identity', jws.ok && jws.data.identity.credential === 'browser' && !!jws.data.identity.entered_at && !('cookie' in jws.data.headers), jws)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has tab_entry_granted and tab_entered', rows.some((a) => a.action === 'tab_entry_granted') && rows.some((a) => a.action === 'tab_entered'))

// live page sockets (tab-a)
const rws = await openWs('/tab-a/live', { Cookie: resident.cookie, Origin: BASE })
check('page socket: identity of the session', rws.ok && rws.data.identity.credential === 'browser' && rws.data.identity.person === residentId, rws)
check('page socket from another origin = 403', (await upgradeStatus('/tab-a/live', { Cookie: resident.cookie, Origin: 'https://evil.example' })) === 403)
check('page socket without Origin = 403', (await upgradeStatus('/tab-a/live', { Cookie: resident.cookie })) === 403)
check('page socket signed out = 401', (await upgradeStatus('/tab-a/live', { Origin: BASE })) === 401)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit header on a socket answer is recorded', rows.some((a) => a.action === 'tab-a.socket_opened'))

// fixed screens
const tv = client()
const ps = await tv.req('POST', '/api/pair/start', {})
check('pair start', ps.status === 201 && /^[A-Z2-9]{3}-[A-Z2-9]{3}$/.test(ps.data.code) && ps.data.pair_url.endsWith('/?pair=' + ps.data.code.replace('-', '')), ps.data)
check('pair status waiting', (await tv.req('POST', '/api/pair/status', { secret: ps.data.secret })).data.status === 'waiting')
check('pair status bad secret = 404', (await tv.req('POST', '/api/pair/status', { secret: 'x'.repeat(40) })).status === 404)
check('resident cannot approve a screen', (await resident.req('POST', '/api/admin/pair', { code: ps.data.code, name: 'TV' })).status === 403)
const look = await owner.req('GET', `/api/admin/pair?code=${ps.data.code}`)
check('owner sees who is asking, with IP', look.status === 200 && typeof look.data.label === 'string' && !!look.data.ip && look.data.same_ip === true, look.data)
// a request from another network is refused (wrangler local passes CF-Connecting-IP through)
const spoof = await owner.req('GET', `/api/admin/pair?code=${ps.data.code}`, undefined, { 'CF-Connecting-IP': '203.0.113.9' })
if (spoof.data.same_ip === false) {
  check('lookup flags another network', spoof.data.other_ip_refused === true, spoof.data)
  const ref = await owner.req('POST', '/api/admin/pair', { code: ps.data.code, name: 'TV' }, { 'CF-Connecting-IP': '203.0.113.9' })
  check('approval from another network = 409', ref.status === 409 && ref.data.error === 'pair_other_network', ref)
  check('refusal audited', (await owner.req('GET', '/api/admin/audit')).data.some((a) => a.action === 'screen_pair_refused'))
} else console.log('skip other-IP pairing cases: CF-Connecting-IP not settable locally')
check('wrong code = 404', (await owner.req('POST', '/api/admin/pair', { code: 'ZZZ-ZZZ', name: 'TV' })).status === 404)
const ap1 = await owner.req('POST', '/api/admin/pair', { code: ps.data.code.toLowerCase(), name: 'TV <b>sala</b>' })
check('owner approves a new screen account', ap1.status === 200 && ap1.data.screen > 0, ap1.data)
check('code is single use for approval', (await owner.req('POST', '/api/admin/pair', { code: ps.data.code, name: 'TV2' })).status === 404)
const pst = await tv.req('POST', '/api/pair/status', { secret: ps.data.secret })
check('screen gets a 1-year cookie', pst.data.status === 'ok' && /Max-Age=31536000/.test(pst.setCookie || '') && /HttpOnly; Secure; SameSite=Lax/.test(pst.setCookie || ''), [pst.data, pst.setCookie])
check('pairing secret single use', (await tv.req('POST', '/api/pair/status', { secret: ps.data.secret })).data.status === 'used')
const tvMe = (await tv.req('GET', '/api/me')).data
check('screen is a resident, never admin', tvMe.credential === 'screen' && tvMe.admin === false && tvMe.tabs.join() === 'tab-a' && !/[<>]/.test(tvMe.person.name), tvMe)
const tvEcho = await tv.req('GET', '/tab-a/echo', undefined, CORS)
check('screen identity reaches the tab', tvEcho.status === 200 && tvEcho.data.identity.credential === 'screen' && tvEcho.data.identity.person === ap1.data.screen, tvEcho.data)
check('screen has no admin access', (await tv.req('GET', '/api/admin/people')).status === 403)
check('screen cannot register a passkey', (await tv.req('POST', '/api/passkey/create/options', {})).status === 403)
check('screen cannot join the owner group', (await owner.req('POST', `/api/admin/people/${ap1.data.screen}`, { groups: ['owner'] })).status === 409)
const tvws = await openWs('/tab-a/live', { Cookie: tv.cookie, Origin: BASE })
check('screen page socket', tvws.ok && tvws.data.identity.credential === 'screen', tvws)
const tvTabs = await tv.req('GET', '/api/tabs')
check('fixed screen: no selector, tab-a only, no counts', tvTabs.status === 200 && tvTabs.data.selector === false && tvTabs.data.tabs.map((t) => t.id).join() === 'tab-a' && tvTabs.data.tabs.every((t) => t.badge === null), tvTabs.data)
const tvPeople = (await owner.req('GET', '/api/admin/people')).data.find((p) => p.id === ap1.data.screen)
check('screen listed as kind screen without a phone', tvPeople && tvPeople.kind === 'screen' && tvPeople.phone === null, tvPeople)
const tvDev = (await owner.req('GET', '/api/admin/devices')).data.find((d) => d.person_id === ap1.data.screen)
check('screen session listed in all devices', tvDev && tvDev.kind === 'screen', tvDev)
// pairing the same account again replaces the old screen session
const tv2 = client()
const ps2 = await tv2.req('POST', '/api/pair/start', {})
check('re-pair existing screen account', (await owner.req('POST', '/api/admin/pair', { code: ps2.data.code, screen: ap1.data.screen })).status === 200)
check('new screen signs in', (await tv2.req('POST', '/api/pair/status', { secret: ps2.data.secret })).data.status === 'ok')
check('old screen session is gone', (await tv.req('GET', '/api/me')).status === 401)
check('tabs told to close the old screen session', (await tabRevoked()).some((r) => r.session === tvDev.id), await tabRevoked())
// revoke from "all devices"
const tv2sid = (await tv2.req('GET', '/api/me')).data.session_id
check('owner revokes the screen', (await owner.req('DELETE', `/api/admin/devices/${tv2sid}`)).status === 200)
check('revoked screen = 401', (await tv2.req('GET', '/tab-a/echo', undefined, CORS)).status === 401)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has screen_paired and screen_signed_in', rows.some((a) => a.action === 'screen_paired') && rows.some((a) => a.action === 'screen_signed_in'))

// machine bridges
const mk = await owner.req('POST', '/api/admin/machines', { tab: 'tab-a', label: 'Pi ⚡' })
check('machine key created once', mk.status === 200 && /^pa5_maq_[A-Za-z0-9_-]{43}$/.test(mk.data.key), mk.data)
check('machine key for unknown tab = 400', (await owner.req('POST', '/api/admin/machines', { tab: 'nothing', label: 'x' })).status === 400)
check('resident cannot create machine keys', (await resident.req('POST', '/api/admin/machines', { tab: 'tab-a', label: 'x' })).status === 403)
const ml = (await owner.req('GET', '/api/admin/machines')).data
check('machine list never shows the key', ml.length === 1 && !JSON.stringify(ml).includes(mk.data.key) && !('key_hash' in ml[0]), ml)
const KEY = { 'X-A5-Machine-Key': mk.data.key }
const bws = await openWs('/_bridge/tab-a', { ...KEY, Cookie: owner.cookie })
check('identity header survives non-Latin-1 names', bws.ok && bws.data.identity.name === 'Pi ⚡', bws)
check('bridge: tab gets a machine identity', bws.ok && bws.data.identity.credential === 'machine' && bws.data.identity.machine === mk.data.id &&
  bws.data.identity.person === null && bws.data.identity.groups.length === 0, bws)
check('bridge: key and cookie never reach the tab', bws.ok && !('x-a5-machine-key' in bws.data.headers) && !('cookie' in bws.data.headers), bws.data?.headers)
check('bridge: key for another tab = 401', (await upgradeStatus('/_bridge/tab-b', KEY)) === 401)
check('bridge: wrong key = 401', (await upgradeStatus('/_bridge/tab-a', { 'X-A5-Machine-Key': 'pa5_maq_' + 'A'.repeat(43) })) === 401)
check('bridge: one byte changed = 401', (await upgradeStatus('/_bridge/tab-a', { 'X-A5-Machine-Key': mk.data.key.slice(0, -1) + (mk.data.key.endsWith('A') ? 'B' : 'A') })) === 401)
check('bridge: no key = 401', (await upgradeStatus('/_bridge/tab-a', {})) === 401)
check('bridge: robot key = 401', (await upgradeStatus('/_bridge/tab-a', { 'X-A5-Machine-Key': ROBO_KEY })) === 401)
check('bridge: session cookie alone = 401', (await upgradeStatus('/_bridge/tab-a', { Cookie: owner.cookie, Origin: BASE })) === 401)
check('bridge: without upgrade = 426', (await rawGet('/_bridge/tab-a', KEY)).status === 426)
check('bridge: unknown tab = 404', (await upgradeStatus('/_bridge/nothing', KEY)) === 404)
check('bridge: other paths = 404', (await upgradeStatus('/_bridge/tab-a/x', KEY)) === 404)
check('machine key on /api = 401', (await fetch(BASE + '/api/me', { headers: KEY })).status === 401)
check('machine key on a tab page = 401', (await fetch(BASE + '/tab-a/echo', { headers: { ...KEY, ...CORS } })).status === 401)
// reconnecting more than 3 times in an hour warns the admins
for (let i = 0; i < 3; i++) await openWs('/_bridge/tab-a', KEY)
me = (await owner.req('GET', '/api/me')).data
check('bridge reconnect burst alerts the owner', me.alerts.some((a) => a.kind === 'bridge' && a.label === 'tab-a:Pi ⚡'), me.alerts)
const moved = await openWs('/_bridge/tab-a', { ...KEY, 'CF-Connecting-IP': '203.0.113.7' })
if (moved.ok) {
  me = (await owner.req('GET', '/api/me')).data
  check('key used from a new IP alerts the owner', me.alerts.some((a) => a.kind === 'bridge_ip'), me.alerts)
}
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has bridge_connected and bridge_refused', rows.some((a) => a.action === 'bridge_connected') && rows.some((a) => a.action === 'bridge_refused'))
check('owner revokes the machine key', (await owner.req('DELETE', `/api/admin/machines/${mk.data.id}`)).status === 200)
check('revoked key = 401', (await upgradeStatus('/_bridge/tab-a', KEY)) === 401)
check('tab told to close the revoked bridge', (await tabRevoked()).some((r) => r.machine === mk.data.id))

// changing a person's groups or taking a tab from a group makes the tabs re-check sockets
check('person groups change', (await owner.req('POST', `/api/admin/people/${residentId}`, { groups: ['residents'] })).status === 200)
check('tabs told when a person\'s groups change', (await tabRevoked()).some((r) => r.person === residentId))
const revBefore = (await tabRevoked()).length
check('group loses tab-a', (await owner.req('POST', '/api/admin/groups/residents', { tabs: [] })).status === 200)
check('resident lost the tab at once', (await resident.req('GET', '/tab-a/echo', undefined, CORS)).status === 403)
check('group gets tab-a back', (await owner.req('POST', '/api/admin/groups/residents', { tabs: ['tab-a'] })).status === 200)
const revAfter = await tabRevoked()
check('tabs told when a group loses a tab', revAfter.length > revBefore && revAfter.slice(revBefore).some((r) => r.person === residentId), revAfter.slice(revBefore))

// shell v2: /api/tabs, badge, the account page and the shared selector files
check('/api/tabs signed out = 401', (await anon.req('GET', '/api/tabs')).status === 401)
check('/api/tabs is GET only', (await owner.req('POST', '/api/tabs', {})).status === 404)
const t0 = Date.now()
const ot = await owner.req('GET', '/api/tabs?current=tab-a')
const took = Date.now() - t0
check('owner: every bound tab in binding order, reserved name dropped', ot.status === 200 && ot.data.selector === true && ot.data.tabs.map((t) => t.id).join() === 'tab-a,tab-b,tab-slow,tab-odd', ot.data)
check('owner: account entry at /conta/', ot.data.account && ot.data.account.id === 'conta' && ot.data.account.path === '/conta/', ot.data.account)
check('current echoed only for a listed tab', ot.data.current === 'tab-a' && (await owner.req('GET', '/api/tabs?current=nothing')).data.current === null &&
  (await owner.req('GET', '/api/tabs?current=conta')).data.current === 'conta')
const byId = Object.fromEntries(ot.data.tabs.map((t) => [t.id, t]))
check('badge comes from the tab', byId['tab-a'].badge === 3 && byId['tab-b'].badge === 3, byId)
check('slow badge: no number, and the answer does not wait for it', byId['tab-slow'].badge === null && took < 1500, [byId['tab-slow'], took])
check('badge that is not a count: no number', byId['tab-odd'].badge === null, byId['tab-odd'])
check('entry kind per tab', byId['tab-b'].entry === 'passkey' && byId['tab-a'].entry === 'session')
check('list carries id, path, label, icon, badge and entry only', ot.data.tabs.every((t) => Object.keys(t).sort().join() === 'badge,entry,icon,id,label,path'), ot.data.tabs)
check('label and icon from the configuration', byId['tab-a'].label === 'Tab A' && byId['tab-a'].icon === 'bolt' && byId['tab-slow'].label === null && byId['tab-slow'].icon === null, byId)
check('a tab without a written policy is never routed', (await navigate(owner, '/tab-nopolicy/')).status === 404 && (await owner.req('GET', '/tab-nopolicy/echo', undefined, CORS)).status === 404)
check('a tab with an unknown key is never routed', (await navigate(owner, '/tab-bad/')).status === 404)
let calls = (await resident.req('GET', '/tab-a/badges', undefined, CORS)).data
const ownerCall = calls.find((c) => c.person === ownerId)
check('badge gets the person\'s identity, with no entry and never strong', ownerCall && ownerCall.credential === 'browser' && ownerCall.entered_at === null && ownerCall.entry_until === null && ownerCall.strong === false, ownerCall)
const nCalls = calls.length
await owner.req('GET', '/api/tabs')
check('badge kept for a minute (no new call to the tab)', (await resident.req('GET', '/tab-a/badges', undefined, CORS)).data.length === nCalls)
const rt = await resident.req('GET', '/api/tabs?current=tab-a')
check('resident: Tab A + Conta only', rt.status === 200 && rt.data.selector === true && rt.data.tabs.map((t) => t.id).join() === 'tab-a' && rt.data.account.path === '/conta/', rt.data)
calls = (await resident.req('GET', '/tab-a/badges', undefined, CORS)).data
check('resident: no count, and the tab is never asked', rt.data.tabs[0].badge === null && !calls.some((c) => c.person === residentId), rt.data)
check('fixed screen: the tab is never asked for a count', !calls.some((c) => c.credential === 'screen'))
const sj = await fetch(BASE + '/_shell/tabs.js')
const sjt = await sj.text()
check('/_shell/tabs.js served as a script, no innerHTML', sj.status === 200 && /javascript/.test(sj.headers.get('content-type') || '') && sjt.includes('A5Tabs') && !/innerHTML|insertAdjacentHTML|outerHTML/.test(sjt))
check('/_shell/tabs.css served', (await fetch(BASE + '/_shell/tabs.css')).status === 200)
check('locale exposes the selector texts under A5_TEXT', /window\.A5_TEXT = window\.T/.test(await (await fetch(BASE + '/locale/pt-BR.js')).text()))
check('portal page loads the selector', /\/_shell\/tabs\.js/.test(home.data) && /\/_shell\/tabs\.css/.test(home.data))
const acc = await navigate(owner, '/conta/')
check('account page: the portal page with the portal CSP', acc.status === 200 && /id="title"/.test(acc.data) && acc.headers.get('content-security-policy') === ownerCsp, [acc.status, acc.headers.get('content-security-policy')])
check('account page answers signed out too (sign-in screen)', (await navigate(anon, '/conta/')).status === 200)
check('/conta redirects to /conta/', (await navigate(owner, '/conta')).status === 301)
check('reserved name: /conta/* never reaches a tab', (await navigate(owner, '/conta/echo')).status === 404)
check('reserved name: no machine key for it', (await owner.req('POST', '/api/admin/machines', { tab: 'conta', label: 'x' })).status === 400)

// ------------------------------------------------------------------ stage 3: commands and Shortcuts keys
// tab-a carries a test catalog (scripts/test_local.sh); the fake tab logs every command() call.
const freshen = async (c, a) => { const g = await c.req('POST', '/api/passkey/get/options', {}); return (await c.req('POST', '/api/passkey/get/verify', await a.get(g.data))).status === 200 }
const cmdLog = async () => (await owner.req('GET', '/tab-a/commands', undefined, CORS)).data
const cmd = (c, tab, action, params, headers) => c.req('POST', `/${tab}/_cmd/${action}`, params === undefined ? {} : { params }, headers)
// writes to the local D1 the wrangler dev is serving (scripts/test_local.sh passes STATE)
const d1 = (sql) => { try { execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--command', sql], { stdio: 'ignore' }); return true } catch { return false } }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

check('C01 a tab with one malformed command is never routed', (await owner.req('GET', '/tab-badcmd/echo', undefined, CORS)).status === 404)
const rEcho = (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
check('identity.actions: resident gets common actions only (no presence, no sensitive)', rEcho.actions.join() === 'tv,ac,light,slow,boom', rEcho.actions)
check('identity.shortcut is null for a page', rEcho.shortcut === null)
check('freshen owner', await freshen(owner, auth))
const oEcho = (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
check('identity.actions: owner with Face ID gets admin and sensitive actions', ['presence', 'wipe'].every((a) => oEcho.actions.includes(a)), oEcho.actions)

// C08: a new non-admin device waits 24 h or the owner's release
let n0 = (await cmdLog()).length
const young = await cmd(resident, 'tab-a', 'tv', { mode: 'on' })
check('C08 new resident device: first command held', young.status === 403 && young.data.error === 'device_too_new', young)
const resSid = (await resident.req('GET', '/api/me')).data.session_id
check('owner releases the resident device', (await owner.req('POST', `/api/admin/devices/${resSid}/commands`, {})).status === 200)
check('resident cannot release devices', (await resident.req('POST', `/api/admin/devices/${resSid}/commands`, {})).status === 403)

const tv1 = await cmd(resident, 'tab-a', 'tv', { mode: 'on' })
check('resident common command = 200 done', tv1.status === 200 && tv1.data.status === 'done' && tv1.data.ok === true && UUID.test(tv1.data.id), tv1)
check('only declared result fields come back', JSON.stringify(tv1.data.result) === '{"state":"on"}', tv1.data)
let log = await cmdLog()
const got = log[log.length - 1]
check('tab gets id, action, exact params and a 60 s expiry', got.cmd.id === tv1.data.id && got.cmd.action === 'tv' && JSON.stringify(got.cmd.params) === '{"mode":"on"}' &&
  Math.abs(Date.parse(got.cmd.expires_at) - Date.now() - 60e3) < 15e3, got.cmd)
check('tab gets the resident identity with its actions', got.identity.credential === 'browser' && got.identity.person === residentId && got.identity.actions.includes('tv') && !got.identity.actions.includes('presence'), got.identity)
check('held command never reached the tab', log.length === n0 + 1)

// C07: levels
n0 = (await cmdLog()).length
const rp = await cmd(resident, 'tab-a', 'presence', { state: 'out' })
check('C07 resident: admin action (presence) = 403', rp.status === 403 && rp.data.error === 'admin_only', rp)
check('C07 resident: sensitive action = 403', (await cmd(resident, 'tab-a', 'wipe')).data.error === 'admin_only')

// C01: action and parameters
check('C01 unknown action = 404', (await cmd(resident, 'tab-a', 'shell', {})).data.error === 'unknown_action')
check('C01 param outside the enum = 400', (await cmd(resident, 'tab-a', 'tv', { mode: 'rm -rf' })).data.error === 'bad_param')
check('C01 extra param = 400', (await cmd(resident, 'tab-a', 'tv', { mode: 'on', url: 'http://x' })).data.error === 'unknown_param')
check('C01 missing param = 400', (await cmd(resident, 'tab-a', 'tv', {})).data.error === 'missing_param')
check('C01 wrong type = 400', (await cmd(resident, 'tab-a', 'tv', { mode: 1 })).data.error === 'bad_param')
check('C01 extra top-level field = 400', (await resident.req('POST', '/tab-a/_cmd/tv', { params: { mode: 'on' }, exec: 'x' })).data.error === 'bad_params')
check('C01 params not an object = 400', (await resident.req('POST', '/tab-a/_cmd/tv', { params: ['on'] })).data.error === 'bad_params')
check('C01 bad JSON = 400', (await fetch(BASE + '/tab-a/_cmd/tv', { method: 'POST', headers: { Cookie: resident.cookie, Origin: BASE, 'X-Portal': '1', 'Content-Type': 'application/json' }, body: '{' })).status === 400)
check('no refused command reached the tab', (await cmdLog()).length === n0)
check('GET on a command = 405', (await resident.req('GET', '/tab-a/_cmd/tv', undefined, CORS)).status === 405)
check('/_cmd paths never reach the tab', (await resident.req('GET', '/tab-a/_cmd', undefined, CORS)).status === 404 && (await resident.req('POST', '/tab-a/_cmd/tv/x', {})).status === 404)
check('page command without X-Portal = 403', (await cmd(resident, 'tab-a', 'tv', { mode: 'on' }, { 'X-Portal': undefined })).status === 403)
check('page command from another origin = 403', (await cmd(resident, 'tab-a', 'tv', { mode: 'on' }, { Origin: 'https://evil.example' })).status === 403)
check('page command signed out = 401', (await cmd(anon, 'tab-a', 'tv', { mode: 'on' })).status === 401)
check('page command on a tab the person lacks = 403', (await cmd(resident, 'tab-b', 'ping')).status === 403)

// limits and intervals
let tvl
for (let i = 0; i < 5; i++) tvl = await cmd(resident, 'tab-a', 'tv', { mode: 'off' })
check('perHour per caller (tv 5/h) = 429', tvl.status === 429 && tvl.data.error === 'too_many_commands', tvl)
const ac1 = await cmd(resident, 'tab-a', 'ac', { unit: 'a' })
const ac2 = await cmd(owner, 'tab-a', 'ac', { unit: 'a' })
check('gap: same unit within 180 s = 429 for anyone, with retry_after', ac1.status === 200 && ac2.status === 429 && ac2.data.error === 'too_soon' && ac2.data.retry_after > 100, [ac1.data, ac2.data])
check('gap is per unit', (await cmd(owner, 'tab-a', 'ac', { unit: 'b' })).status === 200)
const sl = await cmd(owner, 'tab-a', 'slow')
check('bridge not answering in time = 202 sent', sl.status === 202 && sl.data.status === 'sent' && sl.data.ok === false, sl)
const bm = await cmd(owner, 'tab-a', 'boom')
check('tab error = 502 failed, no stack', bm.status === 502 && bm.data.status === 'failed' && bm.data.error === 'tab_error' && !JSON.stringify(bm.data).includes('boom'), bm)

// fixed screens: only common actions marked for screens
const tvc = client()
const psc = await tvc.req('POST', '/api/pair/start', {})
await owner.req('POST', '/api/admin/pair', { code: psc.data.code, name: 'TV commands' })
await tvc.req('POST', '/api/pair/status', { secret: psc.data.secret })
check('screen: common action for screens = 200', (await cmd(tvc, 'tab-a', 'tv', { mode: 'globo' })).status === 200)
check('screen: common action not for screens = 403', (await cmd(tvc, 'tab-a', 'light')).data.error === 'not_for_screens')
check('screen: admin action = 403', (await cmd(tvc, 'tab-a', 'presence', { state: 'home' })).status === 403)

// C07: an admin session that never did a passkey check is weak for admin actions
const ADMIN3 = '5561900000005'
check('owner adds a third admin', (await owner.req('POST', '/api/admin/people', { name: 'Admin3', phone: ADMIN3, groups: ['owner'] })).status === 200)
const admin3 = client()
await signIn(admin3, ADMIN3, ADMIN3)
const pe = await cmd(admin3, 'tab-b', 'ping')
check('Face ID tab: a command needs the entry too', pe.status === 401 && pe.data.error === 'entry_required', pe)
check('Face ID tab: a command inside a live entry is fine', (await cmd(owner, 'tab-b', 'ping')).status === 200)
const wp = await cmd(admin3, 'tab-a', 'presence', { state: 'out' })
check('C07 weak admin session: admin action = 403 passkey_required', wp.status === 403 && wp.data.error === 'passkey_required', wp)
// owner's decision (05/11): admin commands from a browser need this session's passkey in the last 12 h
const a3sid = (await admin3.req('GET', '/api/me')).data.session_id
const setPasskeyAt = (ms) => d1(`UPDATE sessions SET passkey_at = '${new Date(Date.now() - ms).toISOString()}' WHERE id = ${a3sid}`)
if (setPasskeyAt(12 * 3600e3 + 60e3)) {
  const old = await cmd(admin3, 'tab-a', 'presence', { state: 'out' })
  check('B2 passkey 12 h 1 min ago: admin action = 403 passkey_required', old.status === 403 && old.data.error === 'passkey_required', old)
  check('B2 ... and identity.actions leaves it out', !(await admin3.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.actions.includes('presence'))
  setPasskeyAt(12 * 3600e3 - 60e3)
  check('B2 passkey 11 h 59 min ago: admin action ok', (await cmd(admin3, 'tab-a', 'presence', { state: 'home' })).status === 200)
  check('B2 ... and identity.actions lists it; sensitive still needs 5 min', (await admin3.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.actions.includes('presence') &&
    (await cmd(admin3, 'tab-a', 'wipe')).data.error === 'passkey_required')
  d1(`UPDATE sessions SET passkey_at = NULL WHERE id = ${a3sid}`)
} else check('B2 local D1 reachable from the test', false)
check('weak admin session: common action ok (admins are not held)', (await cmd(admin3, 'tab-a', 'light')).status === 200)
const op = await cmd(owner, 'tab-a', 'presence', { state: 'out' })
check('owner device with passkey: admin action ok, nothing read back', op.status === 200 && op.data.result === undefined, op)
check('owner with fresh Face ID: sensitive ok', (await freshen(owner, auth)) && (await cmd(owner, 'tab-a', 'wipe')).status === 200)

// C06: Shortcuts keys
check('resident cannot list or create keys', (await resident.req('GET', '/api/me/shortcuts')).status === 403 &&
  (await resident.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-a/tv'] })).status === 403)
const wk = await admin3.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-a/tv'] })
check('C06 creating a key from a weak session = 403 passkey', wk.status === 403 && wk.data.passkey === true, wk)
check('freshen owner (keys)', await freshen(owner, auth))
check('key scope with a sensitive action = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-a/wipe'] })).data.error === 'bad_scope')
check('key scope on a Face ID tab = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-b/ping'] })).data.error === 'bad_scope')
check('key scope with an unknown action = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-a/nope'] })).data.error === 'bad_scope')
check('key without a label = 400', (await owner.req('POST', '/api/me/shortcuts', { scope: ['tab-a/tv'] })).status === 400)
const k1 = await owner.req('POST', '/api/me/shortcuts', { label: 'iPhone · <b>TV</b>', scope: ['tab-a/tv', 'tab-a/presence', 'tab-a/light'] })
check('key created once with pa5_atl_ prefix', k1.status === 200 && /^pa5_atl_[A-Za-z0-9_-]{43}$/.test(k1.data.key) && !/[<>]/.test(k1.data.label), k1.data)
const KEYH = (k) => ({ Authorization: `Bearer ${k}` })
const sc = (path, params, headers = KEYH(k1.data.key), method = 'POST') => fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: method === 'POST' ? JSON.stringify(params === undefined ? {} : { params }) : undefined })
  .then(async (r) => ({ status: r.status, data: await r.json().catch(() => null), headers: r.headers }))

const s1 = await sc('/_cmd/tab-a/presence', { state: 'home' })
check('shortcut: admin action in scope = 200, nothing read back', s1.status === 200 && s1.data.status === 'done' && s1.data.result === undefined, s1)
log = await cmdLog()
const sid1 = log[log.length - 1].identity
check('shortcut identity: credential shortcut, key id, no session, never strong', sid1.credential === 'shortcut' && sid1.shortcut === k1.data.id && sid1.session === null && sid1.strong === false && sid1.person === ownerId, sid1)
me = (await owner.req('GET', '/api/me')).data
const placeAlerts = me.alerts.filter((x) => x.kind === 'shortcut_place')
check('R1 first use of a key from a new place warns the admins', placeAlerts.length === 1 && placeAlerts[0].label.includes('iPhone'), me.alerts)
await sc('/_cmd/tab-a/light')
check('R1 same place again: no new warning', (await owner.req('GET', '/api/me')).data.alerts.filter((x) => x.kind === 'shortcut_place').length === 1)
check('shortcut answers carry no cookie', !(await sc('/_cmd/tab-a/light')).headers.get('set-cookie'))
check('C06 shortcut: action out of scope = 403', (await sc('/_cmd/tab-a/ac', { unit: 'b' })).data?.error === 'out_of_scope')
check('C06 shortcut: sensitive action = 403', (await sc('/_cmd/tab-a/wipe')).data?.error === 'not_for_shortcuts')
check('C06 shortcut: Face ID tab = 403', (await sc('/_cmd/tab-b/ping')).data?.error === 'not_for_shortcuts')
check('shortcut: wrong key = 401', (await sc('/_cmd/tab-a/light', undefined, KEYH('pa5_atl_' + 'A'.repeat(43)))).status === 401)
check('shortcut: one byte changed = 401', (await sc('/_cmd/tab-a/light', undefined, KEYH(k1.data.key.slice(0, -1) + (k1.data.key.endsWith('A') ? 'B' : 'A')))).status === 401)
check('shortcut: no key = 401', (await sc('/_cmd/tab-a/light', undefined, {})).status === 401)
check('shortcut: machine or robot key = 401', (await sc('/_cmd/tab-a/light', undefined, KEYH('pa5_maq_' + 'A'.repeat(43)))).status === 401 && (await sc('/_cmd/tab-a/light', undefined, KEYH(ROBO_KEY))).status === 401)
check('shortcut: session cookie alone = 401', (await sc('/_cmd/tab-a/light', undefined, { Cookie: owner.cookie, Origin: BASE, 'X-Portal': '1' })).status === 401)
check('shortcut: GET = 405', (await sc('/_cmd/tab-a/light', undefined, KEYH(k1.data.key), 'GET')).status === 405)
check('shortcut: unknown tab or bad path = 404', (await sc('/_cmd/nothing/light')).status === 404 && (await sc('/_cmd/tab-a')).status === 404)
check('shortcut key opens nothing else: /api/me, a tab page, a bridge', (await fetch(BASE + '/api/me', { headers: KEYH(k1.data.key) })).status === 401 &&
  (await fetch(BASE + '/tab-a/echo', { headers: { ...KEYH(k1.data.key), ...CORS } })).status === 401 &&
  (await upgradeStatus('/_bridge/tab-a', { 'X-A5-Machine-Key': k1.data.key })) === 401)
const kl = (await owner.req('GET', '/api/me/shortcuts')).data
const kRow = kl.keys.find((k) => k.id === k1.data.id)
check('key list: last use and place, never the key or its hash', kRow && !!kRow.last_used_at && !!kRow.last_ip && !JSON.stringify(kl).includes(k1.data.key) && !('key_hash' in kRow), kRow)
check('key list offers keyable actions only (no sensitive, no Face ID tab)', kl.available.some((a) => a.tab === 'tab-a' && a.action === 'tv') && !kl.available.some((a) => a.action === 'wipe' || a.tab === 'tab-b'), kl.available)
// 30 an hour per key
let kl30
for (let i = 0; i < 30; i++) kl30 = await sc('/_cmd/tab-a/light')
check('shortcut: 30/h per key = 429', kl30.status === 429 && kl30.data.error === 'too_many_commands', kl30)
check('resident cannot revoke the owner key', (await resident.req('DELETE', `/api/me/shortcuts/${k1.data.id}`)).status === 404)
const k2 = await owner.req('POST', '/api/me/shortcuts', { label: 'Watch', scope: ['tab-a/light'] })
check('second key', k2.status === 200)
check('another admin cannot revoke someone else\'s key', (await admin3.req('DELETE', `/api/me/shortcuts/${k2.data.id}`)).status === 404)
check('owner revokes the key', (await owner.req('DELETE', `/api/me/shortcuts/${k2.data.id}`)).status === 200)
check('revoked key = 401', (await sc('/_cmd/tab-a/light', undefined, KEYH(k2.data.key))).status === 401)

// the brake
check('weak admin pulls the brake', (await admin3.req('POST', '/api/admin/commands', { off: true })).status === 200)
check('brake shown to admins', (await owner.req('GET', '/api/me')).data.commands_off === true && (await resident.req('GET', '/api/me')).data.commands_off === undefined)
const br = await cmd(resident, 'tab-a', 'light')
check('brake: page command = 503 commands_off', br.status === 503 && br.data.error === 'commands_off', br)
const k3 = await owner.req('POST', '/api/me/shortcuts', { label: 'brake test', scope: ['tab-a/light'] })
check('brake: shortcut = 503', (await sc('/_cmd/tab-a/light', undefined, KEYH(k3.data.key))).status === 503)
check('resident cannot touch the brake', (await resident.req('POST', '/api/admin/commands', { off: false })).status === 403)
const rel = await admin3.req('POST', '/api/admin/commands', { off: false })
check('releasing the brake needs Face ID', rel.status === 403 && rel.data.passkey === true, rel)
check('brake value must be a boolean', (await owner.req('POST', '/api/admin/commands', { off: 'no' })).status === 400)
check('owner with Face ID releases the brake', (await freshen(owner, auth)) && (await owner.req('POST', '/api/admin/commands', { off: false })).status === 200)
check('commands work again', (await cmd(resident, 'tab-a', 'light')).status === 200)

// audit
rows = (await owner.req('GET', '/api/admin/audit')).data
for (const a of ['command', 'command_refused', 'shortcut_key_created', 'shortcut_key_revoked', 'shortcut_refused', 'commands_off', 'commands_on', 'device_commands_allowed'])
  check(`audit has ${a}`, rows.some((r) => r.action === a))
const shRow = rows.find((r) => r.action === 'command' && r.strength === 'shortcut')
check('shortcut command audited with the key id and person, never the key', shRow && shRow.person_id === ownerId && JSON.parse(shRow.detail).shortcut > 0 && !rows.some((r) => String(r.detail).includes('pa5_atl_')), shRow)
const refRow = rows.find((r) => r.action === 'command_refused' && JSON.parse(r.detail).reason === 'device_too_new')
check('refusal audited with its reason', !!refRow && refRow.target === 'tab-a/tv', refRow)

// the selector in a real browser (owner, resident and a freshly paired screen)
const g5 = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(g5.data))
const tv3 = client()
const ps3 = await tv3.req('POST', '/api/pair/start', {})
await owner.req('POST', '/api/admin/pair', { code: ps3.data.code, name: 'TV browser' })
await tv3.req('POST', '/api/pair/status', { secret: ps3.data.secret })
check('screen for the browser test paired', !!tv3.cookie)
await browserChecks({ base: BASE, check, owner: owner.cookie, resident: resident.cookie, screen: tv3.cookie,
  approve: async (code) => check('browser pairing approved', (await owner.req('POST', '/api/admin/pair', { code, name: 'TV deep link' })).status === 200) })

// ------------------------------------------------------------------ house agents (pa5_adm_, D11/D12)
{ // own scope: these names must not clash with the rest of the battery
const agentCall = (method, path, body, key, headers = {}) => fetch(BASE + path, {
  method,
  headers: { ...(key ? { Authorization: `Bearer ${key}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
}).then(async (r) => ({ status: r.status, data: await r.json().catch(() => null) }))
const ownerFaceId = async (purpose) => {
  const op = await owner.req('POST', '/api/passkey/get/options', purpose ? { purpose } : {})
  if (op.status !== 200) return op
  return owner.req('POST', '/api/passkey/get/verify', await auth.get(op.data))
}
await ownerFaceId()
check('resident cannot create an agent key', (await resident.req('POST', '/api/admin/agents', { label: 'x' })).status === 403)
const ak = await owner.req('POST', '/api/admin/agents', { label: 'House Mac' })
check('agent key created once', ak.status === 200 && /^pa5_adm_[A-Za-z0-9_-]{43}$/.test(ak.data.key), ak.data)
const AK = ak.data.key
const akList = (await owner.req('GET', '/api/admin/agents')).data
check('agent key list has no key or hash', akList.length >= 1 && !JSON.stringify(akList).includes('pa5_adm_') && !('key_hash' in akList[0]), akList)
check('agent: no key = 401', (await agentCall('GET', '/_agent/me')).status === 401)
check('agent: other prefix = 401', (await agentCall('GET', '/_agent/me', undefined, mk.data.key)).status === 401)
check('agent: unknown key = 401', (await agentCall('GET', '/_agent/me', undefined, 'pa5_adm_' + 'A'.repeat(43))).status === 401)
check('agent: key works', (await agentCall('GET', '/_agent/me', undefined, AK)).data?.label === 'House Mac')
check('agent: key does not open /api/admin', [401, 403].includes((await agentCall('GET', '/api/admin/people', undefined, AK)).status))
check('agent: key does not open a tab', [302, 401].includes((await agentCall('GET', '/tab-a/echo', undefined, AK)).status))
check('agent: no route to create keys or change people', (await agentCall('POST', '/_agent/machines', { tab: 'tab-a', label: 'x' }, AK)).status === 404 &&
  (await agentCall('POST', '/_agent/people', { name: 'x' }, AK)).status === 404 && (await agentCall('POST', '/_agent/groups/residents', { tabs: ['*'] }, AK)).status === 404)
const agScreens = await agentCall('GET', '/_agent/screens', undefined, AK)
check('agent lists screens with groups and sessions', agScreens.status === 200 && agScreens.data.some((s) => s.id === ap1.data.screen && Array.isArray(s.sessions) && s.groups.includes('residents')), agScreens.data)
const agDevices = (await agentCall('GET', '/_agent/devices', undefined, AK)).data
const ownerSid = (await owner.req('GET', '/api/me')).data.session_id
check('agent lists devices, admin flagged, no phones', agDevices.some((d) => d.id === ownerSid && d.admin === true) && !JSON.stringify(agDevices).includes(OWNER), agDevices)
check('agent lists machine keys and groups', (await agentCall('GET', '/_agent/machines', undefined, AK)).status === 200 &&
  (await agentCall('GET', '/_agent/groups', undefined, AK)).data.some((g) => g.id === 'owner-screens' && g.is_admin === 0))
const agAudit = await agentCall('GET', '/_agent/audit', undefined, AK)
check('agent reads the audit with numbers masked', agAudit.status === 200 && agAudit.data.length > 0 && !JSON.stringify(agAudit.data).includes(OWNER) && !JSON.stringify(agAudit.data).includes(RESIDENT), agAudit.data.slice(0, 3))
check('agent cannot disconnect an admin device', (await agentCall('DELETE', `/_agent/devices/${ownerSid}`, undefined, AK)).status === 403)
check('agent cannot rename an admin device', (await agentCall('POST', `/_agent/devices/${ownerSid}`, { name: 'x' }, AK)).status === 403)
check('owner still signed in', (await owner.req('GET', '/api/me')).status === 200)
const resPhoneSid = (await resident.req("GET", "/api/me")).data.session_id
check('agent cannot disconnect a resident phone used this month', (await agentCall('DELETE', `/_agent/devices/${resPhoneSid}`, undefined, AK)).data?.error === 'device_in_use')
check('agent sees no place on people devices', agDevices.filter((d) => d.kind !== 'screen').every((d) => d.place === null))
check('agent audit: no address on people rows', agAudit.data.filter((a) => ['weak', 'strong'].includes(a.strength)).every((a) => a.ip === null && a.place === null && !/"ip":"/.test(a.detail || '')))

// pairing prepared by the agent, approved with one Face ID
// G1: "home" is where a live machine key last connected from; no live bridge = no home
check('agent: no live bridge = not at home', (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'residents' }, AK)).data?.error === 'not_at_home')
await ownerFaceId()
const homeKey = await owner.req('POST', '/api/admin/machines', { tab: 'tab-a', label: 'Home bridge' })
const hb = await openWs('/_bridge/tab-a', { 'X-A5-Machine-Key': homeKey.data.key })
check('home bridge connects', hb.ok, hb)
check('agent: pair needs a group', (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X' }, AK)).data?.error === 'group_required')
const away = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'residents' }, AK, { 'CF-Connecting-IP': '203.0.113.50' })
if (away.status !== 201) check('agent: a request from outside home = 409 not_at_home', away.status === 409 && away.data.error === 'not_at_home', away)
else console.log('skip not-at-home by address: CF-Connecting-IP not settable locally')
// IPv6 compares by /64
const v6Key = await owner.req('POST', '/api/admin/machines', { tab: 'tab-a', label: 'v6 bridge' })
const v6b = await openWs('/_bridge/tab-a', { 'X-A5-Machine-Key': v6Key.data.key, 'CF-Connecting-IP': '2001:db8:a:b::5' })
if (v6b.ok) {
  const in64 = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'V6 same', group: 'residents' }, AK, { 'CF-Connecting-IP': '2001:0db8:a:b:1:2:3:4' })
  check('agent: same IPv6 /64 as a bridge = home', in64.status === 201, in64)
  const out64 = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'V6 other', group: 'residents' }, AK, { 'CF-Connecting-IP': '2001:db8:a:c::5' })
  check('agent: other IPv6 /64 = not home', out64.status === 409 && out64.data.error === 'not_at_home', out64)
  check('agent: an IPv4 never matches an IPv6 home', (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'residents' }, AK, { 'CF-Connecting-IP': '32.1.13.184' })).status === 409)
  await agentCall('DELETE', `/_agent/requests/${in64.data.id}`, undefined, AK)
}
check('agent: screen never in an admin group', (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'owner' }, AK)).status === 409)
check('agent: next must be a portal path', (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'residents', next: '//evil.example/' }, AK)).status === 400 &&
  (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'X', group: 'residents', next: 'https://evil.example/' }, AK)).status === 400)
await ownerFaceId()
await owner.req('POST', '/api/admin/groups/owner-screens', { tabs: ['tab-a'] })
const pr = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'Bedroom <b>monitor</b>', group: 'owner-screens', next: '/tab-a/?view=landscape' }, AK)
check('agent prepares a pairing', pr.status === 201 && /\/#screen_ticket=[A-Za-z0-9_-]{32}$/.test(pr.data.screen_url) && /\/conta\/\?agent_request=\d+$/.test(pr.data.approve_url) && !/[<>]/.test(pr.data.name), pr.data)
const ticket = new URL(pr.data.screen_url).hash.slice(1).replace(/^screen_ticket=/, '')
check('nothing was created before approval', !(await agentCall('GET', '/_agent/screens', undefined, AK)).data.some((s) => s.name.startsWith('Bedroom')))
check('typed-code lookup never finds an agent pairing', (await owner.req('GET', `/api/admin/pair?code=${ticket.slice(0, 6)}`)).status === 404)
const early = await owner.req('POST', '/api/passkey/get/options', { purpose: `agent:${pr.data.id}` })
check('approval waits until the screen opened the link', early.status === 409 && early.data.error === 'pair_not_claimed', early)
const mon = client()
const spoofClaim = await mon.req('POST', '/api/pair/claim', { ticket }, { 'CF-Connecting-IP': '203.0.113.9' })
if (spoofClaim.status === 409) {
  check('screen on another internet cannot open the link', spoofClaim.data.error === 'claim_other_network', spoofClaim)
} else console.log('skip other-IP claim case: CF-Connecting-IP not settable locally', spoofClaim.status)
check('claim without Origin = 403', (await mon.req('POST', '/api/pair/claim', { ticket }, { Origin: undefined })).status === 403)
const cl = await mon.req('POST', '/api/pair/claim', { ticket })
check('screen opens the link', cl.status === 200 && cl.data.secret.length >= 30 && cl.data.next === '/tab-a/?view=landscape', cl)
check('link is single use', (await client().req('POST', '/api/pair/claim', { ticket })).status === 404)
check('screen waits', (await mon.req('POST', '/api/pair/status', { secret: cl.data.secret })).data.status === 'waiting')
check('resident cannot see agent requests', (await resident.req('GET', '/api/admin/agent-requests')).status === 403)
check('resident cannot approve', (await resident.req('POST', '/api/passkey/get/options', { purpose: `agent:${pr.data.id}` })).status === 403)
check('agent cannot approve its own request', (await agentCall('POST', '/api/passkey/get/options', { purpose: `agent:${pr.data.id}` }, AK)).status === 403)
const agPend = (await owner.req("GET", "/api/admin/agent-requests")).data
const one = agPend.find((x) => x.id === pr.data.id)
check('owner sees the request with the screen and the agent', one && one.claimed === true && one.same_ip === true && one.agent === 'House Mac' && one.group === 'owner-screens' && !JSON.stringify(one).includes(ticket), one)
const apr = await ownerFaceId(`agent:${pr.data.id}`)
check('one Face ID approves', apr.status === 200 && apr.data.ok === true && apr.data.name === one.name, apr)
const monSt = await mon.req('POST', '/api/pair/status', { secret: cl.data.secret })
check('screen signs in', monSt.data.status === 'ok' && /Max-Age=31536000/.test(monSt.setCookie || ''), monSt)
const monMe = (await mon.req('GET', '/api/me')).data
check('screen in owner-screens, never admin', monMe.credential === 'screen' && monMe.admin === false && monMe.groups.map((g) => g.id).join() === 'owner-screens' && monMe.tabs.join() === 'tab-a', monMe)
check('owner-screens screen does not see the Face ID tab', !(await mon.req('GET', '/api/tabs')).data.tabs.some((t) => t.id === 'tab-b'))
check('approved request cannot be approved again', (await owner.req('POST', '/api/passkey/get/options', { purpose: `agent:${pr.data.id}` })).status === 404)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit: prepared, claimed, paired via agent', rows.some((a) => a.action === 'agent_pair_prepared' && a.strength === 'agent') &&
  rows.some((a) => a.action === 'agent_pair_claimed') && rows.some((a) => a.action === 'screen_paired' && /"via":"agent"/.test(a.detail || '')))
const monId = monMe.person.id

// rename and disconnect: the agent does it alone
check('agent renames a screen', (await agentCall('POST', `/_agent/screens/${monId}`, { name: 'Bedroom monitor' }, AK)).status === 200)
const monSid = (await mon.req('GET', '/api/me')).data.session_id
check('agent renames a screen device', (await agentCall('POST', `/_agent/devices/${monSid}`, { name: 'Pi kiosk' }, AK)).status === 200)
check('agent renames a machine key', (await agentCall('POST', `/_agent/machines/${mk.data.id}`, { name: 'Pi' }, AK)).status === 200)
check('agent: rename of a person = 404', (await agentCall('POST', `/_agent/screens/${ownerId}`, { name: 'x' }, AK)).status === 404)
check('agent disconnects the screen', (await agentCall('DELETE', `/_agent/devices/${monSid}`, undefined, AK)).status === 200)
check('disconnected screen = 401', (await mon.req('GET', '/api/me')).status === 401)

// a blocked screen comes back only with the owner's Face ID
await ownerFaceId()
check('owner blocks the screen', (await owner.req('POST', `/api/admin/people/${monId}`, { status: 'blocked' })).status === 200)
check('agent: change of a blocked screen must say unblock', (await agentCall('POST', '/_agent/requests', { kind: 'screen', screen: monId, group: 'residents' }, AK)).status === 409)
const ch = await agentCall('POST', '/_agent/requests', { kind: 'screen', screen: monId, group: 'residents', unblock: true }, AK)
check('agent prepares unblock + group change', ch.status === 201 && ch.data.unblock === true && !ch.data.screen_url, ch.data)
check('still blocked before approval', (await agentCall('GET', '/_agent/screens', undefined, AK)).data.find((s) => s.id === monId).status === 'blocked')
check('Face ID approves the change', (await ownerFaceId(`agent:${ch.data.id}`)).data?.ok === true)
const monRow = (await agentCall('GET', '/_agent/screens', undefined, AK)).data.find((s) => s.id === monId)
check('screen unblocked and moved', monRow.status === 'active' && monRow.groups.join() === 'residents', monRow)
check('tabs told to recheck the screen', (await tabRevoked()).some((r) => r.person === monId))
if (v6b.ok) {
  const v6req = await agentCall('POST', '/_agent/requests', { kind: 'screen', screen: monId, group: 'owner-screens' }, AK, { 'CF-Connecting-IP': '2001:db8:a:b::77' })
  check('agent asks from the IPv6 home', v6req.status === 201 && v6req.data && !v6req.data.screen_url, v6req)
  await ownerFaceId()
  await owner.req('DELETE', `/api/admin/machines/${v6Key.data.id}`)
  const late = await ownerFaceId(`agent:${v6req.data.id}`)
  check('approval refused once that home bridge is revoked', late.status === 409 && late.data.error === 'not_at_home', late)
  await agentCall('DELETE', `/_agent/requests/${v6req.data.id}`, undefined, AK)
}
check('agent: nothing to change = 400', (await agentCall('POST', '/_agent/requests', { kind: 'screen', screen: monId }, AK)).status === 400)

// re-pairing an existing (blocked) account: the approval says it unblocks
await ownerFaceId()
await owner.req('POST', `/api/admin/people/${monId}`, { status: 'blocked' })
const rp = await agentCall('POST', '/_agent/requests', { kind: 'pair', screen: monId, group: 'owner-screens' }, AK)
check('pairing a blocked account asks to unblock', rp.status === 201 && rp.data.unblock === true && rp.data.name === 'Bedroom monitor', rp.data)
const mon2 = client()
const cl2 = await mon2.req('POST', '/api/pair/claim', { ticket: new URL(rp.data.screen_url).hash.slice(1).replace(/^screen_ticket=/, '') })
const rpView = (await owner.req('GET', `/api/admin/agent-requests/${rp.data.id}`)).data
check('approval page shows existing, blocked, current group', rpView.existing === true && rpView.blocked === true && rpView.current_groups.join() === 'residents', rpView)
await ownerFaceId(`agent:${rp.data.id}`)
check('re-paired screen signs in, unblocked', (await mon2.req('POST', '/api/pair/status', { secret: cl2.data.secret })).data.status === 'ok' &&
  (await mon2.req('GET', '/api/me')).data.groups.map((g) => g.id).join() === 'owner-screens')

// refuse and cancel
const rf = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'Hall TV', group: 'residents' }, AK)
check('owner refuses (no Face ID needed)', (await owner.req('POST', `/api/admin/agent-requests/${rf.data.id}/refuse`, {})).status === 200)
check('refused link is dead', (await client().req('POST', '/api/pair/claim', { ticket: new URL(rf.data.screen_url).hash.slice(1).replace(/^screen_ticket=/, '') })).status === 404)
const cc = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'Hall TV', group: 'residents' }, AK)
check('agent cancels its own request', (await agentCall('DELETE', `/_agent/requests/${cc.data.id}`, undefined, AK)).status === 200)
check('cancel twice = 404', (await agentCall('DELETE', `/_agent/requests/${cc.data.id}`, undefined, AK)).status === 404)
const myReqs = (await agentCall('GET', '/_agent/requests', undefined, AK)).data
check('agent sees its requests and their state', ['approved', 'refused', 'cancelled'].every((s) => myReqs.some((r) => r.state === s)), myReqs)
let lastPend
for (let i = 0; i < 6; i++) lastPend = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: `Screen ${i}`, group: 'residents' }, AK)
check('at most 5 open requests per agent', lastPend.status === 429 && lastPend.data.error === 'too_many_pending', lastPend)

// the key used from somewhere new warns the admins
const moved2 = await agentCall('GET', '/_agent/me', undefined, AK, { 'CF-Connecting-IP': '203.0.113.8' })
if (moved2.status === 200 && (await owner.req('GET', '/api/me')).data.alerts.some((a) => a.kind === 'agent_ip')) check('agent key on a new address warns the admins', true)
else console.log('skip agent new-IP alert: CF-Connecting-IP not settable locally')

// cancel the open ones (at most 5 per agent)
for (const r of (await agentCall('GET', '/_agent/requests', undefined, AK)).data.filter((x) => x.state === 'waiting'))
  await agentCall('DELETE', `/_agent/requests/${r.id}`, undefined, AK)

// scripts/agent.sh against this portal (key from a throwaway file, never the Keychain here)
{
  const { execFileSync } = await import('node:child_process')
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const dir = mkdtempSync(tmpdir() + '/a5-agent-')
  writeFileSync(dir + '/key', AK, { mode: 0o600 })
  const sh = (...a) => { try { return { ok: true, out: execFileSync('bash', ['scripts/agent.sh', ...a], { env: { ...process.env, PORTAL_A5_URL: BASE, PORTAL_A5_KEY_FILE: dir + '/key' }, encoding: 'utf8', stdio: 'pipe' }) } } catch (e) { return { ok: false, out: String(e.stdout) + String(e.stderr) } } }
  try {
    check('agent.sh get me', /House Mac/.test(sh('get', 'me').out))
    check('agent.sh get screens', sh('get', 'screens').out.includes('Bedroom monitor'))
    const r = sh('pair', 'Shell "screen"', 'owner-screens', '/tab-a/?view=landscape')
    check('agent.sh pair prints both links', r.ok && /screen_ticket=/.test(r.out) && /agent_request=/.test(r.out), r.out)
    check('agent.sh cancel', r.ok && sh('cancel', String(JSON.parse(r.out).id)).ok)
    check('agent.sh error exits non-zero', !sh('revoke', 'devices', String(ownerSid)).ok)
    check('agent.sh rejects a bad command', !sh('get', 'people').ok)
    check('agent.sh refuses a bad URL', !execFileSync('bash', ['-c', 'PORTAL_A5_URL=http://evil.example bash scripts/agent.sh get me 2>&1 || true'], { encoding: 'utf8' }).includes('House Mac'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// the same flow in a real browser
await agentPairChecks({ base: BASE, check, owner: owner.cookie,
  prepare: async () => (await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'Desk monitor', group: 'owner-screens', next: '/tab-a/?view=landscape' }, AK)).data,
  approve: async (id) => check('browser: agent pairing approved', (await ownerFaceId(`agent:${id}`)).data?.ok === true) })

// revoking the key ends it and what it left waiting
const leftover = await agentCall('POST', '/_agent/requests', { kind: 'pair', name: 'Left behind', group: 'residents' }, AK)
await ownerFaceId()
const mk2 = await owner.req('POST', '/api/admin/machines', { tab: 'tab-a', label: 'Spare Pi' })
check('agent revokes a machine key', (await agentCall('DELETE', `/_agent/machines/${mk2.data.id}`, undefined, AK)).status === 200 &&
  (await owner.req('GET', '/api/admin/machines')).data.find((m) => m.id === mk2.data.id).revoked_at)
check('owner revokes the agent key', (await owner.req('DELETE', `/api/admin/agents/${ak.data.id}`)).status === 200)
check('revoked agent key = 401', (await agentCall('GET', '/_agent/me', undefined, AK)).status === 401)
check('its open requests are gone', !(await owner.req('GET', '/api/admin/agent-requests')).data.length)
check('and their screen links are dead', (await client().req('POST', '/api/pair/claim', { ticket: new URL(leftover.data.screen_url).hash.slice(1).replace(/^screen_ticket=/, '') })).status === 404)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit: agent refusals and key lifecycle', ['agent_refused', 'agent_key_created', 'agent_key_revoked', 'agent_renamed_screen', 'screen_changed'].every((x) => rows.some((a) => a.action === x)))

}

// pairing start is capped per IP (last: it uses up the bucket)
let pl
for (let i = 0; i < 10; i++) pl = await client().req('POST', '/api/pair/start', {})
check('pair start 10/h per IP', pl.status === 429, pl.status)

// logout
check('logout clears cookie', /Max-Age=0/.test((await resident.req('POST', '/api/logout', {})).setCookie || ''))
check('after logout = 401', (await resident.req('GET', '/api/me')).status === 401)

// session ids are never reused
const oldSid = rme.session_id
const again = client()
const ag = await signIn(again, RESIDENT, RESIDENT)
const newSid = (await again.req('GET', '/api/me')).data.session_id
check('new session never takes an old id', ag.status.data.status === 'ok' && newSid > oldSid && newSid > me.session_id, [oldSid, newSid])
check('owner logout', (await owner.req('POST', '/api/logout', {})).status === 200)

console.log(failures ? `\n${failures} FAILED` : '\nall passed')
process.exit(failures ? 1 : 0)
