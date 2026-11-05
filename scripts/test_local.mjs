// Drives the whole sign-in flow against a local `wrangler dev`, including a fake WhatsApp
// reader (POST /robo/login) and a software passkey. Run through scripts/test_local.sh.
import { webcrypto as wc } from 'node:crypto'
import http from 'node:http'
import { browserChecks } from './test_browser.mjs'

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
check('resident tabs = energia, not admin', rme.admin === false && rme.tabs.join() === 'energia', rme)
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
// Two tabs are bound to a fake tab worker (test/fake_tab): energia (residents) and jarvis
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
const tabRevoked = async () => (await resident.req('GET', '/energia/revoked', undefined, CORS)).data

// signed out
check('tab signed out: navigation redirects to sign-in', (await navigate(anon, '/energia/')).headers.get('location') === '/?next=%2Fenergia%2F')
check('tab signed out: fetch = 401', (await anon.req('GET', '/energia/echo', undefined, CORS)).status === 401)

// identity and request headers
const echo = await resident.req('GET', '/energia/echo', undefined, {
  ...CORS, 'X-Portal-Person': 'owner', 'X-A5-Identity': '{"person":1,"groups":["owner"]}', Authorization: 'Bearer x', 'X-A5-Machine-Key': 'pa5_maq_fake',
})
const id = echo.data.identity
check('tab gets identity from the portal', echo.status === 200 && id.credential === 'browser' && id.person === residentId &&
  id.groups.join() === 'residents' && id.strong === false && id.machine === null && Array.isArray(id.actions), echo.data)
const fh = echo.data.headers || {}
check('forged portal headers never reach the tab', !('x-portal-person' in fh) && !('x-a5-identity' in fh) && !('x-a5-machine-key' in fh), fh)
check('tab never sees Cookie or Authorization', !('cookie' in fh) && !('authorization' in fh), fh)

const bad = (await navigate(resident, '/energia/html'))
check('Set-Cookie from the tab removed', !/stolen/.test(bad.setCookie || ''), bad.setCookie)
check('tab cannot send Clear-Site-Data, Service-Worker-Allowed or CORS', !bad.headers.get('clear-site-data') && !bad.headers.get('service-worker-allowed') &&
  ![...bad.headers.keys()].some((k) => k.startsWith('access-control-')))
const tabCspE = bad.headers.get('content-security-policy') || ''
check('portal CSP replaces the tab CSP (inline script blocked)', tabCspE.includes(`script-src ${BASE}/energia/ ${BASE}/_shell/tabs.js ${BASE}/locale/pt-BR.js;`) && !/unsafe-inline|\*/.test(tabCspE) && tabCspE.includes("frame-ancestors 'none'"), tabCspE)
check('tab CSP: connect only under the tab path plus /api/tabs; form-action only the tab', tabCspE.includes(`connect-src ${BASE}/energia/ ${WS_BASE}/energia/ ${BASE}/api/tabs;`) && tabCspE.includes(`form-action ${BASE}/energia/`), tabCspE)
const cspPart = (csp, d) => (csp.split(';').map((x) => x.trim()).find((x) => x.startsWith(d + ' ')) || '').split(' ').slice(1)
check('tab CSP: the only portal scripts are the two shell files', cspPart(tabCspE, 'script-src').join() === [`${BASE}/energia/`, `${BASE}/_shell/tabs.js`, `${BASE}/locale/pt-BR.js`].join(), cspPart(tabCspE, 'script-src'))
check('tab CSP: the only portal API is /api/tabs (no /api/ prefix, no self)', cspPart(tabCspE, 'connect-src').join() === [`${BASE}/energia/`, `${WS_BASE}/energia/`, `${BASE}/api/tabs`].join(), cspPart(tabCspE, 'connect-src'))
check('portal pages keep the portal CSP', ownerCsp.includes("script-src 'self'") && !ownerCsp.includes('/energia/'), ownerCsp)
check('tab page keeps nosniff and DENY', bad.headers.get('x-content-type-options') === 'nosniff' && bad.headers.get('x-frame-options') === 'DENY')
const ppE = bad.headers.get('permissions-policy') || ''
check('energia: wake lock on, microphone off', ppE.includes('screen-wake-lock=(self)') && ppE.includes('microphone=()') && ppE.includes('camera=()'), ppE)
const ppHome = home.headers.get('permissions-policy') || ''
check('portal pages: microphone and wake lock off', ppHome.includes('microphone=()') && ppHome.includes('screen-wake-lock=()'), ppHome)

// writes to a tab follow the portal's CSRF rule
check('tab POST without X-Portal = 403', (await resident.req('POST', '/energia/echo', { a: 1 }, { 'X-Portal': undefined })).status === 403)
check('tab POST from other origin = 403', (await resident.req('POST', '/energia/echo', { a: 1 }, { Origin: 'https://evil.example' })).status === 403)
const post = await resident.req('POST', '/energia/echo', { a: 1 })
check('tab POST body reaches the tab', post.status === 200 && post.data.body === '{"a":1}', post.data)
check('tab streams pass through', (await resident.req('GET', '/energia/stream', undefined, CORS)).data === 'data: one\n\n')

// no tab in the group
check('resident on jarvis = 403', (await resident.req('GET', '/jarvis/echo', undefined, CORS)).status === 403)
check('resident navigating to jarvis = 403', (await navigate(resident, '/jarvis/')).status === 403)

// audit through X-Tab-Audit
const au = await resident.req('GET', '/energia/audit', undefined, CORS)
check('X-Tab-Audit stripped from the answer', au.status === 200 && !au.headers.get('x-tab-audit'))
await resident.req('GET', '/energia/badaudit', undefined, CORS)
let rows = (await owner.req('GET', '/api/admin/audit')).data
const tabRow = rows.find((a) => a.action === 'energia.turn_on')
check('tab audit recorded with the portal\'s person', tabRow && tabRow.person_id === residentId && tabRow.target === 'ac:living' && /"credential":"browser"/.test(tabRow.detail), tabRow)
check('malformed tab audit recorded as invalid', rows.some((a) => a.action === 'energia.invalid_audit' && a.person_id === residentId))

// Face ID on every entry into jarvis
const nav1 = (await navigate(owner, '/jarvis/'))
check('jarvis entry without Face ID -> step-up page', nav1.status === 302 && nav1.headers.get('location') === '/?step_up=jarvis&next=%2Fjarvis%2F', [nav1.status, nav1.headers.get('location')])
const in1 = await owner.req('GET', '/jarvis/echo', undefined, CORS)
check('jarvis request without entry = 401 entry_required', in1.status === 401 && in1.data.error === 'entry_required' && in1.data.step_up, in1.data)
check('jarvis socket without entry = 401', (await upgradeStatus('/jarvis/live', { Cookie: owner.cookie, Origin: BASE })) === 401)
// a passkey check without the entry purpose does not open the tab
const plain = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(plain.data))
check('plain passkey check is not an entry', (await navigate(owner, '/jarvis/')).status === 302)
check('entry purpose for a session-only tab = 400', (await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:energia' })).status === 400)
check('entry purpose for an unknown tab = 400', (await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:nothing' })).status === 400)
check('resident cannot ask a jarvis entry', (await resident.req('POST', '/api/passkey/get/options', { purpose: 'entry:jarvis' })).status === 400)
const eo = await owner.req('POST', '/api/passkey/get/options', { purpose: 'entry:jarvis' })
const ev = await owner.req('POST', '/api/passkey/get/verify', await auth.get(eo.data))
check('entry passkey ok', ev.status === 200 && ev.data.next === '/jarvis/', ev.data)
const nav2 = (await navigate(owner, '/jarvis/'))
check('jarvis entry after Face ID = 200 with entered_at', nav2.status === 200 && !!nav2.data.identity.entered_at && nav2.data.identity.strong === true, nav2.data)
check('identity says when the entry ends (4 h)', Date.parse(nav2.data.identity.entry_until) - Date.parse(nav2.data.identity.entered_at) === 4 * 3600e3, nav2.data.identity)
check('jarvis refuses a service worker', (await owner.req('GET', '/jarvis/sw.js', undefined, { ...CORS, 'Service-Worker': 'script' })).status === 403)
check('energia allows a service worker', (await resident.req('GET', '/energia/sw.js', undefined, { ...CORS, 'Service-Worker': 'script' })).status === 200)
const ppJ = nav2.headers.get('permissions-policy') || ''
check('jarvis: microphone and wake lock on, camera off', ppJ.includes('microphone=(self)') && ppJ.includes('screen-wake-lock=(self)') && ppJ.includes('camera=()'), ppJ)
check('jarvis inside: requests free after entry', (await owner.req('GET', '/jarvis/echo', undefined, CORS)).status === 200)
check('jarvis: the grant is single use (reload asks again)', (await navigate(owner, '/jarvis/')).status === 302)
const jws = await openWs('/jarvis/live', { Cookie: owner.cookie, Origin: BASE })
check('jarvis socket after entry carries identity', jws.ok && jws.data.identity.credential === 'browser' && !!jws.data.identity.entered_at && !('cookie' in jws.data.headers), jws)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has tab_entry_granted and tab_entered', rows.some((a) => a.action === 'tab_entry_granted') && rows.some((a) => a.action === 'tab_entered'))

// live page sockets (energia)
const rws = await openWs('/energia/live', { Cookie: resident.cookie, Origin: BASE })
check('page socket: identity of the session', rws.ok && rws.data.identity.credential === 'browser' && rws.data.identity.person === residentId, rws)
check('page socket from another origin = 403', (await upgradeStatus('/energia/live', { Cookie: resident.cookie, Origin: 'https://evil.example' })) === 403)
check('page socket without Origin = 403', (await upgradeStatus('/energia/live', { Cookie: resident.cookie })) === 403)
check('page socket signed out = 401', (await upgradeStatus('/energia/live', { Origin: BASE })) === 401)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit header on a socket answer is recorded', rows.some((a) => a.action === 'energia.socket_opened'))

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
check('screen is a resident, never admin', tvMe.credential === 'screen' && tvMe.admin === false && tvMe.tabs.join() === 'energia' && !/[<>]/.test(tvMe.person.name), tvMe)
const tvEcho = await tv.req('GET', '/energia/echo', undefined, CORS)
check('screen identity reaches the tab', tvEcho.status === 200 && tvEcho.data.identity.credential === 'screen' && tvEcho.data.identity.person === ap1.data.screen, tvEcho.data)
check('screen has no admin access', (await tv.req('GET', '/api/admin/people')).status === 403)
check('screen cannot register a passkey', (await tv.req('POST', '/api/passkey/create/options', {})).status === 403)
check('screen cannot join the owner group', (await owner.req('POST', `/api/admin/people/${ap1.data.screen}`, { groups: ['owner'] })).status === 409)
const tvws = await openWs('/energia/live', { Cookie: tv.cookie, Origin: BASE })
check('screen page socket', tvws.ok && tvws.data.identity.credential === 'screen', tvws)
const tvTabs = await tv.req('GET', '/api/tabs')
check('fixed screen: no selector, energia only, no counts', tvTabs.status === 200 && tvTabs.data.selector === false && tvTabs.data.tabs.map((t) => t.id).join() === 'energia' && tvTabs.data.tabs.every((t) => t.badge === null), tvTabs.data)
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
check('revoked screen = 401', (await tv2.req('GET', '/energia/echo', undefined, CORS)).status === 401)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has screen_paired and screen_signed_in', rows.some((a) => a.action === 'screen_paired') && rows.some((a) => a.action === 'screen_signed_in'))

// machine bridges
const mk = await owner.req('POST', '/api/admin/machines', { tab: 'energia', label: 'Pi ⚡' })
check('machine key created once', mk.status === 200 && /^pa5_maq_[A-Za-z0-9_-]{43}$/.test(mk.data.key), mk.data)
check('machine key for unknown tab = 400', (await owner.req('POST', '/api/admin/machines', { tab: 'nothing', label: 'x' })).status === 400)
check('resident cannot create machine keys', (await resident.req('POST', '/api/admin/machines', { tab: 'energia', label: 'x' })).status === 403)
const ml = (await owner.req('GET', '/api/admin/machines')).data
check('machine list never shows the key', ml.length === 1 && !JSON.stringify(ml).includes(mk.data.key) && !('key_hash' in ml[0]), ml)
const KEY = { 'X-A5-Machine-Key': mk.data.key }
const bws = await openWs('/_bridge/energia', { ...KEY, Cookie: owner.cookie })
check('identity header survives non-Latin-1 names', bws.ok && bws.data.identity.name === 'Pi ⚡', bws)
check('bridge: tab gets a machine identity', bws.ok && bws.data.identity.credential === 'machine' && bws.data.identity.machine === mk.data.id &&
  bws.data.identity.person === null && bws.data.identity.groups.length === 0, bws)
check('bridge: key and cookie never reach the tab', bws.ok && !('x-a5-machine-key' in bws.data.headers) && !('cookie' in bws.data.headers), bws.data?.headers)
check('bridge: key for another tab = 401', (await upgradeStatus('/_bridge/jarvis', KEY)) === 401)
check('bridge: wrong key = 401', (await upgradeStatus('/_bridge/energia', { 'X-A5-Machine-Key': 'pa5_maq_' + 'A'.repeat(43) })) === 401)
check('bridge: one byte changed = 401', (await upgradeStatus('/_bridge/energia', { 'X-A5-Machine-Key': mk.data.key.slice(0, -1) + (mk.data.key.endsWith('A') ? 'B' : 'A') })) === 401)
check('bridge: no key = 401', (await upgradeStatus('/_bridge/energia', {})) === 401)
check('bridge: robot key = 401', (await upgradeStatus('/_bridge/energia', { 'X-A5-Machine-Key': ROBO_KEY })) === 401)
check('bridge: session cookie alone = 401', (await upgradeStatus('/_bridge/energia', { Cookie: owner.cookie, Origin: BASE })) === 401)
check('bridge: without upgrade = 426', (await rawGet('/_bridge/energia', KEY)).status === 426)
check('bridge: unknown tab = 404', (await upgradeStatus('/_bridge/nothing', KEY)) === 404)
check('bridge: other paths = 404', (await upgradeStatus('/_bridge/energia/x', KEY)) === 404)
check('machine key on /api = 401', (await fetch(BASE + '/api/me', { headers: KEY })).status === 401)
check('machine key on a tab page = 401', (await fetch(BASE + '/energia/echo', { headers: { ...KEY, ...CORS } })).status === 401)
// reconnecting more than 3 times in an hour warns the admins
for (let i = 0; i < 3; i++) await openWs('/_bridge/energia', KEY)
me = (await owner.req('GET', '/api/me')).data
check('bridge reconnect burst alerts the owner', me.alerts.some((a) => a.kind === 'bridge' && a.label === 'energia:Pi ⚡'), me.alerts)
const moved = await openWs('/_bridge/energia', { ...KEY, 'CF-Connecting-IP': '203.0.113.7' })
if (moved.ok) {
  me = (await owner.req('GET', '/api/me')).data
  check('key used from a new IP alerts the owner', me.alerts.some((a) => a.kind === 'bridge_ip'), me.alerts)
}
rows = (await owner.req('GET', '/api/admin/audit')).data
check('audit has bridge_connected and bridge_refused', rows.some((a) => a.action === 'bridge_connected') && rows.some((a) => a.action === 'bridge_refused'))
check('owner revokes the machine key', (await owner.req('DELETE', `/api/admin/machines/${mk.data.id}`)).status === 200)
check('revoked key = 401', (await upgradeStatus('/_bridge/energia', KEY)) === 401)
check('tab told to close the revoked bridge', (await tabRevoked()).some((r) => r.machine === mk.data.id))

// changing a person's groups or taking a tab from a group makes the tabs re-check sockets
check('person groups change', (await owner.req('POST', `/api/admin/people/${residentId}`, { groups: ['residents'] })).status === 200)
check('tabs told when a person\'s groups change', (await tabRevoked()).some((r) => r.person === residentId))
const revBefore = (await tabRevoked()).length
check('group loses energia', (await owner.req('POST', '/api/admin/groups/residents', { tabs: [] })).status === 200)
check('resident lost the tab at once', (await resident.req('GET', '/energia/echo', undefined, CORS)).status === 403)
check('group gets energia back', (await owner.req('POST', '/api/admin/groups/residents', { tabs: ['energia'] })).status === 200)
const revAfter = await tabRevoked()
check('tabs told when a group loses a tab', revAfter.length > revBefore && revAfter.slice(revBefore).some((r) => r.person === residentId), revAfter.slice(revBefore))

// shell v2: /api/tabs, badge, the account page and the shared selector files
check('/api/tabs signed out = 401', (await anon.req('GET', '/api/tabs')).status === 401)
check('/api/tabs is GET only', (await owner.req('POST', '/api/tabs', {})).status === 404)
const t0 = Date.now()
const ot = await owner.req('GET', '/api/tabs?current=energia')
const took = Date.now() - t0
check('owner: every bound tab in binding order, reserved name dropped', ot.status === 200 && ot.data.selector === true && ot.data.tabs.map((t) => t.id).join() === 'energia,jarvis,lento,torto', ot.data)
check('owner: account entry at /conta/', ot.data.account && ot.data.account.id === 'conta' && ot.data.account.path === '/conta/', ot.data.account)
check('current echoed only for a listed tab', ot.data.current === 'energia' && (await owner.req('GET', '/api/tabs?current=nothing')).data.current === null &&
  (await owner.req('GET', '/api/tabs?current=conta')).data.current === 'conta')
const byId = Object.fromEntries(ot.data.tabs.map((t) => [t.id, t]))
check('badge comes from the tab', byId.energia.badge === 3 && byId.jarvis.badge === 3, byId)
check('slow badge: no number, and the answer does not wait for it', byId.lento.badge === null && took < 1500, [byId.lento, took])
check('badge that is not a count: no number', byId.torto.badge === null, byId.torto)
check('entry kind per tab', byId.jarvis.entry === 'passkey' && byId.energia.entry === 'session')
check('list carries id, path, badge and entry only', ot.data.tabs.every((t) => Object.keys(t).sort().join() === 'badge,entry,id,path'), ot.data.tabs)
let calls = (await resident.req('GET', '/energia/badges', undefined, CORS)).data
const ownerCall = calls.find((c) => c.person === ownerId)
check('badge gets the person\'s identity, with no entry and never strong', ownerCall && ownerCall.credential === 'browser' && ownerCall.entered_at === null && ownerCall.entry_until === null && ownerCall.strong === false, ownerCall)
const nCalls = calls.length
await owner.req('GET', '/api/tabs')
check('badge kept for a minute (no new call to the tab)', (await resident.req('GET', '/energia/badges', undefined, CORS)).data.length === nCalls)
const rt = await resident.req('GET', '/api/tabs?current=energia')
check('resident: Energia + Conta only', rt.status === 200 && rt.data.selector === true && rt.data.tabs.map((t) => t.id).join() === 'energia' && rt.data.account.path === '/conta/', rt.data)
calls = (await resident.req('GET', '/energia/badges', undefined, CORS)).data
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

// the selector in a real browser (owner, resident and a freshly paired screen)
const g5 = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(g5.data))
const tv3 = client()
const ps3 = await tv3.req('POST', '/api/pair/start', {})
await owner.req('POST', '/api/admin/pair', { code: ps3.data.code, name: 'TV browser' })
await tv3.req('POST', '/api/pair/status', { secret: ps3.data.secret })
check('screen for the browser test paired', !!tv3.cookie)
await browserChecks({ base: BASE, check, owner: owner.cookie, resident: resident.cookie, screen: tv3.cookie })

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
