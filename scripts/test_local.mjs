// Drives the whole sign-in flow against a local `wrangler dev`, including a fake WhatsApp
// reader (POST /robo/login) and a software passkey. Run through scripts/test_local.sh.
import { webcrypto as wc } from 'node:crypto'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import { agentPairChecks, browserChecks, entryChecks } from './test_browser.mjs'

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
    // the same key for Chrome's virtual authenticator (scripts/test_browser.mjs, entryChecks)
    async forChrome() { return { id: Buffer.from(credId).toString('base64'), pkcs8: Buffer.from(await wc.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64') } },
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

// ------------------------------------------------------------------ house rules check (scripts/check_rules.mjs)
{
  const rules = (f) => { try { execFileSync('node', ['scripts/check_rules.mjs', f], { stdio: 'ignore' }); return 0 } catch (e) { return e.status } }
  check('house rules: the entry page passes', rules('public/entry.html') === 0)
  check('house rules: a page without the shell fails', rules('test/rules_bad.html') === 1)
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
check('/api/me: fresh_until about 5 minutes ahead while strong', me.fresh_until && Date.parse(me.fresh_until) - Date.now() > 4 * 60e3 && Date.parse(me.fresh_until) - Date.now() <= 5 * 60e3, me.fresh_until)

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
check('resident may start registering a first passkey at once (08/11)', (await resident.req('POST', '/api/passkey/create/options', {})).status === 200)

// someone else sends the resident's code: nobody signs in until the owner approves
const victimTab = client()
const mm = await signIn(victimTab, RESIDENT, STRANGER)
check('mismatch -> pending', mm.robot.data?.reason === 'awaiting_owner' && mm.status.data.status === 'pending', [mm.robot.data, mm.status.data])
check('pending tab has no cookie', !victimTab.cookie)
const reqs = (await owner.req('GET', '/api/admin/requests')).data
const pend = reqs.find((x) => x.sender_phone === STRANGER)
check('request listed with sender number', !!pend && pend.typed_phone === RESIDENT, reqs)
check('request says why: new number, other than the one typed', pend.why === 'new_other', pend)
check('visitor told: other number', mm.status.data.why === 'other_number', mm.status.data)
check('a person is never approved into a screens group', (await owner.req('POST', `/api/admin/requests/${pend.id}/approve`, { name: 'Visitor', groups: ['owner-screens'] })).status === 409)
{
  const NEWNUM = '5561900000021'
  const nn = await signIn(client(), NEWNUM, NEWNUM)
  check('new number typed and sent: visitor told it is new', nn.status.data.status === 'pending' && nn.status.data.why === 'new_number', nn.status.data)
  const nr = (await owner.req('GET', '/api/admin/requests')).data.find((x) => x.sender_phone === NEWNUM)
  check('request says why: new number', nr?.why === 'new_number', nr)
  await owner.req('POST', `/api/admin/requests/${nr.id}/refuse`, {})
  check('a person is never added to a screens group', (await owner.req('POST', '/api/admin/people', { name: 'X', phone: '5561900000022', groups: ['residents', 'owner-screens'] })).status === 409 &&
    !(await owner.req('GET', '/api/admin/people')).data.some((x) => x.phone === '5561900000022'))
  const rid = (await owner.req('GET', '/api/admin/people')).data.find((x) => x.phone === RESIDENT).id
  const eg = await owner.req('POST', `/api/admin/people/${rid}`, { groups: ['owner-screens'] })
  check('a person is never moved to a screens group', eg.status === 409 && eg.data.error === 'group_for_screens', eg.data)
}
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
// Face ID on entry, in place: the portal's page at the tab's own address, with the options inside
const entryPageOf = (r) => r.status === 200 && typeof r.data === 'string' && r.data.includes('id="a5-entry"')
const entryData = (r) => JSON.parse(/<script type="application\/json" id="a5-entry">([^<]*)<\/script>/.exec(r.data)[1])
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
check('tab-b entry without Face ID -> Face ID page in place (200, same address)', entryPageOf(nav1), [nav1.status, nav1.headers.get('location')])
{
  const d = entryData(nav1)
  check('entry page: options for this tab, nothing of the tab', d.tab === 'tab-b' && d.options.challenge && d.options.allowCredentials.length && d.options.userVerification === 'required' &&
    !/identity|entered_at/.test(nav1.data), d)
  check('entry page: no-store, the portal CSP, no inline script', nav1.headers.get('cache-control') === 'no-store' && /script-src 'self'/.test(nav1.headers.get('content-security-policy') || '') &&
    !/<script(?![^>]*\b(src=|type="application\/json"))/.test(nav1.data))
  check('entry page: title is the tab list button, with the tab label', /<h1><button type="button" data-a5-tabs>[^<]+<\/button><\/h1>/.test(nav1.data) && !nav1.data.includes('__A5_'))
  check('entry page: shell, locale and entry scripts', ['/_shell/tabs.js', '/_shell/tabs.css', '/locale/pt-BR.js', '/_shell/entry.js'].every((f) => nav1.data.includes(f)))
}
{
  const cross = await rawGet('/tab-b/', { ...NAV, 'Sec-Fetch-Site': 'cross-site', Cookie: owner.cookie })
  const same = await rawGet('/tab-b/', { ...NAV, 'Sec-Fetch-Site': 'same-origin', Cookie: owner.cookie })
  check('entry page: Face ID opens by itself only from the portal or a typed address', entryPageOf(cross) && entryData(cross).auto === false && entryData(same).auto === true && entryData(nav1).auto === true)
}
check('tab-b entry page keeps the address with the query (no redirect)', entryPageOf(await navigate(owner, '/tab-b/?v=1')))
function d1Count(sql) { return JSON.parse(execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--json', '--command', sql], { encoding: 'utf8' }))[0].results[0].n }
const in1 = await owner.req('GET', '/tab-b/echo', undefined, CORS)
check('tab-b request without entry = 401 entry_required, step_up = the tab itself', in1.status === 401 && in1.data.error === 'entry_required' && in1.data.step_up === '/tab-b/', in1.data)
check('tab-b socket without entry = 401', (await upgradeStatus('/tab-b/live', { Cookie: owner.cookie, Origin: BASE })) === 401)
// a passkey check without the entry purpose does not open the tab
const plain = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(plain.data))
check('plain passkey check is not an entry', entryPageOf(await navigate(owner, '/tab-b/')))
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
const nav3 = await navigate(owner, '/tab-b/')
check('tab-b: reload inside the entry window = 200, window neither moves nor grows (09/11)', nav3.status === 200 &&
  nav3.data.identity.entered_at === nav2.data.identity.entered_at && nav3.data.identity.entry_until === nav2.data.identity.entry_until, nav3.data)
check('tab-b: a reload leaves no grant behind and no new entry', d1Count(`SELECT COUNT(*) AS n FROM tab_entries WHERE tab = 'tab-b' AND used_at IS NOT NULL`) === 1)
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
check('screen: identity.actions never lists an admin action (no Face ID window on a screen)', !tvEcho.data.identity.actions.includes('presence') && tvEcho.data.identity.admin_until === null, tvEcho.data.identity)
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
check('/api/tabs POST takes only view_as', (await owner.req('POST', '/api/tabs', {})).status === 400 && (await owner.req('PUT', '/api/tabs', {})).status === 404)
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
check('list carries id, path, label, hint, icon, badge and entry only', ot.data.tabs.every((t) => Object.keys(t).sort().join() === 'badge,entry,hint,icon,id,label,path'), ot.data.tabs)
check('who: only the own name and the admin group', ot.data.who && Object.keys(ot.data.who).sort().join() === 'group,name' && ot.data.who.group === 'owner' && typeof ot.data.who.name === 'string' && ot.data.who.name.length > 0, ot.data.who)
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
check('account page: the portal page with the portal CSP', acc.status === 200 && /id="toast"/.test(acc.data) && /\/visual\.css/.test(acc.data) && acc.headers.get('content-security-policy') === ownerCsp, [acc.status, acc.headers.get('content-security-policy')])
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
let residentAuth = null
const d1json = (sql) => JSON.parse(execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--json', '--command', sql], { encoding: 'utf8' }))[0].results
const d1 = (sql) => { try { execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--command', sql], { stdio: 'ignore' }); return true } catch { return false } }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

check('C01 a tab with one malformed command is never routed', (await owner.req('GET', '/tab-badcmd/echo', undefined, CORS)).status === 404)
const rEcho = (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
check('identity.actions: resident gets common actions only (no presence, no sensitive)', rEcho.actions.join() === 'tv,ac,light,slow,boom,limit,note', rEcho.actions)
check('identity.shortcut is null for a page', rEcho.shortcut === null)
check('freshen owner', await freshen(owner, auth))
const oEcho = (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
check('identity.actions: owner with Face ID gets admin and sensitive actions', ['presence', 'wipe'].every((a) => oEcho.actions.includes(a)), oEcho.actions)

// C08 (dropped by the owner, 08/11): a new resident device acts at once; the owner gets an alert instead
let n0 = (await cmdLog()).length
const young = await cmd(resident, 'tab-a', 'light')
check('C08 new resident device: first command goes at once', young.status === 200, young)
const resAlert = (await owner.req('GET', '/api/me')).data.alerts.find((x) => x.kind === 'resident_login')
check('C1 a resident sign-in is an alert on the owner page, with the live session', !!resAlert && resAlert.live === true && resAlert.session_id > 0, (await owner.req('GET', '/api/me')).data.alerts)
check('C1 the resident sees no such alert', (await resident.req('GET', '/api/me')).data.alerts.length === 0)
n0 = (await cmdLog()).length
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
check('passkey_required on a page points to the portal Face ID for commands', wp.data.step_up === '/?step_up=tab-a&purpose=command&next=%2Ftab-a%2F', wp.data)
check('identity.admin_until: null without a passkey check', (await admin3.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.admin_until === null)
{
  const ro = await resident.req('POST', '/api/passkey/get/options', { purpose: 'command:tab-slow' })
  check('command Face ID: refused to a resident on a tab without passkey actions', ro.status === 403, ro)
  const so = await owner.req('POST', '/api/passkey/get/options', { purpose: 'command:tab-slow' })
  check('command Face ID: refused for a tab without owner commands', so.status === 400 && so.data.error === 'bad_purpose', so)
  const co = await owner.req('POST', '/api/passkey/get/options', { purpose: 'command:tab-a' })
  const cv = await owner.req('POST', '/api/passkey/get/verify', await auth.get(co.data))
  check('command Face ID: ok, back to the tab', co.status === 200 && cv.status === 200 && cv.data.next === '/tab-a/', [co.status, cv])
  const until = (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.admin_until
  const left = Date.parse(until) - Date.now()
  check('identity.admin_until: about 12 h after the Face ID', left > 11.9 * 3600e3 && left <= 12 * 3600e3, until)
}
// owner's decision (05/11): admin commands from a browser need this session's passkey in the last 12 h
const a3sid = (await admin3.req('GET', '/api/me')).data.session_id
const setPasskeyAt = (ms) => d1(`UPDATE sessions SET passkey_at = '${new Date(Date.now() - ms).toISOString()}' WHERE id = ${a3sid}`)
if (setPasskeyAt(12 * 3600e3 + 60e3)) {
  const old = await cmd(admin3, 'tab-a', 'presence', { state: 'out' })
  check('B2 passkey 12 h 1 min ago: admin action = 403 passkey_required', old.status === 403 && old.data.error === 'passkey_required', old)
  const b2id = (await admin3.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
  check('B2 ... but identity.actions still lists it (the page asks for Face ID first), never a sensitive one',
    b2id.actions.includes('presence') && !b2id.actions.includes('wipe') && b2id.admin_until === null, b2id)
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
check('key list offers keyable actions only (no sensitive, no Face ID tab beyond its write-only actions)', kl.available.some((a) => a.tab === 'tab-a' && a.action === 'tv') && !kl.available.some((a) => a.action === 'wipe' || (a.tab === 'tab-b' && !['jot', 'named'].includes(a.action))), kl.available)
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
const refRow = rows.find((r) => r.action === 'command_refused' && JSON.parse(r.detail).reason === 'admin_only')
check('refusal audited with its reason', !!refRow, refRow)

// entry window ends: a navigation asks Face ID again (09/11); put back after
{
  const sidE = (await owner.req('GET', '/api/me')).data.session_id
  const usedE = d1json(`SELECT used_at FROM tab_entries WHERE session_id = ${sidE} AND tab = 'tab-b' ORDER BY used_at DESC LIMIT 1`)[0].used_at
  check('age the owner tab-b entry past 4 h', d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 5 * 3600e3).toISOString()}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  const again = await navigate(owner, '/tab-b/')
  check('tab-b: navigation after the entry window = Face ID page in place', entryPageOf(again))
  // the in-place flow end to end: the page's own options -> verify -> reload of the same address = the tab
  const ivr = await owner.req('POST', '/api/passkey/get/verify', await auth.get(entryData(again).options))
  check('entry page options verify (entry grant)', ivr.status === 200 && ivr.data.next === '/tab-b/', ivr.data)
  const inPlace = await navigate(owner, '/tab-b/')
  check('reload after the in-place Face ID = the tab itself', inPlace.status === 200 && !!inPlace.data.identity?.entered_at, inPlace.data)
  check('age it past 4 h again', d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 5 * 3600e3).toISOString()}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  // a 4 h entry is reused by a navigation for 15 min only; the rest of the tab keeps the 4 h
  check('entry 20 min old', d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 20 * 60e3).toISOString()}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  check('tab-b (4 h entry): navigation 20 min after the entry = Face ID page', entryPageOf(await navigate(owner, '/tab-b/')))
  check('tab-b (4 h entry): requests 20 min after the entry still = 200', (await owner.req('GET', '/tab-b/echo', undefined, CORS)).status === 200)
  check('entry 10 min old', d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 10 * 60e3).toISOString()}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  check('tab-b (4 h entry): navigation 10 min after the entry = 200', (await navigate(owner, '/tab-b/')).status === 200)
  check('age it past 4 h', d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 5 * 3600e3).toISOString()}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  check('tab-b: request after the entry window = 401', (await owner.req('GET', '/tab-b/echo', undefined, CORS)).status === 401)
  check('put the entry back', d1(`UPDATE tab_entries SET used_at = '${usedE}' WHERE session_id = ${sidE} AND tab = 'tab-b'`))
  { const a3 = await navigate(admin3, '/tab-b/')
    check('tab-b: another session of an admin without its own entry = Face ID again (in place, or the step-up page without a passkey)', entryPageOf(a3) || (a3.status === 302 && a3.headers.get('location') === '/?step_up=tab-b&next=%2Ftab-b%2F'), a3.status) }
}

// R1b: a keyWriteOnly action is the one way a key reaches a tab with Face ID on entry
{
  check('freshen owner (R1b)', await freshen(owner, auth))
  check('R1b write-only action next to another in a key = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-b/jot', 'tab-a/tv'] })).data.error === 'bad_scope')
  check('R1b unmarked action of a Face ID tab still = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-b/ping'] })).data.error === 'bad_scope')
  check('R1b resident cannot put the admin write-only action in a key', (await resident.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-b/jot'] })).status === 403)
  const kj = await owner.req('POST', '/api/me/shortcuts', { label: 'jot', scope: ['tab-b/jot'] })
  check('R1b key holding only the write-only action', kj.status === 200 && JSON.stringify(kj.data.scope) === '["tab-b/jot"]', kj.data)
  const n1 = (await cmdLog()).length
  const j1 = await sc('/_cmd/tab-b/jot', { cents: 250 }, KEYH(kj.data.key))
  check('R1b key on the write-only action = 200 with {ok, id} only', j1.status === 200 && JSON.stringify(Object.keys(j1.data).sort()) === '["id","ok"]' && j1.data.ok === true && UUID.test(j1.data.id), j1)
  log = await cmdLog()
  const jl = log[log.length - 1]
  check('R1b the tab got it once, identity.actions = that action only', log.length === n1 + 1 && jl.cmd.action === 'jot' && jl.identity.credential === 'shortcut' &&
    JSON.stringify(jl.identity.actions) === '["jot"]' && jl.identity.strong === false, jl)
  check('R1b same key on another action of the tab = 403', (await sc('/_cmd/tab-b/ping', undefined, KEYH(kj.data.key))).status === 403)
  check('R1b key without that action in scope = 403 out_of_scope', (await sc('/_cmd/tab-b/jot', { cents: 1 })).data?.error === 'out_of_scope')
  check('R1b bad params still = 400', (await sc('/_cmd/tab-b/jot', { cents: 5000 }, KEYH(kj.data.key))).status === 400)
  check('R1b refusals never reached the tab', (await cmdLog()).length === n1 + 1)
  check('R1b the key opens no page of the tab', (await fetch(BASE + '/tab-b/echo', { headers: { ...KEYH(kj.data.key), ...CORS } })).status === 401)
  // a forged scope with a second entry (written straight to D1) is refused at use too
  check('R1b forge a two-action scope in D1', d1(`UPDATE shortcut_keys SET scope = '["tab-b/jot","tab-a/light"]' WHERE id = ${kj.data.id}`))
  check('R1b two-action key on the write-only action = 403', (await sc('/_cmd/tab-b/jot', { cents: 3 }, KEYH(kj.data.key))).status === 403 && (await cmdLog()).length === n1 + 1)
  // marked action in a tab without Face ID on entry: no new access, only the trimmed answer to a key
  const kn = await owner.req('POST', '/api/me/shortcuts', { label: 'note', scope: ['tab-a/note', 'tab-a/light'] })
  check('R1b marked action on a session tab: key with two actions as before', kn.status === 200, kn.data)
  const nn = await sc('/_cmd/tab-a/note', undefined, KEYH(kn.data.key))
  check('R1b marked action on a session tab: key gets {ok, id}', nn.status === 200 && JSON.stringify(Object.keys(nn.data).sort()) === '["id","ok"]', nn)
  log = await cmdLog()
  check('R1b marked action on a session tab: identity.actions as for any key', JSON.stringify(log[log.length - 1].identity.actions) === '["light","note"]', log[log.length - 1].identity)
  check('R1b marked action on a session tab: page answer unchanged', (await cmd(resident, 'tab-a', 'note')).data.status === 'done')
  check('R1b marked action on a session tab: other actions still refused to the key', (await sc('/_cmd/tab-a/tv', { mode: 'on' }, KEYH(kn.data.key))).data?.error === 'out_of_scope')
  // the expense params are the sender's: another admin sees them masked in the audit
  const mine = (await owner.req('GET', '/api/admin/audit')).data.find((r) => r.action === 'command' && r.target === 'tab-b/jot')
  check('R1b owner sees own write-only params', mine && JSON.parse(mine.detail).params.cents === 250, mine)
  // a write-only command sent by someone else (written straight to D1): the owner sees its params masked
  check('R1b plant another admin\'s write-only command in the audit', d1(`INSERT INTO audit (at, person_id, strength, action, target, detail) VALUES ('${new Date().toISOString()}', ${a2id}, 'shortcut', 'command', 'tab-b/jot', '{"id":"x","params":{"cents":777},"credential":"shortcut","status":"done"}')`))
  check('freshen owner (R1b audit)', await freshen(owner, auth))
  const audR = (await owner.req('GET', '/api/admin/audit')).data
  const other = audR.find((r) => r.action === 'command' && r.target === 'tab-b/jot' && r.person_id === a2id)
  check('R1b another person\'s write-only params are masked', other && JSON.parse(other.detail).params.cents === '***' && !String(other.detail).includes('777'), other)
  const tvOther = audR.find((r) => r.action === 'command' && r.target === 'tab-a/tv' && r.person_id !== ownerId)
  check('R1b other commands keep their params', tvOther && JSON.parse(tvOther.detail).params.mode !== '***', tvOther)
  for (const id of [kj.data.id, kn.data.id]) await owner.req('DELETE', `/api/me/shortcuts/${id}`)
}

// letters-only text (a name from a bank e-mail): the tab gets the normalized value, the audit its length
{
  check('freshen owner (letters)', await freshen(owner, auth))
  const kl = await owner.req('POST', '/api/me/shortcuts', { label: 'named', scope: ['tab-b/named'] })
  check('letters: key holding only the named action', kl.status === 200, kl.data)
  const n0 = (await cmdLog()).length
  const l1 = await sc('/_cmd/tab-b/named', { name: '  Bakery   Cora\u0303o ', n: 0 }, KEYH(kl.data.key))
  check('letters: normalized name = 200 {ok, id}', l1.status === 200 && JSON.stringify(Object.keys(l1.data).sort()) === '["id","ok"]', l1)
  const ll = (await cmdLog()).at(-1)
  check('letters: the tab got NFC, trimmed, single spaces', (await cmdLog()).length === n0 + 1 && ll.cmd.params.name === 'Bakery Cor\u00e3o' && ll.cmd.params.n === 0, ll.cmd)
  check('letters: empty name = 200', (await sc('/_cmd/tab-b/named', { name: '', n: 1 }, KEYH(kl.data.key))).status === 200 && (await cmdLog()).at(-1).cmd.params.name === '')
  const n2 = (await cmdLog()).length
  for (const bad of ['Shop 24h', 'Smith & Co', 'a\nb', 'x'.repeat(61), 'Ana \u{1F600}'])
    check(`letters: refused ${JSON.stringify(bad).slice(0, 20)} = 400 bad_param`, (await sc('/_cmd/tab-b/named', { name: bad, n: 1 }, KEYH(kl.data.key))).data?.error === 'bad_param')
  check('letters: refusals never reached the tab', (await cmdLog()).length === n2)
  const au = (await owner.req('GET', '/api/admin/audit')).data.find((r) => r.action === 'command' && r.target === 'tab-b/named')
  check('letters: audit keeps the length only', au && JSON.parse(au.detail).params.name.startsWith('[text:') && !String(au.detail).includes('Bakery'), au)
  await owner.req('DELETE', `/api/me/shortcuts/${kl.data.id}`)
}

// page-only text (owner's note on a row, 11/11): the owner's page sends it, no key, no screen, length only in the audit
{
  check('freshen owner (page text)', await freshen(owner, auth))
  const n0 = (await cmdLog()).length
  const ok1 = await cmd(owner, 'tab-a', 'annotate', { n: 7, words: 'Lunch at the fair' })
  check('page text: owner sends it = 200', ok1.status === 200 && ok1.data.status === 'done', ok1)
  const last = (await cmdLog()).at(-1)
  check('page text: the tab got the text as sent', (await cmdLog()).length === n0 + 1 && last.cmd.action === 'annotate' && last.cmd.params.words === 'Lunch at the fair' && last.cmd.params.n === 7, last)
  check('page text: delete sends', (await cmd(owner, 'tab-a', 'annotate_del', { n: 7 })).status === 200)
  const n1 = (await cmdLog()).length
  for (const [label, params] of [['empty', { n: 7, words: '' }], ['141', { n: 7, words: 'a'.repeat(141) }], ['NUL', { n: 7, words: 'a\u0000b' }],
    ['U+2028', { n: 7, words: 'a\u2028b' }], ['lone surrogate', { n: 7, words: 'a\ud800b' }], ['not a string', { n: 7, words: 5 }]])
    check(`page text: ${label} = 400 bad_param`, (await cmd(owner, 'tab-a', 'annotate', params)).data?.error === 'bad_param')
  check('page text: extra param = 400 unknown_param', (await cmd(owner, 'tab-a', 'annotate', { n: 7, words: 'ok', kind: 'work' })).data?.error === 'unknown_param')
  check('page text: refusals never reached the tab', (await cmdLog()).length === n1)
  const au = (await owner.req('GET', '/api/admin/audit')).data.find((r) => r.action === 'command' && r.target === 'tab-a/annotate')
  check('page text: audit keeps the length only', au && JSON.parse(au.detail).params.words === '[text:17]' && !String(au.detail).includes('fair'), au)
  for (const a of ['annotate', 'annotate_del'])
    check(`page text: no key may hold ${a}`, (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: [`tab-a/${a}`] })).status === 400)
  check('page text: a resident cannot send it', (await cmd(resident, 'tab-a', 'annotate', { n: 7, words: 'x' })).status === 403)
}

// common action with its own passkey window (TV volume limiter, 08/11): Face ID every time, residents too
{
  const lim = { on: true, top: 30 }
  const rid = (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
  check('P1 resident identity lists the passkey action, window closed', rid.actions.includes('limit') && JSON.stringify(rid.passkey_until) === '{}', rid)
  const nm = await cmd(resident, 'tab-a', 'limit', lim)
  check('P2 resident without any passkey = 403 passkey_missing, no step_up', nm.status === 403 && nm.data.error === 'passkey_missing' && !nm.data.step_up, nm)
  const no = await resident.req('POST', '/api/passkey/get/options', { purpose: 'command:tab-a' })
  check('P3 resident step_up allowed for a tab with a passkey action, but no passkey = 409 no_passkey', no.status === 409 && no.data.error === 'no_passkey', no)
  // K1 (since 08/11): a new device registers its first key at once, no invite, no waiting
  d1(`UPDATE sessions SET commands_ok_at = NULL WHERE id = ${resSid}`)
  const ni = await resident.req('POST', '/api/passkey/create/options', {})
  check('K1 resident on a new device without invite: options 200', ni.status === 200, ni)
  const nme = (await resident.req('GET', '/api/me')).data
  check('K1 resident /api/me: no invite, passkeys 0, can add', nme.passkey_invite === false && nme.passkey_can_add === true && nme.passkey_add_after === null, nme)
  check('P5 weak admin cannot invite', (await admin3.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})).status === 403)
  check('P5 resident cannot invite', (await resident.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})).status === 403)
  check('freshen owner (invite)', await freshen(owner, auth))
  check('P5 owner invites the resident', (await owner.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})).status === 200)
  check('P5 resident /api/me shows the invite', (await resident.req('GET', '/api/me')).data.passkey_invite === true)
  const authR = residentAuth = await makeAuthenticator()
  const rco = await resident.req('POST', '/api/passkey/create/options', {})
  // R1: another device used the invite between these options and this verify: this one loses
  d1(`UPDATE passkey_invites SET used_at = '${new Date().toISOString()}' WHERE person_id = ${residentId} AND used_at IS NULL`)
  const lost = await resident.req('POST', '/api/passkey/create/verify', await (await makeAuthenticator()).create(rco.data))
  // (a first key needs no invite since 08/11: the lost invite only means the key is self-registered)
  check('R1 an invite used elsewhere is not claimed twice: this key registers as self', lost.status === 200 &&
    (await owner.req('GET', '/api/admin/audit')).data.some((r) => r.action === 'passkey_added' && r.person_id === residentId && JSON.parse(r.detail).self === true), lost)
  d1(`DELETE FROM passkeys WHERE person_id = ${residentId}`)
  check('freshen owner (second invite)', await freshen(owner, auth))
  check('R1 owner invites again', (await owner.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})).status === 200)
  const rco3 = await resident.req('POST', '/api/passkey/create/options', {})
  const rcv = rco3.status === 200 ? await resident.req('POST', '/api/passkey/create/verify', await authR.create(rco3.data)) : rco3
  check('P6 invited resident registers a passkey (K4: the invite skips the new-device hold)', rcv.status === 200, [rco3.status, rcv])
  const rme2 = (await resident.req('GET', '/api/me')).data
  check('P6 invite used once; resident still not admin', rme2.passkey_invite === false && rme2.passkeys === 1 && rme2.admin === false, rme2)
  check('K2 registering is not a Face ID check: passkey_at stays empty', !d1json(`SELECT passkey_at FROM sessions WHERE id = ${resSid}`)[0].passkey_at)
  const second = await resident.req('POST', '/api/passkey/create/options', {})
  check('K3 a second key without a fresh portal Face ID = 403 passkey_required', second.status === 403 && second.data.error === 'passkey_required' && second.data.passkey === true, second)
  d1(`UPDATE sessions SET commands_ok_at = '${new Date().toISOString()}' WHERE id = ${resSid}`)
  check('freshen resident (portal Face ID)', await freshen(resident, authR))
  check('K8 resident /api/me strong false right after a portal Face ID', (await resident.req('GET', '/api/me')).data.strong === false)
  check('K8 resident identity.strong false too', (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.strong === false)
  check('P6 a resident with a fresh Face ID still gets no admin reads or actions', (await resident.req('GET', '/api/admin/people')).status === 403 &&
    (await cmd(resident, 'tab-a', 'presence', { state: 'home' })).data.error === 'admin_only')
  const ok1 = await cmd(resident, 'tab-a', 'limit', lim)
  check('P7 resident with a passkey check under 5 min: passkey action ok', ok1.status === 200 && ok1.data.status === 'done', ok1)
  const pu = (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.passkey_until
  const pl = Date.parse(pu.limit) - Date.now()
  check('P7 identity.passkey_until.limit about 5 min ahead, only passkey actions', Object.keys(pu).join() === 'limit' && pl > 4 * 60e3 && pl <= 5 * 60e3, pu)
  check('P7 parameters still checked', (await cmd(resident, 'tab-a', 'limit', { on: true, top: 70 })).data.error === 'bad_param')
  d1(`UPDATE sessions SET passkey_at = '${new Date(Date.now() - 5 * 60e3 - 30e3).toISOString()}' WHERE id = ${resSid}`)
  const old = await cmd(resident, 'tab-a', 'limit', lim)
  check('P8 passkey 5 min 30 s ago: 403 passkey_required with the step_up address', old.status === 403 && old.data.error === 'passkey_required' &&
    old.data.step_up === '/?step_up=tab-a&purpose=command&next=%2Ftab-a%2F', old)
  check('P8 identity: window closed, action still listed', (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.passkey_until.limit === undefined)
  const so2 = await resident.req('POST', '/api/passkey/get/options', { purpose: 'command:tab-a' })
  const sv2 = so2.status === 200 ? await resident.req('POST', '/api/passkey/get/verify', await authR.get(so2.data)) : so2
  check('P9 resident step_up Face ID: ok, back to the tab', sv2.status === 200 && sv2.data.next === '/tab-a/', [so2.status, sv2])
  check('P9 ... then the passkey action works', (await cmd(resident, 'tab-a', 'limit', lim)).status === 200)
  const osid = (await owner.req('GET', '/api/me')).data.session_id
  d1(`UPDATE sessions SET passkey_at = '${new Date(Date.now() - 6 * 60e3).toISOString()}' WHERE id = ${osid}`)
  const ow = await cmd(owner, 'tab-a', 'limit', lim)
  check('P10 owner too: admin window open (12 h) but passkey 6 min ago = passkey_required', ow.status === 403 && ow.data.error === 'passkey_required' && !!ow.data.step_up, ow)
  check('P10 ... while admin actions still pass', (await cmd(owner, 'tab-a', 'presence', { state: 'home' })).status === 200)
  check('P11 screen: passkey action = not_for_screens', (await cmd(tvc, 'tab-a', 'limit', lim)).data.error === 'not_for_screens')
  check('P11 screen identity never lists it', !(await tvc.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.actions.includes('limit'))
  check('freshen owner (keys, limit)', await freshen(owner, auth))
  check('P12 key scope with a passkey action = 400', (await owner.req('POST', '/api/me/shortcuts', { label: 'x', scope: ['tab-a/limit'] })).data.error === 'bad_scope')
  const scr = (await owner.req('GET', '/api/admin/people')).data.find((p) => p.kind === 'screen')
  check('P13 no passkey invite for a fixed screen', !scr || (await owner.req('POST', `/api/admin/people/${scr.id}/passkey-invite`, {})).data.error === 'invite_not_allowed')
  check('P14 the screen session cannot register a passkey', (await tvc.req('POST', '/api/passkey/create/options', {})).status === 403)
}

// Face ID asked by the tab page itself (/<tab>/_passkey/*, 08/11): only the system sheet, no portal page
{
  const lim = { on: true, top: 30 }
  const resSid2 = (await resident.req('GET', '/api/me')).data.session_id
  const ownSid = (await owner.req('GET', '/api/me')).data.session_id
  const ago = (ms) => new Date(Date.now() - ms).toISOString()
  d1(`UPDATE sessions SET passkey_at = '${ago(10 * 60e3)}', command_passkey_at = NULL WHERE id = ${resSid2}`)
  d1(`UPDATE sessions SET passkey_at = '${ago(13 * 3600e3)}', command_passkey_at = NULL WHERE id = ${ownSid}`)
  check('T0 owner admin window closed before', (await cmd(owner, 'tab-a', 'presence', { state: 'home' })).data.error === 'passkey_required')
  check('T1 GET on the tab passkey route = 405', (await resident.req('GET', '/tab-a/_passkey/options', undefined, CORS)).status === 405)
  check('T1 unknown tab passkey route = 404', (await resident.req('POST', '/tab-a/_passkey/other', {})).status === 404)
  check('T1 another origin = 403', (await resident.req('POST', '/tab-a/_passkey/options', {}, { Origin: 'https://evil.example' })).status === 403)
  check('T1 without X-Portal = 403', (await resident.req('POST', '/tab-a/_passkey/options', {}, { 'X-Portal': undefined })).status === 403)
  check('T1 a tab with no action that needs Face ID = 400 bad_purpose (owner) / 403 admin_only (resident)',
    (await owner.req('POST', '/tab-badcmd/_passkey/options', {})).status >= 400)
  const to = await resident.req('POST', '/tab-a/_passkey/options', {})
  check('T2 resident options from the tab page: challenge for this host', to.status === 200 && to.data.rpId === new URL(BASE).hostname &&
    to.data.userVerification === 'required' && to.data.allowCredentials.length === 1, to)
  const purpose = d1json(`SELECT purpose FROM passkey_challenges WHERE session_id = ${resSid2} AND kind = 'get'`)
  check('T2 the challenge is bound to tabcmd:tab-a', purpose[0]?.purpose === 'tabcmd:tab-a', purpose)
  const tv = await resident.req('POST', '/tab-a/_passkey/verify', await residentAuth.get(to.data))
  const pl = tv.status === 200 ? Date.parse(tv.data.passkey_until.limit) - Date.now() : 0
  check('T3 verify: ok, passkey_until.limit about 5 min, admin_until null', tv.status === 200 && pl > 4 * 60e3 && pl <= 5 * 60e3 && tv.data.admin_until === null, tv)
  check('T3 ... then the passkey action works', (await cmd(resident, 'tab-a', 'limit', lim)).status === 200)
  const sess = d1json(`SELECT passkey_at, command_passkey_at FROM sessions WHERE id = ${resSid2}`)[0]
  check('T3 only command_passkey_at moved, passkey_at kept old', Date.parse(sess.passkey_at) < Date.now() - 9 * 60e3 && Date.now() - Date.parse(sess.command_passkey_at) < 60e3, sess)
  check('T3 identity.strong stays false', (await resident.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.strong === false)
  check('T4 the same assertion twice = 400 challenge_expired', (await resident.req('POST', '/tab-a/_passkey/verify', await residentAuth.get(to.data))).data.error === 'challenge_expired')
  // owner: admin and passkey actions open, account and sensitive stay closed
  const oo = await owner.req('POST', '/tab-a/_passkey/options', {})
  const ov = await owner.req('POST', '/tab-a/_passkey/verify', await auth.get(oo.data))
  const al = ov.status === 200 ? Date.parse(ov.data.admin_until) - Date.now() : 0
  check('T5 owner verify from the tab: admin_until open (12 h)', ov.status === 200 && al > 11 * 3600e3, ov)
  check('T5 ... admin and passkey actions pass', (await cmd(owner, 'tab-a', 'presence', { state: 'home' })).status === 200 &&
    (await cmd(owner, 'tab-a', 'limit', lim)).status === 200)
  const other = (await owner.req('GET', '/tab-slow/echo', undefined, CORS)).data.identity
  check('R1 the tab Face ID counts only in its own tab (another tab: admin_until null)', other && other.admin_until === null, other)
  check('R3 audit strength of a tab Face ID is tab_passkey', (await owner.req('GET', '/api/admin/audit')).data.some((r) => r.action === 'command_passkey_ok' && r.strength === 'tab_passkey'))
  const ws = await cmd(owner, 'tab-a', 'wipe')
  check('T6 sensitive action still needs the portal Face ID', ws.status === 403 && ws.data.error === 'passkey_required', ws)
  const inv = await owner.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})
  check('T6 account admin write still needs the portal Face ID', inv.status === 403 && inv.data.passkey === true, inv)
  check('T6 /api/me not strong', (await owner.req('GET', '/api/me')).data.strong !== true)
  // a portal challenge pending (no purpose) is never taken by the tab route
  const po = await owner.req('POST', '/api/passkey/get/options', {})
  const pa = await auth.get(po.data)
  const steal = await owner.req('POST', '/tab-a/_passkey/verify', pa)
  check('T7 the tab route never takes a portal challenge', steal.status === 400 && steal.data.error === 'challenge_expired', steal)
  check('T7 ... which still works on the portal', (await owner.req('POST', '/api/passkey/get/verify', pa)).status === 200)
  // A1: a tab challenge and a portal challenge live side by side, both ways
  d1(`UPDATE sessions SET passkey_at = '${ago(13 * 3600e3)}', command_passkey_at = NULL WHERE id = ${ownSid}`)
  const p1 = await owner.req('POST', '/api/passkey/get/options', {})
  const t1 = await owner.req('POST', '/tab-a/_passkey/options', {})
  check('A1 portal options, then tab options, then portal verify = 200', (await owner.req('POST', '/api/passkey/get/verify', await auth.get(p1.data))).status === 200)
  check('A1 ... and the tab verify after it = 200', (await owner.req('POST', '/tab-a/_passkey/verify', await auth.get(t1.data))).status === 200)
  const t2 = await owner.req('POST', '/tab-a/_passkey/options', {})
  const p2 = await owner.req('POST', '/api/passkey/get/options', {})
  check('A1 tab options, then portal options, then tab verify = 200', (await owner.req('POST', '/tab-a/_passkey/verify', await auth.get(t2.data))).status === 200)
  check('A1 ... and the portal verify after it = 200', (await owner.req('POST', '/api/passkey/get/verify', await auth.get(p2.data))).status === 200)
  d1(`UPDATE sessions SET passkey_at = '${ago(13 * 3600e3)}', command_passkey_at = NULL WHERE id = ${ownSid}`)
  const t3 = await owner.req('POST', '/tab-a/_passkey/options', {})
  const viaPortal = await owner.req('POST', '/api/passkey/get/verify', await auth.get(t3.data))
  check('A1 the portal verify never takes a tab challenge (no strong session from it)', viaPortal.status === 400 && viaPortal.data.error === 'challenge_expired' &&
    d1json(`SELECT passkey_at FROM sessions WHERE id = ${ownSid}`)[0].passkey_at < ago(12 * 3600e3), viaPortal)
  check('T8 screen: tab passkey options refused', (await tvc.req('POST', '/tab-a/_passkey/options', {})).status === 403)
  const nor = client()
  check('T8 signed out = 401', (await nor.req('POST', '/tab-a/_passkey/options', {})).status === 401)
  const bo = await owner.req('POST', '/tab-b/_passkey/options', {})
  check('T8 tab-b (entry passed, only a common action): 400 bad_purpose', bo.status === 400 && bo.data.error === 'bad_purpose', bo)
  const rows = (await owner.req('GET', '/api/admin/audit')).data
  const ar = rows.find((r) => r.action === 'command_passkey_ok' && r.target === 'tab-a' && JSON.parse(r.detail ?? 'null')?.via === 'tab')
  check('T9 audit: command_passkey_ok via tab', !!ar, rows.slice(0, 5))
  // a bad assertion is audited and opens nothing
  d1(`UPDATE sessions SET command_passkey_at = NULL WHERE id = ${resSid2}`)
  const bo2 = await resident.req('POST', '/tab-a/_passkey/options', {})
  const bad = await residentAuth.get(bo2.data)
  bad.signature = bad.signature.slice(0, -4) + 'AAAA'
  const br2 = await resident.req('POST', '/tab-a/_passkey/verify', bad)
  check('T10 bad signature = 400, window still closed', br2.status === 400 && (await cmd(resident, 'tab-a', 'limit', lim)).data.error === 'passkey_required', br2)
}

// residents register their own Face ID (08/11)
{
  const ago = (ms) => new Date(Date.now() - ms).toISOString()
  const ownSid = (await owner.req('GET', '/api/me')).data.session_id
  const rows0 = (await owner.req('GET', '/api/admin/audit')).data
  // K3: second key, with only the tab's Face ID = refused; with the portal's = ok
  d1(`UPDATE sessions SET passkey_at = NULL WHERE id = ${resSid}`)
  const to = await resident.req('POST', '/tab-a/_passkey/options', {})
  check('K3 tab Face ID done', (await resident.req('POST', '/tab-a/_passkey/verify', await residentAuth.get(to.data))).status === 200)
  check('K3 ... does not count for a second key', (await resident.req('POST', '/api/passkey/create/options', {})).data.error === 'passkey_required')
  check('freshen resident', await freshen(resident, residentAuth))
  const a2 = await makeAuthenticator()
  const c2 = await resident.req('POST', '/api/passkey/create/options', {})
  const v2 = c2.status === 200 ? await resident.req('POST', '/api/passkey/create/verify', await a2.create(c2.data)) : c2
  check('K3 second key after the portal Face ID = 200', v2.status === 200, v2)
  const a3 = await makeAuthenticator()
  const c3 = await resident.req('POST', '/api/passkey/create/options', {})
  check('K3 third key ok', c3.status === 200 && (await resident.req('POST', '/api/passkey/create/verify', await a3.create(c3.data))).status === 200)
  const me3 = (await resident.req('GET', '/api/me')).data
  check('K5 three keys: /api/me says limit, cannot add', me3.passkeys === 3 && me3.passkey_can_add === false && me3.passkey_limit === true, me3)
  check('K5 a fourth = 409 passkey_limit', (await resident.req('POST', '/api/passkey/create/options', {})).data.error === 'passkey_limit')
  check('freshen owner (invite at the limit)', await freshen(owner, auth))
  await owner.req('POST', `/api/admin/people/${residentId}/passkey-invite`, {})
  check('K5 ... also with an invite', (await resident.req('POST', '/api/passkey/create/options', {})).data.error === 'passkey_limit')
  // K2 / R3: every registration is an alert on the owner's page and audited with the session age
  const ome = (await owner.req('GET', '/api/me')).data
  check('K2 owner sees a passkey alert per resident registration', ome.alerts.filter((x) => x.kind === 'passkey').length >= 3, ome.alerts)
  const added = (await owner.req('GET', '/api/admin/audit')).data.filter((r) => r.action === 'passkey_added' && r.person_id === residentId)
  check('K2/R3 audit: self or invite, with session hours and released flag', added.length >= 3 && added.every((r) => { const d = JSON.parse(r.detail); return (d.self || d.invite) && typeof d.session_hours === 'number' && 'released' in d }), added)
  // K6: removing one's own key
  const mine = (await resident.req('GET', '/api/me/passkeys')).data
  check('K6 resident lists own keys (no key material)', mine.length === 3 && mine.every((k) => k.id && k.label && !('public_key' in k) && !('credential_id' in k)), mine)
  d1(`UPDATE sessions SET passkey_at = '${ago(10 * 60e3)}' WHERE id = ${resSid}`)
  const rm0 = await resident.req('DELETE', `/api/me/passkeys/${mine[2].id}`)
  check('K6 remove own without a fresh Face ID = 403 passkey_required', rm0.status === 403 && rm0.data.passkey === true, rm0)
  const ownerKeys = (await owner.req('GET', '/api/me/passkeys')).data
  check('freshen resident (remove)', await freshen(resident, residentAuth))
  check('K6 a key of another person through /api/me = 404', (await resident.req('DELETE', `/api/me/passkeys/${ownerKeys[0].id}`)).status === 404)
  const tw = await resident.req('POST', '/tab-a/_passkey/options', {})
  await resident.req('POST', '/tab-a/_passkey/verify', await residentAuth.get(tw.data))
  check('K6 remove own with a fresh Face ID = 200', (await resident.req('DELETE', `/api/me/passkeys/${mine[2].id}`)).status === 200)
  const after = d1json(`SELECT passkey_at, command_passkey_at FROM sessions WHERE id = ${resSid}`)[0]
  check('R1 removing closes every Face ID window of the person', !after.passkey_at && !after.command_passkey_at, after)
  check('K6 audit passkey_removed', (await owner.req('GET', '/api/admin/audit')).data.some((r) => r.action === 'passkey_removed' && r.target === String(residentId)))
  // K7: the owner removes a resident's key, strong only
  const theirs = (await owner.req('GET', `/api/admin/people/${residentId}/passkeys`)).data
  check('K7 owner lists the resident keys', Array.isArray(theirs) && theirs.length === 2, theirs)
  check('K7 resident cannot list another person keys', (await resident.req('GET', `/api/admin/people/${residentId}/passkeys`)).status === 403)
  d1(`UPDATE sessions SET passkey_at = '${ago(10 * 60e3)}' WHERE id = ${ownSid}`)
  check('K7 weak owner cannot remove = 403', (await owner.req('DELETE', `/api/admin/people/${residentId}/passkeys/${theirs[1].id}`)).status === 403)
  check('freshen owner (remove)', await freshen(owner, auth))
  check('K7 strong owner removes = 200', (await owner.req('DELETE', `/api/admin/people/${residentId}/passkeys/${theirs[1].id}`)).status === 200)
  check('K7 ... and the resident is down to one', (await resident.req('GET', '/api/me')).data.passkeys === 1)
  // K8: strong is an admin's only
  check('K8 owner strong true after a portal Face ID', (await owner.req('GET', '/api/me')).data.strong === true &&
    (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity.strong === true)
  // K9: screens never register
  check('K9 screen cannot register', (await tvc.req('POST', '/api/passkey/create/options', {})).status === 403)
  check('K9 screen /api/me cannot add', (await tvc.req('GET', '/api/me')).data.passkey_can_add === false)
  void rows0
}

// the selector in a real browser (owner, resident and a freshly paired screen)
const g5 = await owner.req('POST', '/api/passkey/get/options', {})
await owner.req('POST', '/api/passkey/get/verify', await auth.get(g5.data))
const tv3 = client()
const ps3 = await tv3.req('POST', '/api/pair/start', {})
await owner.req('POST', '/api/admin/pair', { code: ps3.data.code, name: 'TV browser' })
await tv3.req('POST', '/api/pair/status', { secret: ps3.data.secret })
check('screen for the browser test paired', !!tv3.cookie)
// a fresh Face ID check on the owner's session (the software passkey)
// The page may ask for its own options at the same moment (it keeps them ready for the Face ID button), which
// replaces this session's challenge: try again until the check lands.
const strongNow = async () => {
  for (let i = 0; i < 4; i++) {
    const r = await owner.req('POST', '/api/passkey/get/verify', await auth.get((await owner.req('POST', '/api/passkey/get/options', {})).data))
    if (r.status === 200) return r
    console.log(`note: strong check try ${i + 1} = ${r.status} ${r.data?.error ?? ''}`)
    await new Promise((res) => setTimeout(res, 300))
  }
}
await browserChecks({ base: BASE, check, owner: owner.cookie, resident: resident.cookie, screen: tv3.cookie, strong: strongNow,
  approve: async (code) => check('browser pairing approved', (await owner.req('POST', '/api/admin/pair', { code, name: 'TV deep link' })).status === 200) })
{
  // Face ID on entry in place, in Chrome: the owner's tab-b entries aged past 4 h, then put back
  const sidB = (await owner.req('GET', '/api/me')).data.session_id
  const keep = d1json(`SELECT id, granted_at, used_at FROM tab_entries WHERE session_id = ${sidB} AND tab = 'tab-b'`)
  // Chrome's virtual authenticator counts up; the software passkey keeps sending 0: put the count back
  const count0 = d1json(`SELECT sign_count AS n FROM passkeys WHERE credential_id = '${auth.id}'`)[0].n
  await entryChecks({ base: BASE, check, owner: owner.cookie, cred: await auth.forChrome(),
    stale: async () => d1(`UPDATE sessions SET passkey_at = '${new Date(Date.now() - 3600e3).toISOString()}' WHERE id = ${sidB}`),
    age: async () => d1(`UPDATE tab_entries SET used_at = '${new Date(Date.now() - 5 * 3600e3).toISOString()}', granted_at = '${new Date(Date.now() - 5 * 3600e3).toISOString()}' WHERE session_id = ${sidB} AND tab = 'tab-b'`),
    restore: async () => {
      d1(`DELETE FROM tab_entries WHERE session_id = ${sidB} AND tab = 'tab-b' AND id NOT IN (${keep.map((k) => k.id).join(',') || 0})`)
      d1(`UPDATE passkeys SET sign_count = ${count0} WHERE credential_id = '${auth.id}'`)
      for (const k of keep) d1(`UPDATE tab_entries SET granted_at = '${k.granted_at}', used_at = ${k.used_at ? `'${k.used_at}'` : 'NULL'} WHERE id = ${k.id}`)
    } })
}

// ------------------------------------------------------------------ "see as" (an admin sees the portal as another group)
{
  const ot0 = (await owner.req('GET', '/api/tabs')).data
  check('see as: owner gets the non-admin groups to see as, nobody else', ot0.view_as === null &&
    ot0.view_options.map((g) => g.id).join() === 'owner-screens,residents' &&
    (await resident.req('GET', '/api/tabs')).data.view_options.length === 0 && (await tv3.req('GET', '/api/tabs')).data.view_options.length === 0, ot0)
  check('see as: a resident cannot turn it on', (await resident.req('POST', '/api/tabs', { view_as: 'residents' })).status === 403)
  check('see as: a screen cannot turn it on', (await tv3.req('POST', '/api/tabs', { view_as: 'residents' })).status === 403)
  check('see as: never an admin group', (await owner.req('POST', '/api/tabs', { view_as: 'owner' })).data.error === 'view_as_admin_group')
  check('see as: unknown group = 404', (await owner.req('POST', '/api/tabs', { view_as: 'nobody' })).status === 404)
  check('see as: bad value = 400', (await owner.req('POST', '/api/tabs', { view_as: 7 })).status === 400 && (await owner.req('POST', '/api/tabs', { view_as: 'Bad Id' })).status === 400)
  check('see as: needs X-Portal and the same origin', (await owner.req('POST', '/api/tabs', { view_as: 'residents' }, { 'X-Portal': undefined })).status === 403 &&
    (await owner.req('POST', '/api/tabs', { view_as: 'residents' }, { Origin: 'https://evil.example' })).status === 403)
  check('see as: still the owner after the refusals', (await owner.req('GET', '/api/me')).data.admin === true)

  const on = await owner.req('POST', '/api/tabs?current=tab-b', { view_as: 'residents' })
  check('see as on: answers the new list (Tab A only), current tab-b no longer listed', on.status === 200 && on.data.view_as?.id === 'residents' &&
    on.data.tabs.map((t) => t.id).join() === 'tab-a' && on.data.current === null && on.data.view_options.length === 2, on.data)
  const vEcho = (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
  check('see as: identity.actions never lists an admin action, Face ID window or not', !vEcho.actions.includes('presence') && vEcho.admin_until === null, vEcho)
  const vme = (await owner.req('GET', '/api/me')).data
  check('see as: /api/me is a resident, same person', vme.admin === false && vme.groups.map((g) => g.id).join() === 'residents' && vme.tabs.join() === 'tab-a' &&
    vme.person.id === ownerId && vme.view_as?.id === 'residents' && vme.alerts.length === 0 && vme.commands_off === undefined && vme.passkeys === 0, vme)
  check('see as: no counts in the list', (await owner.req('GET', '/api/tabs')).data.tabs.every((t) => t.badge === null))
  check('see as: account admin pages = 403', (await owner.req('GET', '/api/admin/people')).status === 403 && (await owner.req('GET', '/api/admin/audit')).status === 403 &&
    (await owner.req('GET', '/api/me/shortcuts')).status === 403)
  check('see as: admin write refused even with a fresh passkey', (await owner.req('POST', '/api/admin/people', { name: 'X', phone: '5561900000099' })).status === 403)
  check('see as: tab outside the group = 403', (await owner.req('GET', '/tab-b/echo', undefined, CORS)).status === 403 && (await navigate(owner, '/tab-b/')).status === 403 &&
    (await owner.req('GET', '/tab-slow/echo', undefined, CORS)).status === 403)
  const vid = (await owner.req('GET', '/tab-a/echo', undefined, CORS)).data.identity
  check('see as: the tab gets a resident identity (groups, common actions only)', vid.person === ownerId && vid.groups.join() === 'residents' &&
    vid.actions.join() === 'tv,ac,light,slow,boom,limit,note', vid)
  check('see as: a page-only text action is refused before the tab', (await cmd(owner, 'tab-a', 'annotate', { n: 7, words: 'x' })).status === 403)
  const vp = await cmd(owner, 'tab-a', 'presence', { state: 'home' })
  check('see as: admin command refused', vp.status === 403 && vp.data.error === 'admin_only', vp)
  check('see as: sensitive command refused', (await cmd(owner, 'tab-a', 'wipe')).data.error === 'admin_only')
  check('see as: Face ID from the tab page refused', (await owner.req('POST', '/tab-a/_passkey/options', {})).data.error === 'admin_only')
  check('K9 see as: registering refused', (await owner.req('POST', '/api/passkey/create/options', {})).status === 403)
  check('K8 see as: strong false', (await owner.req('GET', '/api/me')).data.strong === false)
  const logBefore = (await cmdLog()).length
  const vl = await cmd(owner, 'tab-a', 'light')
  check('rehearsal: common command answers done + simulated (no new-device hold)', vl.status === 200 && vl.data.status === 'done' && vl.data.ok === true && vl.data.simulated === true && UUID.test(vl.data.id), vl)
  check('rehearsal: the command never reached the tab', (await cmdLog()).length === logBefore)
  check('rehearsal: bad params still refused', (await cmd(owner, 'tab-a', 'light', { nope: 1 })).status === 400)
  check('rehearsal: the tab identity carries rehearsal', vid.rehearsal === true)
  check('rehearsal: /api/me says rehearsal, devices = only this one', vme.rehearsal === true &&
    (await (async () => { const d = (await owner.req('GET', '/api/me/devices')).data; return d.length === 1 && d[0].current === true && d[0].id === vme.session_id })()))
  const lo = await owner.req('POST', '/api/logout', {})
  check('rehearsal: sign out on the server refused, session kept', lo.status === 403 && lo.data.error === 'view_as_active' && !lo.setCookie &&
    (await owner.req('GET', '/api/me')).status === 200, lo)
  check('rehearsal: sign out with real:false is still refused', (await owner.req('POST', '/api/logout', { real: 'yes' })).status === 403)
  check('see as: audit rows written in the mode carry view_as', (await (async () => { await strongNow(); await owner.req('POST', '/api/tabs', { view_as: null }); const r = (await owner.req('GET', '/api/admin/audit')).data; await owner.req('POST', '/api/tabs', { view_as: 'residents' }); return r })())
    .some((a) => a.action === 'command' && /"view_as":"residents"/.test(String(a.detail)) && /"simulated":true/.test(String(a.detail))))
  check('see as: cannot disconnect another of the owner\'s devices', (await owner.req('DELETE', "/api/me/devices/999999")).data.error === 'view_as_active')
  check('see as: no passkey registration', (await owner.req('POST', '/api/passkey/create/options', {})).status === 403)
  const sw = await owner.req('POST', '/api/tabs', { view_as: 'owner-screens' })
  check('see as: switch to another group', sw.status === 200 && sw.data.view_as?.id === 'owner-screens', sw.data)

  await strongNow()
  check('see as off: with a fresh Face ID', (await owner.req('POST', '/api/tabs', { view_as: null })).status === 200)
  await strongNow()
  await owner.req('POST', '/api/tabs', { view_as: 'residents' })
  const weak = await owner.req('POST', '/api/tabs', { view_as: null })
  check('see as off: Face ID made before going in does not count', weak.status === 403 && weak.data.error === 'passkey_required' && weak.data.passkey === true &&
    (await owner.req('GET', '/api/me')).data.view_as?.id === 'residents', weak.data)
  check('see as: switching groups inside the mode asks for nothing', (await owner.req('POST', '/api/tabs', { view_as: 'owner-screens' })).status === 200)
  check('see as: Face ID works inside the mode', (await strongNow()).status === 200)
  const off = await owner.req('POST', '/api/tabs', { view_as: null })
  check('see as off: back to the owner after a fresh Face ID', off.status === 200 && off.data.view_as === null && off.data.tabs.length === 4 && (await owner.req('GET', '/api/me')).data.admin === true, off.data)
  check('see as off twice: no-op', (await owner.req('POST', '/api/tabs', { view_as: null })).status === 200)
  check('see as off: admin pages back', (await owner.req('GET', '/api/admin/people')).status === 200)
  const va = (await owner.req('GET', '/api/admin/audit')).data
  check('audit: view_as_on and view_as_off with the group', va.some((a) => a.action === 'view_as_on' && a.target === 'residents') &&
    va.some((a) => a.action === 'view_as_off' && a.target === 'residents') && va.some((a) => a.action === 'view_as_on' && a.target === 'owner-screens'), va.slice(0, 6))
  // an admin group set behind the portal's back is ignored (never more than the session has)
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--command',
    `UPDATE sessions SET view_as = 'residents' WHERE id = ${me.session_id}`], { stdio: 'ignore' })
  const forced = (await owner.req('GET', '/api/me')).data
  check('see as: stored on the session (this device only)', forced.view_as?.id === 'residents' && forced.session_id === me.session_id, forced)
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--command',
    `UPDATE sessions SET view_as = 'owner' WHERE id = ${me.session_id}`], { stdio: 'ignore' })
  check('see as: an admin group in the row is ignored', (await owner.req('GET', '/api/me')).data.view_as === null)
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'portal_a5', '--local', '--persist-to', process.env.STATE, '--command',
    `UPDATE sessions SET view_as = 'residents' WHERE person_id = ${residentId}`], { stdio: 'ignore' })
  const rv = (await resident.req('GET', '/api/me')).data
  check('see as: ignored for a non-admin', rv.view_as === null && rv.tabs.join() === 'tab-a', rv)
  await owner.req('POST', '/api/tabs', { view_as: null })
}

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
{
  const nope = await owner.req('POST', '/api/admin/groups/owner-screens', { tabs: ['tab-a', 'tab-b'] })
  check('screens group refuses a tab that takes no screen', nope.status === 409 && nope.data.error === 'tab_not_for_screens', nope.data)
  check('screens group refuses a tab that does not exist', (await owner.req('POST', '/api/admin/groups/owner-screens', { tabs: ['tab-gone'] })).status === 409)
  check('mixed group still takes a browser-only tab', (await owner.req('POST', '/api/admin/groups/residents', { tabs: ['tab-a', 'tab-b'] })).status === 200)
  await owner.req('POST', '/api/admin/groups/residents', { tabs: ['tab-a'] })
  const gl = (await owner.req('GET', '/api/admin/groups')).data
  check('a refused save leaves the screens group as it was', JSON.stringify(gl.find((g) => g.id === 'owner-screens').tabs) === '["tab-a"]', gl)
  check('groups say which are for screens', gl.find((g) => g.id === 'owner-screens').screens_only === true && gl.find((g) => g.id === 'residents').screens_only === false, gl)
  const m = (await owner.req('GET', '/api/me')).data
  check('me lists the tabs that open on screens', m.screen_tabs.includes('tab-a') && !m.screen_tabs.includes('tab-b'), m.screen_tabs)
}
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

// L1/L2: read keys (pa5_ler_), docs/READ_KEYS.md. tab-b takes them on /echo and /audit, 8 an hour.
const rk = (path, key, method = 'GET', headers = {}) => fetch(BASE + path, { method, headers: { ...KEYH(key), ...headers }, body: method === 'POST' ? '{}' : undefined })
  .then(async (r) => ({ status: r.status, data: await r.json().catch(() => null), headers: r.headers }))
check('resident cannot list or create read keys', (await resident.req('GET', '/api/me/readkeys')).status === 403 &&
  (await resident.req('POST', '/api/me/readkeys', { label: 'x', tab: 'tab-b' })).status === 403)
const wrk = await admin3.req('POST', '/api/me/readkeys', { label: 'x', tab: 'tab-b' })
check('L1 creating a read key from a weak session = 403 passkey', wrk.status === 403 && wrk.data.passkey === true, wrk)
check('freshen owner (read keys)', await freshen(owner, auth))
check('read key on a tab without readKey = 400', (await owner.req('POST', '/api/me/readkeys', { label: 'x', tab: 'tab-a' })).data.error === 'bad_tab')
check('read key without a label = 400', (await owner.req('POST', '/api/me/readkeys', { tab: 'tab-b' })).status === 400)
const r1k = await owner.req('POST', '/api/me/readkeys', { label: 'Mac · contador', tab: 'tab-b' })
check('read key created once, pa5_ler_ prefix, no end date', r1k.status === 200 && /^pa5_ler_[A-Za-z0-9_-]{43}$/.test(r1k.data.key) && !('expires_at' in r1k.data), r1k.data)
const RK = r1k.data.key
const rg = await rk('/tab-b/echo', RK)
check('L1 GET on its path = 200, no entry asked', rg.status === 200 && rg.data.method === 'GET', rg)
const rid = rg.data.identity
check('L1 identity: read_key, key id, no session, never strong, no actions, no admin window', rid.credential === 'read_key' && rid.read_key === r1k.data.id &&
  rid.session === null && rid.shortcut === null && rid.strong === false && rid.admin_until === null && rid.entered_at === null && rid.actions.length === 0 && rid.person === ownerId, rid)
check('L1 the tab never sees the key or a cookie', !('authorization' in rg.data.headers) && !('cookie' in rg.data.headers))
check('L1 answer carries no cookie and no-store', !rg.headers.get('set-cookie') && rg.headers.get('cache-control') === 'no-store')
check('L1 cookie sent along is ignored (same read-key identity)', (await rk('/tab-b/echo', RK, 'GET', { Cookie: owner.cookie })).data?.identity?.credential === 'read_key')
check('L1 POST on its own path = 403', (await rk('/tab-b/echo', RK, 'POST', { Origin: BASE, 'X-Portal': '1', 'Content-Type': 'application/json' })).data?.error === 'read_key_scope')
check('L1 command from the page path = 403', (await rk('/tab-b/_cmd/jot', RK, 'POST', { Origin: BASE, 'X-Portal': '1' })).data?.error === 'read_key_scope')
check('L1 shortcut command path = 403', (await rk('/_cmd/tab-b/jot', RK, 'POST')).data?.error === 'read_key_scope')
check('L1 tab Face ID path = 403', (await rk('/tab-b/_passkey/options', RK, 'POST', { Origin: BASE, 'X-Portal': '1' })).data?.error === 'read_key_scope')
check('L1 other path of the tab = 403', (await rk('/tab-b/', RK)).data?.error === 'read_key_scope' && (await rk('/tab-b/echo/x', RK)).status === 403)
check('L1 another tab = 403', (await rk('/tab-a/echo', RK)).data?.error === 'read_key_scope')
check('L1 portal API, account, see-as = 403', (await rk('/api/me', RK)).status === 403 && (await rk('/conta/', RK)).status === 403 &&
  (await rk('/api/tabs', RK, 'POST', { Origin: BASE, 'X-Portal': '1' })).status === 403 && (await rk('/api/me/readkeys', RK)).status === 403)
check('L1 socket = 403', (await upgradeStatus('/tab-b/echo', KEYH(RK))) === 403)
check('L1 wrong or changed key = 401', (await rk('/tab-b/echo', 'pa5_ler_' + 'A'.repeat(43))).status === 401 &&
  (await rk('/tab-b/echo', RK.slice(0, -1) + (RK.endsWith('A') ? 'B' : 'A'))).status === 401 && (await rk('/tab-b/echo', 'pa5_ler_short')).status === 401)
check('L1 a shortcut key is no read key', (await rk('/tab-b/echo', k1.data.key)).status === 401)
const ra = await rk('/tab-b/audit', RK)
check('L1 second path of the policy = 200', ra.status === 200)
rows = (await owner.req('GET', '/api/admin/audit')).data
check('L1 every use audited with the key id (portal row + X-Tab-Audit)', rows.filter((r) => r.action === 'read_key_used' && JSON.parse(r.detail).read_key === r1k.data.id).length >= 3 &&
  rows.some((r) => r.action === 'tab-b.turn_on' && r.strength === 'read_key' && JSON.parse(r.detail).read_key === r1k.data.id), rows.slice(0, 6))
check('L1 refusals audited, never the key', rows.some((r) => r.action === 'read_key_refused' && JSON.parse(r.detail).reason === 'out_of_scope') && !rows.some((r) => String(r.detail).includes('pa5_ler_')))
check('read key: first use from a new place warns the admins', (await owner.req('GET', '/api/me')).data.alerts.some((x) => x.kind === 'read_key_place'))
let rl
for (let i = 0; i < 8; i++) rl = await rk('/tab-b/echo', RK)
check('L1 hourly limit of the tab policy = 429', rl.status === 429, rl.status)
const rkl = (await owner.req('GET', '/api/me/readkeys')).data
check('read key list: no key, no hash; tab-b available, tab-a not', !JSON.stringify(rkl).includes(RK) && !('key_hash' in rkl.keys[0]) &&
  rkl.available.map((a) => a.tab).join() === 'tab-b' && rkl.keys.find((k) => k.id === r1k.data.id).today >= 5, rkl)
// L2 (no end date): warn past 30 uses in a day and at a second IP in the same day
const r2k = await owner.req('POST', '/api/me/readkeys', { label: 'daily', tab: 'tab-b' })
const IP1 = { 'CF-Connecting-IP': '198.51.100.7' }
check('L2 first use today = 200', (await rk('/tab-b/echo', r2k.data.key, 'GET', IP1)).status === 200)
const dayAlerts = async (kind) => (await owner.req('GET', '/api/me')).data.alerts.filter((x) => x.kind === kind && x.label === 'daily').length
check('L2 one IP: no IP warning', (await dayAlerts('read_key_ip')) === 0)
await rk('/tab-b/echo', r2k.data.key, 'GET', { 'CF-Connecting-IP': '198.51.100.8' })
check('L2 second IP the same day warns the admins', (await dayAlerts('read_key_ip')) === 1)
await rk('/tab-b/echo', r2k.data.key, 'GET', IP1)
check('L2 back to a known IP: no new warning', (await dayAlerts('read_key_ip')) === 1)
d1(`UPDATE read_keys SET use_day_n = 30 WHERE id = ${r2k.data.id}`)
check('L2 30 uses: no day warning yet', (await dayAlerts('read_key_day')) === 0)
await rk('/tab-b/echo', r2k.data.key, 'GET', IP1)
check('L2 31st use in the day warns the admins', (await dayAlerts('read_key_day')) === 1)
await rk('/tab-b/echo', r2k.data.key, 'GET', IP1)
check('L2 32nd: no second day warning', (await dayAlerts('read_key_day')) === 1)
d1(`UPDATE read_keys SET use_day = '2000-01-01' WHERE id = ${r2k.data.id}`)
await rk('/tab-b/echo', r2k.data.key, 'GET', { 'CF-Connecting-IP': '198.51.100.9' })
check('L2 a new day starts the counters again (one IP, no warning)', (await dayAlerts('read_key_ip')) === 1 &&
  (await owner.req('GET', '/api/me/readkeys')).data.keys.find((k) => k.id === r2k.data.id).today === 1)
check('another admin cannot revoke the owner read key', (await admin3.req('DELETE', `/api/me/readkeys/${r2k.data.id}`)).status === 404)
check('owner revokes a read key without Face ID', (await owner.req('DELETE', `/api/me/readkeys/${r2k.data.id}`)).status === 200 &&
  (await rk('/tab-b/echo', r2k.data.key)).status === 401)
// P2: refusals of a valid key are audited at most 30 an hour per key
const r4k = await owner.req('POST', '/api/me/readkeys', { label: 'noisy', tab: 'tab-b' })
for (let i = 0; i < 35; i++) await rk('/tab-a/echo', r4k.data.key)
check('P2 still 403 past the audit cap', (await rk('/tab-a/echo', r4k.data.key)).status === 403)
check('P2 refusals of one key: at most 30 audit rows an hour', d1Count(`SELECT COUNT(*) AS n FROM audit WHERE action = 'read_key_refused' AND detail LIKE '%"read_key":${r4k.data.id}%'`) === 30)
check('owner revokes the noisy key', (await owner.req('DELETE', `/api/me/readkeys/${r4k.data.id}`)).status === 200)
// an admin seeing as a resident cannot list or make read keys
check('see as: admin3 goes in', (await admin3.req('POST', '/api/tabs', { view_as: 'residents' })).status === 200)
check('see as: POST /api/me/readkeys = 403, list = 403', (await admin3.req('POST', '/api/me/readkeys', { label: 'x', tab: 'tab-b' })).status === 403 &&
  (await admin3.req('GET', '/api/me/readkeys')).status === 403)
const r3k = await owner.req('POST', '/api/me/readkeys', { label: 'moved', tab: 'tab-b' })
d1(`UPDATE read_keys SET person_id = ${res.id} WHERE id = ${r3k.data.id}`)
check('L1 key of someone outside the owner group = 401', (await rk('/tab-b/echo', r3k.data.key)).status === 401)
check('owner revokes the first read key; it stops at once', (await owner.req('DELETE', `/api/me/readkeys/${r1k.data.id}`)).status === 200 &&
  (await rk('/tab-b/echo', RK)).status === 401)

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
