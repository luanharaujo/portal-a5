// Drives the whole sign-in flow against a local `wrangler dev`, including a fake WhatsApp
// reader (POST /robo/login) and a software passkey. Run through scripts/test_local.sh.
import { webcrypto as wc } from 'node:crypto'

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
  fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-A5-Robo-Chave': key }, body: JSON.stringify(body) })
    .then(async (r) => ({ status: r.status, data: await r.json().catch(() => null) }))

async function signIn(c, typed, sender, self = false) {
  const s = await c.req('POST', '/api/login/start', { phone: typed })
  const code = /A5-[A-Z0-9]{4}/.exec(s.data.message)[0]
  const r = await robot({ codigo: code, numero: sender, msg_id: 'test-' + Math.random(), eu_mesmo: self })
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
check('robot wrong key = 401', (await robot({ codigo: code0, numero: OWNER }, 'pa5_robo_wrong')).status === 401)
check('robot key on other /robo route = 404', (await robot({}, ROBO_KEY, '/robo/caixa')).status === 404)
check('robot key on /api = 401/403', [401, 403].includes((await fetch(BASE + '/api/me', { headers: { 'X-A5-Robo-Chave': ROBO_KEY } })).status))
check('eu_mesmo with other number = 400', (await robot({ codigo: code0, numero: RESIDENT, eu_mesmo: true })).status === 400)

// owner signs in (self chat)
const owner = client()
const o = await signIn(owner, OWNER, OWNER, true)
check('owner robot ok', o.robot.data?.ok === true, o.robot.data)
check('robot reply names the device', typeof o.robot.data?.aparelho === 'string')
check('owner status ok + cookie', o.status.data.status === 'ok' && /__Host-a5s=.{40,}; Path=\/; HttpOnly; Secure; SameSite=Lax/.test(o.status.setCookie || ''), o.status.setCookie)
check('code is single use', (await owner.req('POST', '/api/login/status', { secret: o.start.data.secret })).data.status === 'used')
let me = (await owner.req('GET', '/api/me')).data
check('owner is admin, weak', me.admin === true && me.strong === false, me)
check('new-device alert shown', me.alerts?.length === 1, me.alerts)

// a second owner login inside 10 minutes is refused by the worker
const o2 = await signIn(client(), OWNER, OWNER, true)
check('owner 1 per 10 min', o2.robot.data?.motivo === 'limite_admin', o2.robot.data)

// weak session: reads yes, writes no
check('weak admin read ok', (await owner.req('GET', '/api/admin/people')).status === 200)
const w = await owner.req('POST', '/api/admin/people', { name: 'Morador', phone: RESIDENT, groups: ['residents'] })
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
check('mismatch -> pending', mm.robot.data?.motivo === 'aguardando_dono' && mm.status.data.status === 'pending', [mm.robot.data, mm.status.data])
check('pending tab has no cookie', !victimTab.cookie)
const reqs = (await owner.req('GET', '/api/admin/requests')).data
const pend = reqs.find((x) => x.sender_phone === STRANGER)
check('request listed with sender number', !!pend && pend.typed_phone === RESIDENT, reqs)
const ap = await owner.req('POST', `/api/admin/requests/${pend.id}/approve`, { name: 'Visita', groups: ['residents'] })
check('approve ok', ap.status === 200 && ap.data.code_valid === true, ap.data)
const after = await victimTab.req('POST', '/api/login/status', { secret: mm.start.data.secret })
check('approved tab signs in as the SENDER', after.data.status === 'ok' && after.data.name === 'Visita', after.data)

// sender rate limit: 3 per hour
const spam = client()
let last
for (let i = 0; i < 4; i++) last = await signIn(spam, '5561900000009', '5561900000009')
check('robot 3/h per sender', last.robot.data?.motivo === 'limite_remetente', last.robot.data)

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
check('unknown tab = 404', (await owner.req('GET', '/energia/')).status === 404)

// audit has the trail
const auditRows = (await owner.req('GET', '/api/admin/audit')).data
const actions = new Set(auditRows.map((a) => a.action))
for (const a of ['login_admin', 'passkey_added', 'passkey_ok', 'person_added', 'request_approved', 'device_revoked', 'robot_pending'])
  check(`audit has ${a}`, actions.has(a))
check('audit marks strength', auditRows.some((a) => a.strength === 'strong') && auditRows.some((a) => a.strength === 'weak'))

// logout
check('logout clears cookie', /Max-Age=0/.test((await resident.req('POST', '/api/logout', {})).setCookie || ''))
check('after logout = 401', (await resident.req('GET', '/api/me')).status === 401)

console.log(failures ? `\n${failures} FAILED` : '\nall passed')
process.exit(failures ? 1 : 0)
