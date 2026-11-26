// Unit checks for src/login_guard.ts. No server needed:
//   node scripts/test_login_guard.mjs
import { attemptLog, verifyTurnstile } from '../src/login_guard.ts'

let failures = 0
function check(name, cond, extra) {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${!cond && extra !== undefined ? ' -> ' + JSON.stringify(extra) : ''}`)
  if (!cond) failures++
}

let asked = null
let answer = { success: true, hostname: 'portal.example', action: 'login' }
globalThis.fetch = async (url, init) => { asked = { url: String(url), body: String(init.body) }; return new Response(JSON.stringify(answer)) }
const REAL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const go = (env, o = {}) => verifyTurnstile({ TURNSTILE_SECRET: 's', ...env }, { token: 't', hostname: 'portal.example', action: 'login', ip: '203.0.113.1', ...o })

check('a good answer passes', (await go({})) === null)
check('asks Cloudflare with secret, token and address', asked.url === REAL && asked.body === 'secret=s&response=t&remoteip=203.0.113.1', asked)
for (const url of ['https://evil.example/siteverify', 'http://evil.example/siteverify', 'http://127.0.0.1.evil.example:80/x', 'http://localhost:1' + '@evil.example/x',
  'https://127.0.0.1:1/siteverify', 'http://127.0.0.1/siteverify', 'http://localhost:80/a?u=http://evil.example']) {
  await go({ TURNSTILE_VERIFY_URL: url })
  check(`test override ignored: ${url}`, asked.url === REAL, asked.url)
}
for (const url of ['http://127.0.0.1:8000/siteverify', 'http://localhost:9/siteverify']) {
  await go({ TURNSTILE_VERIFY_URL: url })
  check(`test override used on this machine: ${url}`, asked.url === url, asked.url)
}
asked = null
check('no secret = not configured, nothing asked', (await go({ TURNSTILE_SECRET: '' })) === 'not_configured' && !asked)
check('no token = refused before asking', (await go({}, { token: '' })) === 'no_token' && (await go({}, { token: 5 })) === 'no_token' && (await go({}, { token: 'x'.repeat(2049) })) === 'no_token' && !asked)
answer = { success: false }
check('refused token', (await go({})) === 'refused')
answer = { success: 'true', hostname: 'portal.example', action: 'login' }
check('success must be the boolean', (await go({})) === 'refused')
answer = { success: true, hostname: 'evil.example', action: 'login' }
check('another hostname', (await go({})) === 'wrong_hostname')
answer = { success: true, hostname: 'portal.example', action: 'pair' }
check('another action', (await go({})) === 'wrong_action')
globalThis.fetch = async () => { throw new Error('down') }
check('siteverify down = refused', (await go({})) === 'unreachable')
globalThis.fetch = async () => new Response('x', { status: 500 })
check('siteverify error = refused', (await go({})) === 'unreachable')

const lines = []
const log = console.log
console.log = (s) => lines.push(s)
attemptLog('login_attempt', 'whatsapp_code')('ok', 'low', 'code_issued')
console.log = log
check('event: fixed fields only', lines.length === 1 && lines[0] === '{"event":"login_attempt","auth_method":"whatsapp_code","result":"ok","risk":"low","reason":"code_issued"}', lines)

process.exit(failures ? 1 : 0)
