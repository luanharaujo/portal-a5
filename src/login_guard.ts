// The robot filter of the public sign-in routes: the Turnstile check, the progressive delay and
// the sign-in event. Nothing here refuses by phone number: past a threshold a request only waits.

// Workers `ratelimits` binding (wrangler.toml): cheap, per Cloudflare location, approximate.
export interface RateLimiter { limit(options: { key: string }): Promise<{ success: boolean }> }

export interface TurnstileEnv {
  TURNSTILE_SECRET?: string
  TURNSTILE_SITEKEY?: string
  // tests only: a stand-in siteverify, accepted just for http://127.0.0.1 or http://localhost
  TURNSTILE_VERIFY_URL?: string
}

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const VERIFY_TIMEOUT_MS = 8_000
const TOKEN_MAX = 2048

export type ChallengeFailure = 'not_configured' | 'no_token' | 'refused' | 'wrong_hostname' | 'wrong_action' | 'unreachable'

// null = passed. A token works once: Cloudflare refuses the second use.
export async function verifyTurnstile(env: TurnstileEnv, o: { token: unknown; hostname: string; action: string; ip: string }): Promise<ChallengeFailure | null> {
  const secret = env.TURNSTILE_SECRET ?? ''
  if (!secret) return 'not_configured'
  const token = typeof o.token === 'string' ? o.token : ''
  if (!token || token.length > TOKEN_MAX) return 'no_token'
  const local = env.TURNSTILE_VERIFY_URL ?? ''
  // the stand-in counts only as plain http to this machine's own host, with a port
  const url = /^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}(\/[\w-]*)*$/.test(local) ? local : SITEVERIFY
  let r: { success?: unknown; hostname?: unknown; action?: unknown }
  try {
    const res = await fetch(url, {
      method: 'POST',
      body: new URLSearchParams({ secret, response: token, remoteip: o.ip }),
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    })
    if (!res.ok) return 'unreachable'
    r = await res.json()
  } catch {
    return 'unreachable'
  }
  if (r?.success !== true) return 'refused'
  if (r.hostname !== o.hostname) return 'wrong_hostname'
  if (r.action !== o.action) return 'wrong_action'
  return null
}

const DELAY_STEP_MS = 500
const DELAY_MAX_MS = 4_000

// `over` = how far past the free threshold: half a second more each time, at most four
export function slowDown(over: number): Promise<void> {
  const ms = Math.min(Math.max(over, 0) * DELAY_STEP_MS, DELAY_MAX_MS)
  return ms ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve()
}

export type Risk = 'low' | 'medium' | 'high'
export type Result = 'ok' | 'fail' | 'limited' | 'turnstile_failed'

// One structured line per sign-in attempt. Only fixed words: never a number, address, user
// agent, code or anything derived from them.
export function attemptLog(event: 'login_attempt', auth_method: 'whatsapp_code' | 'passkey') {
  return (result: Result, risk: Risk, reason: string) => console.log(JSON.stringify({ event, auth_method, result, risk, reason }))
}
