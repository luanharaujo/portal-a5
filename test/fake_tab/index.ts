// LOCAL TESTS ONLY. Echoes what the portal hands a tab, and misbehaves on purpose
// (inline script, loose headers, cookies) so the tests can check what the router removes.
import { WorkerEntrypoint } from 'cloudflare:workers'

interface Identity { credential: string; [k: string]: unknown }

export class FakeTab extends WorkerEntrypoint {
  async handle(req: Request, identity: Identity): Promise<Response> {
    const url = new URL(req.url)
    const headers = Object.fromEntries(req.headers)
    const p = url.pathname.replace(/^\/[a-z][a-z0-9-]*/, '')
    if (p === '/html') {
      return new Response('<!doctype html><title>x</title><script>alert(1)</script>', {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "script-src 'unsafe-inline' *",
          'Permissions-Policy': 'microphone=*, camera=*',
          'Set-Cookie': '__Host-a5s=stolen; Path=/; Secure',
          'Clear-Site-Data': '"cookies"',
          'Service-Worker-Allowed': '/',
          'Access-Control-Allow-Origin': 'https://evil.example',
          'Access-Control-Allow-Credentials': 'true',
        },
      })
    }
    if (p === '/audit') {
      return Response.json({ ok: true }, { headers: { 'X-Tab-Audit': JSON.stringify({ action: 'turn_on', target: 'ac:living', detail: { by: 'test' } }) } })
    }
    if (p === '/badaudit') {
      return Response.json({ ok: true }, { headers: { 'X-Tab-Audit': JSON.stringify({ action: 'DROP TABLE', person: 1 }) } })
    }
    if (p === '/revoked') return Response.json(revoked)
    if (p === '/badges') return Response.json(badgeCalls)
    if (p === '/commands') return Response.json(commandLog)
    if (p === '/page-own') {
      // a tab page with its own pull to refresh: the shared one must stay off
      return new Response('<!doctype html><html lang="pt-BR" data-a5-pull="own"><head><meta charset="utf-8"><title>tab</title>' +
        '<link rel="stylesheet" href="/_shell/tabs.css"><script src="/locale/pt-BR.js" defer></script><script src="/_shell/tabs.js" defer></script>' +
        '</head><body><h1><button type="button" data-a5-tabs>Panel</button></h1><input id="field"><div id="sheet" data-a5-sheet hidden></div></body></html>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    }
    if (p === '/fake.css') {
      // a dark tab like the real ones, so the screenshots look like them
      return new Response('body{margin:0;padding:calc(env(safe-area-inset-top) + 16px + var(--a5-bar, 0px)) 20px 20px;background:#0d1117;color:#eef2f6;font:16px/1.4 sans-serif}' +
        'h1{margin:0 0 16px;font-size:28px}.card{height:140px;margin:0 0 14px;border-radius:18px;background:#161d27;border:1px solid #2a3542}',
        { headers: { 'Content-Type': 'text/css; charset=utf-8' } })
    }
    if (p === '/long') {
      // a long tab page: the list must open where the title is, without scrolling the page
      return new Response('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>tab</title>' +
        '<link rel="stylesheet" href="/_shell/tabs.css"><link rel="stylesheet" href="fake.css"><script src="/locale/pt-BR.js" defer></script><script src="/_shell/tabs.js" defer></script>' +
        '</head><body><h1><button type="button" data-a5-tabs>Panel</button></h1>' + '<div class="card"></div>'.repeat(14) + '</body></html>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    }
    if (p === '/page') {
      // a tab page using the shared selector, for the browser test
      return new Response('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>tab</title>' +
        '<link rel="stylesheet" href="/_shell/tabs.css"><link rel="stylesheet" href="fake.css"><script src="/locale/pt-BR.js" defer></script><script src="/_shell/tabs.js" defer></script>' +
        '</head><body><h1><button type="button" data-a5-tabs>Panel</button></h1><p id="probe"></p><input id="field"><div id="sheet" data-a5-sheet hidden></div></body></html>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    }
    if (p === '/stream') {
      const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('data: one\n\n')); c.close() } })
      return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } })
    }
    const body = req.method === 'GET' ? null : await req.text()
    return Response.json({ path: url.pathname, method: req.method, headers, identity, body })
  }

  // Long-lived connections (bridges, live pages): identity arrives in X-A5-Identity.
  async fetch(req: Request): Promise<Response> {
    if (req.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return new Response('not found', { status: 404 })
    let identity: Identity
    try {
      const raw = req.headers.get('X-A5-Identity') ?? ''
      const bin = atob(raw.replace(/-/g, '+').replace(/_/g, '/'))
      identity = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))))
    } catch {
      return new Response('unauthorized', { status: 401 })
    }
    const pair = new WebSocketPair()
    const [client, server] = Object.values(pair)
    server.accept()
    const headers = Object.fromEntries(req.headers)
    server.send(JSON.stringify({ path: new URL(req.url).pathname, identity, headers }))
    server.addEventListener('message', (ev) => server.send(String(ev.data)))
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'X-Tab-Audit': JSON.stringify({ action: 'socket_opened', target: new URL(req.url).pathname }) },
    })
  }

  // The portal calls this when a session, screen or machine key is revoked.
  async revoke(ref: { session?: number; machine?: number }): Promise<void> {
    revoked.push(ref)
  }
  async revokedLog(): Promise<unknown[]> { return revoked }

  // The selector's count: 3 for everyone, and a log of who asked.
  async badge(identity: Identity): Promise<{ count: number }> {
    badgeCalls.push(identity)
    return { count: 3 }
  }

  // One checked command (docs/COMMANDS.md). Logs what arrived; 'slow' answers after the portal
  // stopped waiting, 'boom' throws. The result carries fields the portal must not pass on.
  async command(cmd: { id: string; action: string; params: unknown; expires_at: string }, identity: Identity): Promise<unknown> {
    commandLog.push({ cmd, identity })
    if (cmd.action === 'slow') await new Promise((r) => setTimeout(r, 10000))
    if (cmd.action === 'boom') throw new Error('boom')
    return { status: 'done', result: { state: 'on', secret: 'leak', nested: { a: 1 } } }
  }
}
const revoked: unknown[] = []
const badgeCalls: unknown[] = []
const commandLog: unknown[] = []

// A tab whose badge never answers in time, and one that answers garbage: neither may slow
// down or break the selector.
export class SlowTab extends FakeTab {
  async badge(identity: Identity): Promise<{ count: number }> {
    await new Promise((r) => setTimeout(r, 2000))
    return super.badge(identity)
  }
}
export class OddTab extends FakeTab {
  async badge(): Promise<{ count: number }> {
    return { count: -4.5 }
  }
}

export default {
  async fetch(): Promise<Response> {
    return new Response('not found', { status: 404 })
  },
} satisfies ExportedHandler
