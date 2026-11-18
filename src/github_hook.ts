// Relay for the GitHub webhook: the POST (one isolate) and the Mac's outbound WebSocket (another)
// meet in this Durable Object. It keeps nothing: no body, no repository name, no queue. With no
// socket connected a notice is dropped (the Mac has its own daily safety net).
import { DurableObject } from 'cloudflare:workers'

const NOTICE = '{"t":"actions"}'
const ALERT = '{"t":"alerta"}'

export class GithubHook extends DurableObject {
  constructor(ctx: DurableObjectState, env: never) {
    super(ctx, env)
    // answered without waking the object
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'))
  }

  async fetch(req: Request): Promise<Response> {
    if (req.headers.get('Upgrade') === 'websocket') {
      // one listener: a new connection replaces the old one
      for (const old of this.ctx.getWebSockets()) { try { old.close(1000, 'replaced') } catch { /* already gone */ } }
      const pair = new WebSocketPair()
      this.ctx.acceptWebSocket(pair[1])
      return new Response(null, { status: 101, webSocket: pair[0] })
    }
    if (req.method === 'POST') {
      const msg = new URL(req.url).pathname === '/alert' ? ALERT : NOTICE
      for (const ws of this.ctx.getWebSockets()) { try { ws.send(msg) } catch { /* dropped */ } }
      return new Response(null, { status: 204 })
    }
    return new Response(null, { status: 405 })
  }

  webSocketMessage(): void { /* the Mac only listens */ }
  webSocketClose(ws: WebSocket): void { try { ws.close() } catch { /* already closed */ } }
}
