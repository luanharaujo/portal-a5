# portal-a5

A small home portal on Cloudflare Workers, free plan. People sign in by sending a code over WhatsApp, and the portal decides who they are, which device they are on and which tabs they can open. Each tab is its own private Worker; the portal is the only public address.

There is no password and no SMS. The sign-in is inverted: the page shows a ready-made message, the person sends it from their own WhatsApp, and a reader on a machine at home reports which number sent it. Identity is the number WhatsApp proves, never the number typed on the page.

## Pieces

- `src/index.ts`: the Worker. API under `/api/*`, the reader's endpoint at `/robo/login`, tab router for `/<tab>/*`.
- `src/webauthn.ts`: passkey checks (ES256 only).
- `public/`: the page, served by Workers Static Assets from the same origin as the API.
- `migrations/`: D1 schema.
- `scripts/test_local.sh`: end-to-end test against `wrangler dev` with a fake reader and a software passkey.
- `scripts/deploy.sh`: deploy with an API token from the macOS Keychain.

## Sign-in flow

1. The page posts the typed number to `POST /api/login/start` and gets a one-time code (`A5-XXXX`, 10 minutes), a tab secret and a `wa.me` link with the exact phrase `Entrar no Portal A5: A5-XXXX`. Known and unknown numbers get the same answer.
2. The person sends the phrase. The reader matches the whole text and calls `POST /robo/login`.
3. The page polls `POST /api/login/status` with its secret. On `ok` the code is burned and the session cookie is set.

If the sender is not the number that was typed, or is unknown, nobody signs in: the code turns into a pending request and the owner approves or refuses it. Approving signs the waiting tab in as the sender.

Only SHA-256 hashes of codes, tab secrets and session tokens are stored.

### Reader contract

```
POST /robo/login
X-A5-Robo-Chave: <ROBO_LOGIN_CHAVE>
Content-Type: application/json

{"codigo": "A5-XXXX", "numero": "<digits, country code first>", "msg_id": "<message id>", "eu_mesmo": false}
```

`eu_mesmo: true` means the owner's own "message yourself" chat and is accepted only with the owner's number. Answers are always 200 with `{"ok": true}` or `{"ok": false, "motivo": ...}`; `motivo` is one of `codigo_invalido`, `aguardando_dono`, `bloqueado`, `limite_remetente`, `limite_total`, `limite_admin`, `pendentes_demais`. Successful answers carry `aparelho` (device that asked for the code) and `pedido_em`. Bad key: 401. The key opens this route and nothing else.

Limits in the Worker, on top of whatever the reader does: 3 accepted calls per sender per hour, 30 per hour in total, one sign-in every 10 minutes for admin numbers.

## Sessions: weak and strong

A WhatsApp sign-in gives a weak session: it can read everything its groups allow and disconnect its own devices. Admin writes (people, groups, pending requests, other people's devices) need a passkey check from the last 5 minutes on that session. The first passkey of an admin can be added from a weak session; any later one needs a fresh check.

If the owner loses every passkey, delete the rows from `passkeys` in D1 with wrangler and register again.

Session cookie: `__Host-a5s`, `HttpOnly; Secure; SameSite=Lax`, 180 days, renewed on use. Lax and not Strict so a link opened from WhatsApp arrives signed in. Every non-GET request must carry `Origin` equal to the portal origin and `X-Portal: 1`; GET never changes state.

Every new device of an admin shows a banner on all their devices until it is confirmed with a passkey.

## Groups and tabs

Two groups to start: `owner` (every tab, admin) and `residents` (the `energia` tab). The owner's number lives in the `OWNER_PHONE` secret and joins `owner` on first sign-in.

A tab is a Worker with `workers_dev = false`, `preview_urls = false` and no route. It exports a `WorkerEntrypoint` with `handle(request, identity)` and answers 404 on its default `fetch`. The portal checks the group, strips `Cookie`, `Authorization` and any `X-Portal-*`/`X-A5-*` header, calls `handle` over RPC, then removes `Set-Cookie` from the answer and puts its own CSP on it, since the tab shares the portal's origin. Register a tab with a `[[services]]` binding and an entry in the `TABS` var.

## Running locally

```
npm install
npm test          # migrations on a throwaway D1, wrangler dev on 127.0.0.1:8941, full flow, index check
```

Every query on a hot path must use an index; the test runs `EXPLAIN QUERY PLAN` on them and fails on a full scan. The free D1 plan caps rows read per day, so a scan on a busy table takes the site down until midnight UTC.

## Deploying

`npm run deploy` reads the token, the account id, the reader key and the owner's number from the Keychain, checks that the token sees only the portal account, creates the D1 database on first run, applies migrations, deploys and sets the secrets through stdin. Account and database ids go into a git-ignored config, never into this repository.

## License

MIT
