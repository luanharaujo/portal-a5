// Portal A5 page. No framework, no innerHTML: every value from the server goes in as text.
// Look: /visual.css ("the house"): a cover with the house drawing for sign-in, pairing and
// Face ID, and the account as an index with one part per page (side by side on wide screens).
'use strict'

const $toast = document.getElementById('toast')
const ACCOUNT = '/conta/'
const onAccount = () => location.pathname === ACCOUNT
const MODE = (window.matchMedia('(display-mode: standalone)').matches || navigator.standalone) ? 'app' : 'browser'
const WIDE = window.matchMedia('(orientation: landscape) and (min-width: 900px)')
let ME = null

// ------------------------------------------------------------------ helpers
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v)
    else if (k === 'class') e.className = v
    else e.setAttribute(k, v === true ? '' : String(v))
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)))
  return e
}

// Line icons (24 x 24, stroke only). Each one is a list of [tag, attributes].
const ICONS = {
  chat: [['path', { d: 'M20.5 11.6a8.4 8.4 0 0 1-12.3 7.5L3.5 20.5l1.4-4.5A8.4 8.4 0 1 1 20.5 11.6z' }], ['path', { d: 'M8.5 11.5h.01M12 11.5h.01M15.5 11.5h.01', 'stroke-width': '2.6' }]],
  screen: [['rect', { x: '2.5', y: '4.5', width: '19', height: '13', rx: '2' }], ['path', { d: 'M8 21h8M12 17.5V21' }]],
  phone: [['rect', { x: '7', y: '2.5', width: '10', height: '19', rx: '2.5' }], ['path', { d: 'M11 18.5h2' }]],
  chev: [['path', { d: 'm9 6 6 6-6 6' }]],
  back: [['path', { d: 'm15 6-6 6 6 6' }]],
  faceid: [['path', { d: 'M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2' }], ['path', { d: 'M9 9.5v1M15 9.5v1M12 9.5v3.5h-1M9.5 15.5c1.5 1.2 3.5 1.2 5 0' }]],
  hourglass: [['path', { d: 'M6.5 3h11M6.5 21h11M7.5 3v3.5a4.5 4.5 0 0 0 9 0V3M7.5 21v-3.5a4.5 4.5 0 0 1 9 0V21' }]],
  inbox: [['path', { d: 'M3 13h5l1.5 2.5h5L16 13h5' }], ['path', { d: 'M5.5 5h13l2.5 8v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-5z' }]],
  people: [['circle', { cx: '9', cy: '8', r: '3.5' }], ['path', { d: 'M2.5 20c.8-3.4 3.4-5.5 6.5-5.5s5.7 2.1 6.5 5.5' }], ['path', { d: 'M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.8c1.8.7 3 2.5 3.5 5.2' }]],
  layers: [['path', { d: 'm12 3 9 5-9 5-9-5z' }], ['path', { d: 'm3 13 9 5 9-5' }]],
  key: [['circle', { cx: '7.5', cy: '15.5', r: '4' }], ['path', { d: 'm10.5 12.5 9-9M17 6l3 3M14.5 8.5l2 2' }]],
  devices: [['rect', { x: '2.5', y: '5', width: '13', height: '10', rx: '1.5' }], ['path', { d: 'M1 18h16' }], ['rect', { x: '17.5', y: '9', width: '5', height: '10', rx: '1.2' }]],
  list: [['path', { d: 'M8 6h13M8 12h13M8 18h13' }], ['path', { d: 'M3.5 6h.01M3.5 12h.01M3.5 18h.01', 'stroke-width': '3' }]],
  logout: [['path', { d: 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3' }], ['path', { d: 'M10 17l-5-5 5-5M5 12h11' }]],
  check: [['path', { d: 'm5 12.5 4.5 4.5L19 7.5' }]],
  wifi: [['path', { d: 'M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0' }], ['circle', { cx: '12', cy: '19.5', r: '.8' }]],
  alert: [['path', { d: 'M12 3.5 2.5 20h19z' }], ['path', { d: 'M12 10v4.5M12 17.2h.01' }]],
  bolt: [['path', { d: 'M13 2.5 4.5 13.5H12l-1 8 8.5-11H12z' }]],
  power: [['path', { d: 'M12 3v8' }], ['path', { d: 'M6.6 6.6a7.5 7.5 0 1 0 10.8 0' }]],
  robot: [['rect', { x: '4', y: '7', width: '16', height: '12', rx: '3' }], ['path', { d: 'M12 3v4M9 12.5h.01M15 12.5h.01M9.5 16h5', 'stroke-width': '2.2' }]],
  plus: [['path', { d: 'M12 5v14M5 12h14' }]],
}
const SVGNS = 'http://www.w3.org/2000/svg'
function icon(name, cls) {
  const s = document.createElementNS(SVGNS, 'svg')
  s.setAttribute('class', cls || 'ico')
  s.setAttribute('viewBox', '0 0 24 24')
  s.setAttribute('aria-hidden', 'true')
  for (const [tag, attrs] of ICONS[name]) {
    const p = document.createElementNS(SVGNS, tag)
    for (const [k, v] of Object.entries(attrs)) p.setAttribute(k, v)
    s.append(p)
  }
  return s
}

// The house drawing: day in the light theme, night in the dark one; wide art when the screen lies down.
function houseArt(wide) {
  return el('picture', {},
    wide ? el('source', { media: '(orientation: landscape) and (prefers-color-scheme: dark)', srcset: '/art/house-night-wide.svg' }) : null,
    wide ? el('source', { media: '(orientation: landscape)', srcset: '/art/house-day-wide.svg' }) : null,
    el('source', { media: '(prefers-color-scheme: dark)', srcset: '/art/house-night-tall.svg' }),
    el('img', { src: '/art/house-day-tall.svg', alt: '' }))
}

// replaceChildren with nested lists and empty slots, like el()
const fill = (node, ...kids) => node.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false))

function setPage(cls, ...nodes) {
  document.body.className = cls
  document.body.replaceChildren(...nodes, $toast)
}

let toastTimer
function toast(msg) {
  $toast.textContent = msg
  $toast.hidden = false
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { $toast.hidden = true }, 4000)
}

const when = (iso) => iso ? new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : ''
// "hoje 17:51", "ontem 09:10", "05/11 17:51": for alerts and list lines
function shortWhen(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
  const diff = Math.round((day(new Date()) - day(d)) / 864e5)
  const t = hhmm(d)
  return diff === 0 ? `${T.today} ${t}` : diff === 1 ? `${T.yesterday} ${t}` : `${d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${t}`
}
const city = (place) => place ? String(place).split(',')[0].trim() : ''
const hhmm = (d) => d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
const fmtPhone = (d) => d ? '+' + d : ''
const groupName = (g) => (T.groupNames && T.groupNames[g.id || g]) || g.name || g
const initial = (name) => (String(name || '?').trim()[0] || '?').toUpperCase()

class ApiError extends Error { constructor(status, data) { super(T.errors[data.error] || data.error || T.genericError); this.status = status; this.data = data } }

async function rawApi(method, path, body) {
  const opts = { method, headers: { 'X-Portal': '1' }, credentials: 'same-origin' }
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body) }
  const r = await fetch(path, opts)
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new ApiError(r.status, data)
  return data
}

// Admin writes may answer "confirm with Face ID": do the passkey check and retry once.
async function api(method, path, body) {
  try {
    return await rawApi(method, path, body)
  } catch (e) {
    if (e instanceof ApiError && e.data.passkey) {
      await passkeyCheck()
      return await rawApi(method, path, body)
    }
    throw e
  }
}

async function guarded(fn) {
  try { await fn() } catch (e) {
    if (e instanceof ApiError && e.status === 401) return start()
    toast(e.name === 'NotAllowedError' ? T.cancelled : e.message || T.genericError)
  }
}

// ------------------------------------------------------------------ passkeys
const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer
const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

async function passkeyCreate() {
  const o = await rawApi('POST', '/api/passkey/create/options', {})
  const cred = await navigator.credentials.create({
    publicKey: {
      ...o,
      challenge: b64uToBuf(o.challenge),
      user: { ...o.user, id: b64uToBuf(o.user.id) },
      excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    },
  })
  const r = cred.response
  await rawApi('POST', '/api/passkey/create/verify', {
    id: cred.id,
    clientDataJSON: bufToB64u(r.clientDataJSON),
    authenticatorData: bufToB64u(r.getAuthenticatorData()),
    publicKey: bufToB64u(r.getPublicKey()),
    publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
  })
}

async function passkeyCheck(purpose) {
  const o = await rawApi('POST', '/api/passkey/get/options', purpose ? { purpose } : {})
  const cred = await navigator.credentials.get({
    publicKey: { ...o, challenge: b64uToBuf(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) })) },
  })
  const r = cred.response
  return rawApi('POST', '/api/passkey/get/verify', {
    id: cred.id,
    clientDataJSON: bufToB64u(r.clientDataJSON),
    authenticatorData: bufToB64u(r.authenticatorData),
    signature: bufToB64u(r.signature),
  })
}

// ------------------------------------------------------------------ small pieces
function btn(label, fn, cls, ico) {
  return el('button', { type: 'button', class: 'btn ' + (cls || ''), onclick: () => guarded(fn) }, ico ? icon(ico) : null, ico ? el('span', {}, label) : label)
}

// A red button that asks twice: the first tap only arms it for a few seconds.
function confirmButton(label, confirmLabel, fn) {
  let armed = null
  const b = el('button', { type: 'button', class: 'btn btn-sm btn-danger', onclick: () => {
    if (!armed) {
      b.textContent = confirmLabel
      armed = setTimeout(() => { armed = null; b.textContent = label }, 5000)
      return
    }
    clearTimeout(armed); armed = null; b.textContent = label
    guarded(fn)
  } }, label)
  return b
}

// On/off pills (groups of a person, tabs of a group). Read back with picked().
function toggles(options, selected) {
  return el('div', { class: 'toggles' }, options.map(([value, label]) => {
    const b = el('button', { type: 'button', 'data-v': value, 'aria-pressed': selected.includes(value) ? 'true' : 'false' }, label)
    b.addEventListener('click', () => b.setAttribute('aria-pressed', b.getAttribute('aria-pressed') === 'true' ? 'false' : 'true'))
    return b
  }))
}
const picked = (box) => [...box.querySelectorAll('[aria-pressed="true"]')].map((b) => b.dataset.v)

const status = (text, live) => el('div', { class: 'status' }, live ? el('span', { class: 'pulse' }) : null, el('span', { class: 'status-text' }, text))
function setStatus(box, text, live) { box.replaceWith(status(text, live)) }
const backLink = (label, fn) => el('button', { type: 'button', class: 'back', onclick: fn }, icon('back'), label)
const field = (label, input) => el('label', { class: 'field' }, el('span', { class: 'caps' }, label), input)
const textInput = (attrs) => el('input', { class: 'text-input', ...attrs })
const line = (lead, title, small, ...end) => el('div', { class: 'line' }, lead, el('span', { class: 'row-text' }, el('b', {}, title), small ? el('small', {}, small) : null), ...end)
const screenIcon = (name) => el('span', { class: 'screen-icon' }, icon(name || 'screen'))
const avatar = (name, id, extra) => el('div', { class: `avatar ${id ? 'c' + (2 + (Number(id) % 4)) : ''} ${extra || ''}` }, initial(name))
const keyOnce = (text, key) => el('div', { class: 'key-once' }, el('p', {}, text), el('span', { class: 'code' }, key),
  btn(T.bridges.copy, () => navigator.clipboard.writeText(key).then(() => toast(T.bridges.copied)), 'btn-sm'))

// ------------------------------------------------------------------ cover: sign-in, pairing, Face ID
function cover(kids, pair) {
  const sheet = el('main', { class: 'sheet' }, kids)
  setPage(pair ? 'cover pair' : 'cover',
    el('div', { class: 'scene' }, houseArt(true)),
    el('a', { class: 'brand', href: '/' }, el('img', { src: '/favicon.svg', alt: '' }), el('b', {}, T.title)),
    sheet)
  return sheet
}

function steps(now) {
  const names = [T.steps.number, T.steps.message, T.steps.approval].slice(0, Math.max(2, now))
  const out = el('div', { class: 'steps' })
  names.forEach((n, i) => {
    if (i) out.append(el('span', { class: 'dash' }))
    const k = i + 1
    out.append(el('span', { class: 'step ' + (k < now ? 'done' : k === now ? 'now' : '') }, el('span', { class: 'num' }, k < now ? '✓' : String(k)), n))
  })
  return out
}

function nextPath() {
  const n = new URLSearchParams(location.search).get('next') || ''
  return /^\/[a-z][a-z0-9-]*(\/|$)/.test(n) ? n : null
}

function loginView() {
  clearTimeout(pollTimer)
  const input = el('input', { type: 'tel', inputmode: 'tel', autocomplete: 'tel', placeholder: T.phonePlaceholder, required: true, id: 'phone' })
  cover([
    el('form', { onsubmit: (ev) => { ev.preventDefault(); guarded(() => askCode(input.value)) } },
      el('h1', {}, T.signInTitle),
      el('p', { class: 'sub' }, T.signInSub),
      el('label', { class: 'field' }, el('span', { class: 'caps' }, T.phoneLabel), el('div', { class: 'tel' }, el('span', { class: 'ddi' }, '+55'), input)),
      el('button', { type: 'submit', class: 'btn btn-wa btn-block' }, icon('chat'), el('span', {}, T.signIn)),
      el('p', { class: 'hint' }, T.signInHint)),
    el('button', { type: 'button', class: 'screen-link', onclick: () => guarded(pairScreenView) }, icon('screen'), el('span', {}, T.pair.isScreen), icon('chev', 'ico chev')),
  ])
  if (!window.matchMedia('(pointer: coarse)').matches) input.focus()
}

// the message as WhatsApp will show it, with the code in bold
function bubble(message, code) {
  const i = code ? message.lastIndexOf(code) : -1
  const text = i < 0 ? [message] : [message.slice(0, i), el('span', { class: 'code' }, code), message.slice(i + code.length)]
  return el('div', { class: 'bubble-wrap' }, el('div', { class: 'bubble' }, text, el('small', {}, hhmm(new Date()))))
}

let pollTimer
async function askCode(phone) {
  const r = await rawApi('POST', '/api/login/start', { phone, mode: MODE })
  const backToStart = () => { clearTimeout(pollTimer); loginView() }
  let st = status(T.status.waiting, true)
  cover([
    steps(2),
    el('h1', {}, T.sendTitle),
    el('p', { class: 'sub' }, T.sendHint),
    bubble(r.message, r.code),
    el('p', { class: 'bubble-note' }, T.bubbleNote),
    el('a', { class: 'btn btn-wa btn-block', href: r.wa_link, target: '_blank', rel: 'noopener' }, icon('chat'), el('span', {}, T.openWhatsApp)),
    st,
    backLink(T.back, backToStart),
  ])
  let pendingShown = false
  const pendingView = () => {
    pendingShown = true
    st = status(T.status.waitingApproval, true)
    cover([
      steps(3),
      el('h1', {}, T.pendingTitle),
      el('div', { class: 'notice' }, icon('hourglass'), el('div', {}, el('b', {}, T.pendingHead), T.status.pending)),
      st,
      backLink(T.back, backToStart),
    ])
  }
  const poll = async () => {
    let s
    try { s = await rawApi('POST', '/api/login/status', { secret: r.secret, mode: MODE }) } catch (e) { const n = status(e.message); st.replaceWith(n); st = n; return }
    if (s.status === 'ok') { const n = nextPath(); if (n) location.href = n; else start(); return }
    if (s.status === 'pending' && !pendingShown) pendingView()
    else if (s.status !== 'waiting' && s.status !== 'pending') { const n = status(T.status[s.status] || s.status); st.replaceWith(n); st = n }
    if (s.status === 'waiting' || s.status === 'pending') pollTimer = setTimeout(poll, 2000)
  }
  pollTimer = setTimeout(poll, 2000)
}

// ------------------------------------------------------------------ fixed screen pairing (screen side)
function drawQr(text) {
  const qr = qrcode(0, 'M')
  qr.addData(text)
  qr.make()
  const n = qr.getModuleCount()
  const scale = 6
  const quiet = 2
  const size = (n + quiet * 2) * scale
  const c = el('canvas', { width: size, height: size, role: 'img', 'aria-label': T.pair.qrLabel })
  const g = c.getContext('2d')
  g.fillStyle = '#fff'
  g.fillRect(0, 0, size, size)
  g.fillStyle = '#000'
  for (let r = 0; r < n; r++) for (let k = 0; k < n; k++) if (qr.isDark(r, k)) g.fillRect((k + quiet) * scale, (r + quiet) * scale, scale, scale)
  return el('div', { class: 'qr' }, c)
}

const howTo = () => T.pair.howTo.map((part, i) => i % 2 ? el('b', {}, part) : part)

async function pairScreenView() {
  clearTimeout(pollTimer)
  const r = await rawApi('POST', '/api/pair/start', {})
  const chars = r.code.replace(/[^A-Z0-9]/gi, '').split('')
  let st = status(T.pair.waiting, true)
  const voltar = el('button', { type: 'button', class: 'btn btn-ghost pair-back', onclick: () => { clearTimeout(pollTimer); loginView() } }, icon('back'), el('span', {}, T.back))
  cover([
    el('span', { class: 'caps' }, T.pair.kicker),
    el('h1', {}, T.pair.title),
    el('p', { class: 'sub' }, howTo()),
    el('div', { class: 'code-qr' }, el('div', { class: 'pair-code', 'aria-label': r.code }, chars.map((c) => el('span', {}, c))), drawQr(r.pair_url)),
    st,
    voltar,
  ], true)
  const say = (text, live) => { const n = status(text, live); st.replaceWith(n); st = n }
  const poll = async () => {
    let s
    // a screen is unattended: a network blip must not stop the polling for good
    try { s = await rawApi('POST', '/api/pair/status', { secret: r.secret }) } catch (e) {
      if (e instanceof ApiError && e.status === 404) return pairScreenView()
      say(T.offline)
      pollTimer = setTimeout(poll, 5000)
      return
    }
    if (s.status === 'ok') { location.replace(nextPath() || '/'); return }
    if (s.status === 'expired') return pairScreenView() // a fresh code, the screen stays unattended
    say(T.pair.status[s.status] || T.pair.waiting, s.status === 'waiting')
    if (s.status === 'waiting') pollTimer = setTimeout(poll, 3000)
  }
  pollTimer = setTimeout(poll, 3000)
}

// ------------------------------------------------------------------ pairing prepared by a house agent (screen side)
// The agent opened "/#screen_ticket=…" on this screen. The ticket works once, so it leaves the
// address bar at once; the screen then waits for the owner's Face ID.
async function screenTicketView(ticket) {
  clearTimeout(pollTimer)
  history.replaceState(null, '', '/')
  let r
  try { r = await rawApi('POST', '/api/pair/claim', { ticket }) } catch (e) {
    cover([el('span', { class: 'caps' }, T.pair.kicker), el('h1', {}, T.pair.title), el('p', { class: 'sub' }, e.message)], true)
    return
  }
  const next = /^\/[a-z][a-z0-9-]*(\/|$)/.test(r.next || '') ? r.next : '/'
  let st = status(T.agentReq.screenWaiting, true)
  cover([el('span', { class: 'caps' }, T.pair.kicker), el('h1', {}, r.name), el('p', { class: 'sub' }, T.agentReq.screenHowTo), st], true)
  const say = (text, live) => { const n = status(text, live); st.replaceWith(n); st = n }
  const poll = async () => {
    let s
    try { s = await rawApi('POST', '/api/pair/status', { secret: r.secret }) } catch (e) {
      if (e instanceof ApiError && e.status === 404) { say(T.agentReq.screenStatus.refused); return }
      say(T.offline)
      pollTimer = setTimeout(poll, 5000)
      return
    }
    if (s.status === 'ok') { location.replace(next); return }
    if (s.status === 'waiting') { say(T.agentReq.screenWaiting, true); pollTimer = setTimeout(poll, 3000); return }
    say(T.agentReq.screenStatus[s.status] || T.agentReq.screenStatus.refused)
  }
  pollTimer = setTimeout(poll, 3000)
}

// ------------------------------------------------------------------ Face ID before entering a tab (D9)
function stepUpView(tab) {
  const next = nextPath() || `/${tab}/`
  cover([
    el('div', { class: 'faceid-mark' }, icon('faceid')),
    el('h1', {}, T.stepUp.title(tab.charAt(0).toUpperCase() + tab.slice(1))),
    el('p', { class: 'sub' }, T.stepUp.why),
    el('button', { type: 'button', class: 'btn btn-primary btn-block', onclick: () => guarded(async () => {
      const r = await passkeyCheck(`entry:${tab}`)
      location.href = next.startsWith(`/${tab}/`) ? next : r.next
    }) }, icon('faceid'), el('span', {}, T.stepUp.confirm)),
    backLink(T.back, () => { if (history.length > 1) history.back(); else location.assign(ACCOUNT) }),
  ])
  // the tab's own name, when the list knows it
  if (window.A5Tabs) window.A5Tabs.load().then((d) => {
    const t = d && d.tabs.find((x) => x.id === tab)
    const h = document.querySelector('.sheet h1')
    if (t && t.label && h) h.textContent = T.stepUp.title(t.label)
  }).catch(() => {})
}

// ------------------------------------------------------------------ opening
// No home page: "/" opens the last tab used on this device, else the first tab, else the account.
async function openLastTab() {
  const data = window.A5Tabs ? await window.A5Tabs.load() : null
  if (!data) { location.replace(ACCOUNT); return }
  const last = window.A5Tabs.lastTab()
  const tab = last === data.account.id ? data.account : data.tabs.find((t) => t.id === last) || data.tabs[0] || data.account
  location.replace(tab.path)
}

// ------------------------------------------------------------------ the account tab: index + parts
// /conta/ is the index; /conta/#<part> opens one part. Phone: one or the other. Wide screen: both.
const D = {} // what the index and the parts show, loaded together
let $index, $pane, $title
let agentReqId = null // ?agent_request=<id> shows that request in the pane

const PARTS = {
  aparelhos: { ico: 'phone', color: 'off', title: () => T.myDevices, render: partMyDevices },
  faceid: { admin: true, ico: 'faceid', color: 'ok', title: () => T.faceId, render: partFaceId },
  pedidos: { admin: true, ico: 'inbox', color: 'sun', title: () => T.requests, render: partRequests },
  pessoas: { admin: true, ico: 'people', color: 'on', title: () => T.people, render: partPeople },
  grupos: { admin: true, ico: 'layers', color: 'gray', title: () => T.groups, render: partGroups },
  telas: { admin: true, ico: 'screen', color: 'off', title: () => T.pair.screens, render: partScreens },
  agentes: { admin: true, ico: 'robot', color: 'gray', title: () => T.agents.title, render: partAgents },
  pontes: { admin: true, ico: 'key', color: 'gray', title: () => T.bridges.title, render: partBridges },
  comandos: { admin: true, ico: 'power', color: 'gray', title: () => T.commands.title, render: partCommands },
  atalhos: { admin: true, ico: 'bolt', color: 'gray', title: () => T.shortcuts.title, render: partShortcuts },
  todos: { admin: true, ico: 'devices', color: 'gray', title: () => T.allDevices, render: partAllDevices },
  auditoria: { admin: true, ico: 'list', color: 'gray', title: () => T.audit, render: partAudit },
}
const YOU = ['aparelhos', 'faceid']
const HOUSE = ['pedidos', 'pessoas', 'grupos', 'telas', 'agentes', 'pontes', 'comandos', 'atalhos', 'todos', 'auditoria']
const allowed = (k) => PARTS[k] && (!PARTS[k].admin || ME.admin)

async function loadData() {
  const get = (p) => rawApi('GET', p)
  D.devices = await get('/api/me/devices')
  if (!ME.admin) return
  const [people, groups, requests, all, machines, shortcuts, agents, agentReqs] = await Promise.all([
    get('/api/admin/people'), get('/api/admin/groups'), get('/api/admin/requests'), get('/api/admin/devices'),
    get('/api/admin/machines'), get('/api/me/shortcuts'), get('/api/admin/agents'), get('/api/admin/agent-requests'),
  ])
  Object.assign(D, { people: people.filter((p) => p.kind !== 'screen'), screens: people.filter((p) => p.kind === 'screen'),
    groups, requests, all, machines, shortcuts, agents, agentReqs })
}

// reload what the server knows and draw again (after every change)
async function refresh() {
  ME = await rawApi('GET', '/api/me')
  await loadData()
  renderAccount()
}

function accountShell() {
  if (document.body.classList.contains('account') && $index) return
  $title = el('h1', { class: 'account-title' })
  $index = el('nav', { class: 'index', 'aria-label': T.account })
  $pane = el('main', { class: 'pane' })
  setPage('account', el('div', { class: 'side' }, el('div', { class: 'account-top' }, houseArt(false), $title), $index), $pane)
  // the title is the tab selector too (Conta + arrow), except on a fixed screen
  if (ME.credential !== 'browser' || !window.A5Tabs) $title.replaceChildren(T.account)
  else { const b = el('button', { type: 'button', 'data-a5-tabs': true }, T.account); $title.replaceChildren(b); window.A5Tabs.mount(b) }
}

function currentPart() {
  const h = location.hash.slice(1)
  if (allowed(h)) return { part: h, chosen: true }
  if (agentReqId) return { part: 'agentes', chosen: true }
  return { part: ME.admin && D.requests && D.requests.length ? 'pedidos' : 'aparelhos', chosen: false }
}

function renderAccount() {
  accountShell()
  const { part, chosen } = currentPart()
  const showPane = chosen || WIDE.matches
  document.body.classList.toggle('at-pane', chosen)
  renderIndex(showPane ? part : null)
  if (!showPane) { $pane.replaceChildren(); return }
  const p = PARTS[part]
  const top = (title, intro, extra) => el('div', { class: 'pane-top' },
    backLink(T.account, () => { agentReqId = null; history.pushState(null, '', ACCOUNT); renderAccount(); window.scrollTo(0, 0) }),
    el('h1', {}, el('span', {}, title), extra || null), intro ? el('p', {}, intro) : null)
  if (part === 'agentes' && agentReqId) return guarded(() => partAgentRequest(top, agentReqId))
  fill($pane, WIDE.matches ? alerts() : null, p.render(top))
}

function indexRow(key, small, end, current) {
  const p = PARTS[key]
  return el('a', { class: 'row', href: '#' + key, 'aria-current': current ? 'page' : null },
    el('span', { class: 'row-icon ' + p.color }, icon(p.ico)),
    el('span', { class: 'row-text' }, el('b', {}, p.title()), small ? el('small', {}, small) : null),
    el('span', { class: 'row-end' }, end != null ? end : null, icon('chev')))
}

function renderIndex(current) {
  const me = D.devices.find((d) => d.current)
  const groups = ME.groups || []
  const profile = el('div', { class: 'card profile' }, avatar(ME.person.name, null),
    el('div', {}, el('b', {}, ME.person.name), el('small', {}, T.thisDeviceIs(me ? me.label || T.device : T.device)),
      el('div', { class: 'chips' }, groups.map((g) => el('span', { class: 'chip fill ' + (g.id === 'owner' ? 'sun' : 'ok') }, groupName(g))),
        ME.passkeys ? el('span', { class: 'chip fill ok' }, T.faceId) : null)))
  const rows = (keys) => el('div', { class: 'group' }, keys.filter(allowed).map((k) => indexRow(k, ...summary(k), k === current)))
  fill($index, profile, WIDE.matches ? null : alerts(),
    el('span', { class: 'section caps' }, T.you), rows(YOU),
    ME.admin ? [el('span', { class: 'section caps' }, T.house), rows(HOUSE)] : null,
    el('button', { type: 'button', class: 'logout', onclick: () => guarded(async () => { await rawApi('POST', '/api/logout', {}); start() }) }, icon('logout'), T.nav.logout))
}

// the small line and the end (count or badge) of each index row
function summary(k) {
  const names = (list, n) => list.slice(0, n || 3).map((x) => x.name || x.label).join(' · ')
  const badge = (n) => n ? el('span', { class: 'badge' }, String(n)) : null
  switch (k) {
    case 'aparelhos': return [D.devices.map((d) => (d.label || T.device) + (d.current ? T.thisOne : '')).slice(0, 2).join(', '), String(D.devices.length)]
    case 'faceid': return [ME.passkeys ? T.passkeyShort(ME.passkeys) : T.noPasskeyShort, ME.passkeys ? null : badge('!')]
    case 'pedidos': return [D.requests.length ? T.requestsLine(D.requests.length) : T.noRequests, badge(D.requests.length)]
    case 'pessoas': return [names(D.people, 4), String(D.people.length)]
    case 'grupos': return [D.groups.map(groupName).join(' · '), null]
    case 'telas': return [names(D.screens) || T.pair.noScreens, String(D.screens.length)]
    case 'agentes': return [D.agentReqs.length ? T.agents.waiting(D.agentReqs.length) : names(D.agents.filter((a) => !a.revoked_at)) || T.agents.none, D.agentReqs.length ? badge(D.agentReqs.length) : null]
    case 'pontes': { const live = D.machines.filter((m) => !m.revoked_at); return [live.map((m) => m.label).slice(0, 3).join(' · ') || T.bridges.none, String(live.length)] }
    case 'comandos': return [ME.commands_off ? T.commands.offShort : T.commands.onShort, ME.commands_off ? el('span', { class: 'chip bad' }, T.commands.offTag) : null]
    case 'atalhos': { const live = D.shortcuts.keys.filter((x) => !x.revoked_at); return [live.map((x) => x.label).slice(0, 2).join(' · ') || T.shortcuts.none, String(live.length)] }
    case 'todos': return [T.allDevicesSub, String(D.all.length)]
    case 'auditoria': return [T.auditSub, null]
  }
  return [null, null]
}

function alerts() {
  return (ME.alerts || []).map((a) => el('div', { class: 'alert' }, icon(a.kind === 'device' ? 'faceid' : 'alert'),
    el('div', {},
      el('b', {}, (a.kind === 'bridge' ? T.bridgeAlert : a.kind === 'bridge_ip' ? T.bridgeIpAlert : a.kind === 'shortcut_place' ? T.shortcutPlaceAlert : a.kind === 'agent_ip' ? T.agentIpAlert : T.newDevice(ME.person.name)).replace(/:\s*$/, '')),
      `${a.label || T.device}, ${shortWhen(a.created_at)}${a.place ? ', ' + city(a.place) : ''}${a.current ? T.thisDevice : ''}.`,
      el('div', { class: 'btn-row' },
        btn(T.itWasMe, async () => { await api('POST', `/api/me/alerts/${a.id}/ack`, {}); await refresh() }, 'btn-sm'),
        a.current || !a.live || a.kind !== 'device' ? null : btn(T.revoke, async () => { await api('DELETE', `/api/me/devices/${a.session_id}`); await refresh() }, 'btn-sm btn-danger')))))
}

// ---- parts
function deviceItem(d, owner, release) {
  const mine = d.current || d.id === ME.session_id
  return el('div', { class: 'item' },
    line(screenIcon(d.kind === 'screen' ? 'screen' : 'phone'), owner ? `${d.name} · ${d.label || T.device}` : d.label || T.device,
      T.devLine(when(d.created_at), d.place, when(d.last_used_at)),
      mine ? el('span', { class: 'chip gray' }, T.thisTag) : null,
      d.kind === 'screen' && owner ? el('span', { class: 'chip ok' }, T.pair.screenChip) : null),
    release || !mine ? el('div', { class: 'btn-row more' }, release,
      mine ? null : btn(T.disconnect, async () => {
        await api('DELETE', owner ? `/api/admin/devices/${d.id}` : `/api/me/devices/${d.id}`); await refresh()
      }, 'btn-sm btn-danger')) : null)
}

function partMyDevices(top) {
  return [top(T.myDevices, T.myDevicesIntro), el('div', { class: 'group' }, D.devices.map((d) => deviceItem(d, false)))]
}

function partAllDevices(top) {
  return [top(T.allDevices, T.allDevicesSub), el('div', { class: 'group' }, D.all.map((d) => deviceItem(d, true,
    // a new device of a resident sends commands only after 24 h, or once released here
    d.kind === 'browser' && !d.commands_ok_at && Date.now() - Date.parse(d.created_at) < 864e5
      ? btn(T.commands.release, async () => { await api('POST', `/api/admin/devices/${d.id}/commands`, {}); toast(T.commands.released); await refresh() }, 'btn-sm') : null)))]
}

function partFaceId(top) {
  const add = async () => {
    await passkeyCreate().catch(async (e) => { if (!(e instanceof ApiError && e.data.passkey)) throw e; await passkeyCheck(); await passkeyCreate() })
    toast(T.passkeyAdded); await refresh()
  }
  return [top(T.faceId, ME.passkeys ? T.passkeyCount(ME.passkeys) : T.noPasskey),
    el('div', { class: 'card pad' }, el('div', { class: 'faceid-mark' }, icon('faceid')),
      btn(ME.passkeys ? T.addAnotherPasskey : T.addPasskeyHere, add, ME.passkeys ? 'btn-block' : 'btn-primary btn-block', 'plus'))]
}

const groupOptions = () => D.groups.map((g) => [g.id, groupName(g)])

function partRequests(top) {
  return [top(T.requests, T.requestsIntro), D.requests.length ? el('div', { class: 'group' }, D.requests.map((r) => {
    const name = textInput({ placeholder: T.name, maxlength: 40 })
    const gs = toggles(groupOptions(), ['residents'])
    return el('div', { class: 'item' },
      line(avatar(r.sender_known_as || '?', r.id), fmtPhone(r.sender_phone) + (r.sender_known_as ? ` (${r.sender_known_as})` : ''), T.reqLine(fmtPhone(r.typed_phone), r.device || '', shortWhen(r.created_at), r.code_valid)),
      r.sender_person_id ? null : el('div', { class: 'edit' }, field(T.name, name), el('span', { class: 'caps' }, T.groups), gs),
      el('div', { class: 'btn-row' },
        btn(T.approve, async () => { await api('POST', `/api/admin/requests/${r.id}/approve`, { name: name.value, groups: picked(gs) }); await refresh() }, 'btn-sm btn-primary', 'check'),
        btn(T.refuse, async () => { await api('POST', `/api/admin/requests/${r.id}/refuse`, {}); await refresh() }, 'btn-sm btn-danger')))
  })) : el('div', { class: 'card pad muted' }, T.noRequests)]
}

function partPeople(top) {
  const list = el('div', { class: 'group' })
  const addItem = () => {
    const name = textInput({ placeholder: T.name, maxlength: 40 })
    const phone = textInput({ type: 'tel', placeholder: T.phoneWithArea })
    const gs = toggles(groupOptions(), ['residents'])
    const it = el('div', { class: 'item open' }, el('div', { class: 'edit' }, field(T.name, name), field(T.phoneWithArea, phone), el('span', { class: 'caps' }, T.groups), gs),
      el('div', { class: 'btn-row' }, btn(T.add, async () => { await api('POST', '/api/admin/people', { name: name.value, phone: phone.value, groups: picked(gs) }); await refresh() }, 'btn-sm btn-primary', 'check')))
    list.prepend(it); name.focus()
  }
  for (const p of D.people) {
    const it = el('div', { class: 'item' })
    let edit = null
    const head = el('button', { type: 'button', class: 'line line-btn', 'aria-expanded': 'false', onclick: () => {
      const open = !it.classList.contains('open')
      it.classList.toggle('open', open); head.setAttribute('aria-expanded', String(open))
      if (open && !edit) { edit = personEdit(p); it.append(edit) }
      if (edit) edit.hidden = !open
    } }, avatar(p.name, p.id), el('span', { class: 'row-text' }, el('b', {}, p.name),
      el('small', {}, fmtPhone(p.phone) + T.devicesCount(p.devices) + (p.status === 'blocked' ? T.blocked : ''))), icon('chev'))
    it.append(head, el('div', { class: 'more' }, p.groups.map((g) => el('span', { class: 'chip ' + (g === 'owner' ? 'sun' : 'gray') }, groupName(g)))))
    list.append(it)
  }
  return [top(T.people, T.peopleIntro, btn(T.add, addItem, 'btn-sm', 'plus')), list]
}

function personEdit(p) {
  const name = textInput({ value: p.name, maxlength: 40 })
  const gs = toggles(groupOptions(), p.groups)
  return el('div', { class: 'edit' }, field(T.name, name), el('span', { class: 'caps' }, T.groups), gs,
    el('div', { class: 'btn-row' },
      btn(T.save, async () => { await api('POST', `/api/admin/people/${p.id}`, { name: name.value, groups: picked(gs) }); toast(T.saved); await refresh() }, 'btn-sm btn-primary'),
      p.status === 'blocked'
        ? btn(T.unblock, async () => { await api('POST', `/api/admin/people/${p.id}`, { status: 'active' }); await refresh() }, 'btn-sm')
        : confirmButton(T.block, T.confirmBlock, async () => { await api('POST', `/api/admin/people/${p.id}`, { status: 'blocked' }); await refresh() }),
      p.groups.includes('owner') && p.id !== ME.person.id
        ? btn(T.invitePasskey, async () => { await api('POST', `/api/admin/people/${p.id}/passkey-invite`, {}); toast(T.inviteSent) }, 'btn-sm') : null))
}

function partGroups(top) {
  const tabs = [...new Set([...(ME.all_tabs || []), ...D.groups.flatMap((g) => g.tabs || [])])]
  const label = (t) => (tabLabels[t]) || t
  return [top(T.groups, T.groupsIntro), el('div', { class: 'group' }, D.groups.map((g) => {
    if (g.is_admin) return el('div', { class: 'item' }, line(el('span', { class: 'row-icon sun' }, icon('layers')), groupName(g), T.seesAll))
    // a tab that takes no screen credential: off and not clickable in a screens group, a note in a mixed one
    const noScreen = (t) => !(ME.screen_tabs || []).includes(t)
    const box = toggles(tabs.map((t) => [t, label(t)]), g.screens_only ? g.tabs.filter((t) => !noScreen(t)) : g.tabs)
    if (g.screens_only) for (const b of box.children) if (noScreen(b.dataset.v)) { b.disabled = true; b.title = T.notOnScreens; b.append(el('small', { class: 'toggle-note' }, ' · ' + T.notOnScreens)) }
    const hidden = g.screens_only ? g.tabs.filter(noScreen) : []
    const note = g.screens_only ? null : tabs.filter(noScreen).length ? el('small', { class: 'muted toggle-hint' }, T.screensSkip(tabs.filter(noScreen).map(label).join(', '))) : null
    return el('div', { class: 'item' }, line(el('span', { class: 'row-icon gray' }, icon('layers')), groupName(g), g.screens_only ? T.groupTabsScreens : T.groupTabs),
      el('div', { class: 'more' }, box, note, hidden.length ? el('small', { class: 'muted toggle-hint' }, T.screensDropped(hidden.map(label).join(', '))) : null, btn(T.save, async () => { await api('POST', `/api/admin/groups/${g.id}`, { tabs: picked(box) }); toast(T.saved); await refresh() }, 'btn-sm btn-primary')))
  }))]
}
let tabLabels = {}

function partScreens(top) {
  const paired = el('section', {}, el('span', { class: 'caps' }, T.screens.paired),
    D.screens.length ? el('div', { class: 'group' }, D.screens.map((s) => el('div', { class: 'item' },
      el('div', { class: 'line' }, screenIcon('screen'), el('span', { class: 'row-text' }, el('b', {}, s.name, ...(s.groups || []).map((g) => el('span', { class: 'chip ' + (g === 'owner-screens' ? 'sun' : 'gray') + ' group-chip' }, groupName(g)))),
        el('small', { class: 'with-chip' }, s.status === 'blocked' ? null : el('span', { class: 'chip ' + (s.devices ? 'ok' : 'warn') }, s.devices ? T.screens.onAir : T.screens.waitingTag),
          (s.devices ? T.screens.live : T.screens.idle) + (s.status === 'blocked' ? T.blocked : ''))),
        s.status === 'blocked'
          ? btn(T.unblock, async () => { await api('POST', `/api/admin/people/${s.id}`, { status: 'active' }); await refresh() }, 'btn-sm')
          : confirmButton(T.block, T.confirmBlock, async () => { await api('POST', `/api/admin/people/${s.id}`, { status: 'blocked' }); await refresh() }))))) : el('div', { class: 'card pad muted' }, T.pair.noScreens))

  // type the code shown on the screen (or arrive here from its QR): six boxes over a hidden input
  const code = el('input', { id: 'pair-code', inputmode: 'text', autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', maxlength: 12, 'aria-label': T.pair.codePlaceholder, value: partScreens.code || '' })
  partScreens.code = ''
  const boxes = el('label', { class: 'code-boxes', for: 'pair-code' })
  const drawBoxes = () => {
    const v = code.value.toUpperCase().replace(/[^A-Z0-9]/g, '')
    boxes.replaceChildren(code, ...Array.from({ length: Math.max(6, v.length) }, (_, i) => el('span', { class: i === v.length ? 'cur' : '' }, v[i] || '')))
  }
  drawBoxes()
  const info = el('div')
  let chosen = ''
  const name = textInput({ placeholder: T.pair.screenName, maxlength: 40 })
  const seg = el('div', { class: 'seg', role: 'group' })
  const drawSeg = () => seg.replaceChildren(...[...D.screens.map((s) => [String(s.id), s.name]), ['', T.screens.new]].map(([v, l]) =>
    el('button', { type: 'button', 'aria-pressed': v === chosen ? 'true' : 'false', onclick: () => { chosen = v; name.hidden = !!v; drawSeg() } }, l)))
  drawSeg()
  let last = ''
  const lookup = async () => {
    const v = code.value.trim()
    if (v.replace(/[^A-Za-z0-9]/g, '').length < 6 || v === last) return
    last = v
    try {
      const p = await rawApi('GET', `/api/admin/pair?code=${encodeURIComponent(v)}`)
      const far = !p.same_ip
      info.replaceChildren(el('div', { class: 'screen-request' + (far ? ' far' : '') }, icon(far ? 'alert' : 'wifi'),
        el('div', {}, el('b', {}, T.screens.requestNow), T.pair.asking(p.label || T.device, city(p.place), shortWhen(p.created_at), p.ip),
          far ? el('p', {}, p.other_ip_refused ? T.pair.otherIpRefused(p.ip, p.admin_ip) : T.pair.otherIp(p.ip, p.admin_ip)) : null)))
    } catch (e) { info.replaceChildren(el('p', { class: 'muted small' }, e.message)) }
  }
  code.addEventListener('input', () => { drawBoxes(); code.focus(); guarded(lookup) })
  if (code.value) guarded(lookup)
  const pairCard = el('section', {}, el('span', { class: 'caps' }, T.screens.pairOne),
    el('div', { class: 'card pad' }, el('span', { class: 'caps code-caption' }, T.screens.codeCaption), boxes, info, D.screens.length ? seg : null, name,
      btn(T.pair.approve, async () => {
        await api('POST', '/api/admin/pair', chosen ? { code: code.value, screen: Number(chosen) } : { code: code.value, name: name.value })
        toast(T.pair.approved); await refresh()
      }, 'btn-primary btn-block pad-top', 'check')))
  return [top(T.pair.screens, T.screens.intro), el('div', { class: 'two-cols' }, paired, pairCard)]
}

function partAgents(top) {
  const label = textInput({ placeholder: T.agents.label, maxlength: 40 })
  const out = el('div')
  return [top(T.agents.title, T.agents.what),
    D.agentReqs.length ? [el('span', { class: 'caps' }, T.agents.requests), el('div', { class: 'group' }, D.agentReqs.map((r) => el('div', { class: 'item' },
      line(screenIcon('robot'), r.kind === 'pair' ? T.agentReq.pairTitle(r.name) : T.agentReq.changeTitle(r.name), `${r.agent || T.agentReq.anAgent} · ${shortWhen(r.created_at)}`,
        btn(T.agents.see, async () => { agentReqId = r.id; history.pushState(null, '', `${ACCOUNT}?agent_request=${r.id}`); renderAccount() }, 'btn-sm')))))] : null,
    el('span', { class: 'caps' }, T.agents.keys),
    D.agents.length ? el('div', { class: 'group' }, D.agents.map((a) => el('div', { class: 'item' },
      line(screenIcon('robot'), a.label + (a.revoked_at ? T.bridges.revoked : ''), T.bridges.line(when(a.created_at), when(a.last_used_at), a.last_ip),
        a.revoked_at ? null : btn(T.revoke, async () => { await api('DELETE', `/api/admin/agents/${a.id}`); await refresh() }, 'btn-sm btn-danger'))))) : el('div', { class: 'card pad muted' }, T.agents.none),
    el('span', { class: 'caps' }, T.agents.add),
    el('div', { class: 'card pad' }, label, btn(T.bridges.create, async () => {
      const r = await api('POST', '/api/admin/agents', { label: label.value })
      out.replaceChildren(keyOnce(T.agents.copyOnce, r.key))
    }, 'btn-primary btn-block pad-top', 'plus'), out)]
}

// what an agent asked (admin side, 1 tap + Face ID)
async function partAgentRequest(top, id) {
  const r = await rawApi('GET', `/api/admin/agent-requests/${id}`)
  const leave = () => { agentReqId = null; history.replaceState(null, '', ACCOUNT + '#agentes') }
  const groupLabel = (g) => (T.groupNames && T.groupNames[g]) || g
  const warn = (text) => el('div', { class: 'notice' }, icon('alert'), el('div', {}, text))
  fill($pane,
    top(r.kind === 'pair' ? T.agentReq.pairTitle(r.name) : T.agentReq.changeTitle(r.name), T.agentReq.asked(r.agent || T.agentReq.anAgent, when(r.created_at))),
    el('div', { class: 'card pad' },
      r.kind === 'pair' ? el('p', {}, r.existing ? T.agentReq.existing(r.name) : T.agentReq.newScreen(r.name)) : null,
      r.group ? el('p', {}, T.agentReq.group(groupLabel(r.group), r.current_groups.map(groupLabel).join(', '))) : null,
      r.at_home ? null : warn(T.agentReq.notHome),
      r.unblock ? warn(T.agentReq.unblock) : null,
      r.kind === 'pair' && !r.claimed ? warn(T.agentReq.notOpened) : null,
      r.kind === 'pair' && r.claimed ? el('div', { class: 'screen-request' + (r.same_ip === false ? ' far' : '') }, icon(r.same_ip === false ? 'alert' : 'wifi'),
        el('div', {}, el('b', {}, T.screens.requestNow), T.agentReq.screen(r.screen_label || T.device, r.screen_place, r.screen_ip),
          r.same_ip === false ? el('p', {}, T.agentReq.otherIp(r.screen_ip, r.agent_ip)) : null)) : null,
      el('div', { class: 'btn-row pad-top' },
        el('button', { type: 'button', class: 'btn btn-primary', disabled: r.kind === 'pair' && !r.claimed, onclick: () => guarded(async () => {
          await passkeyCheck(`agent:${r.id}`)
          leave(); toast(r.kind === 'pair' ? T.agentReq.paired(r.name) : T.agentReq.changed(r.name)); await refresh()
        }) }, T.agentReq.approve),
        r.kind === 'pair' && !r.claimed ? btn(T.agentReq.reload, () => partAgentRequest(top, id), 'btn-ghost') : null,
        btn(T.refuse, async () => { await rawApi('POST', `/api/admin/agent-requests/${r.id}/refuse`, {}); leave(); toast(T.agentReq.refused); await refresh() }, 'btn-danger'))))
}

function partBridges(top) {
  const tabNames = ME.all_tabs || []
  const tab = el('select', { class: 'text-input' }, tabNames.map((t) => el('option', { value: t }, tabLabels[t] || t)))
  const label = textInput({ placeholder: T.bridges.label, maxlength: 40 })
  const out = el('div')
  return [top(T.bridges.title, T.bridges.intro),
    D.machines.length ? el('div', { class: 'group' }, D.machines.map((m) => el('div', { class: 'item' },
      line(screenIcon('key'), `${tabLabels[m.tab] || m.tab} · ${m.label}${m.revoked_at ? T.bridges.revoked : ''}`, T.bridges.line(when(m.created_at), when(m.last_used_at), m.last_ip),
        m.revoked_at ? null : btn(T.revoke, async () => { await api('DELETE', `/api/admin/machines/${m.id}`); await refresh() }, 'btn-sm btn-danger'))))) : el('div', { class: 'card pad muted' }, T.bridges.none),
    tabNames.length ? [el('span', { class: 'caps' }, T.bridges.add), el('div', { class: 'card pad' }, field(T.bridges.tab, tab), field(T.bridges.machine, label),
      btn(T.bridges.create, async () => {
        const r = await api('POST', '/api/admin/machines', { tab: tab.value, label: label.value })
        out.replaceChildren(keyOnce(T.bridges.copyOnce, r.key))
      }, 'btn-primary btn-block pad-top', 'plus'), out)] : null]
}

// the brake: no command reaches the house while it is off
function partCommands(top) {
  return [top(T.commands.title, T.commands.intro),
    el('div', { class: 'card pad' },
      el('div', { class: ME.commands_off ? 'screen-request far' : 'screen-request' }, icon(ME.commands_off ? 'alert' : 'power'), el('div', {}, ME.commands_off ? T.commands.offNow : T.commands.onNow)),
      btn(ME.commands_off ? T.commands.turnOn : T.commands.turnOff, async () => { await api('POST', '/api/admin/commands', { off: !ME.commands_off }); await refresh() },
        (ME.commands_off ? 'btn-primary' : 'btn-danger') + ' btn-block pad-top'))]
}

// Shortcuts keys: one per device and shortcut, shown once
function partShortcuts(top) {
  const s = D.shortcuts
  const label = textInput({ placeholder: T.shortcuts.label, maxlength: 60 })
  const scope = toggles(s.available.map((a) => [`${a.tab}/${a.action}`, `${a.tab} · ${a.action}`]), [])
  const out = el('div')
  return [top(T.shortcuts.title, T.shortcuts.intro),
    s.keys.length ? el('div', { class: 'group' }, s.keys.map((k) => el('div', { class: 'item' },
      line(screenIcon('bolt'), k.label + (k.revoked_at ? T.shortcuts.revoked : ''), T.shortcuts.line(when(k.created_at), when(k.last_used_at), k.last_ip, k.last_place),
        k.revoked_at ? null : btn(T.revoke, async () => { await api('DELETE', `/api/me/shortcuts/${k.id}`); await refresh() }, 'btn-sm btn-danger')),
      el('div', { class: 'more' }, k.scope.map((x) => el('span', { class: 'chip gray' }, x.replace('/', ' · '))))))) : el('div', { class: 'card pad muted' }, T.shortcuts.none),
    s.available.length ? [el('span', { class: 'caps' }, T.shortcuts.add), el('div', { class: 'card pad' }, field(T.shortcuts.labelCaps, label), el('span', { class: 'caps' }, T.shortcuts.actions), scope,
      btn(T.shortcuts.create, async () => {
        const r = await api('POST', '/api/me/shortcuts', { label: label.value, scope: picked(scope) })
        out.replaceChildren(keyOnce(T.shortcuts.copyOnce, r.key))
      }, 'btn-primary btn-block pad-top', 'plus'), out)] : el('p', { class: 'muted small pad-top' }, T.shortcuts.noActions)]
}

function partAudit(top) {
  const list = el('div', { class: 'group audit' })
  const more = btn(T.showAudit, async () => {
    const rows = await rawApi('GET', '/api/admin/audit')
    list.replaceChildren(...rows.map((a) => el('div', { class: 'item' }, el('time', { datetime: a.at }, when(a.at)),
      el('span', {}, `${a.name || '-'} · ${a.strength || ''} · ${a.action}${a.target ? ' · ' + a.target : ''}${a.place ? ' · ' + a.place : ''}`))))
    more.remove()
  }, 'btn-block', 'list')
  return [top(T.audit, T.auditSub), more, list]
}

// ------------------------------------------------------------------ boot
async function account(q) {
  await loadData()
  if (window.A5Tabs) window.A5Tabs.load().then((d) => { if (d) { tabLabels = Object.fromEntries(d.tabs.map((t) => [t.id, t.label || t.id])); if ($index) renderAccount() } }).catch(() => {})
  if (q.get('pair') && ME.admin) {
    partScreens.code = q.get('pair').slice(0, 12)
    history.replaceState(null, '', ACCOUNT + '#telas')
  }
  renderAccount()
}

function loading() {
  setPage('loading', el('p', { class: 'muted loading-text' }, T.loading))
}

async function start() {
  clearTimeout(pollTimer)
  $index = null
  const ticket = new URLSearchParams(location.hash.slice(1)).get('screen_ticket')
  if (ticket) return guarded(() => screenTicketView(ticket.slice(0, 64)))
  try {
    ME = await rawApi('GET', '/api/me')
  } catch (e) {
    ME = null
    if (e instanceof ApiError && e.status === 401) {
      if (new URLSearchParams(location.search).get('screen') === '1') return guarded(pairScreenView)
      return loginView()
    }
    setPage('loading', el('p', { class: 'muted loading-text' }, T.offline))
    return
  }
  const q = new URLSearchParams(location.search)
  const stepUp = q.get('step_up')
  if (stepUp && /^[a-z][a-z0-9-]{0,30}$/.test(stepUp)) return stepUpView(stepUp)
  const agentReq = q.get('agent_request')
  if (agentReq && /^\d{1,12}$/.test(agentReq) && ME.admin) {
    if (!onAccount()) { location.replace(`${ACCOUNT}?agent_request=${agentReq}`); return }
    agentReqId = Number(agentReq)
  }
  const n = nextPath()
  if (n && ME.credential === 'screen') { location.href = n; return }
  if (!onAccount()) {
    // the pairing QR lands on "/?pair=": hand it to the account page
    if (q.get('pair') && ME.admin) { location.replace(`${ACCOUNT}?pair=${encodeURIComponent(q.get('pair').slice(0, 12))}`); return }
    return openLastTab()
  }
  return guarded(() => account(q))
}

window.addEventListener('hashchange', () => { if ($index && ME) { if (allowed(location.hash.slice(1))) agentReqId = null; renderAccount(); if (!WIDE.matches) window.scrollTo(0, 0) } })
window.addEventListener('popstate', () => { if ($index && ME) { const a = new URLSearchParams(location.search).get('agent_request'); agentReqId = a && /^\d{1,12}$/.test(a) ? Number(a) : null; renderAccount() } })
WIDE.addEventListener('change', () => { if ($index && ME) renderAccount() })

loading()
start()
