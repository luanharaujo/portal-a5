// Portal A5 page. No framework, no innerHTML: every value from the server goes in as text.
'use strict'

const $main = document.getElementById('main')
const $who = document.getElementById('who')
const $alerts = document.getElementById('alerts')
const $toast = document.getElementById('toast')
const $title = document.getElementById('title')
const ACCOUNT = '/conta/'
const onAccount = () => location.pathname === ACCOUNT
const MODE = (window.matchMedia('(display-mode: standalone)').matches || navigator.standalone) ? 'app' : 'browser'
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
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)))
  return e
}

function show(...nodes) { $main.replaceChildren(...nodes) }

let toastTimer
function toast(msg) {
  $toast.textContent = msg
  $toast.hidden = false
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { $toast.hidden = true }, 4000)
}

const when = (iso) => iso ? new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : ''
const fmtPhone = (d) => d ? '+' + d : ''
const groupName = (g) => (T.groupNames && T.groupNames[g.id]) || g.name

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

// A red button that asks twice: the first tap only arms it for a few seconds.
function confirmButton(label, confirmLabel, fn) {
  let armed = null
  const b = el('button', { class: 'danger', onclick: () => {
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

// ------------------------------------------------------------------ login
function nextPath() {
  const n = new URLSearchParams(location.search).get('next') || ''
  return /^\/[a-z][a-z0-9-]*(\/|$)/.test(n) ? n : null
}

function loginView() {
  plainTitle(T.title)
  $who.textContent = ''
  $alerts.replaceChildren()
  const input = el('input', { type: 'tel', inputmode: 'tel', autocomplete: 'tel', placeholder: T.phonePlaceholder, required: true, id: 'phone' })
  const form = el('form', {
    class: 'card',
    onsubmit: (ev) => { ev.preventDefault(); guarded(() => askCode(input.value)) },
  },
  el('label', { for: 'phone' }, T.phoneLabel),
  input,
  el('button', { type: 'submit' }, T.signIn),
  el('p', { class: 'muted' }, T.signInHint))
  show(form, el('p', {}, el('button', { class: 'link', onclick: () => guarded(pairScreenView) }, T.pair.isScreen)))
  input.focus()
}

let pollTimer
async function askCode(phone) {
  const r = await rawApi('POST', '/api/login/start', { phone, mode: MODE })
  const status = el('p', { class: 'muted' }, T.status.waiting)
  show(el('div', { class: 'card' },
    el('p', {}, T.sendHint),
    el('a', { class: 'button', href: r.wa_link, target: '_blank', rel: 'noopener' }, T.openWhatsApp),
    el('p', { class: 'code' }, r.message),
    status,
    el('button', { class: 'link', onclick: () => { clearTimeout(pollTimer); loginView() } }, T.back)))
  const poll = async () => {
    let s
    try { s = await rawApi('POST', '/api/login/status', { secret: r.secret, mode: MODE }) } catch (e) { status.textContent = e.message; return }
    if (s.status === 'ok') { const n = nextPath(); if (n) location.href = n; else start(); return }
    const msg = T.status[s.status] || s.status
    status.textContent = msg
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
  const quiet = 4
  const size = (n + quiet * 2) * scale
  const c = el('canvas', { width: size, height: size, class: 'qr', 'aria-label': T.pair.qrLabel })
  const g = c.getContext('2d')
  g.fillStyle = '#fff'
  g.fillRect(0, 0, size, size)
  g.fillStyle = '#000'
  for (let r = 0; r < n; r++) for (let k = 0; k < n; k++) if (qr.isDark(r, k)) g.fillRect((k + quiet) * scale, (r + quiet) * scale, scale, scale)
  return c
}

async function pairScreenView() {
  clearTimeout(pollTimer)
  const r = await rawApi('POST', '/api/pair/start', {})
  const status = el('p', { class: 'muted' }, T.pair.waiting)
  show(el('div', { class: 'card pair' },
    el('h2', {}, T.pair.title),
    el('p', {}, T.pair.howTo),
    el('p', { class: 'pair-code' }, r.code),
    drawQr(r.pair_url),
    status,
    el('button', { class: 'link', onclick: () => { clearTimeout(pollTimer); loginView() } }, T.back)))
  const poll = async () => {
    let s
    // a screen is unattended: a network blip must not stop the polling for good
    try { s = await rawApi('POST', '/api/pair/status', { secret: r.secret }) } catch (e) {
      if (e instanceof ApiError && e.status === 404) return pairScreenView()
      status.textContent = T.offline
      pollTimer = setTimeout(poll, 5000)
      return
    }
    if (s.status === 'ok') { location.replace(nextPath() || '/'); return }
    if (s.status === 'expired') return pairScreenView() // a fresh code, the screen stays unattended
    status.textContent = T.pair.status[s.status] || T.pair.waiting
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
    show(el('div', { class: 'card pair' }, el('h2', {}, T.pair.title), el('p', {}, e.message)))
    return
  }
  const next = /^\/[a-z][a-z0-9-]*(\/|$)/.test(r.next || '') ? r.next : '/'
  const status = el('p', { class: 'muted' }, T.agentReq.screenWaiting)
  show(el('div', { class: 'card pair' }, el('h2', {}, r.name), el('p', {}, T.agentReq.screenHowTo), status))
  const poll = async () => {
    let s
    try { s = await rawApi('POST', '/api/pair/status', { secret: r.secret }) } catch (e) {
      if (e instanceof ApiError && e.status === 404) { status.textContent = T.agentReq.screenStatus.refused; return }
      status.textContent = T.offline
      pollTimer = setTimeout(poll, 5000)
      return
    }
    if (s.status === 'ok') { location.replace(next); return }
    if (s.status === 'waiting') { pollTimer = setTimeout(poll, 3000); return }
    status.textContent = T.agentReq.screenStatus[s.status] || T.agentReq.screenStatus.refused
  }
  pollTimer = setTimeout(poll, 3000)
}

// ------------------------------------------------------------------ what an agent asked (admin side, 1 tap + Face ID)
async function agentRequestView(id) {
  const r = await rawApi('GET', `/api/admin/agent-requests/${id}`)
  const leave = () => history.replaceState(null, '', ACCOUNT)
  const groupLabel = (g) => (T.groupNames && T.groupNames[g]) || g
  show(nav(), el('section', { class: 'card' },
    el('h2', {}, r.kind === 'pair' ? T.agentReq.pairTitle(r.name) : T.agentReq.changeTitle(r.name)),
    el('p', { class: 'muted' }, T.agentReq.asked(r.agent || T.agentReq.anAgent, when(r.created_at))),
    r.kind === 'pair' ? el('p', {}, r.existing ? T.agentReq.existing(r.name) : T.agentReq.newScreen(r.name)) : null,
    r.group ? el('p', {}, T.agentReq.group(groupLabel(r.group), r.current_groups.map(groupLabel).join(', '))) : null,
    r.at_home ? null : el('p', { class: 'danger-box' }, T.agentReq.notHome),
    r.unblock ? el('p', { class: 'danger-box' }, T.agentReq.unblock) : null,
    r.kind === 'pair' && !r.claimed ? el('p', { class: 'danger-box' }, T.agentReq.notOpened) : null,
    r.kind === 'pair' && r.claimed ? el('p', { class: 'muted' }, T.agentReq.screen(r.screen_label || T.device, r.screen_place, r.screen_ip)) : null,
    r.kind === 'pair' && r.claimed && r.same_ip === false ? el('p', { class: 'danger-box' }, T.agentReq.otherIp(r.screen_ip, r.agent_ip)) : null,
    el('button', { disabled: r.kind === 'pair' && !r.claimed, onclick: () => guarded(async () => {
      await passkeyCheck(`agent:${r.id}`)
      leave(); toast(r.kind === 'pair' ? T.agentReq.paired(r.name) : T.agentReq.changed(r.name)); adminView()
    }) }, T.agentReq.approve),
    r.kind === 'pair' && !r.claimed ? el('button', { class: 'link', onclick: () => guarded(() => agentRequestView(id)) }, T.agentReq.reload) : null,
    el('button', { class: 'danger', onclick: () => guarded(async () => {
      await rawApi('POST', `/api/admin/agent-requests/${r.id}/refuse`, {}); leave(); toast(T.agentReq.refused); adminView()
    }) }, T.refuse)))
}

// ------------------------------------------------------------------ Face ID before entering a tab (D9)
function stepUpView(tab) {
  const next = nextPath() || `/${tab}/`
  show(el('div', { class: 'card' },
    el('h2', {}, T.stepUp.title(tab)),
    el('p', {}, T.stepUp.why),
    el('button', { onclick: () => guarded(async () => {
      const r = await passkeyCheck(`entry:${tab}`)
      location.href = next.startsWith(`/${tab}/`) ? next : r.next
    }) }, T.stepUp.confirm),
    el('button', { class: 'link', onclick: () => { if (history.length > 1) history.back(); else location.assign(ACCOUNT) } }, T.back)))
}

// ------------------------------------------------------------------ opening and the account tab
function plainTitle(t) { $title.replaceChildren(t) }

// The account page's title is the tab selector too (Conta + arrow), except on a fixed screen.
function accountTitle() {
  if ($title.querySelector('[data-a5-tabs]')) return
  if (ME.credential !== 'browser' || !window.A5Tabs) return plainTitle(T.account)
  const b = el('button', { type: 'button', 'data-a5-tabs': true }, T.account)
  $title.replaceChildren(b)
  window.A5Tabs.mount(b)
}

// No home page: "/" opens the last tab used on this device, else the first tab, else the account.
async function openLastTab() {
  const data = window.A5Tabs ? await window.A5Tabs.load() : null
  if (!data) { location.replace(ACCOUNT); return }
  const last = window.A5Tabs.lastTab()
  const tab = last === data.account.id ? data.account : data.tabs.find((t) => t.id === last) || data.tabs[0] || data.account
  location.replace(tab.path)
}

function nav() {
  return el('nav', { class: 'nav' },
    el('button', { onclick: () => guarded(devicesView) }, T.nav.devices),
    ME.admin ? el('button', { onclick: () => guarded(adminView) }, T.nav.admin) : null,
    el('button', { class: 'link', onclick: () => guarded(async () => { await rawApi('POST', '/api/logout', {}); start() }) }, T.nav.logout))
}

function renderAlerts() {
  const list = ME.alerts || []
  $alerts.replaceChildren(...list.map((a) => el('div', { class: 'alert' },
    el('strong', {}, a.kind === 'bridge' ? T.bridgeAlert : a.kind === 'bridge_ip' ? T.bridgeIpAlert : a.kind === 'shortcut_place' ? T.shortcutPlaceAlert : a.kind === 'agent_ip' ? T.agentIpAlert : T.newDevice(ME.person.name)),
    `${a.label || T.device}, ${when(a.created_at)}${a.place ? ', ' + a.place : ''}${a.current ? T.thisDevice : ''}. `,
    el('button', { onclick: () => guarded(async () => { await api('POST', `/api/me/alerts/${a.id}/ack`, {}); await start() }) }, T.itWasMe),
    a.current || !a.live || a.kind !== 'device' ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/me/devices/${a.session_id}`); await start() }) }, T.revoke))))
}

async function devicesView() {
  const list = await rawApi('GET', '/api/me/devices')
  show(nav(), el('section', { class: 'card' },
    el('h2', {}, T.myDevices),
    el('ul', { class: 'rows' }, list.map((d) => el('li', {},
      el('div', {}, el('strong', {}, d.label || T.device), d.current ? T.thisOne : ''),
      el('div', { class: 'muted' }, T.devLine(when(d.created_at), d.place, when(d.last_used_at))),
      d.current ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/me/devices/${d.id}`); devicesView() }) }, T.disconnect))))))
}

// ------------------------------------------------------------------ admin
async function adminView() {
  const [allPeople, groups, requests, devices, machines, shortcuts, agents, agentReqs] = await Promise.all([
    rawApi('GET', '/api/admin/people'), rawApi('GET', '/api/admin/groups'),
    rawApi('GET', '/api/admin/requests'), rawApi('GET', '/api/admin/devices'),
    rawApi('GET', '/api/admin/machines'), rawApi('GET', '/api/me/shortcuts'),
    rawApi('GET', '/api/admin/agents'), rawApi('GET', '/api/admin/agent-requests'),
  ])
  const people = allPeople.filter((p) => p.kind !== 'screen')
  const screens = allPeople.filter((p) => p.kind === 'screen')
  const groupBoxes = (selected, name) => el('span', { class: 'boxes' }, groups.map((g) =>
    el('label', {}, el('input', { type: 'checkbox', name, value: g.id, checked: selected.includes(g.id) }), groupName(g))))
  const checked = (form, name) => [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((i) => i.value)

  const passkeyCard = el('section', { class: 'card' }, el('h2', {}, T.faceId),
    ME.passkeys === 0
      ? [el('p', {}, T.noPasskey),
        el('button', { onclick: () => guarded(async () => { await passkeyCreate(); toast(T.passkeyAdded); await start(); adminView() }) }, T.addPasskeyHere)]
      : [el('p', { class: 'muted' }, T.passkeyCount(ME.passkeys)),
        el('button', { class: 'link', onclick: () => guarded(async () => { await passkeyCreate().catch(async (e) => { if (!(e instanceof ApiError && e.data.passkey)) throw e; await passkeyCheck(); await passkeyCreate() }); toast(T.passkeyAdded); await start(); adminView() }) }, T.addAnotherPasskey)])

  const reqCard = el('section', { class: 'card' }, el('h2', {}, T.requests),
    requests.length ? el('ul', { class: 'rows' }, requests.map((r) => {
      const f = el('form', { onsubmit: (ev) => ev.preventDefault() })
      const name = el('input', { placeholder: T.name, maxlength: 40 })
      f.append(
        el('div', {}, el('strong', {}, fmtPhone(r.sender_phone)), r.sender_known_as ? ` (${r.sender_known_as})` : ''),
        el('div', { class: 'muted' }, T.reqLine(fmtPhone(r.typed_phone), r.device || '', when(r.created_at), r.code_valid)),
        r.sender_person_id ? null : [name, groupBoxes(['residents'], `rg${r.id}`)],
        el('button', { onclick: () => guarded(async () => {
          await api('POST', `/api/admin/requests/${r.id}/approve`, { name: name.value, groups: checked(f, `rg${r.id}`) }); adminView()
        }) }, T.approve),
        el('button', { class: 'danger', onclick: () => guarded(async () => { await api('POST', `/api/admin/requests/${r.id}/refuse`, {}); adminView() }) }, T.refuse))
      return el('li', {}, f)
    })) : el('p', { class: 'muted' }, T.noRequests))

  const addForm = el('form', { class: 'inline' })
  const addName = el('input', { placeholder: T.name, maxlength: 40, required: true })
  const addPhone = el('input', { type: 'tel', placeholder: T.phoneWithArea, required: true })
  addForm.append(addName, addPhone, groupBoxes(['residents'], 'newg'), el('button', { type: 'submit' }, T.add))
  addForm.addEventListener('submit', (ev) => { ev.preventDefault(); guarded(async () => {
    await api('POST', '/api/admin/people', { name: addName.value, phone: addPhone.value, groups: checked(addForm, 'newg') }); adminView()
  }) })

  const peopleCard = el('section', { class: 'card' }, el('h2', {}, T.people),
    el('ul', { class: 'rows' }, people.map((p) => {
      const f = el('form', { onsubmit: (ev) => ev.preventDefault() })
      const name = el('input', { value: p.name, maxlength: 40 })
      f.append(
        el('div', {}, el('strong', {}, fmtPhone(p.phone)), p.status === 'blocked' ? T.blocked : '', T.devicesCount(p.devices)),
        name,
        groupBoxes(p.groups, `pg${p.id}`),
        el('button', { onclick: () => guarded(async () => { await api('POST', `/api/admin/people/${p.id}`, { name: name.value, groups: checked(f, `pg${p.id}`) }); toast(T.saved); await start(); adminView() }) }, T.save),
        p.status === 'blocked'
          ? el('button', { onclick: () => guarded(async () => { await api('POST', `/api/admin/people/${p.id}`, { status: 'active' }); adminView() }) }, T.unblock)
          : confirmButton(T.block, T.confirmBlock, async () => { await api('POST', `/api/admin/people/${p.id}`, { status: 'blocked' }); adminView() }),
        p.groups.includes('owner') && p.id !== ME.person.id
          ? el('button', { class: 'link', onclick: () => guarded(async () => { await api('POST', `/api/admin/people/${p.id}/passkey-invite`, {}); toast(T.inviteSent) }) }, T.invitePasskey)
          : null)
      return el('li', {}, f)
    })),
    el('h3', {}, T.addPerson), addForm)

  const groupsCard = el('section', { class: 'card' }, el('h2', {}, T.groups),
    el('ul', { class: 'rows' }, groups.map((g) => {
      if (g.is_admin) return el('li', {}, el('strong', {}, groupName(g)), el('span', { class: 'muted' }, T.seesAll))
      const tabs = el('input', { value: g.tabs.join(', '), placeholder: T.tabsPlaceholder })
      return el('li', {}, el('strong', {}, groupName(g)), ' ', tabs,
        el('button', { onclick: () => guarded(async () => {
          await api('POST', `/api/admin/groups/${g.id}`, { tabs: tabs.value.split(',').map((t) => t.trim()).filter(Boolean) }); toast(T.saved)
        }) }, T.save))
    })))

  const devicesCard = el('section', { class: 'card' }, el('h2', {}, T.allDevices),
    el('ul', { class: 'rows' }, devices.map((d) => el('li', {},
      el('div', {}, el('strong', {}, d.name), ` · ${d.label || ''}`, d.kind === 'screen' ? T.pair.screenTag : ''),
      el('div', { class: 'muted' }, T.devLine(when(d.created_at), d.place, when(d.last_used_at))),
      // a new device of a resident sends commands only after 24 h, or once released here
      d.kind === 'browser' && !d.commands_ok_at && Date.now() - Date.parse(d.created_at) < 864e5
        ? el('button', { onclick: () => guarded(async () => { await api('POST', `/api/admin/devices/${d.id}/commands`, {}); toast(T.commands.released); adminView() }) }, T.commands.release) : null,
      d.id === ME.session_id ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/admin/devices/${d.id}`); adminView() }) }, T.disconnect)))))

  const auditCard = el('section', { class: 'card' }, el('h2', {}, T.audit),
    el('button', { class: 'link', onclick: () => guarded(async () => {
      const rows = await rawApi('GET', '/api/admin/audit')
      auditCard.replaceChildren(el('h2', {}, T.audit), el('ul', { class: 'rows small' }, rows.map((a) =>
        el('li', {}, `${when(a.at)} · ${a.name || '-'} · ${a.strength || ''} · ${a.action}${a.target ? ' · ' + a.target : ''}${a.place ? ' · ' + a.place : ''}`))))
    }) }, T.showAudit))

  // fixed screens: type the code shown on the screen (or arrive here from its QR)
  const pairCode = el('input', { placeholder: T.pair.codePlaceholder, maxlength: 12, value: adminView.pairCode || '', autocapitalize: 'characters' })
  adminView.pairCode = ''
  const pairInfo = el('div')
  const screenSel = el('select', {}, el('option', { value: '' }, T.pair.newScreen), screens.map((s) => el('option', { value: s.id }, s.name)))
  const screenName = el('input', { placeholder: T.pair.screenName, maxlength: 40 })
  screenSel.addEventListener('change', () => { screenName.hidden = !!screenSel.value })
  const lookup = async () => {
    const code = pairCode.value.trim()
    if (!code) return
    try {
      const p = await rawApi('GET', `/api/admin/pair?code=${encodeURIComponent(code)}`)
      pairInfo.replaceChildren(
        el('p', { class: 'muted' }, T.pair.asking(p.label || T.device, p.place, when(p.created_at), p.ip)),
        p.same_ip ? null : el('p', { class: 'danger-box' }, p.other_ip_refused ? T.pair.otherIpRefused(p.ip, p.admin_ip) : T.pair.otherIp(p.ip, p.admin_ip)))
    } catch (e) { pairInfo.replaceChildren(el('p', { class: 'muted' }, e.message)) }
  }
  pairCode.addEventListener('change', () => guarded(lookup))
  if (pairCode.value) guarded(lookup)
  const screensCard = el('section', { class: 'card' }, el('h2', {}, T.pair.screens),
    screens.length ? el('ul', { class: 'rows' }, screens.map((s) => el('li', {},
      el('strong', {}, s.name), T.devicesCount(s.devices), s.status === 'blocked' ? T.blocked : '',
      s.status === 'blocked'
        ? el('button', { onclick: () => guarded(async () => { await api('POST', `/api/admin/people/${s.id}`, { status: 'active' }); adminView() }) }, T.unblock)
        : confirmButton(T.block, T.confirmBlock, async () => { await api('POST', `/api/admin/people/${s.id}`, { status: 'blocked' }); adminView() })))) : el('p', { class: 'muted' }, T.pair.noScreens),
    el('h3', {}, T.pair.pairTitle),
    pairCode, pairInfo, screenSel, screenName,
    el('button', { onclick: () => guarded(async () => {
      await api('POST', '/api/admin/pair', screenSel.value ? { code: pairCode.value, screen: Number(screenSel.value) } : { code: pairCode.value, name: screenName.value })
      toast(T.pair.approved); adminView()
    }) }, T.pair.approve))

  // machine bridges: one key per machine and tab, shown once
  const tabNames = ME.all_tabs || []
  const mTab = el('select', {}, tabNames.map((t) => el('option', { value: t }, t)))
  const mLabel = el('input', { placeholder: T.bridges.label, maxlength: 40 })
  const newKey = el('div')
  const bridgesCard = el('section', { class: 'card' }, el('h2', {}, T.bridges.title),
    machines.length ? el('ul', { class: 'rows' }, machines.map((m) => el('li', {},
      el('div', {}, el('strong', {}, `${m.tab} · ${m.label}`), m.revoked_at ? T.bridges.revoked : ''),
      el('div', { class: 'muted' }, T.bridges.line(when(m.created_at), when(m.last_used_at), m.last_ip)),
      m.revoked_at ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/admin/machines/${m.id}`); adminView() }) }, T.revoke)))) : el('p', { class: 'muted' }, T.bridges.none),
    tabNames.length ? [el('h3', {}, T.bridges.add), mTab, mLabel,
      el('button', { onclick: () => guarded(async () => {
        const r = await api('POST', '/api/admin/machines', { tab: mTab.value, label: mLabel.value })
        newKey.replaceChildren(el('p', {}, T.bridges.copyOnce), el('p', { class: 'code' }, r.key),
          el('button', { onclick: () => navigator.clipboard.writeText(r.key).then(() => toast(T.bridges.copied)) }, T.bridges.copy))
      }) }, T.bridges.create), newKey] : null)

  // commands: the brake, and Shortcuts keys (one per device and shortcut, shown once)
  const brakeCard = el('section', { class: 'card' }, el('h2', {}, T.commands.title),
    el('p', { class: ME.commands_off ? 'danger-box' : 'muted' }, ME.commands_off ? T.commands.offNow : T.commands.onNow),
    el('button', { class: ME.commands_off ? '' : 'danger', onclick: () => guarded(async () => {
      await api('POST', '/api/admin/commands', { off: !ME.commands_off }); await start(); adminView()
    }) }, ME.commands_off ? T.commands.turnOn : T.commands.turnOff))

  const kLabel = el('input', { placeholder: T.shortcuts.label, maxlength: 60 })
  const kBoxes = el('span', { class: 'boxes' }, shortcuts.available.map((a) =>
    el('label', {}, el('input', { type: 'checkbox', name: 'kscope', value: `${a.tab}/${a.action}` }), `${a.tab} · ${a.action}`)))
  const kNew = el('div')
  const shortcutsCard = el('section', { class: 'card' }, el('h2', {}, T.shortcuts.title),
    shortcuts.keys.length ? el('ul', { class: 'rows' }, shortcuts.keys.map((k) => el('li', {},
      el('div', {}, el('strong', {}, k.label), k.revoked_at ? T.shortcuts.revoked : ''),
      el('div', { class: 'muted' }, k.scope.join(', ')),
      el('div', { class: 'muted' }, T.shortcuts.line(when(k.created_at), when(k.last_used_at), k.last_ip, k.last_place)),
      k.revoked_at ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/me/shortcuts/${k.id}`); adminView() }) }, T.revoke)))) : el('p', { class: 'muted' }, T.shortcuts.none),
    shortcuts.available.length ? [el('h3', {}, T.shortcuts.add), kLabel, kBoxes,
      el('button', { onclick: () => guarded(async () => {
        const scope = [...kBoxes.querySelectorAll('input[name="kscope"]:checked')].map((i) => i.value)
        const r = await api('POST', '/api/me/shortcuts', { label: kLabel.value, scope })
        kNew.replaceChildren(el('p', {}, T.shortcuts.copyOnce), el('p', { class: 'code' }, r.key),
          el('button', { onclick: () => navigator.clipboard.writeText(r.key).then(() => toast(T.bridges.copied)) }, T.bridges.copy))
      }) }, T.shortcuts.create), kNew] : el('p', { class: 'muted' }, T.shortcuts.noActions))


  // house agents: one key per agent, shown once; what they ask waits here for a Face ID
  const aLabel = el('input', { placeholder: T.agents.label, maxlength: 40 })
  const newAgentKey = el('div')
  const agentsCard = el('section', { class: 'card' }, el('h2', {}, T.agents.title),
    agentReqs.length ? el('ul', { class: 'rows' }, agentReqs.map((r) => el('li', {},
      el('strong', {}, r.kind === 'pair' ? T.agentReq.pairTitle(r.name) : T.agentReq.changeTitle(r.name)),
      el('span', { class: 'muted' }, ` · ${r.agent || T.agentReq.anAgent} · ${when(r.created_at)}`),
      el('button', { onclick: () => guarded(() => agentRequestView(r.id)) }, T.agents.see)))) : null,
    agents.length ? el('ul', { class: 'rows' }, agents.map((a) => el('li', {},
      el('div', {}, el('strong', {}, a.label), a.revoked_at ? T.bridges.revoked : ''),
      el('div', { class: 'muted' }, T.bridges.line(when(a.created_at), when(a.last_used_at), a.last_ip)),
      a.revoked_at ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/admin/agents/${a.id}`); adminView() }) }, T.revoke)))) : el('p', { class: 'muted' }, T.agents.none),
    el('p', { class: 'muted' }, T.agents.what),
    el('h3', {}, T.agents.add), aLabel,
    el('button', { onclick: () => guarded(async () => {
      const r = await api('POST', '/api/admin/agents', { label: aLabel.value })
      newAgentKey.replaceChildren(el('p', {}, T.agents.copyOnce), el('p', { class: 'code' }, r.key),
        el('button', { onclick: () => navigator.clipboard.writeText(r.key).then(() => toast(T.bridges.copied)) }, T.bridges.copy))
    }) }, T.bridges.create), newAgentKey)

  show(nav(), passkeyCard, reqCard, agentsCard, screensCard, peopleCard, groupsCard, devicesCard, brakeCard, shortcutsCard, bridgesCard, auditCard)
}

// ------------------------------------------------------------------ boot
async function start() {
  clearTimeout(pollTimer)
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
    show(el('p', { class: 'card' }, T.offline))
    return
  }
  $who.textContent = ME.person.name
  renderAlerts()
  const q = new URLSearchParams(location.search)
  const stepUp = q.get('step_up')
  if (stepUp && /^[a-z][a-z0-9-]{0,30}$/.test(stepUp)) return stepUpView(stepUp)
  const agentReq = q.get('agent_request')
  if (agentReq && /^\d{1,12}$/.test(agentReq) && ME.admin) {
    if (!onAccount()) { location.replace(`${ACCOUNT}?agent_request=${agentReq}`); return }
    accountTitle()
    return guarded(() => agentRequestView(Number(agentReq)))
  }
  const n = nextPath()
  if (n && ME.credential === 'screen') { location.href = n; return }
  if (!onAccount()) {
    // the pairing QR lands on "/?pair=": hand it to the account page
    if (q.get('pair') && ME.admin) { location.replace(`${ACCOUNT}?pair=${encodeURIComponent(q.get('pair').slice(0, 12))}`); return }
    return openLastTab()
  }
  accountTitle()
  if (q.get('pair') && ME.admin) {
    adminView.pairCode = q.get('pair').slice(0, 12)
    history.replaceState(null, '', ACCOUNT)
    return guarded(adminView)
  }
  guarded(devicesView)
}

start()
