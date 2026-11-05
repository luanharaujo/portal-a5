// Portal A5 page. No framework, no innerHTML: every value from the server goes in as text.
'use strict'

const $main = document.getElementById('main')
const $who = document.getElementById('who')
const $alerts = document.getElementById('alerts')
const $toast = document.getElementById('toast')
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

async function passkeyCheck() {
  const o = await rawApi('POST', '/api/passkey/get/options', {})
  const cred = await navigator.credentials.get({
    publicKey: { ...o, challenge: b64uToBuf(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) })) },
  })
  const r = cred.response
  await rawApi('POST', '/api/passkey/get/verify', {
    id: cred.id,
    clientDataJSON: bufToB64u(r.clientDataJSON),
    authenticatorData: bufToB64u(r.authenticatorData),
    signature: bufToB64u(r.signature),
  })
}

// ------------------------------------------------------------------ login
function nextPath() {
  const n = new URLSearchParams(location.search).get('next') || ''
  return /^\/[a-z][a-z0-9-]*(\/|$)/.test(n) ? n : null
}

function loginView() {
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
  show(form)
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

// ------------------------------------------------------------------ home
function nav() {
  return el('nav', { class: 'nav' },
    el('button', { onclick: () => homeView() }, T.nav.home),
    el('button', { onclick: () => guarded(devicesView) }, T.nav.devices),
    ME.admin ? el('button', { onclick: () => guarded(adminView) }, T.nav.admin) : null,
    el('button', { class: 'link', onclick: () => guarded(async () => { await rawApi('POST', '/api/logout', {}); start() }) }, T.nav.logout))
}

function renderAlerts() {
  const list = ME.alerts || []
  $alerts.replaceChildren(...list.map((a) => el('div', { class: 'alert' },
    el('strong', {}, T.newDevice(ME.person.name)),
    `${a.label || T.device}, ${when(a.created_at)}${a.place ? ', ' + a.place : ''}${a.current ? T.thisDevice : ''}. `,
    el('button', { onclick: () => guarded(async () => { await api('POST', `/api/me/alerts/${a.id}/ack`, {}); await start() }) }, T.itWasMe),
    a.current || !a.live ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/me/devices/${a.session_id}`); await start() }) }, T.revoke))))
}

function homeView() {
  const tabs = ME.tabs.includes('*') ? [] : ME.tabs
  show(nav(), el('section', { class: 'card' },
    el('h2', {}, T.tabs),
    tabs.length ? el('ul', { class: 'tabs' }, tabs.map((t) => el('li', {}, el('a', { href: `/${t}/` }, t))))
      : el('p', { class: 'muted' }, T.noTabs)))
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
  const [people, groups, requests, devices] = await Promise.all([
    rawApi('GET', '/api/admin/people'), rawApi('GET', '/api/admin/groups'),
    rawApi('GET', '/api/admin/requests'), rawApi('GET', '/api/admin/devices'),
  ])
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
        el('button', { class: p.status === 'blocked' ? '' : 'danger', onclick: () => guarded(async () => {
          await api('POST', `/api/admin/people/${p.id}`, { status: p.status === 'blocked' ? 'active' : 'blocked' }); adminView()
        }) }, p.status === 'blocked' ? T.unblock : T.block),
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
      el('div', {}, el('strong', {}, d.name), ` · ${d.label || ''}`),
      el('div', { class: 'muted' }, T.devLine(when(d.created_at), d.place, when(d.last_used_at))),
      d.id === ME.session_id ? null : el('button', { class: 'danger', onclick: () => guarded(async () => { await api('DELETE', `/api/admin/devices/${d.id}`); adminView() }) }, T.disconnect)))))

  const auditCard = el('section', { class: 'card' }, el('h2', {}, T.audit),
    el('button', { class: 'link', onclick: () => guarded(async () => {
      const rows = await rawApi('GET', '/api/admin/audit')
      auditCard.replaceChildren(el('h2', {}, T.audit), el('ul', { class: 'rows small' }, rows.map((a) =>
        el('li', {}, `${when(a.at)} · ${a.name || '-'} · ${a.strength || ''} · ${a.action}${a.target ? ' · ' + a.target : ''}${a.place ? ' · ' + a.place : ''}`))))
    }) }, T.showAudit))

  show(nav(), passkeyCard, reqCard, peopleCard, groupsCard, devicesCard, auditCard)
}

// ------------------------------------------------------------------ boot
async function start() {
  clearTimeout(pollTimer)
  try {
    ME = await rawApi('GET', '/api/me')
  } catch (e) {
    ME = null
    if (e instanceof ApiError && e.status === 401) return loginView()
    show(el('p', { class: 'card' }, T.offline))
    return
  }
  $who.textContent = ME.person.name
  renderAlerts()
  homeView()
}

start()
