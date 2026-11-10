// Face ID on entry, in place (docs/TABS.md, "Face ID on entry"). The worker serves this page at the
// tab's own address, with a fresh challenge for "entry:<tab>" in #a5-entry, instead of sending the
// person to the portal's step-up page and back. The Face ID prompt opens on load (Safari allows one
// call without a tap per navigation); a reload of the same address then burns the 60 s grant and the
// worker serves the tab itself. After a cancel the page fetches new options at once and shows one
// button, whose tap calls the prompt with nothing awaited before it (iOS wants the tap).
'use strict'
;(() => {
  const box = document.getElementById('a5-entry')
  let data
  try { data = JSON.parse(box.textContent) } catch { return }
  if (!data || !/^[a-z][a-z0-9-]{0,30}$/.test(data.tab || '') || !data.options) return
  const T = (window.T && window.T.entry) || {}
  const go = document.getElementById('a5-entry-go')
  const msg = document.getElementById('a5-entry-msg')
  let options = data.options
  let busy = false

  const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer
  const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const post = (path, body) => fetch(path, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'X-Portal': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  // reload, not replace(href): with a #fragment in the address replace() would only move the fragment
  const enter = () => location.reload()

  function say(text, button) {
    msg.textContent = text || ''
    if (button) { go.textContent = T.button || ''; go.hidden = false } else go.hidden = true
  }

  // new options after any prompt (they serve once); signed out or the entry already done: reload
  async function fresh() {
    options = null
    try {
      const r = await post('/api/passkey/get/options', { purpose: 'entry:' + data.tab })
      if (r.status === 401) return enter()
      if (!r.ok) return say(T.failed, false)
      options = await r.json()
      say(T.why, true)
    } catch { say(T.offline, true) }
  }

  function ask() {
    if (busy) return
    if (!options) { fresh(); return }
    busy = true
    const o = options
    options = null
    let p
    try {
      p = navigator.credentials.get({ publicKey: {
        ...o, challenge: b64uToBuf(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) })),
      } })
    } catch (e) { p = Promise.reject(e) }
    p.then(async (cred) => {
      const res = cred.response
      const r = await post('/api/passkey/get/verify', {
        id: cred.id,
        clientDataJSON: bufToB64u(res.clientDataJSON),
        authenticatorData: bufToB64u(res.authenticatorData),
        signature: bufToB64u(res.signature),
      })
      if (!r.ok) throw new Error('verify')
      enter()
    }).catch((e) => {
      busy = false
      // cancelled: nothing to say, the button is the way back in
      say(e && e.name === 'NotAllowedError' ? T.why : T.failed, false)
      fresh()
    })
  }

  go.addEventListener('click', ask)
  say(T.why, false)
  if (!window.PublicKeyCredential) { say(T.unsupported, false); return }
  // the prompt opens by itself only when the person came from the portal or typed the address
  if (data.auto === false) { say(T.why, true); return }
  if (!document.hidden) ask()
  else document.addEventListener('visibilitychange', function once() {
    if (document.hidden) return
    document.removeEventListener('visibilitychange', once)
    ask()
  })
})()
