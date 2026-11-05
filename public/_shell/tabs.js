// Shared tab selector, served by the portal for every tab (docs/TABS.md, section 9).
// A page marks its own title with data-a5-tabs and loads, in this order:
//   /locale/pt-BR.js  /_shell/tabs.js  (and /_shell/tabs.css)
// The script adds the arrow and the dot, and turns the title into a menu button. Without a
// selector (fixed screens, signed out, any error) the title stays a plain title.
// No HTML strings anywhere: every value goes in as text.
(() => {
  'use strict'
  const KEY = 'a5.lastTab'
  const SVG = 'http://www.w3.org/2000/svg'
  const text = () => (window.A5_TEXT && window.A5_TEXT.shell) || {}

  // localStorage can be missing or throw (private mode, blocked storage): never fatal
  const lastTab = () => { try { return localStorage.getItem(KEY) } catch { return null } }
  const remember = (id) => { try { localStorage.setItem(KEY, id) } catch { /* nothing to keep */ } }

  const pathTab = () => {
    if (location.pathname === '/conta/') return 'conta'
    const m = /^\/([a-z][a-z0-9-]{0,30})\//.exec(location.pathname)
    return m ? m[1] : null
  }

  async function load(current) {
    const q = current ? '?current=' + encodeURIComponent(current) : ''
    try {
      const r = await fetch('/api/tabs' + q, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      return r.ok ? await r.json() : null
    } catch { return null }
  }

  const nameOf = (id) => (text().tabNames && text().tabNames[id]) || id
  const shown = (n) => (n > 9 ? '9+' : String(n))

  function node(tag, cls, ...kids) {
    const e = document.createElement(tag)
    if (cls) e.className = cls
    for (const k of kids) if (k != null) e.append(k)
    return e
  }

  function arrow() {
    const s = document.createElementNS(SVG, 'svg')
    s.setAttribute('viewBox', '0 0 12 12')
    s.setAttribute('class', 'a5-tabs-arrow')
    s.setAttribute('aria-hidden', 'true')
    const p = document.createElementNS(SVG, 'path')
    p.setAttribute('d', 'M2 4l4 4 4-4')
    s.append(p)
    return s
  }

  // Sum of what waits in the other tabs (the current one is already on screen).
  const othersTotal = (data) => data.tabs.reduce((n, t) => n + (t.id !== data.current && t.badge ? t.badge : 0), 0)

  async function mount(title) {
    if (!title || title.dataset.a5TabsOn) return
    title.dataset.a5TabsOn = 'pending'
    let data = await load(pathTab())
    if (!data || !data.selector) { delete title.dataset.a5TabsOn; return }
    title.dataset.a5TabsOn = '1'
    if (data.current) remember(data.current)

    if (title.tagName !== 'BUTTON') { title.setAttribute('role', 'button'); title.tabIndex = 0 }
    title.classList.add('a5-tabs-title')
    title.setAttribute('aria-haspopup', 'menu')
    title.setAttribute('aria-expanded', 'false')
    const sr = node('span', 'a5-tabs-sr', ', ' + (text().switchTab || ''))
    const dot = node('span', 'a5-tabs-dot')
    title.append(arrow(), dot, sr)

    let menu = null
    let backdrop = null
    let items = []
    let picks = []

    function paintDot() {
      const n = othersTotal(data)
      dot.hidden = !n
      dot.textContent = n ? shown(n) : ''
      sr.textContent = ', ' + (text().switchTab || '') + (n && text().waiting ? ', ' + text().waiting(n) : '')
    }

    function entries() {
      const list = data.tabs.map((t) => ({ id: t.id, path: t.path, badge: t.badge, hint: t.entry === 'passkey' ? text().passkeyHint : null }))
      list.push({ id: data.account.id, path: data.account.path, badge: null, hint: text().hints && text().hints[data.account.id], account: true })
      return list
    }

    function render(focusAt) {
      menu.replaceChildren()
      items = []
      picks = []
      for (const e of entries()) {
        if (e.account) menu.append(node('div', 'a5-tabs-sep'))
        const current = e.id === data.current
        const it = node('button', 'a5-tabs-item' + (current ? ' a5-tabs-current' : ''),
          node('span', 'a5-tabs-check', current ? '✓' : ''),
          node('span', 'a5-tabs-name', nameOf(e.id)),
          e.hint ? node('span', 'a5-tabs-hint', e.hint) : null,
          e.badge ? node('span', 'a5-tabs-dot', shown(e.badge)) : null)
        it.type = 'button'
        it.setAttribute('role', 'menuitem')
        it.tabIndex = -1
        if (current) it.setAttribute('aria-current', 'page')
        if (e.badge && text().waiting) it.setAttribute('aria-label', `${nameOf(e.id)}, ${text().waiting(e.badge)}`)
        it.addEventListener('click', () => choose(e))
        menu.append(it)
        items.push(it)
        picks.push(e)
      }
      const at = Math.max(0, Math.min(focusAt, items.length - 1))
      items[at].focus()
    }

    function place() {
      const r = title.getBoundingClientRect()
      menu.style.top = `${Math.round(r.bottom + window.scrollY + 6)}px`
      const left = Math.max(8, Math.min(r.left, window.innerWidth - menu.offsetWidth - 8))
      menu.style.left = `${Math.round(left + window.scrollX)}px`
    }

    function open() {
      if (menu) return
      backdrop = node('div', 'a5-tabs-backdrop')
      backdrop.addEventListener('click', close)
      menu = node('div', 'a5-tabs-menu')
      menu.setAttribute('role', 'menu')
      menu.setAttribute('aria-label', text().menuLabel || '')
      menu.addEventListener('keydown', onKey)
      document.body.append(backdrop, menu)
      const cur = entries().findIndex((e) => e.id === data.current)
      render(cur < 0 ? 0 : cur)
      place()
      title.setAttribute('aria-expanded', 'true')
      window.addEventListener('resize', close)
      // fresh counts each time the list opens (the portal keeps them a minute)
      refresh().then(() => { if (menu) render(items.indexOf(document.activeElement)) })
    }

    function close() {
      if (!menu) return
      menu.remove()
      backdrop.remove()
      menu = backdrop = null
      items = []
      picks = []
      title.setAttribute('aria-expanded', 'false')
      window.removeEventListener('resize', close)
      title.focus()
    }

    function choose(e) {
      if (e.id === data.current) { close(); return }
      remember(e.id)
      location.assign(e.path)
    }

    function onKey(ev) {
      const i = items.indexOf(document.activeElement)
      const go = (n) => { ev.preventDefault(); items[(n + items.length) % items.length].focus() }
      if (ev.key === 'ArrowDown') go(i + 1)
      else if (ev.key === 'ArrowUp') go(i - 1)
      else if (ev.key === 'Home') go(0)
      else if (ev.key === 'End') go(items.length - 1)
      else if (ev.key === 'Tab') go(ev.shiftKey ? i - 1 : i + 1) // focus stays in the list while it is open
      else if (ev.key === 'Escape') { ev.preventDefault(); close() }
      // handled here, not left to the button's own click: some TV remotes send only keydown
      else if ((ev.key === 'Enter' || ev.key === ' ') && i >= 0) { ev.preventDefault(); choose(picks[i]) }
    }

    async function refresh() {
      const d = await load(pathTab())
      if (d && d.selector) { data = d; paintDot() }
    }

    title.addEventListener('click', (ev) => { ev.preventDefault(); menu ? close() : open() })
    title.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'ArrowDown') { ev.preventDefault(); menu ? close() : open() }
    })
    // no polling: counts come back when the page loads, the list opens or the page is seen again
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refresh() })
    paintDot()
  }

  window.A5Tabs = { mount, load, lastTab, remember }
  const auto = () => { const t = document.querySelector('[data-a5-tabs]'); if (t) mount(t) }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', auto)
  else auto()
})()
