// Shared tab selector, served by the portal for every tab (docs/TABS.md, section 9).
// A page marks its own title with data-a5-tabs and loads, in this order:
//   /locale/pt-BR.js  /_shell/tabs.js  (and /_shell/tabs.css)
// The script adds the arrow and the dot, and turns the title into a menu button. Without a
// selector (fixed screens, signed out, any error) the title stays a plain title.
// It also gives every signed-in page pull to refresh (a tab with its own sets
// <html data-a5-pull="own">) and, for an admin, "see as" another group (docs/TABS.md, section 9).
// No HTML strings anywhere: every value goes in as text.
(() => {
  'use strict'
  const KEY = 'a5.lastTab'
  // the rehearsal: seeing as this group, starting from the signed-out pages (app.js reads the flag)
  const REHEARSAL_GROUP = 'residents'
  const REHEARSAL_OUT = 'a5.rehearsalOut'
  const SCREEN_GROUP = 'owner-screens'
  const SVG = 'http://www.w3.org/2000/svg'
  const text = () => (window.A5_TEXT && window.A5_TEXT.shell) || {}
  const madeUp = () => (window.A5_TEXT && window.A5_TEXT.rehearsal && window.A5_TEXT.rehearsal.name) || ''

  // localStorage can be missing or throw (private mode, blocked storage): never fatal
  const lastTab = () => { try { return localStorage.getItem(KEY) } catch { return null } }
  const remember = (id) => { try { localStorage.setItem(KEY, id) } catch { /* nothing to keep */ } }

  const backUrl = () => '/conta/?owner=1&next=' + encodeURIComponent(location.pathname + location.search)

  const portalPage = () => location.pathname === '/' || location.pathname === '/conta/'

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

  async function setView(group) {
    try {
      const r = await fetch('/api/tabs?current=' + encodeURIComponent(pathTab() || ''), {
        method: 'POST', credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Portal': '1' },
        body: JSON.stringify({ view_as: group }),
      })
      return r.ok ? await r.json() : null
    } catch { return null }
  }

  // a tab's name comes with the list (portal configuration); the account's from the locale
  const nameOf = (e) => e.label || (text().tabNames && text().tabNames[e.id]) || e.id
  const groupName = (g) => (text().groupNames && text().groupNames[g.id]) || g.name || g.id
  const viewName = (g) => (text().viewNames && text().viewNames[g.id]) || g.name || g.id
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

  // Fixed line drawings (24x24, stroke only, current color), picked by name in the tab's
  // configuration. Only these shapes are ever drawn; an unknown name draws nothing.
  const ICONS = {
    bolt: [['path', { d: 'M13 2 4 14h7l-1 8 9-12h-7z' }]],
    mic: [['rect', { x: 9, y: 3, width: 6, height: 11, rx: 3 }], ['path', { d: 'M5 11a7 7 0 0 0 14 0M12 18v3' }]],
    terminal: [['rect', { x: 3, y: 4, width: 18, height: 14, rx: 2 }], ['path', { d: 'm7 9 3 3-3 3M13 15h4' }]],
    coin: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M15 9.5c-.5-1-1.6-1.5-3-1.5-1.7 0-3 .8-3 2s1.3 1.7 3 2 3 .8 3 2-1.3 2-3 2c-1.4 0-2.5-.5-3-1.5M12 6v2M12 16v2' }]],
    grid: [['rect', { x: 4, y: 4, width: 6, height: 6, rx: 1 }], ['rect', { x: 14, y: 4, width: 6, height: 6, rx: 1 }], ['rect', { x: 4, y: 14, width: 6, height: 6, rx: 1 }], ['rect', { x: 14, y: 14, width: 6, height: 6, rx: 1 }]],
    person: [['circle', { cx: 12, cy: 8, r: 4 }], ['path', { d: 'M4 21c1-4 4-6 8-6s7 2 8 6' }]],
    eye: [['path', { d: 'M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
    back: [['path', { d: 'M9 14 4 9l5-5' }], ['path', { d: 'M4 9h10a6 6 0 0 1 0 12h-3' }]],
    power: [['path', { d: 'M12 3v8' }], ['path', { d: 'M6.3 6.3a8 8 0 1 0 11.4 0' }]],
    flask: [['path', { d: 'M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3' }], ['path', { d: 'M7.5 15h9' }]],
    screen: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ['path', { d: 'M8 20h8M12 16v4' }]],
  }

  function icon(name) {
    const parts = Object.prototype.hasOwnProperty.call(ICONS, name) ? ICONS[name] : null
    if (!parts) return null
    const s = document.createElementNS(SVG, 'svg')
    s.setAttribute('viewBox', '0 0 24 24')
    s.setAttribute('class', 'a5-tabs-icon')
    s.setAttribute('aria-hidden', 'true')
    for (const [tag, attrs] of parts) {
      const e = document.createElementNS(SVG, tag)
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v))
      s.append(e)
    }
    return s
  }

  // Sum of what waits in the other tabs (the current one is already on screen).
  const othersTotal = (data) => data.view_as ? 0 : data.tabs.reduce((n, t) => n + (t.id !== data.current && t.badge ? t.badge : 0), 0)

  // the yellow rehearsal bar on a tab page (the portal's own pages draw theirs in app.js)
  function band(data) {
    const on = !!data.view_as
    document.documentElement.toggleAttribute('data-a5-rehearsal', on)
    const old = document.querySelector('.a5-rehearsal')
    if (!on) { if (old) old.remove(); return }
    const b = text().band || {}
    const go = node('button', null, b.back || '')
    go.type = 'button'
    go.addEventListener('click', () => location.assign(backUrl()))
    const bar = node('div', 'a5-rehearsal', node('b', null, b.label || ''), node('span', null, b.state ? b.state(data.view_as.id, groupName(data.view_as)) : ''), go)
    bar.setAttribute('role', 'status')
    if (old) old.replaceWith(bar); else document.body.prepend(bar)
  }

  // "<first name> · <group>": whoever holds the page
  function whoLine(data) {
    const w = data.who
    if (!w) return null
    const name = data.view_as ? madeUp() : String(w.name || '').trim().split(/\s+/)[0]
    const g = data.view_as ? viewName(data.view_as) : ((text().whoGroups || {})[w.group] || '')
    return [name, g].filter(Boolean).join(' · ')
  }

  async function mount(title) {
    if (!title || title.dataset.a5TabsOn) return
    title.dataset.a5TabsOn = 'pending'
    let data = await load(pathTab())
    if (!data || !data.selector) { delete title.dataset.a5TabsOn; return }
    title.dataset.a5TabsOn = '1'
    if (data.current) remember(data.current)
    pull()

    if (title.tagName !== 'BUTTON') { title.setAttribute('role', 'button'); title.tabIndex = 0 }
    title.classList.add('a5-tabs-title')
    title.setAttribute('aria-haspopup', 'menu')
    title.setAttribute('aria-expanded', 'false')
    const sr = node('span', 'a5-tabs-sr', ', ' + (text().switchTab || ''))
    const dot = node('span', 'a5-tabs-dot')
    title.append(arrow(), dot, sr)
    // seen as someone else: a mark next to the title, always visible while the mode is on
    const mark = node('span', 'a5-tabs-viewas')
    mark.hidden = true
    title.after(mark)

    let menu = null
    let backdrop = null
    let items = []
    let picks = []

    function paintDot() {
      const n = othersTotal(data)
      dot.hidden = !n
      dot.textContent = n ? shown(n) : ''
      sr.textContent = ', ' + (text().switchTab || '') + (n && text().waiting ? ', ' + text().waiting(n) : '')
      const v = data.view_as
      mark.hidden = !v
      mark.textContent = v && text().seeingAs ? text().seeingAs(groupName(v)) : ''
      document.documentElement.toggleAttribute('data-a5-viewas', !!v)
      if (!portalPage()) band(data)
    }

    // the account's hint lists what this person finds there: admins see more
    function accountHint() {
      const h = text().hints || {}
      const admin = !data.view_as && (data.view_options || []).length > 0
      return admin ? h[data.account.id] : (h[data.account.id + 'Resident'] || h[data.account.id])
    }

    function entries() {
      const t = text()
      const list = []
      if (data.view_as) list.push({ id: '_back', label: t.backToOwner, icon: 'back', view: null, back: true, hint: t.backHint ? t.backHint(groupName(data.view_as)) : null })
      for (const tab of data.tabs) list.push({ id: tab.id, path: tab.path, label: tab.label, icon: tab.icon, badge: tab.badge, hint: tab.hint || (tab.entry === 'passkey' ? t.passkeyHint : null) })
      // the residents first, the screens' group after them
      // while seeing as someone else the list is that group's own: back first, no other view
      const views = data.view_as ? [] : [...(data.view_options || [])].sort((a, b) => (a.id === SCREEN_GROUP) - (b.id === SCREEN_GROUP))
      let caps = !!views.length
      for (const g of views) {
        list.push({ id: '_view:' + g.id, label: viewName(g), icon: g.id === SCREEN_GROUP ? 'screen' : 'eye', view: g.id, hint: t.seeAsHint, caps })
        caps = false
      }
      if (views.some((g) => g.id === REHEARSAL_GROUP)) list.push({ id: '_rehearsal', label: madeUp(), icon: 'flask', view: REHEARSAL_GROUP, out: true, hint: t.rehearsalHint, caps })
      list.push({ id: data.account.id, path: data.account.path, icon: 'person', badge: null, hint: accountHint(), account: true })
      return list
    }

    // the house on top: night when the list is dark (the tabs), day when it follows a light theme
    function head() {
      const bg = getComputedStyle(menu).backgroundColor.match(/\d+(\.\d+)?/g) || ['0', '0', '0']
      const light = (0.299 * bg[0] + 0.587 * bg[1] + 0.114 * bg[2]) > 140
      const art = node('img', 'a5-tabs-art')
      art.alt = ''
      art.src = `/art/house-${light ? 'day' : 'night'}-wide.svg`
      const logo = node('img')
      logo.alt = ''
      logo.src = '/favicon.svg'
      const line = whoLine(data)
      return node('div', 'a5-tabs-head', art, node('div', 'a5-tabs-brand', logo, node('span', null, text().portal || '', line ? node('small', null, line) : null)))
    }

    function render(focusAt) {
      menu.replaceChildren(head())
      items = []
      picks = []
      for (const e of entries()) {
        if (e.account) menu.append(node('div', 'a5-tabs-sep'))
        if (e.caps) menu.append(node('div', 'a5-tabs-sep'), node('span', 'a5-tabs-caps', text().seeAsCaps || ''))
        const current = e.id === data.current
        const drawn = icon(e.icon)
        // no drawing: the first letter of the name on the gray tile
        const tile = node('span', 'a5-tabs-tile', drawn || node('span', 'a5-tabs-letter', String(nameOf(e) || '').charAt(0).toUpperCase()))
        if (drawn) tile.dataset.icon = e.icon
        const it = node('button', 'a5-tabs-item' + (current ? ' a5-tabs-current' : '') + (e.back ? ' a5-tabs-back' : 'view' in e ? ' a5-tabs-view' : ''),
          tile,
          node('span', 'a5-tabs-text', node('span', 'a5-tabs-name', nameOf(e)), e.hint ? node('span', 'a5-tabs-hint', e.hint) : null),
          e.badge ? node('span', 'a5-tabs-dot', shown(e.badge)) : null,
          node('span', 'a5-tabs-check', current ? '✓' : ''))
        it.type = 'button'
        it.setAttribute('role', 'menuitem')
        it.tabIndex = -1
        if (current) it.setAttribute('aria-current', 'page')
        if (e.badge && text().waiting) it.setAttribute('aria-label', `${nameOf(e)}, ${text().waiting(e.badge)}`)
        it.addEventListener('click', () => choose(e))
        menu.append(it)
        items.push(it)
        picks.push(e)
      }
      if (focusAt >= 0) focusItem(focusAt)
    }

    // never scroll the page to the list: the item is kept in view inside the list instead
    function focusItem(i) {
      const it = items[Math.max(0, Math.min(i, items.length - 1))]
      it.focus({ preventScroll: true })
      if (it.offsetTop + it.offsetHeight > menu.scrollTop + menu.clientHeight) menu.scrollTop = it.offsetTop + it.offsetHeight - menu.clientHeight + 8
      else if (it.offsetTop < menu.scrollTop) menu.scrollTop = Math.max(0, it.offsetTop - 8)
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
      // drawn and placed next to the title first, focused after (the focus never scrolls the page)
      render(-1)
      place()
      focusItem(cur < 0 ? 0 : cur)
      title.setAttribute('aria-expanded', 'true')
      window.addEventListener('resize', close)
      // fresh counts each time the list opens (the portal keeps them a minute)
      refresh().then(() => { if (menu) render(Math.max(0, items.indexOf(document.activeElement))) })
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

    let switching = false
    async function choose(e) {
      // back to the owner asks for Face ID, which only the portal page can do (the tabs' CSP)
      if ('view' in e && e.view === null) { location.assign(backUrl()); return }
      if ('view' in e) {
        if (switching) return
        switching = true
        const d = await setView(e.view)
        switching = false
        if (!d) { close(); return }
        // the rehearsal starts from the signed-out pages (app.js draws them, made up)
        if (e.out) {
          try { sessionStorage.setItem(REHEARSAL_OUT, '1') } catch { /* private mode: it starts signed in */ }
          location.assign('/')
          return
        }
        // stay on this page if the new view still opens it; otherwise its first tab, or the account
        const here = pathTab()
        if (here === 'conta' || d.tabs.some((t) => t.id === here)) { location.reload(); return }
        const go = d.tabs[0] ? d.tabs[0] : d.account
        remember(go.id)
        location.assign(go.path)
        return
      }
      if (e.id === data.current) { close(); return }
      remember(e.id)
      location.assign(e.path)
    }

    function onKey(ev) {
      const i = items.indexOf(document.activeElement)
      const go = (n) => { ev.preventDefault(); focusItem((n + items.length) % items.length) }
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

  // ---------------------------------------------------------------- pull to refresh
  // The home-screen app has no reload button: dragging down at the top of the page reloads it.
  // Only for a signed-in person's own device (the selector is on: never a fixed screen), touch
  // only (a TV remote never starts it), one finger (pinch zoom is left alone), only at the top,
  // and never while the tab list, a sheet, a dialog or a text field is open. A tab with its own
  // sets <html data-a5-pull="own">; a tab marks its open sheets with data-a5-sheet (or uses
  // <dialog open> / aria-modal="true").
  const PULL_LIMIT = 80
  const PULL_MAX = 130
  let pullOn = false

  function pull() {
    if (pullOn || !('ontouchstart' in window)) return
    if (document.documentElement.getAttribute('data-a5-pull') === 'own') return
    pullOn = true
    const words = () => text().pull || {}
    let ind = null
    let label = null
    const build = () => {
      label = node('span', null, words().pull || '')
      ind = node('div', 'a5-pull', node('span', 'a5-pull-arrow', '↓'), label)
      ind.setAttribute('aria-hidden', 'true')
      document.body.append(ind)
    }
    const busy = () => {
      const a = document.activeElement
      if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable)) return true
      return !!document.querySelector('.a5-tabs-menu, .a5-tabs-backdrop, dialog[open], [aria-modal="true"], [data-a5-sheet]:not([hidden])')
    }
    const atTop = () => (document.scrollingElement || document.documentElement).scrollTop <= 0 && window.scrollY <= 0
    // a finger inside a box that scrolls on its own and is not at its top is scrolling that box
    const innerScrolled = (el) => {
      for (let n = el; n && n !== document.body && n !== document.documentElement; n = n.parentElement) if (n.scrollTop > 0) return true
      return false
    }
    let y0 = null
    let x0 = 0
    let pulled = 0
    let active = false
    let loading = false
    const show = (px) => {
      ind.style.setProperty('--a5-pull', px + 'px')
      ind.classList.toggle('a5-pull-on', px > 6)
      ind.classList.toggle('a5-pull-ready', px >= PULL_LIMIT)
      label.textContent = (px >= PULL_LIMIT ? words().release : words().pull) || ''
    }
    const reset = () => { y0 = null; pulled = 0; active = false; if (!loading && ind) show(0) }
    document.addEventListener('touchstart', (e) => {
      if (loading || e.touches.length !== 1) { reset(); return }
      if (busy() || !atTop() || innerScrolled(e.target)) return
      if (!ind) build()
      y0 = e.touches[0].clientY; x0 = e.touches[0].clientX; pulled = 0; active = false
    }, { passive: true })
    document.addEventListener('touchmove', (e) => {
      if (y0 === null || loading) return
      if (e.touches.length !== 1) { reset(); return }
      const dy = e.touches[0].clientY - y0
      const dx = Math.abs(e.touches[0].clientX - x0)
      if (dy <= 0 || dx > dy || !atTop() || busy()) { reset(); return }
      active = true
      pulled = Math.min(PULL_MAX, dy * 0.5)
      show(pulled)
    }, { passive: true })
    document.addEventListener('touchend', () => {
      if (y0 === null) return
      if (active && pulled >= PULL_LIMIT && !busy()) {
        loading = true
        ind.classList.add('a5-pull-loading')
        label.textContent = words().refreshing || ''
        location.reload()
        return
      }
      reset()
    }, { passive: true })
    document.addEventListener('touchcancel', reset, { passive: true })
  }

  window.A5Tabs = { mount, load, lastTab, remember }
  const auto = () => { const t = document.querySelector('[data-a5-tabs]'); if (t) mount(t) }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', auto)
  else auto()
})()
