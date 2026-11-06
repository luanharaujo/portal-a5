// The shared tab selector in a real browser: headless Chrome driven over the DevTools protocol,
// against the same local `wrangler dev` as test_local.mjs (which calls this with its sessions).
// Checks the real tab CSP too: the selector must load and run on a tab page without a violation.
import { spawn } from 'node:child_process'
import { mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export async function launch() {
  const dir = mkdtempSync(join(tmpdir(), 'a5-chrome-'))
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] })
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = ''
    const t = setTimeout(() => reject(new Error('chrome did not start')), 15000)
    proc.stderr.on('data', (d) => {
      buf += d
      const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf)
      if (m) { clearTimeout(t); resolve(m[1]) }
    })
  })
  const ws = new WebSocket(wsUrl)
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j })
  let id = 0
  const pending = new Map()
  const listeners = []
  ws.onmessage = (e) => {
    const m = JSON.parse(String(e.data))
    if (m.id && pending.has(m.id)) {
      const { resolve, reject } = pending.get(m.id)
      pending.delete(m.id)
      m.error ? reject(new Error(m.error.message)) : resolve(m.result)
    } else for (const l of listeners) l(m)
  }
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const i = ++id
    pending.set(i, { resolve, reject })
    ws.send(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) }))
  })
  return { send, listeners, close: () => { try { ws.close() } catch {} proc.kill() } }
}

// One isolated browser context (own cookies and storage) with one page.
export async function page(b, base, cookie, { touch = false } = {}) {
  const { browserContextId } = await b.send('Target.createBrowserContext')
  const { targetId } = await b.send('Target.createTarget', { url: 'about:blank', browserContextId })
  const { sessionId } = await b.send('Target.attachToTarget', { targetId, flatten: true })
  const s = (m, p) => b.send(m, p, sessionId)
  const log = []
  b.listeners.push((m) => {
    if (m.sessionId !== sessionId) return
    if (m.method === 'Log.entryAdded') log.push(m.params.entry.text)
    if (m.method === 'Runtime.exceptionThrown') log.push('exception: ' + m.params.exceptionDetails.text)
  })
  await s('Page.enable'); await s('Runtime.enable'); await s('Log.enable'); await s('Network.enable')
  if (touch) {
    await s('Emulation.setDeviceMetricsOverride', { width: 393, height: 852, deviceScaleFactor: 3, mobile: true })
    await s('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 })
  }
  if (cookie) {
    const [name, value] = cookie.split('=')
    await s('Network.setCookie', { name, value, url: base + '/', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' })
  }
  const evaluate = async (expr) => {
    // a page that is navigating can leave a call unanswered: give up after 5 s
    const r = await Promise.race([s('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }),
      sleep(5000).then(() => { throw new Error('evaluate timed out: ' + expr.slice(0, 80)) })])
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text)
    return r.result.value
  }
  const waitFor = async (expr, ms = 5000) => {
    const end = Date.now() + ms
    while (Date.now() < end) {
      try { if (await evaluate(expr)) return true } catch { /* page still loading */ }
      await sleep(50)
    }
    return false
  }
  const go = async (path) => { await Promise.race([s('Page.navigate', { url: base + path }), sleep(5000)]); await sleep(150) }
  const key = async (k, code = k, vk = 0) => {
    for (const type of ['keyDown', 'keyUp']) await s('Input.dispatchKeyEvent', { type, key: k, code, windowsVirtualKeyCode: vk })
    await sleep(60)
  }
  // one finger dragged straight down from (x, y) by dy pixels, then lifted
  // input and screenshots can wait forever on a page that is reloading: never more than 3 s
  const soon = (m, p) => Promise.race([s(m, p), sleep(3000).then(() => { log.push('timeout: ' + m) })])
  const drag = async (dy, { x = 200, y = 120, fingers = 1 } = {}) => {
    const pts = (yy) => Array.from({ length: fingers }, (_, i) => ({ x: x + i * 40, y: yy, id: i }))
    await soon('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: pts(y) })
    for (let i = 1; i <= 10; i++) await soon('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: pts(y + (dy * i) / 10) })
  }
  const lift = () => soon('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
  const shot = async (file) => {
    await soon('Page.bringToFront')
    const r = await soon('Page.captureScreenshot', { format: 'png' })
    if (!r) return
    const { data } = r
    const { writeFileSync } = await import('node:fs')
    writeFileSync(file, Buffer.from(data, 'base64'))
  }
  return { evaluate, waitFor, go, key, log, drag, lift, shot }
}

// Pull to refresh on one page: true when a long pull reloads it (a marker set on the page is gone).
export async function pulls(p, dy = 260, opts) {
  if (process.env.A5_DEBUG) console.error('pull', dy, JSON.stringify(opts || {}))
  await p.evaluate('window.__stay = 1')
  await p.drag(dy, opts)
  const ready = await p.evaluate(`!!document.querySelector('.a5-pull.a5-pull-ready')`)
  await p.lift()
  const reloaded = await p.waitFor(`window.__stay !== 1 && document.readyState === 'complete'`, 2500)
  return { ready, reloaded }
}

const KEYS = { Enter: ['Enter', 'Enter', 13], Escape: ['Escape', 'Escape', 27], ArrowDown: ['ArrowDown', 'ArrowDown', 40], End: ['End', 'End', 35], Tab: ['Tab', 'Tab', 9] }

export async function browserChecks({ base, check, owner, resident, screen, approve }) {
  if (!existsSync(CHROME)) { console.log('skip browser checks: Chrome not found (set CHROME)'); return }
  const b = await launch()
  // touch pages run in a Chrome of their own: a touch cut short by a reload leaves that
  // browser's input stuck, and later pages in it stop loading
  const spare = []
  const own = async () => { const x = await launch(); spare.push(x); return x }
  try {
    const ON = `document.querySelector('[data-a5-tabs]')?.dataset.a5TabsOn === '1'`
    const press = (p, k) => p.key(...KEYS[k])

    // the owner on a tab page using the selector, under the tab's real CSP
    const o = await page(b, base, owner)
    await o.go('/tab-a/page')
    check('browser: selector mounts on a tab page under the tab CSP', await o.waitFor(ON))
    check('browser: no CSP violation or error on the tab page', !o.log.some((t) => /Content Security Policy|exception/i.test(t)), o.log)
    const t = await o.evaluate(`(() => { const b = document.querySelector('[data-a5-tabs]'); return {
      popup: b.getAttribute('aria-haspopup'), expanded: b.getAttribute('aria-expanded'), svg: !!b.querySelector('svg.a5-tabs-arrow'),
      dot: b.querySelector('.a5-tabs-dot').hidden ? null : b.querySelector('.a5-tabs-dot').textContent, last: localStorage.getItem('a5.lastTab'),
      font: getComputedStyle(b).fontSize === getComputedStyle(b.parentElement).fontSize } })()`)
    check('browser: title is a menu button with an SVG arrow, same size as the title', t.popup === 'menu' && t.expanded === 'false' && t.svg && t.font, t)
    check('browser: dot = what waits in the other tabs', t.dot === '3', t)
    check('browser: the tab page records itself as the last tab', t.last === 'tab-a', t)

    await o.evaluate(`document.querySelector('[data-a5-tabs]').focus()`)
    await press(o, 'Enter')
    const m = await o.evaluate(`(() => { const m = document.querySelector('[role=menu]'); if (!m) return null; const it = [...m.querySelectorAll('[role=menuitem]')]; return {
      names: it.map((i) => i.querySelector('.a5-tabs-name').textContent), view: it.map((i) => i.classList.contains('a5-tabs-view')), sep: !!m.querySelector('.a5-tabs-sep'),
      current: it.findIndex((i) => i.getAttribute('aria-current') === 'page'), check: it[0].querySelector('.a5-tabs-check').textContent,
      focused: it.indexOf(document.activeElement), passkeyHint: it[1].querySelector('.a5-tabs-hint')?.textContent,
      passkeyDot: it[1].querySelector('.a5-tabs-dot')?.textContent, heights: it.map((i) => i.getBoundingClientRect().height),
      expanded: document.querySelector('[data-a5-tabs]').getAttribute('aria-expanded') } })()`)
    check('browser: Enter opens the list with every tab, then Conta after a line', m && m.names.filter((n, i) => !m.view[i]).join() === 'Tab A,Tab B,tab-slow,Odd,Conta' && m.sep && m.expanded === 'true', m)
    check('browser: current tab marked and focused', m && m.current === 0 && m.check === '✓' && m.focused === 0, m)
    check('browser: the Face ID tab says so and shows its own count', m && m.passkeyHint === 'Face ID' && m.passkeyDot === '3', m)
    const ic = await o.evaluate(`[...document.querySelectorAll('[role=menuitem]')].map((i) => { const s = i.querySelector('svg.a5-tabs-icon'); return s ? getComputedStyle(s).stroke : null })`)
    check('browser: configured icons drawn, the current one in the accent color; none without an icon',
      ic[0] === 'rgb(246, 183, 60)' && ic[1] && ic[1] !== ic[0] && ic[2] === null && ic[3] === null && ic[4], ic)
    check('browser: items at least 44 px tall', await o.waitFor(`[...document.querySelectorAll('[role=menuitem]')].every((i) => i.getBoundingClientRect().height >= 44)`, 2000), m)
    await press(o, 'ArrowDown')
    check('browser: arrow down moves to the next tab', await o.evaluate(`document.activeElement.textContent.includes('Tab B')`))
    await press(o, 'Tab'); await press(o, 'Tab'); await press(o, 'Tab'); await press(o, 'Tab')
    check('browser: Tab keeps the focus inside the open list', await o.evaluate(`!!document.activeElement.closest('[role=menu]')`))
    await press(o, 'Escape')
    check('browser: Esc closes and gives the focus back to the title', await o.evaluate(`!document.querySelector('[role=menu]') && document.activeElement.matches('[data-a5-tabs]') && document.activeElement.getAttribute('aria-expanded') === 'false'`))
    await o.evaluate(`document.querySelector('[data-a5-tabs]').click()`)
    await o.waitFor(`!!document.querySelector('.a5-tabs-backdrop')`)
    await o.evaluate(`document.querySelector('.a5-tabs-backdrop').click()`)
    check('browser: a tap outside closes the list', await o.evaluate(`!document.querySelector('[role=menu]')`))

    // choose Conta: full page navigation to the portal's account page, with the same selector
    await o.evaluate(`document.querySelector('[data-a5-tabs]').focus()`)
    await press(o, 'Enter'); await press(o, 'End'); await press(o, 'Enter')
    check('browser: choosing Conta opens /conta/', await o.waitFor(`location.pathname === '/conta/' && ${ON}`))
    await o.waitFor(`!!document.querySelector('.index .profile')`)
    const c = await o.evaluate(`({ title: document.querySelector('[data-a5-tabs]').firstChild.textContent, last: localStorage.getItem('a5.lastTab'),
      devices: !!document.querySelector('.index .profile') && !!document.querySelector('.index a.row[href="#aparelhos"]') })`)
    check('browser: Conta has the selector in its title and lists the devices', c.title === 'Conta' && c.devices, c)
    check('browser: Conta is remembered as the last tab', c.last === 'conta', c)
    check('browser: no CSP violation on the account page', !o.log.some((x) => /Content Security Policy|exception/i.test(x)), o.log)
    // the account index opens each part: the brake and the Shortcuts keys, keys listed without the key itself
    await o.evaluate(`document.querySelector('.index a.row[href="#comandos"]').click()`)
    const brake = await o.waitFor(`document.querySelector('.pane h1')?.textContent === T.commands.title`)
    await o.evaluate(`document.querySelector('.index a.row[href="#atalhos"]')?.click() ?? (location.hash = '#atalhos')`)
    const keys = await o.waitFor(`document.querySelector('.pane h1')?.textContent === T.shortcuts.title`)
    check('browser: account parts show the brake and the Shortcuts keys', brake && keys)
    check('browser: Shortcuts part lists keys but never a key value', await o.evaluate(`!document.body.textContent.includes('pa5_atl_') && document.querySelector('.pane').textContent.includes('tab-a · tv')`))
    await o.evaluate(`location.hash = ''`)
    check('browser: back to the index from a part', await o.waitFor(`!!document.querySelector('.index .profile') && getComputedStyle(document.querySelector('.side')).display !== 'none'`))
    check('browser: no error on the admin view', !o.log.some((x) => /Content Security Policy|exception/i.test(x)), o.log)

    // "/" opens the last tab on this device
    await o.go('/')
    check('browser: "/" opens the last tab (Conta)', await o.waitFor(`location.pathname === '/conta/' && ${ON}`))
    await o.evaluate(`localStorage.setItem('a5.lastTab', 'tab-a')`)
    await o.go('/')
    check('browser: "/" opens the last tab (Tab A)', await o.waitFor(`location.pathname === '/tab-a/'`))
    await o.evaluate(`localStorage.setItem('a5.lastTab', 'gone')`)
    await o.go('/')
    check('browser: unknown last tab: "/" opens the first tab', await o.waitFor(`location.pathname === '/tab-a/'`))

    // a resident: Tab A + Conta, no dot
    const r = await page(b, base, resident)
    await r.go('/tab-a/page')
    check('browser: resident gets the selector', await r.waitFor(ON))
    await r.evaluate(`document.querySelector('[data-a5-tabs]').click()`)
    await r.waitFor(`!!document.querySelector('[role=menu]')`)
    const rm = await r.evaluate(`({ names: [...document.querySelectorAll('[role=menuitem] .a5-tabs-name')].map((x) => x.textContent),
      dot: document.querySelector('[data-a5-tabs] > .a5-tabs-dot').hidden })`)
    check('browser: resident sees Tab A and Conta only, no dot', rm.names.join() === 'Tab A,Conta' && rm.dot === true, rm)

    // a fixed screen: plain title, and "/" goes straight to its tab
    if (screen) {
      const s = await page(b, base, screen)
      await s.go('/tab-a/page')
      await sleep(800)
      const st = await s.evaluate(`(() => { const b = document.querySelector('[data-a5-tabs]'); return { on: b.dataset.a5TabsOn || null, svg: !!b.querySelector('svg'), popup: b.getAttribute('aria-haspopup') } })()`)
      check('browser: fixed screen keeps a plain title (no arrow, no menu)', st.on === null && !st.svg && st.popup === null, st)
      await s.go('/')
      check('browser: fixed screen "/" opens its tab', await s.waitFor(`location.pathname === '/tab-a/'`))
    }

    // pairing a new screen from its own page, with a deep link: after approval it lands on `next`
    if (approve) {
      const p = await page(b, base, null)
      await p.go('/?screen=1&next=%2Ftab-a%2F%3Fview%3Dlandscape')
      check('browser: pairing page shows a code', await p.waitFor(`!!document.querySelector('.pair-code')`))
      await sleep(7000) // at least one status poll has answered "waiting"
      const waitingText = await p.evaluate(`document.querySelector('.pair .status').textContent`)
      check('browser: pairing status is translated while waiting', waitingText === await p.evaluate('A5_TEXT.pair.waiting'), waitingText)
      await approve(await p.evaluate(`document.querySelector('.pair-code').textContent`))
      check('browser: paired screen lands on next, query kept', await p.waitFor(`location.pathname + location.search === '/tab-a/?view=landscape'`, 8000), [await p.evaluate('location.href'), await p.evaluate(`document.querySelector('.pair .status')?.textContent`), p.log])
    }

    // pull to refresh (touch), from the shell, on a tab page and on the account page
    const SHOTS = process.env.A5_SHOTS
    const t1 = await page(await own(), base, owner, { touch: true })
    await t1.go('/tab-a/page')
    await t1.waitFor(ON)
    let pr = await pulls(t1)
    check('browser: pull to refresh reloads a tab page', pr.ready && pr.reloaded, pr)
    await t1.waitFor(ON)
    pr = await pulls(t1, 60)
    check('browser: a short pull does not reload', !pr.ready && !pr.reloaded, pr)
    pr = await pulls(t1, 260, { fingers: 2 })
    check('browser: two fingers (pinch) never reload', !pr.reloaded, pr)
    await t1.evaluate(`document.getElementById('field').focus()`)
    pr = await pulls(t1)
    check('browser: no pull while a text field is open', !pr.reloaded, pr)
    await t1.evaluate(`document.activeElement.blur(); document.getElementById('sheet').hidden = false`)
    pr = await pulls(t1)
    check('browser: no pull while a sheet is open', !pr.reloaded, pr)
    await t1.evaluate(`document.getElementById('sheet').hidden = true; document.querySelector('[data-a5-tabs]').click()`)
    await t1.waitFor(`!!document.querySelector('[role=menu]')`)
    pr = await pulls(t1)
    check('browser: no pull while the tab list is open', !pr.reloaded, pr)
    await t1.go('/tab-a/page-own')
    await t1.waitFor(ON)
    pr = await pulls(t1)
    check('browser: a tab with its own pull (data-a5-pull="own") gets none from the shell', !pr.reloaded && !(await t1.evaluate(`!!document.querySelector('.a5-pull')`)), pr)
    check('browser: no CSP violation or error with pull to refresh', !t1.log.some((x) => /Content Security Policy|exception/i.test(x)), t1.log)
    // a fresh page: a touch cut short by a reload can leave the emulated finger down in this one
    const t2 = await page(await own(), base, owner, { touch: true })
    await t2.go('/conta/')
    await t2.waitFor(`${ON} && !!document.querySelector('.index .profile')`)
    pr = await pulls(t2)
    check('browser: pull to refresh reloads the account page', pr.ready && pr.reloaded, pr)
    if (SHOTS) { await t2.waitFor(`${ON} && !!document.querySelector('.index .profile')`); await t2.drag(260); await sleep(200); await t2.shot(SHOTS + '/puxar_conta.png'); await t2.lift() }
    if (screen) {
      const ts = await page(await own(), base, screen, { touch: true })
      await ts.go('/tab-a/page')
      await sleep(800)
      pr = await pulls(ts)
      check('browser: fixed screen never pulls to refresh', !pr.reloaded, pr)
    }

    // "see as": the owner sees the portal as a resident from the selector, and comes back
    const v = await page(await own(), base, owner, { touch: true })
    await v.go('/tab-a/page')
    await v.waitFor(ON)
    await v.evaluate(`document.querySelector('[data-a5-tabs]').click()`)
    await v.waitFor(`!!document.querySelector('[role=menu]')`)
    const X = await v.evaluate(`(() => { const t = A5_TEXT.shell, g = t.groupNames; return { screens: t.seeAs(g['owner-screens']), res: t.seeAs(g.residents),
      seeing: t.seeingAs(g.residents), back: t.backToOwner, conta: t.tabNames.conta } })()`)
    const vn = await v.evaluate(`[...document.querySelectorAll('[role=menuitem] .a5-tabs-name')].map((x) => x.textContent)`)
    check('browser: owner list has the "see as" items above Conta', vn.join() === ['Tab A', 'Tab B', 'tab-slow', 'Odd', X.screens, X.res, X.conta].join(), [vn, X])
    if (SHOTS) await v.shot(SHOTS + '/menu_dono.png')
    await v.evaluate(`[...document.querySelectorAll('[role=menuitem]')].find((i) => i.textContent.includes(${JSON.stringify(X.res)})).click()`)
    check('browser: seeing as a resident, same page reloaded with the mark', await v.waitFor(`${ON} && !document.querySelector('.a5-tabs-viewas').hidden`, 5000))
    const vm = await v.evaluate(`({ mark: document.querySelector('.a5-tabs-viewas').textContent, dot: document.querySelector('[data-a5-tabs] > .a5-tabs-dot').hidden, path: location.pathname })`)
    check('browser: the mark names the group, no dot', vm.mark === X.seeing && vm.dot === true && vm.path === '/tab-a/page', vm)
    if (SHOTS) await v.shot(SHOTS + '/vendo_como_morador.png')
    await v.evaluate(`document.querySelector('[data-a5-tabs]').click()`)
    await v.waitFor(`!!document.querySelector('[role=menu]')`)
    const vn2 = await v.evaluate(`[...document.querySelectorAll('[role=menuitem] .a5-tabs-name')].map((x) => x.textContent)`)
    check('browser: as a resident: back on top, then Tab A, the other view and Conta', vn2.join() === [X.back, 'Tab A', X.screens, X.conta].join(), vn2)
    if (SHOTS) await v.shot(SHOTS + '/menu_morador.png')
    await v.evaluate(`document.querySelector('.a5-tabs-backdrop').click()`)
    await v.go('/conta/')
    await v.waitFor(`${ON} && !!document.querySelector('.index .profile')`)
    const vc = await v.evaluate(`({ house: !!document.querySelector('.index a.row[href="#pessoas"]'), mark: !document.querySelector('.a5-tabs-viewas').hidden })`)
    check('browser: account page as a resident: no people and groups, mark on', !vc.house && vc.mark, vc)
    if (SHOTS) await v.shot(SHOTS + '/conta_como_morador.png')
    await v.evaluate(`document.querySelector('[data-a5-tabs]').click()`)
    await v.waitFor(`!!document.querySelector('[role=menu]')`)
    await v.evaluate(`document.querySelector('[role=menuitem]').click()`)
    check('browser: back to the owner mode brings the owner back on the same page', await v.waitFor(`${ON} && location.pathname === '/conta/' && document.querySelector('.a5-tabs-viewas').hidden && !!document.querySelector('.index a.row[href="#pessoas"]')`, 5000))
    check('browser: no error while seeing as', !v.log.some((x) => /Content Security Policy|exception/i.test(x)), v.log)

    // signed out: "/" and /conta/ show the sign-in page, title without a selector
    const a = await page(b, base, null)
    await a.go('/conta/')
    check('browser: signed out /conta/ shows sign-in, plain title', await a.waitFor(`!!document.querySelector('#phone') && !document.querySelector('[data-a5-tabs]')`))
  } finally {
    for (const x of spare) x.close()
    b.close()
  }
}

// A pairing prepared by a house agent: the screen opens the one-use link, the ticket leaves the
// address bar, the owner's approval page shows the request, and after the approval the screen
// lands on `next`.
export async function agentPairChecks({ base, check, owner, prepare, approve }) {
  if (!existsSync(CHROME)) { console.log('skip agent pairing browser checks: Chrome not found (set CHROME)'); return }
  const b = await launch()
  try {
    const req = await prepare()
    const sp = await page(b, base, null)
    await sp.go(new URL(req.screen_url).pathname + new URL(req.screen_url).hash)
    check('browser: agent link shows the screen name and waits', await sp.waitFor(`document.querySelector('.pair h1')?.textContent === ${JSON.stringify(req.name)}`))
    check('browser: ticket leaves the address bar', await sp.evaluate(`!location.href.includes('screen_ticket')`))
    const o = await page(b, base, owner)
    await o.go(new URL(req.approve_url).pathname + new URL(req.approve_url).search)
    check('browser: approval page shows the request with an enabled Face ID button',
      await o.waitFor(`(() => { const h = document.querySelector('.pane h1'); const btn = [...document.querySelectorAll('main button')].find((x) => x.textContent === A5_TEXT.agentReq.approve); return h && h.textContent === A5_TEXT.agentReq.pairTitle(${JSON.stringify(req.name)}) && btn && !btn.disabled })()`),
      [await o.evaluate(`document.querySelector('main')?.textContent`), o.log])
    check('browser: approval page has no error', !o.log.some((t) => /Content Security Policy|exception/i.test(t)), o.log)
    await approve(req.id)
    // G6: "Bloquear" asks twice; the first tap only changes the label
    await o.go('/conta/#telas')
    const armed = await o.waitFor(`(() => { const b = [...document.querySelectorAll('main button')].find((x) => x.textContent === A5_TEXT.block); if (!b) return false; b.click(); return b.textContent === A5_TEXT.confirmBlock })()`)
    await new Promise((r) => setTimeout(r, 500))
    check('browser: first tap on Bloquear only asks again', armed && await o.evaluate(`!document.querySelector('main').textContent.includes(A5_TEXT.unblock)`), o.log)
    check('browser: screen paired by the agent lands on next', await sp.waitFor(`location.pathname + location.search === '/tab-a/?view=landscape'`, 8000), [await sp.evaluate('location.href'), sp.log])
  } finally {
    b.close()
  }
}
