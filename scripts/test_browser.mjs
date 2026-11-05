// The shared tab selector in a real browser: headless Chrome driven over the DevTools protocol,
// against the same local `wrangler dev` as test_local.mjs (which calls this with its sessions).
// Checks the real tab CSP too: the selector must load and run on a tab page without a violation.
import { spawn } from 'node:child_process'
import { mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function launch() {
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
async function page(b, base, cookie) {
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
  if (cookie) {
    const [name, value] = cookie.split('=')
    await s('Network.setCookie', { name, value, url: base + '/', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' })
  }
  const evaluate = async (expr) => {
    const r = await s('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })
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
  const go = async (path) => { await s('Page.navigate', { url: base + path }); await sleep(150) }
  const key = async (k, code = k, vk = 0) => {
    for (const type of ['keyDown', 'keyUp']) await s('Input.dispatchKeyEvent', { type, key: k, code, windowsVirtualKeyCode: vk })
    await sleep(60)
  }
  return { evaluate, waitFor, go, key, log }
}

const KEYS = { Enter: ['Enter', 'Enter', 13], Escape: ['Escape', 'Escape', 27], ArrowDown: ['ArrowDown', 'ArrowDown', 40], End: ['End', 'End', 35], Tab: ['Tab', 'Tab', 9] }

export async function browserChecks({ base, check, owner, resident, screen, approve }) {
  if (!existsSync(CHROME)) { console.log('skip browser checks: Chrome not found (set CHROME)'); return }
  const b = await launch()
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
      names: it.map((i) => i.querySelector('.a5-tabs-name').textContent), sep: !!m.querySelector('.a5-tabs-sep'),
      current: it.findIndex((i) => i.getAttribute('aria-current') === 'page'), check: it[0].querySelector('.a5-tabs-check').textContent,
      focused: it.indexOf(document.activeElement), passkeyHint: it[1].querySelector('.a5-tabs-hint')?.textContent,
      passkeyDot: it[1].querySelector('.a5-tabs-dot')?.textContent, heights: it.map((i) => i.getBoundingClientRect().height),
      expanded: document.querySelector('[data-a5-tabs]').getAttribute('aria-expanded') } })()`)
    check('browser: Enter opens the list with every tab, then Conta after a line', m && m.names.join() === 'Tab A,Tab B,tab-slow,Odd,Conta' && m.sep && m.expanded === 'true', m)
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
    const c = await o.evaluate(`({ title: document.querySelector('[data-a5-tabs]').firstChild.textContent, last: localStorage.getItem('a5.lastTab'),
      devices: !!document.querySelector('main .card') })`)
    check('browser: Conta has the selector in its title and lists the devices', c.title === 'Conta' && c.devices, c)
    check('browser: Conta is remembered as the last tab', c.last === 'conta', c)
    check('browser: no CSP violation on the account page', !o.log.some((x) => /Content Security Policy|exception/i.test(x)), o.log)
    // the admin view: brake and Shortcuts keys cards, keys listed without the key itself
    await o.evaluate(`[...document.querySelectorAll('nav button, button')].find((b) => b.textContent === T.nav.admin).click()`)
    const adm = await o.waitFor(`[...document.querySelectorAll('main h2')].some((h) => h.textContent === T.shortcuts.title) && [...document.querySelectorAll('main h2')].some((h) => h.textContent === T.commands.title)`)
    check('browser: admin view shows the brake and the Shortcuts keys', adm)
    check('browser: admin view lists keys but never a key value', await o.evaluate(`!document.body.textContent.includes('pa5_atl_') && document.body.textContent.includes('tab-a · tv')`))
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
      const waitingText = await p.evaluate(`document.querySelector('.pair .muted').textContent`)
      check('browser: pairing status is translated while waiting', waitingText === await p.evaluate('A5_TEXT.pair.waiting'), waitingText)
      await approve(await p.evaluate(`document.querySelector('.pair-code').textContent`))
      check('browser: paired screen lands on next, query kept', await p.waitFor(`location.pathname + location.search === '/tab-a/?view=landscape'`, 8000), [await p.evaluate('location.href'), await p.evaluate(`document.querySelector('.pair .muted')?.textContent`), p.log])
    }

    // signed out: "/" and /conta/ show the sign-in page, title without a selector
    const a = await page(b, base, null)
    await a.go('/conta/')
    check('browser: signed out /conta/ shows sign-in, plain title', await a.waitFor(`!!document.querySelector('#phone') && !document.querySelector('[data-a5-tabs]')`))
  } finally {
    b.close()
  }
}
