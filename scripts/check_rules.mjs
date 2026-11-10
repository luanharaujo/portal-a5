#!/usr/bin/env node
// House rules check for tab pages (docs/TABS.md section 0), static: run it on the HTML a tab serves,
// before its deploy. Exit 0 = ok, 1 = a rule is broken (each problem printed), 2 = bad usage.
//
//   node ~/repositories/portal-a5/scripts/check_rules.mjs web/            (every .html under it)
//   node ~/repositories/portal-a5/scripts/check_rules.mjs web/index.html
//
// H1 (never a dead end): /_shell/tabs.css and /_shell/tabs.js (after /locale/pt-BR.js) in <head>, a
// title marked data-a5-tabs in the page itself, data-a5-pull="own" only with a pull of its own.
// H3 (fast): every script deferred (or a module; or marked data-a5-early when it is at most 4 KB and
// must run before the first paint), no inline script, nothing from another origin
// (pages and the stylesheets they link). Face ID (H2) and taps (H4) need a person: the portal's
// maintainer checks those by hand.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'

const args = process.argv.slice(2)
if (!args.length) { console.error('usage: check_rules.mjs <page.html | folder> ...'); process.exit(2) }

const EARLY_MAX = 4096
const SKIP = new Set(['node_modules', '.git', '.wrangler', '.deploy', 'dist', 'test', 'tests'])
function pages(p) {
  if (!existsSync(p)) { console.error(`not found: ${p}`); process.exit(2) }
  if (statSync(p).isFile()) return p.endsWith('.html') ? [p] : []
  return readdirSync(p).flatMap((n) => SKIP.has(n) ? [] : pages(join(p, n)))
}

const attr = (tag, name) => {
  const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)
  return m ? (m[1] ?? m[2] ?? m[3]) : null
}
const has = (tag, name) => new RegExp(`\\s${name}(\\s|=|>|/)`, 'i').test(tag)
const bare = (u) => (u || '').split(/[?#]/)[0]
const external = (u) => /^(https?:)?\/\//i.test(u || '')

function check(file) {
  const html = readFileSync(file, 'utf8')
  const out = []
  const headEnd = html.search(/<\/head>/i)
  if (headEnd < 0) return [`no </head>: not a page?`]
  const head = html.slice(0, headEnd)
  const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => ({ tag: m[0], at: m.index }))
  const links = [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0])

  // H1
  if (!links.some((l) => /stylesheet/i.test(attr(l, 'rel') || '') && bare(attr(l, 'href')) === '/_shell/tabs.css') || !/\/_shell\/tabs\.css/.test(head))
    out.push('H1: <link rel="stylesheet" href="/_shell/tabs.css"> missing from <head>')
  const shell = scripts.find((s) => bare(attr(s.tag, 'src')) === '/_shell/tabs.js')
  const locale = scripts.find((s) => bare(attr(s.tag, 'src')) === '/locale/pt-BR.js')
  if (!shell || shell.at > headEnd) out.push('H1: <script src="/_shell/tabs.js" defer> missing from <head> (tab list and pull to refresh)')
  if (!locale || locale.at > headEnd) out.push('H1: <script src="/locale/pt-BR.js" defer> missing from <head> (the tab list texts)')
  else if (shell && locale.at > shell.at) out.push('H1: /locale/pt-BR.js must come before /_shell/tabs.js')
  if (!/\bdata-a5-tabs\b/.test(html.slice(headEnd))) out.push('H1: no title marked data-a5-tabs in the page (the tap back to the tab list)')
  if (/data-a5-pull\s*=\s*["']?own/i.test(html)) {
    const own = scripts.map((s) => attr(s.tag, 'src')).filter((u) => u && !external(u) && !bare(u).startsWith('/_shell/') && !bare(u).startsWith('/locale/'))
      .map((u) => localFile(file, u)).filter(Boolean)
    if (!own.some((f) => /touch(start|move)/.test(readFileSync(f, 'utf8'))))
      out.push('H1: data-a5-pull="own" but no script of the page handles touches (the shell\'s pull to refresh is off)')
  }

  // H3
  for (const s of scripts) {
    const src = attr(s.tag, 'src'), type = (attr(s.tag, 'type') || '').toLowerCase()
    if (!src) { if (type !== 'application/json' && type !== 'application/ld+json') out.push('H3: inline <script> (the tab CSP blocks it; move it to a file)'); continue }
    if (external(src)) out.push(`H3: script from another origin: ${src}`)
    else if (!has(s.tag, 'defer') && !has(s.tag, 'async') && type !== 'module') {
      // a tiny script that must run before the first paint (picking a layout) may say so
      const f = localFile(file, src)
      const early = has(s.tag, 'data-a5-early') && f && statSync(f).size <= EARLY_MAX
      if (!early) out.push(`H3: script without defer blocks the first paint: ${src}` + (has(s.tag, 'data-a5-early') ? ` (data-a5-early is for files up to ${EARLY_MAX} bytes)` : ' (or data-a5-early, for a tiny one that must run first)'))
    }
  }
  for (const l of links) {
    const href = attr(l, 'href'), rel = (attr(l, 'rel') || '').toLowerCase()
    if (external(href) && /stylesheet|preload|preconnect|dns-prefetch|modulepreload/.test(rel)) out.push(`H3: ${rel} from another origin: ${href}`)
    if (rel === 'stylesheet' && href && !external(href)) {
      const f = localFile(file, href)
      if (f && /@import\s+(url\()?["']?(https?:)?\/\/|url\(\s*["']?(https?:)?\/\//i.test(readFileSync(f, 'utf8'))) out.push(`H3: ${href} loads something from another origin`)
    }
  }
  if (/<style\b/i.test(html)) out.push('H3: inline <style> (the tab CSP blocks it; move it to a file)')
  return out
}

// "/notes/app.js?v=1" from web/index.html -> web/app.js when it exists (the tab's prefix is dropped)
function localFile(page, url) {
  const p = bare(url)
  const base = dirname(resolve(page))
  const parts = p.replace(/^\//, '').split('/')
  for (let i = 0; i < parts.length; i++) {
    const f = join(base, ...parts.slice(i))
    if (existsSync(f) && statSync(f).isFile()) return f
  }
  return null
}

let bad = 0, seen = 0
for (const a of args) for (const f of pages(a)) {
  seen++
  const problems = check(f)
  if (problems.length) { bad++; console.log(`${f}:`); for (const p of problems) console.log(`  ${p}`) } else console.log(`${f}: ok`)
}
if (!seen) { console.error('no .html page found'); process.exit(2) }
process.exit(bad ? 1 : 0)
