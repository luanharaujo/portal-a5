// Unit checks for src/commands.ts (catalog, parameters, levels, key scope). No server needed:
//   node scripts/test_commands.mjs
import { adminWindowOk, passkeyUntil, passkeyWindowOk, parseCatalogStrict, allowedActions, checkParams, checkScope, gapKeyOf, isShortcutKeyShape, parseCatalog, pickReturns, readAnswer, refusal } from '../src/commands.ts'

let failures = 0
function check(name, cond, extra) {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${!cond && extra !== undefined ? ' -> ' + JSON.stringify(extra) : ''}`)
  if (!cond) failures++
}

const cat = parseCatalog({
  tv: { level: 'common', params: { mode: { enum: ['on', 'off'] } }, perHour: 20, screens: true },
  screen: { level: 'admin', params: { mode: { enum: ['on', 'off', 'toggle'] } } },
  presence: { level: 'admin', params: { state: { enum: ['out', 'home'] } }, perHour: 30 },
  ac: { level: 'common', params: { unit: { enum: ['a', 'b'] }, power: { bool: true }, temp: { int: [16, 30] } }, gap: { seconds: 180, by: 'unit' }, returns: ['power'] },
  wipe: { level: 'sensitive' },
  // malformed: each must be dropped
  free_text: { level: 'common', params: { text: { string: true } } },
  extra_field: { level: 'common', run: 'sh' },
  bad_level: { level: 'root' },
  bad_enum: { level: 'common', params: { x: { enum: ['rm -rf /'] } } },
  bad_rate: { level: 'common', perHour: 1e6 },
  bad_gap: { level: 'common', gap: { seconds: 10, by: 'nope' } },
  'Bad-Name': { level: 'common' },
  __proto__: { level: 'common' },
  screen_admin: { level: 'admin', screens: true },
})

// C01: the catalog only keeps well-formed actions
check('catalog keeps the good actions', JSON.stringify(Object.keys(cat).sort()) === JSON.stringify(['ac', 'presence', 'screen', 'screen_admin', 'tv', 'wipe']), Object.keys(cat))
check('catalog: screens only on common', cat.screen_admin.screens === false && cat.tv.screens === true)
check('catalog: sensitive never in a shortcut', cat.wipe.shortcut === false)
check('catalog: gap key defaults to the action', cat.ac.gap.key === 'ac')
check('catalog: not an object = empty', Object.keys(parseCatalog('x')).length === 0 && Object.keys(parseCatalog([1])).length === 0)

// C01: parameters
const ok = checkParams(cat.ac, { unit: 'a', power: true, temp: 22 })
check('params: exact and typed = ok', 'params' in ok && ok.params.unit === 'a' && ok.params.temp === 22)
check('params: extra field refused', checkParams(cat.ac, { unit: 'a', power: true, temp: 22, cmd: 'x' }).error === 'unknown_param')
check('params: __proto__ refused', checkParams(cat.ac, JSON.parse('{"unit":"a","power":true,"temp":22,"__proto__":{"x":1}}')).error === 'unknown_param')
check('params: missing refused', checkParams(cat.ac, { unit: 'a', power: true }).error === 'missing_param')
check('params: outside enum refused', checkParams(cat.ac, { unit: 'c', power: true, temp: 22 }).error === 'bad_param')
check('params: outside range refused', checkParams(cat.ac, { unit: 'a', power: true, temp: 40 }).error === 'bad_param')
check('params: float refused', checkParams(cat.ac, { unit: 'a', power: true, temp: 22.5 }).error === 'bad_param')
check('params: wrong type refused', checkParams(cat.ac, { unit: 'a', power: 'true', temp: 22 }).error === 'bad_param')
check('params: string number refused', checkParams(cat.ac, { unit: 'a', power: true, temp: '22' }).error === 'bad_param')
check('params: array refused', checkParams(cat.tv, ['on']).error === 'bad_params')
check('params: none for no-param action', 'params' in checkParams(cat.wipe, undefined) && checkParams(cat.wipe, { a: 1 }).error === 'unknown_param')
check('gap key per unit', gapKeyOf(cat.ac, { unit: 'b' }) === 'ac:b' && gapKeyOf(cat.tv, {}) === null)

// C06/C07: levels
const resident = { credential: 'browser', admin: false, strong: false, adminFresh: false, scope: null }
const ownerWeak = { credential: 'browser', admin: true, strong: false, adminFresh: false, scope: null }
const ownerDevice = { credential: 'browser', admin: true, strong: false, adminFresh: true, scope: null }
const ownerStrong = { credential: 'browser', admin: true, strong: true, adminFresh: true, scope: null }
const screen = { credential: 'screen', admin: false, strong: false, adminFresh: false, scope: null }
const key = (scope, admin = true) => ({ credential: 'shortcut', admin, strong: false, adminFresh: false, scope })

check('resident: common ok', refusal('h', 'tv', cat.tv, resident) === null)
check('resident: admin action refused', refusal('h', 'presence', cat.presence, resident) === 'admin_only')
check('resident: actions list has no presence', !allowedActions('h', cat, resident).includes('presence'))
check('weak owner session: admin action refused', refusal('h', 'presence', cat.presence, ownerWeak) === 'passkey_required')
check('owner device with passkey once: admin ok', refusal('h', 'presence', cat.presence, ownerDevice) === null)
check('owner device: sensitive needs a fresh passkey', refusal('h', 'wipe', cat.wipe, ownerDevice) === 'passkey_required')
check('strong owner: sensitive ok', refusal('h', 'wipe', cat.wipe, ownerStrong) === null)
check('screen: only common with screens', refusal('h', 'tv', cat.tv, screen) === null && refusal('h', 'ac', cat.ac, screen) === 'not_for_screens' && refusal('h', 'presence', cat.presence, screen) === 'not_for_screens')
check('key: in scope ok', refusal('h', 'tv', cat.tv, key(['h/tv'])) === null)
check('key: out of scope refused', refusal('h', 'ac', cat.ac, key(['h/tv'])) === 'out_of_scope')
check('key: same action, other tab refused', refusal('x', 'tv', cat.tv, key(['h/tv'])) === 'out_of_scope')
check('key: sensitive never', refusal('h', 'wipe', cat.wipe, key(['h/wipe'])) === 'not_for_shortcuts')
check('key of a person who lost admin: admin action refused', refusal('h', 'presence', cat.presence, key(['h/presence'], false)) === 'admin_only')

// key scope at creation
const cats = { h: cat }
check('scope ok', JSON.stringify(checkScope(['h/tv', 'h/presence', 'h/tv'], cats, true)) === JSON.stringify(['h/tv', 'h/presence']))
check('scope: sensitive refused', checkScope(['h/wipe'], cats, true) === null)
check('scope: unknown action refused', checkScope(['h/nope'], cats, true) === null)
check('scope: unknown tab refused', checkScope(['z/tv'], cats, true) === null)
check('scope: admin action for non-admin refused', checkScope(['h/presence'], cats, false) === null)
check('scope: empty or too long refused', checkScope([], cats, true) === null && checkScope(Array(13).fill('h/tv'), cats, true) === null)
check('scope: junk refused', checkScope(['h/tv; rm'], cats, true) === null && checkScope('h/tv', cats, true) === null)

// answers and returns
check('returns: only declared plain fields', JSON.stringify(pickReturns(cat.ac, { power: true, room: 'x', nested: {} })) === JSON.stringify({ power: true }))
check('returns: nothing declared = nothing', pickReturns(cat.presence, { state: 'out' }) === null)
check('answer: bad status = failed', readAnswer({ status: 'ok' }).status === 'failed' && readAnswer(null).status === 'failed')
check('answer: odd error dropped', readAnswer({ status: 'refused', error: '<b>' }).error === undefined)
check('key shape', isShortcutKeyShape('pa5_atl_' + 'A'.repeat(43)) && !isShortcutKeyShape('pa5_atl_' + 'A'.repeat(42)) && !isShortcutKeyShape('pa5_maq_' + 'A'.repeat(43)))

check('strict: one bad action refuses the catalog', parseCatalogStrict({ tv: { level: 'common' }, x: { level: 'root' } }) === null)
check('strict: good catalog kept', Object.keys(parseCatalogStrict({ tv: { level: 'common' } }) || {}).length === 1)
check('strict: not an object refused', parseCatalogStrict([]) === null && parseCatalogStrict('x') === null)
check('strict: __proto__ key refuses', parseCatalogStrict(JSON.parse('{"tv":{"level":"common"},"__proto__":{"level":"common"}}')) === null)

// admin window (owner's decision 05/11: 12 h on this session)
const T0 = Date.parse('2026-11-05T12:00:00Z')
const ago = (ms) => new Date(T0 - ms).toISOString()
check('admin window 12h: 11 h 59 min ago ok', adminWindowOk(ago(12 * 3600e3 - 60e3), '12h', T0))
check('admin window 12h: 12 h 1 min ago refused', !adminWindowOk(ago(12 * 3600e3 + 60e3), '12h', T0))
check('admin window missing = 5 min', adminWindowOk(ago(4 * 60e3), undefined, T0) && !adminWindowOk(ago(6 * 60e3), undefined, T0))
check('admin window: never checked refused', !adminWindowOk(null, 'session', T0) && !adminWindowOk('junk', '12h', T0))
check('admin window: 5m setting', adminWindowOk(ago(4 * 60e3), '5m', T0) && !adminWindowOk(ago(6 * 60e3), '5m', T0))
check('admin window: malformed setting = 5 min', adminWindowOk(ago(4 * 60e3), 'forever', T0) && !adminWindowOk(ago(6 * 60e3), '12 h', T0))
check('admin window: session', adminWindowOk(ago(100 * 86400e3), 'session', T0))

// actions with their own passkey window (TV volume limiter, 08/11)
const pk = parseCatalog({
  limit: { level: 'common', passkey: '5m', params: { on: { bool: true }, top: { int: [10, 60] } }, screens: false, shortcut: false },
  limit_bare: { level: 'common', passkey: '1m' },
  adm: { level: 'admin', passkey: '60m' },
  // each must be dropped
  with_screens: { level: 'common', passkey: '5m', screens: true },
  with_shortcut: { level: 'common', passkey: '5m', shortcut: true },
  on_sensitive: { level: 'sensitive', passkey: '5m' },
  too_long: { level: 'common', passkey: '61m' },
  zero: { level: 'common', passkey: '0m' },
  hours: { level: 'common', passkey: '1h' },
  number: { level: 'common', passkey: 5 },
  empty: { level: 'common', passkey: '' },
})
check('passkey: only well-formed actions kept', Object.keys(pk).sort().join() === 'adm,limit,limit_bare', Object.keys(pk))
check('passkey: window in ms; never screens or keys', pk.limit.passkey === 300e3 && pk.limit_bare.passkey === 60e3 && !pk.limit_bare.screens && !pk.limit_bare.shortcut)
check('passkey: other actions have none', cat.tv.passkey === null)
const N = Date.parse('2026-11-08T12:00:00Z')
const at = (ms) => new Date(N - ms).toISOString()
const rWith = (ms, extra = {}) => ({ ...resident, passkeyAt: ms == null ? null : at(ms), ...extra })
check('passkey: resident never checked = passkey_required', refusal('h', 'limit', pk.limit, rWith(null)) === 'passkey_required')
check('passkey: resident 4 min ago = ok', passkeyWindowOk(pk.limit, rWith(4 * 60e3), N))
check('passkey: window edges', passkeyWindowOk(pk.limit, rWith(299e3), N) && !passkeyWindowOk(pk.limit, rWith(300e3), N))
check('passkey: a check in the future does not count', !passkeyWindowOk(pk.limit, rWith(-5 * 60e3), N))
check('passkey: owner with 12 h window still needs it', refusal('h', 'limit', pk.limit, { ...ownerDevice, passkeyAt: null }) === 'passkey_required')
check('passkey: admin action with passkey: resident admin_only first', refusal('h', 'adm', pk.adm, rWith(0)) === 'admin_only')
check('passkey: screen and key refused', refusal('h', 'limit', pk.limit, screen) === 'not_for_screens' && refusal('h', 'limit', pk.limit, key(['h/limit'])) === 'not_for_shortcuts')
check('passkey: rehearsal counts as open', passkeyWindowOk(pk.limit, rWith(null, { rehearsal: true }), N))
check('passkey: listed in actions for a browser while closed; never for a screen',
  allowedActions('h', pk, rWith(null)).join() === 'limit,limit_bare' && allowedActions('h', pk, screen).length === 0)
check('passkey: admin with passkey action listed for the owner while closed', allowedActions('h', pk, { ...ownerWeak, passkeyAt: null }).includes('adm'))
const pu = passkeyUntil(pk, rWith(60e3), N)
check('passkey_until: open windows only, ISO', pu.limit === new Date(N + 240e3).toISOString() && pu.limit_bare === undefined && pu.adm === new Date(N + 3540e3).toISOString(), pu)
check('passkey_until: empty for screens and keys', Object.keys(passkeyUntil(pk, { ...screen, passkeyAt: at(0) }, N)).length === 0 && Object.keys(passkeyUntil(pk, key(['h/limit']), N)).length === 0)
check('passkey: never in a key scope', checkScope(['h/limit'], { h: pk }, true) === null)

// R1b: keyWriteOnly, the one way a key reaches a tab with Face ID on entry
const wo = parseCatalog({
  gasto: { level: 'admin', keyWriteOnly: true, params: { v: { int: [1, 100] } }, perHour: 30, screens: false, shortcut: true },
  other: { level: 'admin' },
  wo_no_key: { level: 'admin', keyWriteOnly: true, shortcut: false },
  wo_sensitive: { level: 'sensitive', keyWriteOnly: true },
  wo_returns: { level: 'admin', keyWriteOnly: true, returns: ['saldo'] },
  wo_screens: { level: 'common', keyWriteOnly: true, screens: true },
  wo_passkey: { level: 'common', keyWriteOnly: true, passkey: '5m' },
  wo_string: { level: 'admin', keyWriteOnly: 'yes' },
})
check('keyWriteOnly: contradictions drop the action', Object.keys(wo).sort().join() === 'gasto,other', Object.keys(wo))
check('keyWriteOnly: default closed', wo.other.keyWriteOnly === false && cat.tv.keyWriteOnly === false && wo.gasto.keyWriteOnly === true)
const PK = new Set(['f'])
check('keyWriteOnly scope: alone = ok', JSON.stringify(checkScope(['f/gasto'], { f: wo }, true, PK)) === '["f/gasto"]')
check('keyWriteOnly scope: with another entry = null', checkScope(['f/gasto', 'h/tv'], { f: wo, h: cat }, true, PK) === null)
check('keyWriteOnly scope: unmarked action of a Face ID tab = null', checkScope(['f/other'], { f: wo }, true, PK) === null)
check('keyWriteOnly scope: not admin = null', checkScope(['f/gasto'], { f: wo }, false, PK) === null)
const kPK = (scope) => ({ ...key(scope), admin: true, entryPasskey: true })
check('keyWriteOnly refusal: one-action key = ok', refusal('f', 'gasto', wo.gasto, kPK(['f/gasto'])) === null)
check('keyWriteOnly refusal: other action of the tab = not_for_shortcuts', refusal('f', 'other', wo.other, kPK(['f/other'])) === 'not_for_shortcuts')
check('keyWriteOnly refusal: key without it = out_of_scope', refusal('f', 'gasto', wo.gasto, kPK(['h/tv'])) === 'out_of_scope')
check('keyWriteOnly refusal: two-action key = out_of_scope', refusal('f', 'gasto', wo.gasto, kPK(['f/gasto', 'h/tv'])) === 'out_of_scope')
check('keyWriteOnly actions: only that action', allowedActions('f', wo, kPK(['f/gasto'])).join() === 'gasto')
check('keyWriteOnly on a session tab: no change for a key', refusal('h', 'gasto', wo.gasto, { ...key(['h/gasto', 'h/tv']), admin: true }) === null &&
  checkScope(['h/gasto', 'h/tv'], { h: { ...cat, gasto: wo.gasto } }, true, PK) !== null)

// Text parameters: a narrow door (keyWriteOnly only, tab opt-in, never kept in the audit)
import { redactParams, hasText, TEXT_MAX } from '../src/commands.ts'
const tx = parseCatalog({
  create: { level: 'admin', keyWriteOnly: true, params: { title: { text: 120 }, note: { text: 1000 } }, perHour: 30 },
  set_due: { level: 'admin', keyWriteOnly: true, params: { item: { int: [1, 99] } } },
  text_plain: { level: 'admin', params: { t: { text: 10 } } },
  text_big: { level: 'admin', keyWriteOnly: true, params: { t: { text: TEXT_MAX + 1 } } },
  text_zero: { level: 'admin', keyWriteOnly: true, params: { t: { text: 0 } } },
  text_float: { level: 'admin', keyWriteOnly: true, params: { t: { text: 1.5 } } },
  text_two: { level: 'admin', keyWriteOnly: true, params: { t: { text: 5, u: 1 } } },
  purge: { level: 'common', passkey: '5m', windowOnly: true },
  win_nopass: { level: 'common', windowOnly: true },
  win_wo: { level: 'admin', keyWriteOnly: true, windowOnly: true },
})
check('text: only keyWriteOnly actions with a sane size stay', Object.keys(tx).sort().join() === 'create,purge,set_due', Object.keys(tx))
check('text: hasText', hasText(tx.create) && !hasText(tx.set_due))
check('windowOnly: kept only with passkey', tx.purge.windowOnly === true && tx.purge.shortcut === false && tx.purge.screens === false)
check('text: ok', 'params' in checkParams(tx.create, { title: 'Paint the room', note: '' }) && 'params' in checkParams(tx.create, { title: 'a\nb\tc', note: 'naive 😀' }))
check('text: too long', checkParams(tx.create, { title: 'x'.repeat(121), note: '' }).error === 'bad_param')
check('text: counted in characters', 'params' in checkParams(tx.create, { title: '😀'.repeat(120), note: '' }))
check('text: not a string', checkParams(tx.create, { title: 5, note: '' }).error === 'bad_param' && checkParams(tx.create, { title: null, note: '' }).error === 'bad_param')
check('text: NUL and control refused', checkParams(tx.create, { title: 'a\u0000b', note: '' }).error === 'bad_param' && checkParams(tx.create, { title: 'a\u001bb', note: '' }).error === 'bad_param')
check('text: lone surrogate refused', checkParams(tx.create, { title: 'a\ud800b', note: '' }).error === 'bad_param')
check('text: missing refused', checkParams(tx.create, { title: 'a' }).error === 'missing_param')
const red = redactParams(tx.create, { title: 'Secret', note: '' })
check('text: audit keeps the length only', red.title === '[text:6]' && red.note === '[text:0]' && !JSON.stringify(red).includes('Secret'), red)
check('text: ints pass through redaction', redactParams(tx.set_due, { item: 3 }).item === 3)
const TXT = new Set()
check('text key scope: alone in its tab = ok', checkScope(['z/create', 'z/set_due'], { z: tx }, true, TXT) !== null)
check('text key scope: with another tab = null', checkScope(['z/create', 'h/tv'], { z: tx, h: cat }, true, TXT) === null)
check('text key scope: with a non-write-only action = null', checkScope(['z/create', 'z/other'], { z: { ...tx, other: cat.tv }, h: cat }, true, TXT) === null)

// Letters-only text (a name from a bank e-mail): normalized, then letters and single spaces, up to N
const P8 = { amount_cents: { int: [1, 100000000] }, direction: { enum: ['in', 'out'] }, at: { int: [0, 4102444800] },
  kind: { enum: ['instant', 'wire', 'bill', 'card'] }, person: { int: [0, 50] }, ref: { int: [1, 9007199254740991] }, name: { text: 60, letters: true } }
const lt = parseCatalog({
  provisional: { level: 'admin', keyWriteOnly: true, perHour: 30, params: P8 },
  eight: { level: 'admin', keyWriteOnly: true, params: { ...P8, extra: { bool: true } } },
  nine: { level: 'admin', keyWriteOnly: true, params: { ...P8, extra: { bool: true }, more: { bool: true } } },
  letters_false: { level: 'admin', keyWriteOnly: true, params: { n: { text: 60, letters: false } } },
  letters_other: { level: 'admin', keyWriteOnly: true, params: { n: { text: 60, digits: true } } },
  letters_alone: { level: 'admin', keyWriteOnly: true, params: { n: { letters: true } } },
  letters_three: { level: 'admin', keyWriteOnly: true, params: { n: { text: 60, letters: true, x: 1 } } },
  letters_big: { level: 'admin', keyWriteOnly: true, params: { n: { text: TEXT_MAX + 1, letters: true } } },
  letters_plain: { level: 'admin', params: { n: { text: 60, letters: true } } },
})
check('letters: up to 8 params, malformed letters dropped', Object.keys(lt).sort().join() === 'eight,provisional', Object.keys(lt))
check('letters: spec kept', lt.provisional.params.name.letters === true && lt.provisional.params.name.text === 60 && hasText(lt.provisional))
const call = (name) => checkParams(lt.provisional, { amount_cents: 1250, direction: 'out', at: 1762800000, kind: 'instant', person: 0, ref: 77, name })
const nm = (name) => { const r = call(name); return 'params' in r ? r.params.name : r.error }
check('letters: plain name ok', nm('Corner Bakery') === 'Corner Bakery')
check('letters: accents ok', nm('\u00c9mile Zo\u00eb \u00d1and\u00fa') === '\u00c9mile Zo\u00eb \u00d1and\u00fa')
check('letters: NFC applied', nm('Zoe\u0308') === 'Zo\u00eb' && nm('Zoe\u0308').length === 3)
check('letters: spaces trimmed and collapsed', nm('  Big    Bread   Shop  ') === 'Big Bread Shop')
check('letters: empty ok', nm('') === '' && nm('   ') === '')
check('letters: other params intact', call('X').params.person === 0 && call('X').params.ref === 77 && call('X').params.kind === 'instant')
check('letters: digits refused', nm('Shop 24h') === 'bad_param')
check('letters: punctuation refused', nm('Smith & Co.') === 'bad_param' && nm('a-b') === 'bad_param' && nm("D'Avila") === 'bad_param')
check('letters: tab, newline, NBSP refused (not emptied)', nm('a\tb') === 'bad_param' && nm('a\nb') === 'bad_param' && nm('a\u00a0b') === 'bad_param' && nm('Ana\n') === 'bad_param')
check('letters: control and zero-width refused', nm('a\u0000b') === 'bad_param' && nm('a\u200bb') === 'bad_param' && nm('a\u202eb') === 'bad_param')
check('letters: emoji and lone surrogate refused', nm('Ana \ud83d\ude00') === 'bad_param' && nm('a\ud800') === 'bad_param')
check('letters: combining mark without composed form refused', nm('q\u0303') === 'bad_param')
check('letters: 60 after normalizing ok, 61 refused', nm('a'.repeat(60)) === 'a'.repeat(60) && nm('a'.repeat(61)) === 'bad_param')
check('letters: size counted after normalizing', nm('  ' + 'a'.repeat(30) + '      ' + 'b'.repeat(29) + '  ') === 'a'.repeat(30) + ' ' + 'b'.repeat(29))
check('letters: huge input refused', nm('a'.repeat(TEXT_MAX + 1)) === 'bad_param')
check('letters: not a string refused', nm(5) === 'bad_param' && nm(null) === 'bad_param')
check('letters: audit keeps the length only', redactParams(lt.provisional, call('Corner Bakery').params).name === '[text:13]')
check('letters: unknown param refused', checkParams(lt.provisional, { ...call('X').params, extra: 1 }).error === 'unknown_param')

console.log(failures ? `\n${failures} FAILED` : '\nall ok')
process.exit(failures ? 1 : 0)
