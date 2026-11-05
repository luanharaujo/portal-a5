// Unit checks for src/commands.ts (catalog, parameters, levels, key scope). No server needed:
//   node scripts/test_commands.mjs
import { adminWindowOk, parseCatalogStrict, allowedActions, checkParams, checkScope, gapKeyOf, isShortcutKeyShape, parseCatalog, pickReturns, readAnswer, refusal } from '../src/commands.ts'

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

console.log(failures ? `\n${failures} FAILED` : '\nall ok')
process.exit(failures ? 1 : 0)
