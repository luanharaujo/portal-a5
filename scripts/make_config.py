#!/usr/bin/env python3
"""Writes a wrangler config: wrangler.toml plus the tabs (service bindings and the TABS variable)
and, for a deploy, the real D1 and account ids. Used by deploy.sh and test_local.sh.

usage: make_config.py <tabs.json or -> [<d1 id> <account id>]
A missing tabs file means no tabs. Format: tabs.example.json."""
import json, os, re, sys

src = sys.argv[1]
s = open('wrangler.toml').read()
if len(sys.argv) == 4:
    db, acct = sys.argv[2], sys.argv[3]
    s = s.replace('database_id = "00000000-0000-0000-0000-000000000000"', f'database_id = "{db}"')
    s = re.sub(r'^(main = .*)$', rf'\1\naccount_id = "{acct}"', s, count=1, flags=re.M)
    assert f'database_id = "{db}"' in s and 'account_id' in s

tabs = json.load(open(src)) if src != '-' and os.path.exists(src) else {}
assert isinstance(tabs, dict), 'the tabs file must hold an object'
config, services = {}, []
for tab, c in tabs.items():
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,30}', tab), f'bad tab name {tab!r}'
    c = dict(c)
    service, entry = c.pop('service', ''), c.pop('entrypoint', '')
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', service), f'bad service for {tab}'
    assert re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', entry), f'bad entrypoint for {tab}'
    binding = c.pop('binding', None) or 'TAB_' + tab.upper().replace('-', '_')
    config[tab] = {'binding': binding, **c}
    services.append(f'\n[[services]]\nbinding = "{binding}"\nservice = "{service}"\nentrypoint = "{entry}"\n')

assert len(re.findall(r'^TABS = .*$', s, flags=re.M)) == 1, 'wrangler.toml needs exactly one TABS line'
# Cloudflare caps a text variable at about 5 KB, so the JSON goes in pieces: TABS, TABS_2, TABS_3...
# The worker joins them in order before parsing (src/tabs.ts, tabsText). TABS_CHUNK lets the tests
# force a split. A JSON string is a valid TOML basic string.
raw = json.dumps(config, ensure_ascii=True, separators=(',', ':'))
size = int(os.environ.get('TABS_CHUNK', '4000'))
assert 100 <= size <= 4500, 'TABS_CHUNK out of range'
parts = [raw[i:i + size] for i in range(0, len(raw), size)]
assert 1 <= len(parts) <= 9, 'tabs configuration too large'
lines = ['TABS = ' + json.dumps(parts[0])] + [f'TABS_{n} = ' + json.dumps(p) for n, p in enumerate(parts[1:], 2)]
s = re.sub(r'^TABS = .*$', lambda m: '\n'.join(lines), s, flags=re.M)
sys.stdout.write(s + ''.join(services))
print(f'tabs: {", ".join(config) or "none"}', file=sys.stderr)
