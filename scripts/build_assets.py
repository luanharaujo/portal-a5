#!/usr/bin/env python3
"""Copy public/ to a build folder and give every local script and stylesheet in index.html a
version from its content (?v=<sha256 prefix>). The Home Screen app on iOS can keep a script with
the same URL; a new file gets a new URL, so a new deploy is never served with old code.

Usage: build_assets.py <public dir> <out dir>   (prints "<url> <version>" per versioned file)
"""
import hashlib, re, shutil, sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
if out.exists():
    shutil.rmtree(out)
shutil.copytree(src, out)
page = out / "index.html"
html = page.read_text()

def version(m):
    attr, path = m.group(1), m.group(2)
    f = out / path.lstrip("/")
    if not f.is_file():
        sys.exit(f"index.html points to a missing file: {path}")
    v = hashlib.sha256(f.read_bytes()).hexdigest()[:12]
    print(path, v)
    return f'{attr}="{path}?v={v}"'

# same-origin .js and .css only (absolute paths, no query yet)
new = re.sub(r'\b(src|href)="(/[A-Za-z0-9_./-]+\.(?:js|css))"', version, html)
if new == html:
    sys.exit("no script or stylesheet found in index.html")
page.write_text(new)
