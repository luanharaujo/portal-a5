#!/usr/bin/env python3
"""Copy public/ to a build folder and give every local script and stylesheet in index.html (and in
entry.html, the Face ID page served in place at a tab's address) a
version from its content (?v=<sha256 prefix>). The Home Screen app on iOS can keep a script with
the same URL; a new file gets a new URL, so a new deploy is never served with old code.

Usage: build_assets.py <public dir> <out dir> [entry list]
  prints "<url> <version>" per versioned file of index.html; with [entry list], writes the same for
  entry.html there (that page is served only to a signed-in session, so the deploy checks its files alone)
"""
import hashlib, re, shutil, sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
if out.exists():
    shutil.rmtree(out)
shutil.copytree(src, out)

def versioner(lines):
    def version(m):
        attr, path = m.group(1), m.group(2)
        f = out / path.lstrip("/")
        if not f.is_file():
            sys.exit(f"a page points to a missing file: {path}")
        v = hashlib.sha256(f.read_bytes()).hexdigest()[:12]
        lines.append(f"{path} {v}")
        return f'{attr}="{path}?v={v}"'
    return version

listed = {}
for name in ("index.html", "entry.html"):
    page = out / name
    html = page.read_text()
    listed[name] = []
    # same-origin .js and .css only (absolute paths, no query yet)
    new = re.sub(r'\b(src|href)="(/[A-Za-z0-9_./-]+\.(?:js|css))"', versioner(listed[name]), html)
    if new == html:
        sys.exit(f"no script or stylesheet found in {name}")
    page.write_text(new)
print("\n".join(listed["index.html"]))
if len(sys.argv) > 3:
    Path(sys.argv[3]).write_text("\n".join(listed["entry.html"]) + "\n")
