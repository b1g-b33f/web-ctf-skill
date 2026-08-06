#!/usr/bin/env python3
"""jsharvest.py — automatically harvest client-side JS at recon init.

Fetches the root page, pulls every <script src=...> off it, resolves each one
(absolute, protocol-relative, root-relative, and ordinary relative all handled by
urljoin), downloads the .js/.mjs bundles plus their source maps (skipped when the
sourceMappingURL is an inline data: URI), then runs jsmine.py over everything that
landed on disk and writes recon/jsmine.txt + a probe-ready recon/methods.txt.

Every downloaded map also gets exploded: sourcesContent (the original, unminified
per-file source webpack/CRA embeds) is written out to recon/src/<original/path>.js,
vendor (node_modules) and webpack-runtime entries excluded. This is the same virtual
tree Chrome/Firefox DevTools' Sources panel reconstructs from the map client-side —
a component that looks like a real file in the browser (e.g. components/AdminPanel.js)
but 404s/SPA-falls-back over a direct HTTP request is exactly this: present in
sourcesContent, never actually served on disk. Read recon/src/ directly; it's the
signal-only slice of what's normally 90%+ node_modules noise in the raw .map text.

Usage:
  python3 jsharvest.py --base https://target --out recon/
  python3 jsharvest.py --base https://target --out recon/ --root recon/root.html   # reuse
                                                                                   # an already-fetched page instead of fetching a second time

Run it again after login with --token/--cookie: some apps ship different bootstrap
data once authenticated, and re-running re-mines the full accumulated bundle set
(old assets + any new ones), overwriting jsmine.txt/methods.txt with the union.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
from urllib.parse import urljoin, urlsplit

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

SCRIPT_SRC = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)
SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)|/\*[#@]\s*sourceMappingURL=(\S+?)\s*\*/', re.I)

HERE = os.path.dirname(os.path.abspath(__file__))
JSMINE = os.path.join(HERE, "jsmine.py")


def fetch(sess, url, headers, timeout=20):
    try:
        return sess.get(url, headers=headers, timeout=timeout, verify=False)
    except Exception as e:
        print("[!] GET %s failed: %s" % (url, e))
        return None


def extract_sourcemap(map_path, out_dir):
    """Explode a source map's embedded sourcesContent into real files under out_dir/src/.

    DevTools reconstructs this same tree client-side purely from data already in the
    .map file — no extra network requests happen per source. A component like
    AdminPanel.js that 'exists in the browser' (Sources panel) but 404s/SPA-falls-back
    over HTTP is exactly this: it's in sourcesContent, not on the filesystem being served.
    Regex-mining the raw .map text finds it too, in principle, but drowned under
    node_modules noise (typically 90%+ of a CRA/webpack bundle's sources) and past
    jsmine's pattern shapes (comment syntax, key:"value") if the hint is plain prose.
    Exploding to real files gets a clean, greppable, human-readable app-only tree instead.

    Returns the list of extracted (non-vendor) relative paths.
    """
    try:
        with open(map_path, encoding="utf-8", errors="replace") as fh:
            m = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print("      [!] could not parse source map: %s" % e)
        return []

    sources = m.get("sources") or []
    contents = m.get("sourcesContent") or []
    if not sources or not contents or len(sources) != len(contents):
        return []

    NOISE = ("node_modules/", "webpack/bootstrap", "webpack/runtime")
    src_root = os.path.join(out_dir, "src")
    extracted = []
    for src, content in zip(sources, contents):
        if content is None:
            continue
        norm = src.replace("\\", "/").lstrip("./")
        while norm.startswith("../"):
            norm = norm[3:]
        if not norm or any(n in norm for n in NOISE):
            continue
        dest = os.path.join(src_root, *norm.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with open(dest, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(content)
            extracted.append(norm)
        except OSError as e:
            print("      [!] could not write %s: %s" % (norm, e))
    return extracted


def safe_filename(url, used):
    path = urlsplit(url).path
    base = os.path.basename(path) or "bundle.js"
    name, ext = os.path.splitext(base)
    cand, n = base, 1
    while cand in used:
        n += 1
        cand = "%s_%d%s" % (name, n, ext)
    used.add(cand)
    return cand


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", default="recon")
    ap.add_argument("--root", help="reuse an already-fetched copy of the root page instead of fetching it again")
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Key: Value', repeatable")
    a = ap.parse_args()

    base = a.base.rstrip("/")
    os.makedirs(a.out, exist_ok=True)

    headers = {"User-Agent": UA}
    if a.token:
        headers["Authorization"] = "Bearer " + a.token
    if a.cookie:
        headers["Cookie"] = a.cookie
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    sess = requests.Session()

    root_url = base + "/"
    if a.root and os.path.isfile(a.root):
        with open(a.root, encoding="utf-8", errors="replace") as fh:
            root_html = fh.read()
        print("[*] reusing root page from %s" % a.root)
    else:
        r = fetch(sess, root_url, headers)
        root_html = r.text if r is not None else ""
        with open(os.path.join(a.out, "root.html"), "w", encoding="utf-8") as fh:
            fh.write(root_html)
        print("[*] fetched root page: %s (%d bytes)" % (root_url, len(root_html)))

    srcs = SCRIPT_SRC.findall(root_html)
    resolved = sorted({urljoin(root_url, s) for s in srcs})
    print("[*] found %d <script src> tag(s), %d unique URL(s)" % (len(srcs), len(resolved)))

    js_urls = [u for u in resolved if urlsplit(u).path.lower().endswith((".js", ".mjs"))]
    print("[*] %d .js/.mjs bundle(s) to download" % len(js_urls))

    used_names = set(os.path.basename(p) for p in glob.glob(os.path.join(a.out, "*")))
    downloaded, maps = 0, 0
    for url in js_urls:
        r = fetch(sess, url, headers)
        if r is None:
            continue
        fn = safe_filename(url, used_names)
        path = os.path.join(a.out, fn)
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(r.text)
        downloaded += 1
        print("  [+] %s -> %s (%d bytes)" % (url, fn, len(r.text)))

        m = SOURCEMAP.search(r.text[-2000:]) or SOURCEMAP.search(r.text)
        if m:
            map_ref = (m.group(1) or m.group(2) or "").strip()
            if map_ref.startswith("data:"):
                print("      sourceMappingURL is an inline data: URI, skipping")
            elif map_ref:
                map_url = urljoin(url, map_ref)
                mr = fetch(sess, map_url, headers)
                if mr is not None:
                    map_fn = safe_filename(map_url, used_names)
                    map_path = os.path.join(a.out, map_fn)
                    with open(map_path, "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(mr.text)
                    maps += 1
                    print("      sourceMappingURL -> %s (%d bytes)" % (map_fn, len(mr.text)))

                    extracted = extract_sourcemap(map_path, a.out)
                    if extracted:
                        print("      [+] exploded sourcesContent -> %s/src/ (%d app file(s), "
                              "vendor/node_modules excluded):" % (a.out.rstrip("/"), len(extracted)))
                        for p in sorted(extracted):
                            print("          " + p)

    print("[*] downloaded %d bundle(s), %d source map(s)" % (downloaded, maps))

    proc = subprocess.run([sys.executable, JSMINE, a.out], capture_output=True, text=True)
    jsmine_out = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    jsmine_path = os.path.join(a.out, "jsmine.txt")
    with open(jsmine_path, "w", encoding="utf-8") as fh:
        fh.write(jsmine_out)
    print("[*] jsmine output saved to %s" % jsmine_path)

    methods = extract_methods(jsmine_out)
    methods_path = os.path.join(a.out, "methods.txt")
    with open(methods_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(methods) + ("\n" if methods else ""))
    print("[*] %d METHOD -> PATH entries saved to %s" % (len(methods), methods_path))
    for entry in methods:
        print("    " + entry)

    return 0


def extract_methods(jsmine_out):
    """Pull the indented lines out of jsmine's '=== METHOD -> PATH (n) ===' section."""
    lines = jsmine_out.splitlines()
    out, in_section = [], False
    for line in lines:
        if re.match(r'^=== METHOD -> PATH \(\d+\) ===\s*$', line):
            in_section = True
            continue
        if in_section:
            if line.startswith("==="):
                break
            stripped = line.strip()
            if stripped:
                out.append(stripped)
    return out


if __name__ == "__main__":
    sys.exit(main())
