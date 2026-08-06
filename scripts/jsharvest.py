#!/usr/bin/env python3
"""jsharvest.py — automatically harvest client-side JS at recon init.

Fetches the root and optional same-origin pages, mines rendered HTML forms, and
pulls every <script src=...> off them. It resolves each one
(absolute, protocol-relative, root-relative, and ordinary relative all handled by
urljoin), downloads only successful non-HTML bundles plus their source maps (skipped when the
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
For cookie-authenticated server-rendered apps, pass --cookie-file <curl-jar>,
--page /dashboard, and --crawl-pages so form actions are harvested even if JS assets 404.
"""
import argparse
import glob
import http.cookiejar
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
PAGE_HREF = re.compile(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.I)
SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)|/\*[#@]\s*sourceMappingURL=(\S+?)\s*\*/', re.I)

HERE = os.path.dirname(os.path.abspath(__file__))
JSMINE = os.path.join(HERE, "jsmine.py")


def fetch(sess, url, headers, timeout=20):
    try:
        return sess.get(url, headers=headers, timeout=timeout, verify=False)
    except Exception as e:
        print("[!] GET %s failed: %s" % (url, e))
        return None


def usable_asset(response, url, kind="javascript"):
    """Reject error pages before they are saved and mined as successful assets."""
    if response is None:
        return False
    ctype = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
    if not 200 <= response.status_code < 300:
        print("  [!] skipping %s: HTTP %d (%s)" % (url, response.status_code,
                                                     ctype or "unknown content-type"))
        return False
    if kind == "javascript":
        allowed = (not ctype or "javascript" in ctype or "ecmascript" in ctype
                   or ctype in ("text/plain", "application/octet-stream"))
        if not allowed or response.text.lstrip().startswith(("<!DOCTYPE", "<html")):
            print("  [!] skipping %s: expected JavaScript, got %s" %
                  (url, ctype or "an HTML body"))
            return False
    elif "html" in ctype or response.text.lstrip().startswith(("<!DOCTYPE", "<html")):
        print("  [!] skipping %s: expected source map, got %s" %
              (url, ctype or "an HTML body"))
        return False
    return True


def page_links(html, current_url, base):
    """Return safe same-origin GET pages; API/download/static URLs are not crawled."""
    origin = urlsplit(base)
    out = []
    for href in PAGE_HREF.findall(html):
        url = urljoin(current_url, href).split("#", 1)[0]
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            continue
        path = parsed.path or "/"
        if path.startswith(("/api/", "/_next/")) or path in ("/api", "/logout"):
            continue
        if re.search(r'\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|pdf|zip)$', path, re.I):
            continue
        out.append(url)
    return out


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
    ap.add_argument("--cookie-file", help="Netscape-format cookie jar, such as curl -c output")
    ap.add_argument("--page", action="append", default=[],
                    help="additional same-origin page to fetch and mine; repeatable")
    ap.add_argument("--crawl-pages", action="store_true",
                    help="crawl same-origin HTML links with safe GET requests")
    ap.add_argument("--max-pages", type=int, default=30,
                    help="maximum additional pages fetched by --crawl-pages (default: 30)")
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
    if a.cookie_file:
        jar = http.cookiejar.MozillaCookieJar(a.cookie_file)
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
            sess.cookies.update(jar)
        except (OSError, http.cookiejar.LoadError) as e:
            print("[!] could not load cookie jar %s: %s" % (a.cookie_file, e))
            return 2

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

    page_blobs = [(root_url, root_html)]
    queue = [urljoin(root_url, p) for p in a.page]
    if a.crawl_pages:
        queue.extend(page_links(root_html, root_url, base))
    seen_pages = {root_url}
    pages_dir = os.path.join(a.out, "pages")
    fetched_pages = 0
    while queue and fetched_pages < max(0, a.max_pages):
        page_url = queue.pop(0)
        if page_url in seen_pages:
            continue
        seen_pages.add(page_url)
        parsed = urlsplit(page_url)
        origin = urlsplit(base)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            print("[!] refusing cross-origin page: %s" % page_url)
            continue
        r = fetch(sess, page_url, headers)
        if r is None or not 200 <= r.status_code < 300:
            code = r.status_code if r is not None else "request failed"
            print("  [!] page %s -> %s, skipping" % (page_url, code))
            continue
        ctype = r.headers.get("Content-Type", "").lower()
        if "html" not in ctype and not r.text.lstrip().startswith(("<!DOCTYPE", "<html")):
            print("  [!] page %s is not HTML (%s), skipping" % (page_url, ctype or "unknown"))
            continue
        fetched_pages += 1
        os.makedirs(pages_dir, exist_ok=True)
        page_path = os.path.join(pages_dir, "page-%03d.html" % fetched_pages)
        with open(page_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(r.text)
        page_blobs.append((page_url, r.text))
        print("  [+] page %s -> %s (%d bytes)" % (page_url, page_path, len(r.text)))
        if a.crawl_pages:
            queue.extend(page_links(r.text, page_url, base))

    combined_html = "\n".join(body for _, body in page_blobs)
    srcs = SCRIPT_SRC.findall(combined_html)
    resolved = sorted({urljoin(root_url, s) for s in srcs})
    print("[*] found %d <script src> tag(s), %d unique URL(s)" % (len(srcs), len(resolved)))

    js_urls = [u for u in resolved if urlsplit(u).path.lower().endswith((".js", ".mjs"))]
    print("[*] %d .js/.mjs bundle(s) to download" % len(js_urls))

    used_names = set(os.path.basename(p) for p in glob.glob(os.path.join(a.out, "*")))
    downloaded, maps, skipped = 0, 0, 0
    for url in js_urls:
        r = fetch(sess, url, headers)
        if not usable_asset(r, url):
            skipped += 1
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
                if usable_asset(mr, map_url, kind="source map"):
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

    print("[*] downloaded %d bundle(s), skipped %d invalid bundle(s), %d source map(s)" %
          (downloaded, skipped, maps))

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
