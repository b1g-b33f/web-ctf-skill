#!/usr/bin/env python3
"""quickrecon.py — SPA-aware fallback calibration for the meta-file and quick-path
recon jobs.

A calibrated SPA answers *any* unknown path with the same 200 shell, and a jittering
lab rewrites status codes at will — so status-only "not 404" checks report every guess
as a hit. This calibrates the real fallback signature from one randomized nonexistent
path first (body size + normalized content-type + body hash, status ignored), then
checks each candidate against it and against common framework 404 bodies
("Cannot GET /path" and friends). Only genuine hits get printed; everything else is
still saved to disk for review.

Usage:
  python3 quickrecon.py --base https://target --paths robots.txt sitemap.xml admin api \
      --out recon --hitfile meta_hits.txt

  # or feed candidates on stdin, one per line
  printf 'admin\\napi\\ngraphql\\n' | python3 quickrecon.py --base https://target --paths - --out recon

Writes recon/fallback.headers + recon/fallback.body (the calibration response) and one
saved response per candidate under --out. Real hits are written to --hitfile (default:
stdout only) as "status size content-type URL", one per line — the same shape probe.py
uses, so the two tools read the same way.
"""
import argparse
import hashlib
import os
import random
import re
import string
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept": "*/*"}

# Covers every standard HTTP method's default framework-404 body, e.g. Express's
# "Cannot GET /path" — these vary in length with the path, so they never match a
# fixed-size fallback signature and need their own check.
FRAMEWORK_404 = re.compile(
    r'Cannot (?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /', re.I)


def fetch(sess, url, timeout=15):
    try:
        return sess.get(url, headers=HEADERS, timeout=timeout,
                         allow_redirects=False, verify=False)
    except Exception as e:
        return e


def signature(resp):
    """Ignore status entirely — a calibrated SPA fallback can answer 200."""
    if isinstance(resp, Exception):
        return (0, "ERR", "")
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    body = resp.content or b""
    return (len(body), ctype, hashlib.sha256(body).hexdigest())


def safe_name(path):
    return re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_') or "root"


def save(out_dir, name, url, resp):
    fn = os.path.join(out_dir, name + ".txt")
    with open(fn, "w", encoding="utf-8") as fh:
        fh.write("URL: %s\n" % url)
        if isinstance(resp, Exception):
            fh.write("ERROR: %s\n" % resp)
            return
        fh.write("HTTP %s\n" % resp.status_code)
        for k, v in resp.headers.items():
            fh.write("%s: %s\n" % (k, v))
        fh.write("\n")
        fh.write(resp.text or "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--paths", required=True, nargs="+",
                     help="candidate paths (leading / optional), or - to read stdin, one per line")
    ap.add_argument("--out", default="quickrecon_out")
    ap.add_argument("--hitfile", help="also append real hits to this file")
    ap.add_argument("--delay", type=float, default=0.05)
    a = ap.parse_args()

    base = a.base.rstrip("/")
    os.makedirs(a.out, exist_ok=True)

    if a.paths == ["-"]:
        candidates = [l.strip() for l in sys.stdin if l.strip()]
    else:
        candidates = a.paths
    candidates = [c if c.startswith("/") else "/" + c for c in candidates]

    sess = requests.Session()

    bogus = "/" + "".join(random.choices(string.ascii_lowercase, k=20))
    cal_resp = fetch(sess, base + bogus)
    save(a.out, "fallback", base + bogus, cal_resp)
    cal_sig = signature(cal_resp)
    print("[*] fallback signature: size=%s ctype=%s sha256=%s..." %
          (cal_sig[0], cal_sig[1], cal_sig[2][:12] if cal_sig[2] else ""))
    print("[*] (calibrated from %s, status ignored)\n" % (base + bogus))

    hits = []
    for path in candidates:
        url = base + path
        resp = fetch(sess, url)
        time.sleep(a.delay)
        save(a.out, safe_name(path), url, resp)

        if isinstance(resp, Exception):
            print("%-8s %-46s ERR %s" % ("-", path, resp))
            continue

        sig = signature(resp)
        body_head = (resp.text or "")[:400]
        if sig == cal_sig:
            verdict = "fallback"
        elif FRAMEWORK_404.search(body_head):
            verdict = "framework-404"
        else:
            verdict = "HIT"

        ctype = sig[1] or "-"
        print("%-8s %-46s %s %sB %s" % (resp.status_code, path, verdict, sig[0], ctype))
        if verdict == "HIT":
            hits.append("%s %s %s %s" % (resp.status_code, sig[0], ctype, url))

    print("\n%d real hit(s) of %d candidate(s)" % (len(hits), len(candidates)))
    for h in hits:
        print("  " + h)

    if a.hitfile:
        with open(a.hitfile, "a", encoding="utf-8") as fh:
            for h in hits:
                fh.write(h + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
