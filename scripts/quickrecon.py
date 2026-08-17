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

Writes recon/fallback.txt (the calibration response) and one
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
ACTION_PATH = re.compile(
    r'/(?:[^/?#]+/)*(?:magic(?:-link)?|passwordless|inbox|outbox|emails?|mail|claim|'
    r'activation|activate|enrollment|enroll|invite|callback|session|password|recover|reset|'
    r'verify|forgot|search|filter|query|graphql|login|register|signup)'
    r'(?:[/?#-]|$)', re.I)
GATEWAY_FAILURES = {502, 503, 504}


def fetch(sess, url, method="GET", timeout=15):
    try:
        kwargs = dict(headers=HEADERS, timeout=timeout, allow_redirects=False, verify=False)
        if method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = {}
        return sess.request(method, url, **kwargs)
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


def classify(resp, calibration):
    """Return fallback/framework-404/HIT using a per-method calibration."""
    if isinstance(resp, Exception):
        return "ERR"
    if signature(resp) == calibration:
        return "fallback"
    if FRAMEWORK_404.search((resp.text or "")[:400]):
        return "framework-404"
    return "HIT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--paths", required=True, nargs="+",
                     help="candidate paths (leading / optional), or - to read stdin, one per line")
    ap.add_argument("--out", default="quickrecon_out")
    ap.add_argument("--hitfile", help="also append real hits to this file")
    ap.add_argument("--discover-methods", action="store_true",
                    help="for action-shaped GET misses, safely try OPTIONS then POST {}")
    ap.add_argument("--methodfile",
                    help="append discovered METHOD PATH entries, such as recon/methods.txt")
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

    post_cal_sig = None
    health_sig = signature(fetch(sess, base + "/"))
    if a.discover_methods:
        post_cal = fetch(sess, base + bogus, "POST")
        save(a.out, "fallback_post", base + bogus, post_cal)
        post_cal_sig = signature(post_cal)
        print("[*] POST fallback signature: size=%s ctype=%s sha256=%s..." %
              (post_cal_sig[0], post_cal_sig[1], post_cal_sig[2][:12] if post_cal_sig[2] else ""))

    hits, discovered_methods = [], []
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
        verdict = classify(resp, cal_sig)

        ctype = sig[1] or "-"
        print("%-8s %-46s %s %sB %s" % (resp.status_code, path, verdict, sig[0], ctype))
        if verdict == "HIT":
            hits.append("%s %s %s %s" % (resp.status_code, sig[0], ctype, url))
            discovered_methods.append("GET    %s" % path)
            continue

        if not a.discover_methods or not ACTION_PATH.search(path):
            continue

        # Route-specific Allow is strong evidence. A broad CORS header is not.
        allowed = []
        try:
            options = fetch(sess, url, "OPTIONS")
            if not isinstance(options, Exception):
                allowed = [m.strip().upper() for m in
                           (options.headers.get("Allow") or "").split(",") if m.strip()]
        except Exception:
            allowed = []

        methods_to_try = ["POST"] if not allowed else [m for m in allowed if m == "POST"]
        for method in methods_to_try:
            post_resp = fetch(sess, url, method)
            time.sleep(a.delay)
            save(a.out, "%s_%s" % (method.lower(), safe_name(path)), url, post_resp)
            if isinstance(post_resp, Exception):
                print("%-8s %-46s ERR method fallback: %s" % ("-", path, post_resp))
                return 2
            if post_resp.status_code == 429:
                print("[!] 429 during method fallback; negative conclusions are invalid")
                return 2
            if post_resp.status_code in GATEWAY_FAILURES:
                health_now = signature(fetch(sess, base + "/"))
                changed = "changed" if health_now != health_sig else "unchanged"
                print("[!] circuit breaker: %s %s returned %s; root health %s" %
                      (method, path, post_resp.status_code, changed))
                return 3
            post_verdict = classify(post_resp, post_cal_sig)
            post_sig = signature(post_resp)
            print("%-8s %-46s %s %sB %s" %
                  (post_resp.status_code, method + " " + path, post_verdict,
                   post_sig[0], post_sig[1] or "-"))
            if post_verdict == "HIT":
                discovered_methods.append("%-6s %s" % (method, path))
                hits.append("%s %s %s %s" %
                            (post_resp.status_code, post_sig[0], post_sig[1] or "-", url))

    print("\n%d real hit(s) of %d candidate(s)" % (len(hits), len(candidates)))
    for h in hits:
        print("  " + h)

    if a.hitfile:
        with open(a.hitfile, "a", encoding="utf-8") as fh:
            for h in hits:
                fh.write(h + "\n")

    if a.methodfile and discovered_methods:
        existing = []
        if os.path.isfile(a.methodfile):
            with open(a.methodfile, encoding="utf-8") as fh:
                existing = [line.rstrip() for line in fh if line.strip()]
        merged = sorted(set(existing + discovered_methods))
        with open(a.methodfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(merged) + "\n")
        print("[*] %d unique method mapping(s) saved to %s" % (len(merged), a.methodfile))

    return 0


if __name__ == "__main__":
    sys.exit(main())
