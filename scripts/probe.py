#!/usr/bin/env python3
"""probe.py — probe every endpoint with auth AND without, diff the results.

Finds broken access control deliberately instead of by accident, survives status-code
jitter by calibrating the app's not-found body, and scans headers as well as bodies
for flags (flags hide in X-Flag on otherwise-normal 403s).

Usage:
  python probe.py --base https://target [--token TOK | --cookie 'k=v'] --paths paths.txt
  python jsmine.py recon/ | grep '^  /api' | python probe.py --base https://target --token TOK --paths -

  # feed it jsmine's METHOD -> PATH section so POST routes get probed as POST:
  python jsmine.py recon/ | python probe.py --base https://target --token TOK --paths -

Input lines may be either "/api/thing" (probed as GET) or "POST /api/thing".
GET-only probing silently mislabels write-only endpoints as not-a-route: an SPA
serves index.html for GET /api/profile/avatar/import, which looks exactly like a
404 fallback. That endpoint was the entire solve on CafeClub.

Options:
  --out DIR     save every response body (default: ./probe_out)
  --methods     also send OPTIONS to enumerate allowed methods
  --write       also probe PUT/PATCH/DELETE (skipped by default -- they mutate
                your own test state; GET/POST discovery is non-destructive enough)
  --id VAL      substitute for {...} placeholders in jsmine paths (default 1)
  --delay S     per-request delay (default 0.05)
"""
import argparse
import os
import random
import re
import string
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()

FLAG_RE = re.compile(r'(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,90}\}', re.I)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
BASE_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


def scan_flags(resp):
    """Flags can be in the body or any header value."""
    hits = set(FLAG_RE.findall(resp.text or ""))
    for k, v in resp.headers.items():
        hits |= set(FLAG_RE.findall("%s: %s" % (k, v)))
        if "flag" in k.lower():
            hits.add("%s: %s" % (k, v))
    return hits


BODY_METHODS = ("POST", "PUT", "PATCH")
WRITE_METHODS = ("PUT", "PATCH", "DELETE")


def fetch(sess, url, headers, method="GET", timeout=20):
    """An empty JSON body is deliberate: a real endpoint answers a validation
    error ("password required"), a non-route answers the 404/SPA fallback. That
    difference is the discovery signal."""
    try:
        kw = dict(headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        if method in BODY_METHODS:
            kw["json"] = {}
        return sess.request(method, url, **kw)
    except Exception as e:
        return e


def parse_targets(raw, include_write, ident):
    """Accept both '/api/x' and 'POST /api/x'. jsmine emits both shapes."""
    targets, seen = [], set()
    for line in raw.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper() and parts[1].startswith("/"):
            method, path = parts[0], parts[1]
        elif parts[0].startswith("/"):
            method, path = "GET", parts[0]
        else:
            continue
        if method in WRITE_METHODS and not include_write:
            continue
        path = re.sub(r'\{[^}]*\}', ident, path)      # /api/orders/{...} -> /api/orders/1
        if "{" in path or "}" in path:
            continue
        key = (method, path)
        if key not in seen:
            seen.add(key)
            targets.append(key)
    return targets


def describe(r):
    if isinstance(r, Exception):
        return ("ERR", 0, type(r).__name__)
    ctype = (r.headers.get("content-type") or "").split(";")[0]
    return (r.status_code, len(r.content), ctype)


ERROR_HINTS = ("error", "unauthorized", "forbidden", "denied", "required",
               "invalid", "not found", "must be", "missing")

# Express's default 404 embeds the path ("Cannot POST /api/favorites/"), so its
# length changes with every path and pure size-matching never recognises it.
EXPRESS_404 = re.compile(r'Cannot (?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /', re.I)


def is_framework_404(r):
    if isinstance(r, Exception) or r is None:
        return False
    return bool(EXPRESS_404.search((r.text or "")[:400]))


def looks_like_error(r):
    """True for API error envelopes — status codes are unreliable when jittered."""
    if isinstance(r, Exception) or r is None:
        return True
    body = (r.text or "")[:200].lower()
    return any(h in body for h in ERROR_HINTS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--paths", required=True, help="file with one path per line, or - for stdin")
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--out", default="probe_out")
    ap.add_argument("--methods", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--id", default="1")
    ap.add_argument("--delay", type=float, default=0.05)
    a = ap.parse_args()

    base = a.base.rstrip("/")
    raw = sys.stdin.read() if a.paths == "-" else open(a.paths, encoding="utf-8").read()
    targets = parse_targets(raw, a.write, a.id)
    if not targets:
        print("no paths given")
        return 1
    os.makedirs(a.out, exist_ok=True)

    auth = dict(BASE_HEADERS)
    if a.token:
        auth["Authorization"] = "Bearer " + a.token
    if a.cookie:
        auth["Cookie"] = a.cookie
    has_auth = bool(a.token or a.cookie)

    sess = requests.Session()

    # ---- calibrate the not-found body PER METHOD; status codes may be jittered
    # A POST to a bogus path answers differently from a GET to one, so a single
    # GET calibration would mislabel every POST route.
    bogus = "/" + "".join(random.choices(string.ascii_lowercase, k=18))
    cal_by_method = {}
    for m in sorted({t[0] for t in targets}):
        c = fetch(sess, base + bogus, auth, m)
        cs, csize, cctype = describe(c)
        cal_by_method[m] = (csize, cctype)
        print("[*] calibration %-6s %-20s -> status=%s size=%s ctype=%s"
              % (m, bogus, cs, csize, cctype))
    print("[*] size+ctype matching the above = NOT-A-ROUTE (status ignored)\n")

    print("%-46s %-22s %-22s %s" % ("METHOD PATH", "WITH AUTH", "NO AUTH", "VERDICT"))
    print("-" * 110)

    flags, leaks, real = {}, [], []
    for method, p in targets:
        url = base + p
        label = "%-6s %s" % (method, p)
        cal_size, cal_ctype = cal_by_method[method]
        ra = fetch(sess, url, auth, method) if has_auth else None
        time.sleep(a.delay)
        rn = fetch(sess, url, BASE_HEADERS, method)
        time.sleep(a.delay)

        sa = describe(ra) if ra is not None else ("-", 0, "-")
        sn = describe(rn)

        # is it a real route at all?
        def is_fallback(d):
            return d[1] == cal_size and d[2] == cal_ctype

        primary = ra if ra is not None else rn
        if is_fallback(sa if ra is not None else sn) or is_framework_404(primary):
            verdict = "not-a-route"
        elif not has_auth:
            verdict = "reachable"
            real.append(label)
        elif isinstance(rn, Exception):
            verdict = "auth-required"
            real.append(label)
        elif (not is_fallback(sn) and sa[0] != "ERR"
              and (rn.text or "") == (ra.text or "") and sn[1] > 0
              and looks_like_error(rn)):
            # same error, with and without a token. A real denial (401/403) is
            # auth-required and expected; anything else means the error has
            # nothing to do with auth — it's not a data leak, just a route that
            # errors the same way for everyone
            if sn[0] in (401, 403):
                verdict = "auth-required"
            else:
                verdict = "public-error — same response without auth"
            real.append(label)
        elif (not is_fallback(sn) and sa[0] != "ERR"
              and (rn.text or "") == (ra.text or "") and sn[1] > 0):
            # identical *content*, not merely identical length — two same-length
            # error bodies ("Admin access required" vs "Access token required")
            # are not a leak
            verdict = "*** NO-AUTH LEAK — identical body without token ***"
            leaks.append(label)
            real.append(label)
        elif not is_fallback(sn) and sn[2].startswith("application/json") and sn[1] > 40 \
                and not looks_like_error(rn):
            verdict = "*** NO-AUTH DATA — json returned without token ***"
            leaks.append(label)
            real.append(label)
        else:
            verdict = "auth-required"
            real.append(label)

        print("%-46s %-22s %-22s %s" % (
            label[:46], "%s %sB %s" % sa if ra is not None else "-",
            "%s %sB %s" % sn, verdict))

        # save + scan
        for tag, r in (("auth", ra), ("noauth", rn)):
            if isinstance(r, Exception) or r is None:
                continue
            fn = re.sub(r'[^a-zA-Z0-9]+', '_', p).strip('_') or "root"
            fn = "%s.%s" % (method.lower(), fn)
            with open(os.path.join(a.out, "%s.%s.txt" % (fn, tag)), "w", encoding="utf-8") as fh:
                fh.write("HTTP %s\n" % r.status_code)
                for k, v in r.headers.items():
                    fh.write("%s: %s\n" % (k, v))
                fh.write("\n" + (r.text or ""))
            for f in scan_flags(r):
                flags.setdefault(f, []).append("%s (%s)" % (label.strip(), tag))

        if a.methods and not is_fallback(sa if ra is not None else sn):
            try:
                o = sess.options(url, headers=auth, timeout=15, verify=False)
                allow = o.headers.get("allow") or o.headers.get("access-control-allow-methods")
                if allow:
                    print("%-40s OPTIONS -> %s" % ("", allow))
            except Exception:
                pass

    print("\n" + "=" * 110)
    print("real routes: %d   no-auth issues: %d" % (len(set(real)), len(leaks)))
    for p in leaks:
        print("   NO-AUTH: %s" % p)
    if flags:
        print("\n" + "!" * 60)
        for f, where in flags.items():
            print("FLAG: %s   <- %s" % (f, ", ".join(where[:4])))
        print("!" * 60)
    else:
        print("no flag pattern in any response (headers or body)")
    print("\nresponses saved to %s/" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
