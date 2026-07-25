#!/usr/bin/env python3
"""probe.py — probe every endpoint with auth AND without, diff the results.

Finds broken access control deliberately instead of by accident, survives status-code
jitter by calibrating the app's not-found body, and scans headers as well as bodies
for flags (flags hide in X-Flag on otherwise-normal 403s).

Usage:
  python probe.py --base https://target [--token TOK | --cookie 'k=v'] --paths paths.txt
  python jsmine.py recon/ | grep '^  /api' | python probe.py --base https://target --token TOK --paths -

Options:
  --out DIR     save every response body (default: ./probe_out)
  --methods     also send OPTIONS to enumerate allowed methods
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


def fetch(sess, url, headers, timeout=20):
    try:
        return sess.get(url, headers=headers, timeout=timeout, allow_redirects=False, verify=False)
    except Exception as e:
        return e


def describe(r):
    if isinstance(r, Exception):
        return ("ERR", 0, type(r).__name__)
    ctype = (r.headers.get("content-type") or "").split(";")[0]
    return (r.status_code, len(r.content), ctype)


ERROR_HINTS = ("error", "unauthorized", "forbidden", "denied", "required",
               "invalid", "not found", "must be", "missing")


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
    ap.add_argument("--delay", type=float, default=0.05)
    a = ap.parse_args()

    base = a.base.rstrip("/")
    raw = sys.stdin.read() if a.paths == "-" else open(a.paths, encoding="utf-8").read()
    paths = []
    for line in raw.splitlines():
        p = line.strip().split()[0] if line.strip() else ""
        if p.startswith("/") and p not in paths:
            paths.append(p)
    if not paths:
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

    # ---- calibrate the not-found body; status codes may be jittered ----------
    bogus = "/" + "".join(random.choices(string.ascii_lowercase, k=18))
    cal = fetch(sess, base + bogus, auth)
    cal_status, cal_size, cal_ctype = describe(cal)
    print("[*] calibration %-22s -> status=%s size=%s ctype=%s" % (bogus, cal_status, cal_size, cal_ctype))
    print("[*] treating size==%s + ctype==%s as NOT-A-ROUTE (status ignored)\n" % (cal_size, cal_ctype))

    print("%-40s %-22s %-22s %s" % ("PATH", "WITH AUTH", "NO AUTH", "VERDICT"))
    print("-" * 104)

    flags, leaks, real = {}, [], []
    for p in paths:
        url = base + p
        ra = fetch(sess, url, auth) if has_auth else None
        time.sleep(a.delay)
        rn = fetch(sess, url, BASE_HEADERS)
        time.sleep(a.delay)

        sa = describe(ra) if ra is not None else ("-", 0, "-")
        sn = describe(rn)

        # is it a real route at all?
        def is_fallback(d):
            return d[1] == cal_size and d[2] == cal_ctype

        primary = ra if ra is not None else rn
        if is_fallback(sa if ra is not None else sn):
            verdict = "not-a-route"
        elif not has_auth:
            verdict = "reachable"
            real.append(p)
        elif isinstance(rn, Exception):
            verdict = "auth-required"
            real.append(p)
        elif (not is_fallback(sn) and sa[0] != "ERR"
              and (rn.text or "") == (ra.text or "") and sn[1] > 0
              and not looks_like_error(rn)):
            # identical *content*, not merely identical length — two same-length
            # error bodies ("Admin access required" vs "Access token required")
            # are not a leak
            verdict = "*** NO-AUTH LEAK — identical body without token ***"
            leaks.append(p)
            real.append(p)
        elif not is_fallback(sn) and sn[2].startswith("application/json") and sn[1] > 40 \
                and not looks_like_error(rn):
            verdict = "*** NO-AUTH DATA — json returned without token ***"
            leaks.append(p)
            real.append(p)
        else:
            verdict = "auth-required"
            real.append(p)

        print("%-40s %-22s %-22s %s" % (
            p[:40], "%s %sB %s" % sa if ra is not None else "-",
            "%s %sB %s" % sn, verdict))

        # save + scan
        for tag, r in (("auth", ra), ("noauth", rn)):
            if isinstance(r, Exception) or r is None:
                continue
            fn = re.sub(r'[^a-zA-Z0-9]+', '_', p).strip('_') or "root"
            with open(os.path.join(a.out, "%s.%s.txt" % (fn, tag)), "w", encoding="utf-8") as fh:
                fh.write("HTTP %s\n" % r.status_code)
                for k, v in r.headers.items():
                    fh.write("%s: %s\n" % (k, v))
                fh.write("\n" + (r.text or ""))
            for f in scan_flags(r):
                flags.setdefault(f, []).append("%s (%s)" % (p, tag))

        if a.methods and not is_fallback(sa if ra is not None else sn):
            try:
                o = sess.options(url, headers=auth, timeout=15, verify=False)
                allow = o.headers.get("allow") or o.headers.get("access-control-allow-methods")
                if allow:
                    print("%-40s OPTIONS -> %s" % ("", allow))
            except Exception:
                pass

    print("\n" + "=" * 104)
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
