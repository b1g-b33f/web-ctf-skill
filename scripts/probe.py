#!/usr/bin/env python3
"""probe.py — probe every endpoint with auth AND without, diff the results.

Finds broken access control deliberately instead of by accident, survives status-code
jitter by calibrating the app's not-found body, and scans headers as well as bodies
for flags (flags hide in X-Flag on otherwise-normal 403s).

Usage:
  python3 probe.py --base https://target [--token TOK | --cookie 'k=v'] --paths paths.txt
  python3 jsmine.py recon/ | grep '^  /api' | python3 probe.py --base https://target --token TOK --paths -

  # feed it jsmine's METHOD -> PATH section so POST routes get probed as POST:
  python3 jsmine.py recon/ | python3 probe.py --base https://target --token TOK --paths -

  # three identities at once — privileged, low-priv, anonymous:
  python3 probe.py --base https://target --token "$ADMIN" --lowpriv-token "$USER" \
      --write --paths paths.txt

Input lines may be either "/api/thing" (probed as GET) or "POST /api/thing".
GET-only probing silently mislabels write-only endpoints as not-a-route: an SPA
serves index.html for GET /api/profile/avatar/import, which looks exactly like a
404 fallback. That endpoint was the entire solve on CafeClub.

Authenticated-vs-anonymous is only two of the three identities that matter. When a
challenge *hands* you privileged credentials, that axis is the wrong one: as admin a
successful DELETE /api/admin/posts/4 is correct behaviour, and anonymously it 401s —
neither is a finding. Only a second, low-privilege account exposes the missing guard.
That was the whole solve on Ottergram, where DELETE /api/admin/posts/:id was the one
route under /api/admin that never got the requireAdmin middleware.

On write verbs the low-priv identity is probed FIRST. Whichever identity succeeds
destroys the object the others were going to test, so privileged-first ordering reports
"admin 200, low-priv 404" and buries the finding. Any surviving 2xx-then-404 sequence is
labelled INCONCLUSIVE rather than counted as a negative.

Options:
  --out DIR            save every response body (default: ./probe_out)
  --methods            also send OPTIONS to enumerate allowed methods
  --write              also probe PUT/PATCH/DELETE (skipped by default -- they mutate
                       your own test state; GET/POST discovery is non-destructive enough)
  --lowpriv-token TOK  second, unprivileged identity — enables PRIVILEGE GAP detection
  --lowpriv-cookie C   same, as a cookie
  --id VAL             substitute for {...} placeholders in jsmine paths (default 1)
  --delay S            per-request delay (default 0.05)
"""
import argparse
import json
import os
import random
import re
import string
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()

FLAG_RE = re.compile(r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,90}\}', re.I)

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
    targets, skipped_writes, seen = [], [], set()
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
            skipped_writes.append((method, path))
            continue
        path = re.sub(r'\{[^}]*\}', ident, path)      # /api/orders/{...} -> /api/orders/1
        if "{" in path or "}" in path:
            continue
        key = (method, path)
        if key not in seen:
            seen.add(key)
            targets.append(key)
    return targets, skipped_writes


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
PUBLIC_AUTH_ROUTE = re.compile(
    r'/(?:api/)?(?:auth/)?(?:login|register|signup|forgot-password|reset-password|'
    r'password-reset|verify-email)(?:/|$)', re.I)
PUBLIC_ENVELOPE_KEYS = {"message", "error", "success", "status"}


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


def is_expected_public_auth_response(path, r):
    """Recognize a generic public auth-flow envelope, not an authorization leak.

    Login/register/reset initiation routes must work before authentication. Keep
    this deliberately narrow: only known auth paths, 2xx/3xx responses, and JSON
    objects made solely of generic status/message keys qualify. Tokens, user
    objects, reset links, or any other returned field still fall through to the
    leak verdict and flag scan.
    """
    if isinstance(r, Exception) or r is None or not (200 <= r.status_code < 400):
        return False
    if not PUBLIC_AUTH_ROUTE.search(path.split("?", 1)[0]):
        return False
    try:
        data = r.json()
    except ValueError:
        return False
    if not isinstance(data, dict) or not data:
        return False
    keys = {str(k).lower() for k in data}
    return keys <= PUBLIC_ENVELOPE_KEYS


# Routes whose *name* asserts they are privileged. A low-priv identity getting a
# normal answer from one of these is a finding on its own, with no peer needed.
ADMIN_PATH_RE = re.compile(
    r'/(?:admin|administrator|manage|management|moderat\w*|staff|internal|superuser|'
    r'sudo|root|console|backoffice|back-office|owner)(?:/|$|\?)', re.I)

# A denial, however the app words it. Status codes are jittered by labs, so the
# body has to be able to carry the verdict on its own.
DENIAL_RE = re.compile(
    r'(admin (?:access|privileges?) required|access denied|forbidden|not authoriz|'
    r'unauthoriz|insufficient (?:permission|privilege|role|scope)|permission denied|'
    r'requires? (?:admin|elevated)|must be an? admin)', re.I)


def classify_identity(r, cal_size, cal_ctype):
    """How did one identity fare on this route?

    'allowed' is deliberately narrow: a real, non-error, non-denial response. A 404
    or a validation error is not access — it must not read as a privilege gap.
    """
    if r is None:
        return "-"
    if isinstance(r, Exception):
        return "err"
    size, ctype = len(r.content), (r.headers.get("content-type") or "").split(";")[0]
    if (size == cal_size and ctype == cal_ctype) or is_framework_404(r):
        return "not-a-route"
    if r.status_code in (401, 403) or DENIAL_RE.search((r.text or "")[:400]):
        return "denied"
    if 200 <= r.status_code < 400:
        return "ALLOWED"
    return "error"


def prefix_of(path):
    """Group routes by their first two path segments, for peer comparison.

    /api/admin/posts/1 and /api/admin/flagged-posts both -> /api/admin. When some
    routes in a group deny the low-priv identity and others do not, the app has
    told us the group is meant to be guarded and named the one that isn't. This
    catches privileged groups whose name is not in ADMIN_PATH_RE.
    """
    parts = [seg for seg in path.split("?", 1)[0].split("/") if seg]
    if not parts:
        return None
    return "/" + "/".join(parts[:2])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--paths", required=True, help="file with one path per line, or - for stdin")
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--lowpriv-token", dest="lowpriv_token",
                    help="second, unprivileged identity — enables PRIVILEGE GAP detection")
    ap.add_argument("--lowpriv-cookie", dest="lowpriv_cookie")
    ap.add_argument("--out", default="probe_out")
    ap.add_argument("--methods", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--id", default="1")
    ap.add_argument("--delay", type=float, default=0.05)
    a = ap.parse_args()

    base = a.base.rstrip("/")
    raw = sys.stdin.read() if a.paths == "-" else open(a.paths, encoding="utf-8").read()
    targets, skipped_writes = parse_targets(raw, a.write, a.id)
    has_lowpriv = bool(a.lowpriv_token or a.lowpriv_cookie)
    if skipped_writes:
        unique_skipped = list(dict.fromkeys(skipped_writes))
        print("[!] skipped %d write target(s); PUT/PATCH/DELETE require --write because they mutate state"
              % len(unique_skipped))
        for method, path in unique_skipped:
            print("    SKIPPED %-6s %s" % (method, path))
        print("[!] review object IDs and payloads before rerunning with --write")
        if has_lowpriv and any(ADMIN_PATH_RE.search(p) for _, p in unique_skipped):
            print("[!] a privileged route was skipped on a write verb — that is exactly where "
                  "missing function-level guards live (Ottergram: DELETE /api/admin/posts/:id). "
                  "Rerun with --write.")
        print()
    if not targets:
        print("no non-write paths given")
        return 1
    os.makedirs(a.out, exist_ok=True)

    auth = dict(BASE_HEADERS)
    if a.token:
        auth["Authorization"] = "Bearer " + a.token
    if a.cookie:
        auth["Cookie"] = a.cookie
    has_auth = bool(a.token or a.cookie)

    lowpriv = dict(BASE_HEADERS)
    if a.lowpriv_token:
        lowpriv["Authorization"] = "Bearer " + a.lowpriv_token
    if a.lowpriv_cookie:
        lowpriv["Cookie"] = a.lowpriv_cookie
    if has_lowpriv:
        print("[*] low-priv identity supplied — routes answering it normally are "
              "checked for missing function-level authorization")

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

    if has_lowpriv:
        print("%-40s %-20s %-20s %-20s %s"
              % ("METHOD PATH", "WITH AUTH", "LOW-PRIV", "NO AUTH", "VERDICT"))
        print("-" * 130)
    else:
        print("%-46s %-22s %-22s %s" % ("METHOD PATH", "WITH AUTH", "NO AUTH", "VERDICT"))
        print("-" * 110)

    flags, leaks, real = {}, [], []
    gaps, seen_states = [], {}
    for method, p in targets:
        url = base + p
        label = "%-6s %s" % (method, p)
        cal_size, cal_ctype = cal_by_method[method]
        # Order matters on a write verb: the first identity to succeed CONSUMES the
        # object, and every later identity then probes something that no longer
        # exists. Probing privileged-first turned the live Ottergram DELETE into
        # "admin 200, low-priv 404" — a false negative on the exact bug being hunted.
        # The low-priv identity therefore goes first on writes; its answer is the
        # finding, and the privileged 200 is the least informative of the three.
        order = (("lowpriv", "auth", "noauth") if method in WRITE_METHODS
                 else ("auth", "lowpriv", "noauth"))
        got = {}
        for who in order:
            if who == "auth":
                got["auth"] = fetch(sess, url, auth, method) if has_auth else None
            elif who == "lowpriv":
                got["lowpriv"] = fetch(sess, url, lowpriv, method) if has_lowpriv else None
            else:
                got["noauth"] = fetch(sess, url, BASE_HEADERS, method)
            time.sleep(a.delay)
        ra, rl, rn = got["auth"], got["lowpriv"], got["noauth"]

        # Did an earlier identity destroy the thing a later one was meant to test?
        consumed = None
        if method in WRITE_METHODS:
            winner = None
            for who in order:
                r = got.get(who)
                if r is None or isinstance(r, Exception):
                    continue
                if winner and r.status_code in (404, 410):
                    consumed = (winner, who)
                    break
                if 200 <= r.status_code < 300:
                    winner = who

        sa = describe(ra) if ra is not None else ("-", 0, "-")
        sl = describe(rl) if rl is not None else ("-", 0, "-")
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
              and (rn.text or "") == (ra.text or "") and sn[1] > 0
              and is_expected_public_auth_response(p, rn)):
            verdict = "public-endpoint — expected without auth"
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

        # ---- third identity: does an unprivileged account get in too?
        lp_state = classify_identity(rl, cal_size, cal_ctype) if has_lowpriv else "-"
        if has_lowpriv and verdict != "not-a-route":
            seen_states.setdefault(prefix_of(p), []).append((label, lp_state))
            if lp_state == "ALLOWED" and ADMIN_PATH_RE.search(p):
                verdict = "*** PRIVILEGE GAP — low-priv identity reached a privileged route ***"
                gaps.append(label)

        if has_lowpriv:
            print("%-40s %-20s %-20s %-20s %s" % (
                label[:40], "%s %sB %s" % sa if ra is not None else "-",
                "%s %sB %s" % sl if rl is not None else "-",
                "%s %sB %s" % sn, verdict))
        else:
            print("%-46s %-22s %-22s %s" % (
                label[:46], "%s %sB %s" % sa if ra is not None else "-",
                "%s %sB %s" % sn, verdict))

        if consumed:
            print("%-40s [!] INCONCLUSIVE for '%s': the '%s' identity already consumed this "
                  "object (2xx, then 404/410). Re-run this route against a fresh id before "
                  "trusting the '%s' result." % ("", consumed[1], consumed[0], consumed[1]))

        # save + scan
        for tag, r in (("auth", ra), ("lowpriv", rl), ("noauth", rn)):
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
                allow = o.headers.get("allow")
                cors_methods = o.headers.get("access-control-allow-methods")
                if allow:
                    print("%-40s Allow -> %s" % ("", allow))
                if cors_methods:
                    print("%-40s CORS policy -> %s" % ("", cors_methods))
            except Exception:
                pass

    # ---- peer inconsistency: same route group, different low-priv treatment.
    # Catches privileged groups ADMIN_PATH_RE cannot know the name of.
    for group, entries in sorted(seen_states.items()):
        if group is None or len(entries) < 2:
            continue
        denied = [lab for lab, st in entries if st == "denied"]
        allowed = [lab for lab, st in entries if st == "ALLOWED"]
        if not denied or not allowed:
            continue
        for lab in allowed:
            if lab not in gaps:
                gaps.append(lab)
                print("[!] PRIVILEGE GAP %s — %d sibling route(s) under %s deny the low-priv "
                      "identity, this one does not" % (lab.strip(), len(denied), group))

    print("\n" + "=" * 110)
    print("real routes: %d   no-auth issues: %d   privilege gaps: %d"
          % (len(set(real)), len(leaks), len(gaps)))
    for p in leaks:
        print("   NO-AUTH: %s" % p)
    for p in gaps:
        print("   PRIVILEGE GAP: %s" % p.strip())
    if has_lowpriv and not gaps:
        print("   no route treated the low-priv identity as privileged")
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
