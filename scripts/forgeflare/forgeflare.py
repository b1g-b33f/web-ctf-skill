"""Forgeflare anti-bot solver — reusable across BugForge labs.

Forgeflare is a Cloudflare pastiche that HARD-BLOCKS (no app response until cleared).
Three gates:
  1. header fingerprint  -- missing Accept-Language / Sec-Fetch-* => 403 forgeflare_challenge
  2. proof of work       -- sha256(n + ":" + nonce) with `difficulty` leading ZERO BITS
  3. POST /forgeflare/verify {token, nonce, to, hp:"", telemetry} -- telemetry must look human

Yields a `forgeflare_clearance` cookie with a ~60s TTL, so it must be re-solved
continuously. FF.req() handles that automatically.

The on-page checkbox is only a trigger; `hp` is a honeypot field and must stay empty.
Never request /forgeflare/trap (hidden link + robots.txt honeypot).

Usage:
    export FORGEFLARE_TARGET=https://lab-xxxx.labs-app.bugforge.io
    from forgeflare import FF
    f = FF()                      # or FF("https://target")
    r = f.get("/api/whatever")

First seen: WordMess-001 (2026-07-26). See the Obsidian note for the full writeup.
"""
import hashlib, json, os, random, re, time
import requests
import urllib3

urllib3.disable_warnings()

DEFAULT_TARGET = os.environ.get("FORGEFLARE_TARGET", "")

HDRS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="126", "Not)A;Brand";v="24", "Google Chrome";v="126"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def leading_zero_bits(hexdigest):
    b = 0
    for c in hexdigest:
        n = int(c, 16)
        if n == 0:
            b += 4
            continue
        if n < 2: b += 3
        elif n < 4: b += 2
        elif n < 8: b += 1
        break
    return b


def solve_pow(n, difficulty):
    """Find nonce such that sha256(f'{n}:{nonce}') has >= difficulty leading zero bits."""
    i = 0
    while leading_zero_bits(hashlib.sha256(f"{n}:{i}".encode()).hexdigest()) < difficulty:
        i += 1
    return i


class FF:
    """requests.Session that keeps a live Forgeflare clearance."""

    TTL = 45  # re-clear before the server's ~60s expiry

    def __init__(self, base=None, verbose=False):
        self.base = (base or DEFAULT_TARGET).rstrip("/")
        if not self.base:
            raise SystemExit("set FORGEFLARE_TARGET or pass base=")
        self.verbose = verbose
        self.s = requests.Session()
        self.s.headers.update(HDRS)
        self.s.verify = False
        self.cleared_at = 0
        self.clear()

    def clear(self):
        r = self.s.get(f"{self.base}/forgeflare/challenge", params={"to": "/"})
        m = re.search(r'<script id="ff-data" type="application/json">(.*?)</script>',
                      r.text, re.S)
        if not m:
            return False
        ff = json.loads(m.group(1))
        nonce = solve_pow(ff["n"], ff["difficulty"])
        if self.verbose:
            print(f"[ff] pow n={ff['n']} diff={ff['difficulty']} nonce={nonce}")
        self.s.post(f"{self.base}/forgeflare/verify", json={
            "token": ff["token"], "nonce": nonce, "to": ff["to"], "hp": "",
            "telemetry": {
                "mouseMoves": random.randint(40, 90), "clicks": 1,
                "keys": random.randint(2, 8), "scrolls": random.randint(1, 5),
                "dwellMs": random.randint(3500, 9000), "webdriver": False,
                "plugins": 5, "languages": 2, "screen": 1920,
            }}, headers={"Content-Type": "application/json", "Sec-Fetch-Dest": "empty",
                         "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
                         "Referer": f"{self.base}/forgeflare/challenge"})
        self.cleared_at = time.time()
        return True

    def req(self, method, path, **kw):
        if time.time() - self.cleared_at > self.TTL:
            self.clear()
        url = path if path.startswith("http") else self.base + path
        kw.setdefault("allow_redirects", False)
        r = self.s.request(method, url, **kw)
        # edge 403 (forgeflare_challenge) != app 403 (its own authz) -- only retry the former
        if r.status_code == 403 and "forgeflare" in r.text[:400].lower():
            self.clear()
            r = self.s.request(method, url, **kw)
        return r

    def get(self, p, **kw): return self.req("GET", p, **kw)
    def post(self, p, **kw): return self.req("POST", p, **kw)
    def put(self, p, **kw): return self.req("PUT", p, **kw)
    def patch(self, p, **kw): return self.req("PATCH", p, **kw)
    def delete(self, p, **kw): return self.req("DELETE", p, **kw)


def show(r, n=3000):
    print(r.status_code, r.headers.get("Content-Type"), len(r.content))
    for k, v in r.headers.items():
        if k.lower() not in ("date", "etag", "content-length", "content-type",
                             "connection", "keep-alive"):
            print(f"  {k}: {v}")
    print(r.text[:n])


# --- WordPress-clone helpers (WordMess-shaped; adjust per lab) ---------------
def wp_login(f, user, pw, path="/wp-login.php", redirect="/wp-admin"):
    f.post(path, data={"log": user, "pwd": pw, "redirect_to": redirect})
    return f


def wp_nonce(f, admin="/wp-admin"):
    """Pull the REST nonce out of window.wpApiSettings."""
    m = re.search(r"nonce:\s*'([^']+)'", f.get(admin).text)
    return m.group(1) if m else None


if __name__ == "__main__":
    import sys
    f = FF(verbose=True)
    show(f.get(sys.argv[1] if len(sys.argv) > 1 else "/"))
