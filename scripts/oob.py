#!/usr/bin/env python3
"""oob.py — stand up an out-of-band collector + public tunnel in ONE command.

Why this exists: on Vaultly-010 the lab's in-app "Preview beacons" panel never fired,
and two long blind polls on it (3 min + 5 min) were spent before an external collector
was built. Building the collector takes ~40s. On any admin-bot lab, do it BEFORE the
first payload, not after the in-app channel disappoints.

    python3 ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge>

Prints `OOB_URL=<https://...>` on stdout as soon as the tunnel is up, then serves
forever. Run it with run_in_background:true and grep the log:

    grep -a 'HIT' $CTF_ROOT/<name>/oob.log

Every request is logged with method, path, query, body, UA, Origin and Referer, and
flag patterns are flagged inline. Responds to any method, sets `Access-Control-Allow-
Origin: *` so `fetch()` reads succeed, and returns a 1x1 GIF so `<img>` beacons settle.

Tunnel choice: cloudflared by default — ngrok's free tier serves an interstitial to
requests that look like browser *navigations* (`Accept: text/html`), which silently
breaks `<script src>` and top-level redirects. `fetch`/`sendBeacon`/`new Image()` do
get through ngrok (that is what worked on Vaultly-010), but cloudflared has no such
failure mode, so prefer it and keep `--tunnel ngrok` as the fallback.
"""
import argparse, base64, os, re, subprocess, sys, threading, datetime, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTF_ROOT = os.environ.get("CTF_ROOT", os.path.expanduser("~/Offsec/Web_CTF/CTF"))
CF = os.environ.get("CLOUDFLARED", "cloudflared")
NGROK = os.environ.get("NGROK", "ngrok")
FLAG = re.compile(r"(?:HTB|bug|flag|CTF)\{[^}]{4,120}\}", re.I)
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
       b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

LOGPATH = None
_lock = threading.Lock()


def _b64(tok):
    try:
        pad = tok.replace("-", "+").replace("_", "/")
        pad += "=" * (-len(pad) % 4)
        return base64.b64decode(pad).decode("utf-8", "replace")
    except Exception:
        return None


def candidates(blob):
    """Exfil is almost always URL-encoded and sometimes base64'd. Match through both.

    Tokens are split so a `d=<b64>` query pair does not carry its `d=` prefix into
    the decoder — that prefix silently broke base64 detection in testing.
    """
    out = [blob]
    try:
        d = urllib.parse.unquote_plus(blob)
    except Exception:
        d = blob
    if d != blob:
        out.append(d)
    for tok in re.split(r"[^A-Za-z0-9+/=_-]+", d):
        for cand in (tok, tok.split("=", 1)[-1] if "=" in tok else None):
            if cand and len(cand) >= 12:
                v = _b64(cand.rstrip("="))
                if v:
                    out.append(v)
    return out


def record(text):
    with _lock:
        with open(LOGPATH, "a", encoding="utf-8") as f:
            f.write(text)
        sys.stdout.write(text)
        sys.stdout.flush()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        blob = self.path + " " + body
        rec = ["\n===== HIT %s  %s %s" % (datetime.datetime.now().isoformat(timespec="seconds"),
                                          self.command, self.path)]
        for h in ("User-Agent", "Origin", "Referer", "Cookie"):
            v = self.headers.get(h)
            if v:
                rec.append("%-10s %s" % (h + ":", v))
        if body:
            rec.append("BODY: " + body)
        dec = urllib.parse.unquote_plus(self.path)
        if dec != self.path:
            rec.append("DECODED: " + dec)
        found = set()
        for c in candidates(blob):
            found.update(FLAG.findall(c))
        for m in found:
            rec.append("*** FLAG: " + m)
        record("\n".join(rec) + "\n")

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin") or "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(GIF)))
        self.end_headers()
        try:
            self.wfile.write(GIF)
        except Exception:
            pass

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = do_DELETE = _handle

    def log_message(self, *a):
        pass


def tunnel(kind, port):
    """Start the tunnel, return its public URL (or None for --tunnel none)."""
    if kind == "none":
        return "http://127.0.0.1:%d" % port

    if kind == "cloudflared":
        p = subprocess.Popen([CF, "tunnel", "--url", "http://localhost:%d" % port],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", bufsize=1)
        pat = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
        for line in p.stdout:
            m = pat.search(line)
            if m:
                threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
                return m.group(0)
        return None

    subprocess.Popen([NGROK, "http", str(port), "--log", "stdout"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import json, time, urllib.request
    for _ in range(30):
        time.sleep(1)
        try:
            d = json.load(urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2))
            for t in d.get("tunnels", []):
                if t.get("public_url", "").startswith("https://"):
                    return t["public_url"]
        except Exception:
            pass
    return None


def main():
    global LOGPATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", help="challenge name -> $CTF_ROOT/<name>/oob.log")
    ap.add_argument("--log")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--tunnel", choices=["cloudflared", "ngrok", "none"], default="cloudflared")
    a = ap.parse_args()

    LOGPATH = a.log or os.path.join(CTF_ROOT, a.name or "", "oob.log")
    os.makedirs(os.path.dirname(os.path.abspath(LOGPATH)), exist_ok=True)

    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    url = tunnel(a.tunnel, a.port)
    if not url:
        print("TUNNEL FAILED (%s) — falling back to localhost only" % a.tunnel)
        url = "http://127.0.0.1:%d" % a.port
    record("OOB_URL=%s   log=%s\n" % (url, LOGPATH))
    print("OOB_URL=%s" % url, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
