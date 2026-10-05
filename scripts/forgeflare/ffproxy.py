"""Forgeflare-clearing reverse proxy.

Listens on 127.0.0.1:8899 and forwards everything to the target over HTTPS,
injecting the browser header set and a live forgeflare_clearance cookie
(re-solving the proof-of-work as it expires).

This lets UNMODIFIED third-party tooling run against a Forgeflare-protected lab
-- a public PoC, sqlmap, ffuf, nuclei, or plain curl -- none of which can solve
the PoW themselves:

    export FORGEFLARE_TARGET=https://lab-xxxx.labs-app.bugforge.io
    python3 ffproxy.py
    curl -s http://127.0.0.1:8899/wp-json
    sqlmap -u 'http://127.0.0.1:8899/x?id=1' --batch
    ffuf -u http://127.0.0.1:8899/FUZZ -w wordlist.txt

Point tools at the proxy directly (NOT via curl -x); it is a reverse proxy, so
the URL is rewritten to the target. 127.0.0.1 also satisfies "is this local?"
authorization gates that some PoCs enforce before running against a remote host.
"""
import os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from forgeflare import FF, is_edge_challenge

TARGET = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("FORGEFLARE_TARGET", "")).rstrip("/")
PORT = int(os.environ.get("FFPROXY_PORT", "8899"))

_lock = threading.Lock()
_ff = FF(TARGET)

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
       "accept-encoding", "cookie"}
# Headers the caller must NOT be able to override -- these are what Forgeflare
# fingerprints on. A PoC's own User-Agent would get it 403'd instantly.
PIN = ["User-Agent", "Accept", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
       "Sec-Ch-Ua-Platform", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
       "Sec-Fetch-User", "Upgrade-Insecure-Requests"]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in HOP and k.lower() not in {name.lower() for name in PIN}}
        fwd.update({name: _ff.s.headers[name] for name in PIN})
        caller_cookies = [part.strip() for part in self.headers.get("Cookie", "").split(";")
                          if part.strip() and not part.strip().startswith("forgeflare_clearance=")]
        with _lock:
            if time.monotonic() - _ff.cleared_at > _ff.TTL:
                _ff.clear()
            fwd["Cookie"] = "; ".join(
                ["forgeflare_clearance=" + _ff.s.cookies["forgeflare_clearance"]] + caller_cookies)
            r = requests.request(self.command, _ff.base + self.path, data=body,
                                 headers=fwd, verify=False, allow_redirects=False, timeout=60)
            if is_edge_challenge(r):
                _ff.clear()
                fwd["Cookie"] = "; ".join(
                    ["forgeflare_clearance=" + _ff.s.cookies["forgeflare_clearance"]] + caller_cookies)
                r = requests.request(self.command, _ff.base + self.path, data=body,
                                     headers=fwd, verify=False, allow_redirects=False, timeout=60)
        payload = r.content
        self.send_response(r.status_code)
        for k, v in r.headers.items():
            if k.lower() in HOP or k.lower() in {"content-encoding", "set-cookie"}:
                continue
            self.send_header(k, v)
        for cookie in r.raw.headers.getlist("Set-Cookie"):
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _do


if __name__ == "__main__":
    print("[*] forgeflare proxy -> %s  on http://127.0.0.1:%d" % (_ff.base, PORT), flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
