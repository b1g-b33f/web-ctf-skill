#!/usr/bin/env python3
"""fixture_app.py — minimal HTTP server for the SPA-aware recon regression test.

Not part of the CTF harness itself; used only by tests/test_regression.py.

Routes:
  GET  /                -> SPA shell HTML with <script src> tags for /app.js and /mapped.js
  GET  /app.js           -> bundle: one GET route with a query string, one POST route
  GET  /mapped.js         -> bundle advertising a sourceMappingURL, no routes of its own
  GET  /mapped.js.map     -> source map for it: sourcesContent with one node_modules
                              (vendor) entry and one app entry — the app entry's text is a
                              narrative sentence naming a "weak signing key", mirroring the
                              Necromancer lab's AdminPanel.js finding (a hint that reads as
                              prose, not code, and would 404/SPA-fallback if requested
                              directly — it only exists inside the map's sourcesContent)
  GET  /api/data          -> 401, JSON error body, identical with or without auth
  GET  /api/objects/1     -> 404, JSON error body, identical with or without auth
                              (a public error, unrelated to auth)
  anything else           -> the same SPA shell HTML, status 200 — the fallback every
                              unknown path (and every unimplemented quickcheck guess)
                              must resolve to
"""
import json as _json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A real SPA typically serves this exact same shell for both its own root and its
# catch-all fallback, so root and "unknown path" are one body here too.
SPA_HTML = (b'<html><body>SPA shell<script src="/app.js"></script>'
            b'<script src="/mapped.js"></script></body></html>')
APP_JS = b'a.get("/api/data?limit=10");\na.post("/api/submit", {});\n'
DATA_401 = b'{"error":"unauthorized"}'
OBJECT_404 = b'{"error":"not found"}'

MAPPED_JS = b'// mapped bundle, no routes of its own\n//# sourceMappingURL=/mapped.js.map\n'
VENDOR_SRC = "// vendor filler — must be excluded from the extracted src/ tree"
APP_SRC = ('function AdminPanel(){return \'The weak signing key "correcthorse" has '
           "revealed its true nature, a lesson in cryptographic strength.'}")
MAPPED_JS_MAP = _json.dumps({
    "version": 3,
    "file": "mapped.js",
    "sources": ["../node_modules/react/index.js", "components/AdminPanel.js"],
    "sourcesContent": [VENDOR_SRC, APP_SRC],
    "names": [],
    "mappings": "",
}).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _route(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return 200, "text/html", SPA_HTML
        if path == "/app.js":
            return 200, "application/javascript", APP_JS
        if path == "/mapped.js":
            return 200, "application/javascript", MAPPED_JS
        if path == "/mapped.js.map":
            return 200, "application/json", MAPPED_JS_MAP
        if path == "/api/data":
            return 401, "application/json", DATA_401
        if path == "/api/objects/1":
            return 404, "application/json", OBJECT_404
        return 200, "text/html", SPA_HTML

    def _handle(self):
        status, ctype, body = self._route()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def log_message(self, fmt, *args):
        pass


def start():
    """Bind an ephemeral port, serve in a background thread. Returns (server, base_url)."""
    import threading
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = "http://127.0.0.1:%d" % server.server_address[1]
    return server, base_url
