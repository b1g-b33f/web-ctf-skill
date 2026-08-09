#!/usr/bin/env python3
"""fixture_app.py — minimal HTTP server for the SPA-aware recon regression test.

Not part of the CTF harness itself; used only by tests/test_regression.py.

Routes:
  GET  /                -> SPA shell HTML with valid bundles, one missing bundle, and /login link
  GET  /login           -> rendered form exposing POST /api/auth/login
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
  *    /api/forgot-password    -> 200, generic {"message": ...} envelope, identical
                                    with or without auth (a public auth-flow route,
                                    not a leak); ?mode=leak switches in an extra
                                    reset_token field, which must stay a leak
  GET  /api/stocks/search -> 401, JSON error body — a protected leaf nested below
                              /api, reachable only by direct guess since /api itself
                              is the SPA fallback
  OPTIONS *                -> 204 with Access-Control-Allow-Methods set and no
                              route-specific Allow header, so probe.py's --methods
                              output must read "CORS policy", never "Allow"
  anything else           -> the same SPA shell HTML, status 200 — the fallback every
                              unknown path (and every unimplemented quickcheck guess)
                              must resolve to
"""
import json as _json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A real SPA typically serves this exact same shell for both its own root and its
# catch-all fallback, so root and "unknown path" are one body here too.
SPA_HTML = (b'<html><body>SPA shell<a href="/login">login</a>'
            b'<script src="/app.js"></script><script src="/mapped.js"></script>'
            b'<script src="/missing.js"></script><script src="/json.js"></script></body></html>')
LOGIN_HTML = (b'<html><body><form action="/api/auth/login" method="post">'
              b'<input name="email"></form></body></html>')
APP_JS = b'a.get("/api/data?limit=10");\na.post("/api/submit", {});\n'
DATA_401 = b'{"error":"unauthorized"}'
OBJECT_404 = b'{"error":"not found"}'
FORGOT_PASSWORD_PUBLIC = b'{"message":"If that email exists, a reset link was sent."}'
FORGOT_PASSWORD_LEAK = (b'{"message":"If that email exists, a reset link was sent.",'
                        b'"reset_token":"leaked-secret-value"}')
STOCKS_SEARCH_401 = b'{"error":"access token required"}'
CORS_ALLOW_METHODS = "GET,POST,PUT,PATCH,DELETE"

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
        if path == "/login":
            return 200, "text/html", LOGIN_HTML
        if path == "/app.js":
            return 200, "application/javascript", APP_JS
        if path == "/mapped.js":
            return 200, "application/javascript", MAPPED_JS
        if path == "/mapped.js.map":
            return 200, "application/json", MAPPED_JS_MAP
        if path == "/missing.js":
            return 404, "text/plain", b"404 page not found"
        if path == "/json.js":
            return 200, "application/json", b'{"error":"not a bundle"}'
        if path == "/api/data":
            return 401, "application/json", DATA_401
        if path == "/api/objects/1":
            return 404, "application/json", OBJECT_404
        if path == "/api/forgot-password":
            if "mode=leak" in self.path:
                return 200, "application/json", FORGOT_PASSWORD_LEAK
            return 200, "application/json", FORGOT_PASSWORD_PUBLIC
        if path == "/api/stocks/search":
            return 401, "application/json", STOCKS_SEARCH_401
        return 200, "text/html", SPA_HTML

    def _handle(self):
        # Drain any request body before responding: this handler is HTTP/1.1
        # keep-alive, and an unread POST/PUT/PATCH body left on the wire becomes
        # the start of the *next* request line on the same connection, garbling
        # it into a 400/501 -- probe.py reuses one session across every fetch,
        # calibration included, so two body-bearing requests back to back will
        # hit this if the body isn't drained here.
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
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

    def do_OPTIONS(self):
        """CORS-middleware-shaped, not route-shaped: a real Access-Control-Allow-Methods
        header advertising the app's global cross-origin policy, deliberately with no
        route-specific Allow header — probe.py must label this 'CORS policy', not 'Allow'."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        self.send_header("Content-Length", "0")
        self.end_headers()

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
