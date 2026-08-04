#!/usr/bin/env python3
"""fixture_app.py — minimal HTTP server for the SPA-aware recon regression test.

Not part of the CTF harness itself; used only by tests/test_regression.py.

Routes:
  GET  /                -> SPA shell HTML with a <script src="/app.js"> tag
  GET  /app.js           -> bundle: one GET route with a query string, one POST route
  GET  /api/data          -> 401, JSON error body, identical with or without auth
  GET  /api/objects/1     -> 404, JSON error body, identical with or without auth
                              (a public error, unrelated to auth)
  anything else           -> the same SPA shell HTML, status 200 — the fallback every
                              unknown path (and every unimplemented quickcheck guess)
                              must resolve to
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A real SPA typically serves this exact same shell for both its own root and its
# catch-all fallback, so root and "unknown path" are one body here too.
SPA_HTML = b'<html><body>SPA shell<script src="/app.js"></script></body></html>'
APP_JS = b'a.get("/api/data?limit=10");\na.post("/api/submit", {});\n'
DATA_401 = b'{"error":"unauthorized"}'
OBJECT_404 = b'{"error":"not found"}'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _route(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return 200, "text/html", SPA_HTML
        if path == "/app.js":
            return 200, "application/javascript", APP_JS
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
