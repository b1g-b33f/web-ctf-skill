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
  POST /api/graphql       -> authenticated GraphQL endpoint with introspection disabled;
                              validation errors disclose user(id: ID!), whose password
                              field carries a synthetic regression flag
  OPTIONS *                -> 204 with Access-Control-Allow-Methods set and no
                              route-specific Allow header, so probe.py's --methods
                              output must read "CORS policy", never "Allow"
  anything else           -> the same SPA shell HTML, status 200 — the fallback every
                              unknown path (and every unimplemented quickcheck guess)
                              must resolve to
"""
import json as _json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A real SPA typically serves this exact same shell for both its own root and its
# catch-all fallback, so root and "unknown path" are one body here too.
SPA_HTML = (b'<html><body>SPA shell<a href="/login">login</a>'
            b'<a href="/jobs/${job.id}/applicants">dynamic job</a>'
            b'<script src="/app.js"></script><script src="/mapped.js"></script>'
            b'<script src="/socket.io/socket.io.js"></script>'
            b'<script src="/missing.js"></script><script src="/json.js"></script></body></html>')
LOGIN_HTML = (b'<html><body><form action="/api/auth/login" method="post">'
              b'<input name="email"></form></body></html>')
APP_JS = b'''a.get("/api/data?limit=10");
a.post("/api/submit", {});
const LOG_ACTIVITY_MUTATION = `
  mutation LogActivity($event: String!, $userId: ID, $metadata: String) {
    logActivity(event: $event, userId: $userId, metadata: $metadata) {
      id
      event
      timestamp
    }
  }
`;
a.post("/api/graphql", {query: LOG_ACTIVITY_MUTATION});
'''
DATA_401 = b'{"error":"unauthorized"}'
OBJECT_404 = b'{"error":"not found"}'
FORGOT_PASSWORD_PUBLIC = b'{"message":"If that email exists, a reset link was sent."}'
FORGOT_PASSWORD_LEAK = (b'{"message":"If that email exists, a reset link was sent.",'
                        b'"reset_token":"leaked-secret-value"}')
STOCKS_SEARCH_401 = b'{"error":"access token required"}'
CORS_ALLOW_METHODS = "GET,POST,PUT,PATCH,DELETE"
GRAPHQL_FLAG = "bug" + "{GraphqlQuickRegression123}"

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

SOCKET_JS = b'// vendor admin debug comment\n//# sourceMappingURL=/socket.io/socket.io.js.map\n'
SOCKET_MAP = _json.dumps({
    "version": 3,
    "file": "socket.io.js",
    "sources": [
        "webpack://socket.io-client/./build/esm/index.js",
        "webpack://engine.io-parser/./build/esm/commons.js",
    ],
    "sourcesContent": [
        "// socket.io vendor admin comment",
        "// engine.io vendor debug comment",
    ],
    "names": [],
    "mappings": "",
}).encode()

NOSQL_DOCS = [
    {"email": "alpha@example.test", "backupCode": "ALPHA-1", "username": "alpha"},
    {"email": "whiskers@example.test", "backupCode": "bug{aZ9}", "username": "whiskers"},
]


def _mongo_match(actual, wanted):
    if not isinstance(wanted, dict):
        return actual == wanted
    if "$ne" in wanted:
        return actual != wanted["$ne"]
    if "$gt" in wanted:
        return actual > wanted["$gt"]
    if "$eq" in wanted:
        return actual == wanted["$eq"]
    if "$regex" in wanted:
        try:
            return re.search(wanted["$regex"], actual) is not None
        except re.error:
            return False
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _route(self, data=None):
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
        if path == "/socket.io/socket.io.js":
            return 200, "application/javascript", SOCKET_JS
        if path == "/socket.io/socket.io.js.map":
            return 200, "application/json", SOCKET_MAP
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
        if path == "/api/graphql" and self.command == "POST":
            if not self.headers.get("Authorization"):
                return 401, "application/json", b'{"error":"access token required"}'
            query = data.get("query", "") if isinstance(data, dict) else ""
            if "__typename" in query:
                return 200, "application/json", b'{"data":{"__typename":"Query"}}'
            if "__schema" in query:
                body = _json.dumps({"errors": [{
                    "message": "GraphQL introspection has been disabled"
                }]}).encode()
                return 200, "application/json", body
            if re.search(r'\{\s*user\s*\}', query):
                body = _json.dumps({"errors": [
                    {"message": 'Field "user" argument "id" of type "ID!" is required.'},
                    {"message": 'Field "user" of type "User" must have a selection of subfields.'},
                ]}).encode()
                return 200, "application/json", body
            user_query = re.search(
                r'user\s*\(\s*id\s*:\s*["\']?(\d+)["\']?\s*\)\s*\{\s*([A-Za-z_]\w*)\s*\}',
                query)
            if user_query:
                user_id, field = user_query.groups()
                values = {
                    "id": user_id,
                    "username": "admin" if user_id == "1" else "fixture-user",
                    "email": "admin@example.test" if user_id == "1" else "user@example.test",
                    "role": "admin" if user_id == "1" else "user",
                    "password": GRAPHQL_FLAG if user_id == "1" else "not-a-flag",
                }
                if field in values:
                    body = _json.dumps({"data": {"user": {field: values[field]}}}).encode()
                else:
                    body = _json.dumps({"errors": [{
                        "message": 'Cannot query field "%s" on type "User".' % field
                    }]}).encode()
                return 200, "application/json", body
            root = re.search(r'\{\s*([A-Za-z_]\w*)', query)
            name = root.group(1) if root else "unknown"
            body = _json.dumps({"errors": [{
                "message": 'Cannot query field "%s" on type "Query".' % name
            }]}).encode()
            return 200, "application/json", body
        if path == "/api/account/recover" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            matches = [doc for doc in NOSQL_DOCS
                       if _mongo_match(doc["email"], data.get("email"))
                       and _mongo_match(doc["backupCode"], data.get("backupCode"))]
            if matches:
                # Stable lexical selection makes $gt cursor enumeration testable.
                doc = sorted(matches, key=lambda item: item["email"])[0]
                body = _json.dumps({"status": "verified", "email": doc["email"],
                                    "username": doc["username"]}).encode()
                return 200, "application/json", body
            return 400, "application/json", b'{"status":"invalid","error":"verification failed"}'
        if path == "/api/nosql-rate-limit" and self.command == "POST":
            return 429, "application/json", b'{"error":"slow down"}'
        if path == "/api/nosql-crash" and self.command == "POST":
            return 502, "text/plain", b"bad gateway"
        return 200, "text/html", SPA_HTML

    def _handle(self):
        # Drain any request body before responding: this handler is HTTP/1.1
        # keep-alive, and an unread POST/PUT/PATCH body left on the wire becomes
        # the start of the *next* request line on the same connection, garbling
        # it into a 400/501 -- probe.py reuses one session across every fetch,
        # calibration included, so two body-bearing requests back to back will
        # hit this if the body isn't drained here.
        length = int(self.headers.get("Content-Length", 0) or 0)
        data = None
        if length:
            raw = self.rfile.read(length)
            try:
                data = _json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                data = None
        status, ctype, body = self._route(data)
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
        if self.path.split("?", 1)[0] == "/api/account/recover":
            self.send_header("Allow", "POST")
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
