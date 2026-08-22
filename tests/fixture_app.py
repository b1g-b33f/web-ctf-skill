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
  GET  /api/widgets/<id>  -> numeric path parameter concatenated into real SQL: the
                              shape a quote probe cannot distinguish from a bound one,
                              since a stray quote just fails to match. Returns a single
                              row, so a UNION must empty the left side to be seen
  GET  /api/gadgets/<id>  -> the same route with the id bound — the control that must
                              never be reported as injectable
  GET  /api/stocks/search -> 401, JSON error body — a protected leaf nested below
                              /api, reachable only by direct guess since /api itself
                              is the SPA fallback
  GET  /api/post/image    -> Ottergram-shaped file read: a known-valid PNG baseline,
                              standard/four-dot/double-encoded traversal modes,
                              body/header flags, and auth/rate/gateway controls
  POST /api/graphql       -> authenticated GraphQL endpoint with introspection disabled;
                              validation errors disclose user(id: ID!), whose password
                              field carries a synthetic regression flag
  POST /api/indicator     -> Shady-Oaks-shaped valid request whose response adds an
                              undocumented caption="{value}" field; resubmitting that
                              response-only field expands safe context variables and
                              a synthetic high-value flag variable
  *    /api/cmdi/*        -> DiceForge-shaped command-injection fixtures covering JSON,
                              query, form, path, header, and raw multipart transports,
                              plus reflection-only, invalid, rate-limit, and gateway controls
  *    /api/admin/*       -> Ottergram-shaped function-level authorization: a bearer
                              token whose value contains "admin" is the privileged
                              identity, any other token is low-priv, no token is 401.
                              Three routes enforce the role; DELETE /api/admin/posts/1
                              only checks that a token exists and returns a flag —
                              invisible to an auth-vs-anonymous probe, since the
                              privileged identity succeeds on all four by design
  *    /api/reports/*     -> same gap in a group whose *name* carries no privilege
                              signal, so only peer inconsistency can find it
  *    /api/feed/*        -> ordinary group, every identity allowed — the control
                              case that must never be reported as a privilege gap
  OPTIONS *                -> 204 with Access-Control-Allow-Methods set and no
                              route-specific Allow header, so probe.py's --methods
                              output must read "CORS policy", never "Allow"
  anything else           -> the same SPA shell HTML, status 200 — the fallback every
                              unknown path (and every unimplemented quickcheck guess)
                              must resolve to
"""
import base64
import json as _json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

# A real SQLite database, so the path-parameter injection fixture exercises actual SQL
# rather than a hand-rolled imitation: real column counts, real sqlite_master, real
# single-row semantics. /api/widgets/<id> concatenates; /api/gadgets/<id> binds.
_DB_LOCK = threading.Lock()
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript("""
CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT, colour TEXT);
INSERT INTO widgets VALUES (1,'first','red'),(2,'second','blue');
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
INSERT INTO users VALUES (1,'admin','bug{fixture_path_param_union_ok}');
""")


def _widget_row(raw, bound):
    """Return (status, body) for the widget lookup, concatenated or bound."""
    with _DB_LOCK:
        try:
            if bound:
                cur = _DB.execute("SELECT id,name,colour FROM widgets WHERE id = ?", (raw,))
            else:
                cur = _DB.execute("SELECT id,name,colour FROM widgets WHERE id = %s" % raw)
            rows = cur.fetchall()
        except sqlite3.Error:
            # Swallow the SQL error into the ordinary not-found, exactly like the app
            # this models. That is what makes a quote probe useless: a syntax error and
            # a non-matching id are the *same* response, so `1'` -> "not found" says
            # nothing about whether the id is bound.
            return 404, b'{"error":"widget not found"}'
    if not rows:
        return 404, b'{"error":"widget not found"}'
    # Only the first row, exactly like a real /resource/:id handler. This is what makes
    # a naive `1 UNION SELECT <payload>` return the legitimate row and hide the payload.
    r = rows[0]
    return 200, _json.dumps({"id": r[0], "name": r[1], "colour": r[2]}).encode()

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
axios.post('/api/roll', { dice: dicePayload, rollOptions: 'none' });
const postImage = <img src={`/api/post/image?file=${post.image_url}`} />;
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
# A refusing route that answers in styled HTML rather than JSON -- the ordinary
# shape of a gateway/WAF block page. The CSS here is the point: every rule is a
# word followed by a braced block, which a wildcard-prefix flag pattern reads as
# a flag.
STYLED_DENIAL_HTML = (
    b'<html><head><style>'
    b'body{background:#fff;font-family:sans-serif}'
    b'.form{margin:0;padding:0}'
    b'div.card{box-shadow:0 1px 2px}'
    b'</style></head><body><h1>403 Forbidden</h1>'
    b'<p>You do not have permission to access this resource.</p></body></html>')
CORS_ALLOW_METHODS = "GET,POST,PUT,PATCH,DELETE"
GRAPHQL_FLAG = "bug" + "{GraphqlQuickRegression123}"
LFI_FLAG = "bug" + "{LfiQuickRegression123}"
LFI_HEADER_FLAG = "bug" + "{LfiQuickHeaderRegression123}"
LFI_ENV_FLAG = "bug" + "{LfiQuickEnvironmentRegression123}"
LFI_WINDOWS_FLAG = "bug" + "{LfiQuickWindowsConfigRegression123}"
LFI_BASELINE = b"\x89PNG\r\n\x1a\nfixture-image"
LFI_PASSWD = b"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh\n"
LFI_PROC_STATUS = b"Name:\tfixture-app\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t4242\n"
LFI_WININI = b"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"
LFI_MISSING = b'{"error":"File not found"}'

# Ottergram-shaped function-level authorization. Three routes under /api/admin
# enforce the role; DELETE /api/admin/posts/1 only checks that *a* token exists,
# which is the real bug that lab shipped. The privileged identity succeeds on all
# four (correct behaviour) and the anonymous one is refused by all four, so an
# auth-vs-anon probe sees nothing -- only the low-priv identity separates them.
# The flag is worded so flaghook.py's IGNORE rule treats it as a placeholder and
# the regression suite never pollutes the real flag log.
ADMIN_OK = b'{"message":"Welcome to the admin panel"}'
ADMIN_FLAGGED = b'{"flagged":[]}'
ADMIN_APPROVED = b'{"message":"Post approved"}'
ADMIN_DENIED = b'{"error":"Admin access required"}'
NO_TOKEN = b'{"error":"Access token required"}'
BFLA_FLAG = "flag" + "{example_privilege_gap_fixture}"
BFLA_DELETED = ('{"message":"Post deleted successfully","flag":"%s"}' % BFLA_FLAG).encode()

# A privileged group whose name says nothing about privilege -- ADMIN_PATH_RE
# cannot know /api/reports is guarded. Two siblings refuse the low-priv identity
# and one does not, which is the only evidence probe.py gets, and it must be enough.
# Real objects are consumed by the first identity that deletes them. Post 1 is
# idempotent (the simple case); post 2 is stateful and 404s on every call after the
# first, which is what the live Ottergram target actually did -- probing the
# privileged identity first turned the finding into "admin 200, low-priv 404".
DELETED_POSTS = set()
POST_MISSING = b'{"error":"Post not found"}'

REPORT_RESOLVED = b'{"message":"Report resolved"}'
REPORT_DELETED = b'{"message":"Report deleted"}'
# An ordinary any-logged-in-user group: every route answers every identity. A
# low-priv account succeeding here is correct, and must never read as a gap.
FEED_OK = b'{"posts":[{"id":1,"caption":"otter"}]}'

MAPPED_JS = b'// mapped bundle, no routes of its own\n//# sourceMappingURL=/mapped.js.map\n'
VENDOR_SRC = "// vendor filler — must be excluded from the extracted src/ tree"
APP_SRC = ('function AdminPanel(){return \'The weak signing key "correcthorse" has '
           "revealed its true nature, a lesson in cryptographic strength.'}\n"
           "const fragment = decodeURIComponent(location.hash.slice(1));\n"
           "document.querySelector('#preview').innerHTML = fragment;")
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
NOSQL_LIST_DOCS = [
    {"id": 1, "name": "public-one", "is_public": True},
    {"id": 2, "name": "public-two", "is_public": True},
    {"id": 3, "name": "private", "is_public": False,
     "flag": "bug{NosqlFilterRegression_<nonce>}"},
]

TEMPLATE_FLAG = "bug" + "{example_template_variable_fixture}"
CMDI_FLAG = "bug" + "{CmdiQuickRegression123}"
CMDI_ID = "uid=1000(fixture) gid=1000(fixture) groups=1000(fixture)"
CMDI_OOB_LOG = None


def _cmdi_posix_result(value):
    whoami = re.search(r'(?:;|&&|\||\|\||\n)whoami(?:\s|;|#|$)', value)
    if whoami:
        return CMDI_FLAG
    identity = re.search(r'(?:;|&&|\||\|\||\n)id(?:\s|;|#|$)', value)
    if identity:
        return CMDI_ID
    marker = re.search(r'(?:;|&&|\||\|\||\n)printf\s+%s\s+(CMDIQ_[A-Z0-9]+)', value)
    if marker:
        return marker.group(1)
    delay = re.search(r'(?:;|&&|\||\|\||\n)sleep\s+(\d+)', value)
    if delay:
        time.sleep(min(int(delay.group(1)), 2))
        return ""
    return None


def _cmdi_windows_result(value):
    if re.search(r'ver>nul&&whoami(?:\s|&|$)', value, re.I):
        return CMDI_FLAG
    marker = re.search(r'ver>nul&&echo\s+(CMDIQ_[A-Z0-9]+)', value, re.I)
    if marker:
        return marker.group(1)
    delay = re.search(r'ver>nul&&timeout\s+/t\s+(\d+)', value, re.I)
    if delay:
        time.sleep(min(int(delay.group(1)), 2))
        return ""
    return None


def _cmdi_powershell_result(value):
    if not re.search(r'if\(\$PSVersionTable\)\{', value, re.I):
        return None
    if re.search(r'\{whoami(?:\s|;|\}|$)', value, re.I):
        return CMDI_FLAG
    marker = re.search(r'Write-Output\s+(CMDIQ_[A-Z0-9]+)', value, re.I)
    if marker:
        return marker.group(1)
    delay = re.search(r'Start-Sleep\s+-Seconds\s+(\d+)', value, re.I)
    if delay:
        time.sleep(min(int(delay.group(1)), 2))
        return ""
    return None


def _cmdi_result(value):
    """Simulate shell semantics without executing a real command in the test process."""
    value = value if isinstance(value, str) else ""
    for detector in (_cmdi_posix_result, _cmdi_windows_result, _cmdi_powershell_result):
        output = detector(value)
        if output is not None:
            return output
    return None


def _cmdi_body(value, reflect=False, execute=True):
    data = {"status": "ok"}
    if reflect:
        data["value"] = value
    output = _cmdi_result(value) if execute else None
    if output is not None:
        data["output"] = output
    return _json.dumps(data).encode()

# Vaultly-shaped first-use account lifecycle. A magic token can be read from a
# public inbox and is accepted as the undocumented ``code`` registration field
# while the account is still unclaimed. Redeeming the token normally first burns
# that state, leaving the user passwordless. authquick.py must therefore try the
# cross-flow consumer before the intended verification consumer.
AUTH_FLAG = "bug" + "{AuthQuickRegression123}"
AUTH_LOCK = threading.Lock()
AUTH_USERS = {}
AUTH_TOKENS = {}
AUTH_MESSAGES = []
AUTH_SESSIONS = {}
AUTH_COUNTERS = {"token": 0, "session": 0}


def _reset_auth_state():
    with AUTH_LOCK:
        AUTH_USERS.clear()
        AUTH_USERS.update({
            "maya.chen@acme.test": {
                "name": "Maya Chen", "password": None, "claimed": False,
                "verified": False, "executive": True,
            },
            "sofia.garcia@acme.test": {
                "name": "Sofia Garcia", "password": None, "claimed": False,
                "verified": False, "executive": True,
            },
            "burned@acme.test": {
                "name": "Burned Account", "password": None, "claimed": True,
                "verified": True, "executive": True,
            },
            "rate@acme.test": {
                "name": "Rate Limited", "password": None, "claimed": False,
                "verified": False, "executive": True,
            },
            "gateway@acme.test": {
                "name": "Gateway Failure", "password": None, "claimed": False,
                "verified": False, "executive": True,
            },
        })
        AUTH_TOKENS.clear()
        AUTH_MESSAGES.clear()
        AUTH_SESSIONS.clear()
        AUTH_COUNTERS.update({"token": 0, "session": 0})


def _new_auth_token(email):
    with AUTH_LOCK:
        AUTH_COUNTERS["token"] += 1
        token = "fixture-magic-%d" % AUTH_COUNTERS["token"]
        AUTH_TOKENS[token] = {"email": email, "consumed": False}
        AUTH_MESSAGES.append({
            "to": email,
            "link": "/api/auth/magic-link/verify?token=" + token,
        })
        return token


def _new_auth_session(email, method):
    with AUTH_LOCK:
        AUTH_COUNTERS["session"] += 1
        session_id = "fixture-session-%d" % AUTH_COUNTERS["session"]
        AUTH_SESSIONS[session_id] = {"email": email, "method": method}
        return session_id


def _cookie_value(header, name):
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        key, value = part.strip().split("=", 1)
        if key == name:
            return value
    return None


def _unverified_jwt_payload(token):
    """Decode only enough JWT structure to model a deliberately weak fixture verifier."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        raw = parts[1] + "=" * (-len(parts[1]) % 4)
        data = _json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


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
        query = parse_qs(urlparse(self.path).query, keep_blank_values=True)
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
        if path == "/api/post/image" and self.command == "GET":
            file_value = (query.get("file") or [""])[0]
            mode = (query.get("mode") or ["standard"])[0]
            gate = (query.get("gate") or [""])[0]
            if gate == "auth" and not self.headers.get("Authorization"):
                return 401, "application/json", NO_TOKEN
            if file_value == "/uploads/otter1.png":
                return 200, "image/png", LFI_BASELINE
            if mode == "rate":
                return 429, "application/json", b'{"error":"slow down"}'
            if mode == "gateway":
                return 502, "text/plain", b"bad gateway"
            if mode == "standard" and file_value == "../flag.txt":
                return 200, "text/plain", LFI_FLAG.encode()
            if mode == "header" and file_value == "../flag.txt":
                return 200, "text/plain", b"read complete", {"X-Flag": LFI_HEADER_FLAG}
            if mode in ("four-dot", "confirm-only"):
                if file_value == "....//....//etc/passwd":
                    return 200, "text/plain", LFI_PASSWD
                if mode == "four-dot" and file_value == "....//....//flag.txt":
                    return 200, "text/plain", LFI_FLAG.encode()
            if mode == "double-encoded":
                decoded_again = unquote(file_value)
                if decoded_again == "../../etc/passwd":
                    return 200, "text/plain", LFI_PASSWD
                if decoded_again == "../../flag.txt":
                    return 200, "text/plain", LFI_FLAG.encode()
            if mode == "linux-env":
                if file_value == "..//..//etc/passwd":
                    return 200, "text/plain", LFI_PASSWD
                if file_value == "..//..//proc/self/environ":
                    return 200, "application/octet-stream", (
                        b"PATH=/usr/local/bin\x00OBJECTIVE=" + LFI_ENV_FLAG.encode())
            if mode == "windows":
                if file_value == "..\\..\\Windows\\win.ini":
                    return 200, "text/plain", LFI_WININI
                if file_value == "..\\..\\inetpub\\wwwroot\\web.config":
                    return 200, "application/xml", (
                        b"<configuration><add key=\"objective\" value=\""
                        + LFI_WINDOWS_FLAG.encode() + b"\"/></configuration>")
            if mode == "slash-encoded":
                if file_value == "../../etc/passwd":
                    return 200, "text/plain", LFI_PASSWD
                if file_value == "../../app/.env":
                    return 200, "text/plain", b"FLAG=" + LFI_ENV_FLAG.encode()
            if mode == "passwd-blocked":
                if file_value == "../../proc/self/status":
                    return 200, "text/plain", LFI_PROC_STATUS
                if file_value == "../../app/.env":
                    return 200, "text/plain", b"OBJECTIVE=" + LFI_ENV_FLAG.encode()
            if mode == "legacy-null" and file_value == "../flag.txt\x00":
                return 200, "text/plain", LFI_FLAG.encode()
            return 404, "application/json", LFI_MISSING
        if path == "/api/data":
            return 401, "application/json", DATA_401
        if path == "/api/objects/1":
            return 404, "application/json", OBJECT_404
        if path == "/api/forgot-password":
            if "mode=leak" in self.path:
                return 200, "application/json", FORGOT_PASSWORD_LEAK
            return 200, "application/json", FORGOT_PASSWORD_PUBLIC
        if path == "/api/auth/magic-link/request" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            email = str(data.get("email", "")).lower()
            if email == "rate@acme.test":
                return 429, "application/json", b'{"error":"Too many requests."}'
            if email == "gateway@acme.test":
                return 502, "text/plain", b"bad gateway"
            if email in AUTH_USERS:
                _new_auth_token(email)
            return 303, "text/plain", b"", {"Location": "/login?sent=1"}
        if path == "/api/auth/inbox" and self.command == "GET":
            with AUTH_LOCK:
                body = _json.dumps({"messages": list(AUTH_MESSAGES)}).encode()
            return 200, "application/json", body
        if path == "/api/auth/register" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            email = str(data.get("email", "")).lower()
            user = AUTH_USERS.get(email)
            if user:
                token = str(data.get("code", ""))
                record = AUTH_TOKENS.get(token)
                if (not user["claimed"] and record and not record["consumed"]
                        and record["email"] == email and data.get("password")):
                    user["password"] = str(data["password"])
                    user["claimed"] = True
                    return 303, "text/plain", b"", {"Location": "/login?pending=1"}
                return 303, "text/plain", b"", {
                    "Location": "/register?error=account_already_exists"
                }
            return 303, "text/plain", b"", {"Location": "/dashboard"}
        if path == "/api/auth/magic-link/verify" and self.command == "GET":
            token = (query.get("token") or [""])[0]
            record = AUTH_TOKENS.get(token)
            if not record or record["consumed"]:
                return 400, "application/json", b'{"error":"invalid token"}'
            user = AUTH_USERS[record["email"]]
            # Intended redemption also activates the identity. If it happens before
            # register+code, the vulnerable password-setting branch is gone.
            user["claimed"] = True
            user["verified"] = True
            record["consumed"] = True
            session_id = _new_auth_session(record["email"], "magiclink")
            return 303, "text/plain", b"", {
                "Location": "/dashboard",
                "Set-Cookie": "fixture_session=%s; Path=/; HttpOnly" % session_id,
            }
        if path == "/api/auth/login" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            email = str(data.get("email", "")).lower()
            user = AUTH_USERS.get(email)
            if user and user.get("password") and data.get("password") == user["password"]:
                session_id = _new_auth_session(email, "password")
                return 303, "text/plain", b"", {
                    "Location": "/dashboard",
                    "Set-Cookie": "fixture_session=%s; Path=/; HttpOnly" % session_id,
                }
            return 303, "text/plain", b"", {
                "Location": "/login?error=invalid_email_or_password"
            }
        if path == "/api/vault/breakglass" and self.command == "POST":
            session_id = _cookie_value(self.headers.get("Cookie"), "fixture_session")
            session = AUTH_SESSIONS.get(session_id)
            if not session:
                return 401, "application/json", b'{"error":"unauthenticated"}'
            user = AUTH_USERS[session["email"]]
            if not user["executive"]:
                return 403, "application/json", b'{"error":"forbidden"}'
            if session["method"] != "password":
                return 403, "application/json", b'{"error":"step_up_required"}'
            body = _json.dumps({"recovery_key": AUTH_FLAG}).encode()
            return 200, "application/json", body
        if path.startswith("/api/vaults/"):
            # Auth-gated path parameter: every id 401s without a token, which is the
            # pre-auth state of a real API. A sweep must call this UNTESTED, never clean.
            if not self.headers.get("Authorization"):
                return 401, "application/json", b'{"error":"access token required"}'
            return 200, "application/json", b'{"id":1,"name":"vault"}'
        if path.startswith("/api/widgets/"):
            status, body = _widget_row(unquote(path[len("/api/widgets/"):]), bound=False)
            return status, "application/json", body
        if path.startswith("/api/gadgets/"):
            status, body = _widget_row(unquote(path[len("/api/gadgets/"):]), bound=True)
            return status, "application/json", body
        if path == "/api/stocks/search":
            return 401, "application/json", STOCKS_SEARCH_401
        if path == "/api/jwt-styled-denial":
            return 403, "text/html", STYLED_DENIAL_HTML
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
        if path == "/api/indicator" and self.command == "POST":
            if not self.headers.get("Authorization"):
                return 401, "application/json", b'{"error":"access token required"}'
            data = data if isinstance(data, dict) else {}
            if "stock_id" not in data or "formula" not in data:
                return 400, "application/json", b'{"error":"stock_id and formula are required"}'
            caption = data.get("caption", "{value}")
            if "caption" in data and isinstance(caption, str):
                values = {
                    "value": 100,
                    "name": "Oakleaf Holdings",
                    "symbol": "OAKLEAF",
                    "flag": TEMPLATE_FLAG,
                    "api_key": TEMPLATE_FLAG,
                }
                match = re.fullmatch(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', caption)
                if match and match.group(1) in values:
                    caption = values[match.group(1)]
            body = _json.dumps({
                "stock": {"id": 1, "symbol": "OAKLEAF", "name": "Oakleaf Holdings"},
                "formula": data.get("formula"), "value": 100, "caption": caption,
            }).encode()
            return 200, "application/json", body
        if path == "/api/cmdi/json" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            if not isinstance(data.get("dice"), list) or not isinstance(data.get("rollOptions"), str):
                return 400, "application/json", b'{"error":"dice and rollOptions are required"}'
            return 200, "application/json", _cmdi_body(data["rollOptions"])
        if path == "/api/cmdi/json-nested" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            wrapper = data.get("wrapper")
            if not isinstance(wrapper, list) or not wrapper or not isinstance(wrapper[0], dict):
                return 400, "application/json", b'{"error":"wrapper is required"}'
            value = wrapper[0].get("rollOptions")
            if not isinstance(value, str):
                return 400, "application/json", b'{"error":"rollOptions is required"}'
            return 200, "application/json", _cmdi_body(value)
        if path == "/api/cmdi/safe" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            if not isinstance(data.get("rollOptions"), str):
                return 400, "application/json", b'{"error":"rollOptions is required"}'
            return 200, "application/json", _cmdi_body(
                data["rollOptions"], reflect=True, execute=False)
        if path == "/api/cmdi/blind" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            delay = re.search(r';sleep\s+(\d+)', value) if isinstance(value, str) else None
            if delay:
                time.sleep(min(int(delay.group(1)), 2))
            return 200, "application/json", _cmdi_body(value, execute=False)
        if path == "/api/cmdi/blind-windows" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            _cmdi_windows_result(value)
            return 200, "application/json", _cmdi_body(value, execute=False)
        if path == "/api/cmdi/blind-powershell" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            _cmdi_powershell_result(value)
            return 200, "application/json", _cmdi_body(value, execute=False)
        if path == "/api/cmdi/blind-substitution" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            delay = re.search(r'(?:\$\(|`)sleep\s+(\d+)(?:\)|`)', value)
            if delay:
                time.sleep(min(int(delay.group(1)), 2))
            return 200, "application/json", _cmdi_body(value, execute=False)
        if path == "/api/cmdi/windows" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            output = _cmdi_windows_result(value)
            body = {"status": "ok"}
            if output is not None:
                body["output"] = output
            return 200, "application/json", _json.dumps(body).encode()
        if path == "/api/cmdi/powershell" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            output = _cmdi_powershell_result(value)
            body = {"status": "ok"}
            if output is not None:
                body["output"] = output
            return 200, "application/json", _json.dumps(body).encode()
        if path == "/api/cmdi/quote-posix" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            output = (_cmdi_posix_result(value)
                      if re.search(r"(?:'|\");(?:printf|whoami)", value) else None)
            body = {"status": "ok"}
            if output is not None:
                body["output"] = output
            return 200, "application/json", _json.dumps(body).encode()
        if path == "/api/cmdi/oob" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            value = data.get("rollOptions", "")
            marker = re.search(r'https?://[^\s\'\"]+/(CMDIQ_[A-Z0-9]+)', value)
            if marker and CMDI_OOB_LOG:
                with open(CMDI_OOB_LOG, "a", encoding="utf-8") as fh:
                    fh.write("HIT " + marker.group(1) + "\n")
            return 200, "application/json", b'{"status":"queued"}'
        if path == "/api/cmdi/query" and self.command == "GET":
            value = (query.get("host") or [""])[0]
            return 200, "application/json", _cmdi_body(value)
        if path == "/api/cmdi/query-duplicate" and self.command == "GET":
            values = query.get("host") or [""]
            value = values[1] if len(values) > 1 else ""
            return 200, "application/json", _cmdi_body(value)
        if path == "/api/cmdi/form" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            return 200, "application/json", _cmdi_body(data.get("host", ""))
        if path.startswith("/api/cmdi/path/") and self.command == "GET":
            value = unquote(path[len("/api/cmdi/path/"):])
            return 200, "application/json", _cmdi_body(value)
        if path == "/api/cmdi/header" and self.command == "GET":
            return 200, "application/json", _cmdi_body(self.headers.get("X-Diagnostic-Host", ""))
        if path == "/api/cmdi/header-safe" and self.command == "GET":
            return 200, "application/json", _cmdi_body(
                self.headers.get("X-Diagnostic-Host", ""), reflect=True, execute=False)
        if path == "/api/cmdi/cookie" and self.command == "GET":
            cookie = self.headers.get("Cookie", "")
            match = re.search(r'(?:^|;\s*)target=([^;]*)', cookie)
            return 200, "application/json", _cmdi_body(match.group(1) if match else "")
        if path == "/api/cmdi/body" and self.command == "POST":
            raw = getattr(self, "_raw_body", b"").decode("latin-1", "replace")
            match = re.search(r'<host>(.*?)</host>', raw, re.S)
            return 200, "application/json", _cmdi_body(match.group(1) if match else "")
        if path == "/api/cmdi/raw" and self.command == "POST":
            raw = getattr(self, "_raw_body", b"").decode("latin-1", "replace")
            filename = re.search(r'filename="([^"]+)"', raw)
            value = filename.group(1) if filename else ""
            return 200, "application/json", _cmdi_body(value)
        if path == "/api/cmdi/rate" and self.command == "POST":
            return 429, "application/json", b'{"error":"slow down"}'
        if path == "/api/cmdi/gateway" and self.command == "POST":
            return 502, "text/plain", b"bad gateway"
        if path == "/api/cmdi/teapot" and self.command == "POST":
            data = data if isinstance(data, dict) else {}
            return 418, "application/json", _cmdi_body(data.get("rollOptions", ""))
        if path == "/api/items" and self.command == "GET":
            # A bare [ne] key is ignored and falls back to public rows. The real
            # $-prefixed operators reach a Mongoose-style nested filter and return
            # all rows, including the private record; $ne=1 models string-vs-boolean
            # type juggling where even the public rows remain in the response.
            operator_keys = (
                "filter[is_public][$ne]", "filter[is_public][$gt]",
                "filter[is_public][$exists]", "filter[is_public][$regex]",
            )
            rows = (NOSQL_LIST_DOCS if any(key in query for key in operator_keys)
                    else [row for row in NOSQL_LIST_DOCS if row["is_public"]])
            return 200, "application/json", _json.dumps({"items": rows}).encode()
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
        if path == "/api/jwt-cookie/me" and self.command == "GET":
            payload = _unverified_jwt_payload(_cookie_value(
                self.headers.get("Cookie"), "auth_token") or "")
            if payload is None:
                return 401, "application/json", b'{"error":"invalid token"}'
            return 200, "application/json", _json.dumps(
                {"id": payload.get("id"), "authenticated": True}).encode()
        if path == "/api/jwt-cookie/admin" and self.command == "GET":
            payload = _unverified_jwt_payload(_cookie_value(
                self.headers.get("Cookie"), "auth_token") or "")
            if payload is None:
                return 401, "application/json", b'{"error":"invalid token"}'
            if payload.get("id") != 1:
                return 403, "application/json", b'{"error":"admin access required"}'
            return 200, "application/json", b'{"message":"admin identity accepted"}'
        if path.startswith("/api/admin"):
            auth = self.headers.get("Authorization") or ""
            if not auth:
                return 401, "application/json", NO_TOKEN
            is_admin = "admin" in auth.lower()
            # The one route that forgot requireAdmin: any bearer token gets in.
            if path == "/api/admin/posts/1" and self.command == "DELETE":
                return 200, "application/json", BFLA_DELETED
            if path == "/api/admin/posts/2" and self.command == "DELETE":
                if "2" in DELETED_POSTS:
                    return 404, "application/json", POST_MISSING
                DELETED_POSTS.add("2")
                return 200, "application/json", BFLA_DELETED
            if not is_admin:
                return 403, "application/json", ADMIN_DENIED
            if path == "/api/admin/posts/1/approve":
                return 200, "application/json", ADMIN_APPROVED
            if path == "/api/admin/flagged-posts":
                return 200, "application/json", ADMIN_FLAGGED
            return 200, "application/json", ADMIN_OK
        if path.startswith("/api/reports"):
            auth = self.headers.get("Authorization") or ""
            if not auth:
                return 401, "application/json", NO_TOKEN
            if path == "/api/reports/1" and self.command == "DELETE":
                return 200, "application/json", REPORT_DELETED
            if "admin" not in auth.lower():
                return 403, "application/json", ADMIN_DENIED
            return 200, "application/json", REPORT_RESOLVED
        if path.startswith("/api/feed"):
            return 200, "application/json", FEED_OK
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
        self._raw_body = b""
        if length:
            raw = self.rfile.read(length)
            self._raw_body = raw
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                try:
                    data = _json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    data = None
            elif "application/x-www-form-urlencoded" in ctype:
                try:
                    parsed = parse_qs(raw.decode(), keep_blank_values=True)
                    data = {key: values[0] for key, values in parsed.items()}
                except UnicodeDecodeError:
                    data = None
            else:
                try:
                    data = _json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    data = None
        routed = self._route(data)
        status, ctype, body = routed[:3]
        extra_headers = routed[3] if len(routed) > 3 else {}
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra_headers.items():
            self.send_header(key, value)
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
    _reset_auth_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = "http://127.0.0.1:%d" % server.server_address[1]
    return server, base_url
