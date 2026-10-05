"""Black-box regressions for both Forgeflare handshakes and proxy cookie isolation."""

import json
import os
import socket
import subprocess
import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "forgeflare"))
from forgeflare import FF, is_edge_challenge  # noqa: E402


class ForgeflareFixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, obj, cookies=()):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def do_GET(self):
        if self.path.startswith("/forgeflare/challenge"):
            self.server.challenges += 1
            data = {"token": "fixture-token", "n": "fixture-n", "difficulty": 0, "to": "/"}
            script = "/forgeflare/pow /forgeflare/beacon" if self.server.mode == "timed" else "legacy"
            body = (f'<script id="ff-data" type="application/json">{json.dumps(data)}</script>'
                    f'<script>{script}</script>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/app-denied":
            self.send_json(403, {"code": "rest_forbidden"})
            return
        if self.path == "/protected":
            cookies = self.headers.get("Cookie", "")
            if "forgeflare_clearance=ok" not in cookies:
                body = b"<title>Just a moment - Forgeflare</title>"
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("Forgeflare-Ray", "fixture-ray")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            identity = next((p.strip().split("=", 1)[1] for p in cookies.split(";")
                             if p.strip().startswith("app_session=")), None)
            self.send_json(200, {"identity": identity})
            return
        self.send_json(404, {"code": "not_found"})

    def do_POST(self):
        if self.path == "/forgeflare/pow" and self.server.mode == "timed":
            data = self.read_json()
            self.server.proofs += 1
            self.send_json(200, {"ok": data == {"token": "fixture-token", "nonce": 0},
                                 "bsid": "fixture-bsid", "interval": 1})
            return
        if self.path == "/forgeflare/beacon" and self.server.mode == "timed":
            data = self.read_json()
            self.server.beacons += 1
            self.send_json(200, {"ok": data.get("bsid") == "fixture-bsid",
                                 "complete": self.server.beacons >= 2})
            return
        if self.path == "/forgeflare/verify":
            data = self.read_json()
            valid = (data.get("bsid") == "fixture-bsid" and self.server.beacons >= 2
                     if self.server.mode == "timed"
                     else data.get("token") == "fixture-token" and data.get("nonce") == 0)
            self.send_json(200, {"cleared": valid},
                           cookies=["forgeflare_clearance=ok; Path=/"] if valid else [])
            return
        if self.path == "/login":
            self.read_json()
            self.send_json(200, {"ok": True}, cookies=[
                "app_session=alpha; Path=/", "theme=dark; Path=/"])
            return
        self.send_json(404, {"code": "not_found"})


class ForgeflareTest(unittest.TestCase):
    def start_fixture(self, mode):
        server = ThreadingHTTPServer(("127.0.0.1", 0), ForgeflareFixture)
        server.mode = mode
        server.challenges = server.proofs = server.beacons = 0
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, f"http://127.0.0.1:{server.server_port}"

    def test_legacy_verify_still_clears(self):
        server, base = self.start_fixture("legacy")
        client = FF(base)
        self.assertEqual(client.get("/protected").status_code, 200)
        self.assertEqual(server.challenges, 1)
        self.assertEqual(server.proofs, 0)
        self.assertEqual(server.beacons, 0)

    def test_timed_beacons_clear_and_app_denial_does_not_reclear(self):
        server, base = self.start_fixture("timed")
        client = FF(base)
        self.assertEqual(server.proofs, 1)
        self.assertEqual(server.beacons, 2)
        self.assertEqual(client.get("/protected").status_code, 200)
        denial = client.get("/app-denied")
        self.assertEqual(denial.status_code, 403)
        self.assertFalse(is_edge_challenge(denial))
        self.assertEqual(server.challenges, 1)
        edge = requests.get(base + "/protected")
        self.assertTrue(is_edge_challenge(edge))

    def test_proxy_preserves_caller_cookies_and_separate_set_cookie_headers(self):
        _, base = self.start_fixture("timed")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "FFPROXY_PORT": str(port)}
        process = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "forgeflare" / "ffproxy.py"), base],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (process.terminate(), process.wait(timeout=5)) if process.poll() is None else None)
        proxy = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if process.poll() is not None:
                self.fail("proxy exited during startup")
            try:
                response = requests.get(proxy + "/protected", timeout=1)
                break
            except requests.ConnectionError:
                time.sleep(0.05)
        else:
            self.fail("proxy did not start")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["identity"])
        self.assertEqual(requests.get(proxy + "/protected", headers={"Cookie": "app_session=beta"}).json()["identity"], "beta")
        self.assertIsNone(requests.get(proxy + "/protected").json()["identity"])
        login = requests.post(proxy + "/login", json={})
        self.assertEqual(login.status_code, 200)
        self.assertEqual(len(login.raw.headers.getlist("Set-Cookie")), 2)


if __name__ == "__main__":
    unittest.main()
