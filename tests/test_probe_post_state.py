"""Black-box regression for an archived object that remains directly readable."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parent.parent
MARKER = "DISPOSABLE_CONTENT_72f1a9"


class ArchivedObjectHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, status, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if (self.path == "/api/objects/1/archive"
                and self.headers.get("Authorization") == "Bearer owner"):
            self.server.archived = True
            self.send_json(200, {"message": "archived"})
            return
        self.send_json(404, {"error": "not found"})

    def do_GET(self):
        owner = self.headers.get("Authorization") == "Bearer owner"
        if self.path == "/api/objects/1":
            # Deliberate defect: archived detail remains readable to everyone.
            self.send_json(200, {"id": 1, "code": MARKER,
                                 "is_public": not self.server.archived,
                                 "archived": self.server.archived})
        elif self.path == "/api/objects/2":
            # Separate never-public control denies both non-owner identities.
            if owner:
                self.send_json(200, {"id": 2, "code": "PRIVATE_CONTROL",
                                     "is_public": False, "archived": False})
            else:
                self.send_json(403, {"error": "not authorized"})
        elif self.path == "/api/objects":
            # A successful list response after archive does not include object 1.
            self.send_json(200, [] if self.server.archived else [{"id": 1}])
        else:
            self.send_json(404, {"error": "not found"})


class ProbePostStateTest(unittest.TestCase):
    def test_archive_exposes_marker_only_on_direct_detail(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), ArchivedObjectHandler)
        server.archived = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_port
        try:
            before = requests.get(base + "/api/objects/1", timeout=5).json()
            self.assertTrue(before["is_public"])
            result = requests.post(base + "/api/objects/1/archive",
                                   headers={"Authorization": "Bearer owner"}, timeout=5)
            self.assertEqual(result.status_code, 200)

            with tempfile.TemporaryDirectory() as tmp:
                paths = Path(tmp) / "paths.txt"
                paths.write_text("GET /api/objects/1\nGET /api/objects/2\n"
                                 "GET /api/objects\n", encoding="utf-8")
                out_dir = Path(tmp) / "responses"
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "probe.py"),
                     "--base", base, "--token", "owner", "--lowpriv-token", "reader",
                     "--paths", str(paths), "--expect-absent", MARKER,
                     "--delay", "0", "--out", str(out_dir)],
                    text=True, capture_output=True, timeout=30,
                )
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                self.assertIn("POST-STATE EXPOSURE GET    /api/objects/1 — lowpriv", output)
                self.assertIn("POST-STATE EXPOSURE GET    /api/objects/1 — noauth", output)
                self.assertIn("post-state exposures: 2", output)
                self.assertNotIn("POST-STATE EXPOSURE GET    /api/objects/2", output)
                self.assertNotIn("POST-STATE EXPOSURE GET    /api/objects\n", output)
                saved = (out_dir / "get.api_objects_1.noauth.txt").read_text(encoding="utf-8")
                self.assertIn(MARKER, saved)
                self.assertIn('"archived":true', saved)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
