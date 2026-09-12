"""Regressions for method expansion across distinct API route shapes."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "probe.py"


class RouteShapeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _drain_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)

    def _send(self, status, payload, content_type="application/json"):
        body = json.dumps(payload).encode() if isinstance(payload, dict) else payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._send(404, f"Cannot {self.command} {self.path}", "text/html")

    def do_GET(self):
        if self.path == "/api/widgets/7":
            self._send(200, {"id": 7, "name": "control"})
        else:
            self._not_found()

    def do_PATCH(self):
        self._drain_body()
        if self.path == "/api/widgets/7":
            self._send(422, {"error": "name is required"})
        else:
            self._not_found()


class ProbeRouteMethodExpansionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RouteShapeHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_hidden_patch_is_added_to_each_concrete_route_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "methods.txt"
            paths.write_text(
                "GET /api/widgets\nGET /api/widgets/{...}\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "responses"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(PROBE),
                    "--base", self.base,
                    "--token", "fixture-token",
                    "--paths", str(paths),
                    "--id", "7",
                    "--expand-method", "PATCH",
                    "--write",
                    "--delay", "0",
                    "--out", str(out),
                ],
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PATCH  /api/widgets/7", proc.stdout)
            self.assertIn("PATCH  /api/widgets", proc.stdout)
            self.assertIn("not-a-route", proc.stdout)

            detail = out / "patch.api_widgets_7.auth.txt"
            collection = out / "patch.api_widgets.auth.txt"
            self.assertTrue(detail.exists(), sorted(path.name for path in out.iterdir()))
            self.assertIn("HTTP 422", detail.read_text(encoding="utf-8"))
            self.assertTrue(collection.exists())
            self.assertIn("Cannot PATCH /api/widgets", collection.read_text(encoding="utf-8"))

    def test_expanded_write_method_still_requires_explicit_write_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "methods.txt"
            paths.write_text("GET /api/widgets/{...}\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(PROBE),
                    "--base", self.base,
                    "--token", "fixture-token",
                    "--paths", str(paths),
                    "--id", "7",
                    "--expand-method", "PATCH",
                    "--delay", "0",
                    "--out", str(Path(tmp) / "responses"),
                ],
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("skipped 1 write target(s)", proc.stdout)
            self.assertIn("SKIPPED PATCH  /api/widgets/7", proc.stdout)
            self.assertNotIn("PATCH  /api/widgets/7", proc.stdout.split("SKIPPED", 1)[0])


if __name__ == "__main__":
    unittest.main()
