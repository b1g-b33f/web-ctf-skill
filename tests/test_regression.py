#!/usr/bin/env python3
"""test_regression.py — SPA-aware recon regression test.

Exercises quickrecon.py, jsharvest.py and probe.py together against fixture_app.py, a
local HTTP server that serves:
  - the same SPA shell, status 200, for every path it doesn't specifically implement
    (including a handful of admin/api quickcheck guesses)
  - one real JSON endpoint (/api/data) that always answers 401
  - a JS bundle (/app.js) with one GET route carrying a query string and one POST route
  - a public object endpoint (/api/objects/1) that always answers an identical JSON 404,
    with or without authentication

Asserts:
  - the meta/quickcheck fallback guesses produce zero hits (all suppressed as the
    calibrated SPA signature)
  - /api/data is the only survivor of the quickcheck candidate list
  - the JS-mined GET/POST routes land in recon/methods.txt
  - probe.py classifies /api/objects/1 as public-error (not a leak) and /api/data as
    auth-required

Run directly: python tests/test_regression.py
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_app

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def run(script, *args, timeout=60):
    cmd = [sys.executable, os.path.join(SCRIPTS, script)] + list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


class RegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_quickrecon_suppresses_fallback_and_finds_the_real_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            hitfile = os.path.join(tmp, "quickcheck_hits.txt")
            out = run("quickrecon.py", "--base", self.base_url, "--out", os.path.join(tmp, "probe"),
                      "--hitfile", hitfile, "--paths",
                      "robots.txt", "sitemap.xml", "admin", "api", "graphql", "api/data")

            self.assertTrue(os.path.isfile(os.path.join(tmp, "probe", "fallback.txt")),
                             "calibration response was not saved:\n" + out)

            hits = []
            if os.path.isfile(hitfile):
                with open(hitfile, encoding="utf-8") as fh:
                    hits = [l.strip() for l in fh if l.strip()]
            self.assertEqual(len(hits), 1,
                              "expected exactly one survivor of the quickcheck guesses, got %r\n%s"
                              % (hits, out))
            self.assertIn("/api/data", hits[0])
            self.assertTrue(hits[0].startswith("401 "), "expected the 401 status: %r" % hits[0])

    def test_jsharvest_extracts_methods_from_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp)

            methods_path = os.path.join(tmp, "methods.txt")
            self.assertTrue(os.path.isfile(methods_path), "methods.txt was not written:\n" + out)
            with open(methods_path, encoding="utf-8") as fh:
                methods = fh.read()

            self.assertRegex(methods, r'GET\s+/api/data\?limit=10')
            self.assertRegex(methods, r'POST\s+/api/submit')

            jsmine_path = os.path.join(tmp, "jsmine.txt")
            self.assertTrue(os.path.isfile(jsmine_path), "jsmine.txt was not written:\n" + out)

    def test_probe_classifies_public_error_and_auth_required_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths_file = os.path.join(tmp, "paths.txt")
            with open(paths_file, "w", encoding="utf-8") as fh:
                fh.write("GET /api/data\n")
                fh.write("GET /api/objects/1\n")

            out = run("probe.py", "--base", self.base_url, "--token", "faketoken",
                      "--paths", paths_file, "--out", os.path.join(tmp, "probe_out"))

            data_line = next((l for l in out.splitlines() if re.match(r'^GET\s+/api/data\b', l)), None)
            objects_line = next((l for l in out.splitlines() if re.match(r'^GET\s+/api/objects/1\b', l)), None)

            self.assertIsNotNone(data_line, "no output line for /api/data:\n" + out)
            self.assertIn("auth-required", data_line)

            self.assertIsNotNone(objects_line, "no output line for /api/objects/1:\n" + out)
            self.assertIn("public-error", objects_line)
            self.assertNotIn("NO-AUTH", objects_line, "public-error must not be counted as a leak")


if __name__ == "__main__":
    unittest.main()
