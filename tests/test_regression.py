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

    def test_jsharvest_extracts_methods_from_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run("jsharvest.py", "--base", self.base_url, "--out", tmp)

            methods_path = os.path.join(tmp, "methods.txt")
            self.assertTrue(os.path.isfile(methods_path), "methods.txt was not written:\n" + out)
            with open(methods_path, encoding="utf-8") as fh:
                methods = fh.read()

            self.assertRegex(methods, r'GET\s+/api/data\?limit=10')
            self.assertRegex(methods, r'POST\s+/api/submit')
            self.assertRegex(methods, r'POST\s+/api/graphql')

            jsmine_path = os.path.join(tmp, "jsmine.txt")
            self.assertTrue(os.path.isfile(jsmine_path), "jsmine.txt was not written:\n" + out)

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
                self.assertIn("/api/stocks/search", fh.read(),
                             "direct protected-leaf guess missing from quickcheck_hits.txt -- "
                             "recursive fuzzing alone cannot reach a leaf below an SPA-fallback "
                             "/api, so ctf-init.sh's quickcheck job must guess it directly")
            self.assertNotIn("0\n0 hits", out,
                             "empty grep count printed two zeroes instead of one")

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

    def test_unreachable_baseline_is_inconclusive(self):
        # port 1 on loopback: nothing listens there, so this fails fast (ECONNREFUSED)
        # rather than waiting out jwtquick's own 20s request timeout
        token = make_jwt({"id": 1, "role": "user"}, "irrelevant")
        proc = run_full("jwtquick.py", "--token", token, "--no-crack",
                        "--base", "http://127.0.0.1:1", "--test", "/", timeout=30)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("INCONCLUSIVE", proc.stdout)
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
    stderr back to Claude) and land in ~/.claude/ctf-flags.log."""

    def test_synthetic_flag_in_tool_output_is_detected_and_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = "bug{HarnessRegressionSynthetic123}"
            payload = json.dumps({"tool_name": "Bash", "tool_response": marker})
            proc = run_full("flaghook.py", input_text=payload, env={"HOME": tmp})
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            log = os.path.join(tmp, ".claude", "ctf-flags.log")
            self.assertTrue(os.path.isfile(log), "flaghook did not create ctf-flags.log")
            with open(log, encoding="utf-8") as fh:
                self.assertIn(marker, fh.read())


class FlaghookHealthMarkerTest(unittest.TestCase):
    """A synthetic flag proves the script's own regex works, but the Shady Oaks
    Financial run showed that alone isn't enough: the same session's real
    PostToolUse hook produced no log entry for either a real flag or a synthetic
    one, because invoking flaghook.py directly only proves the script -- never
    whether PostToolUse actually calls it. A dedicated bug{CodexHarnessHookCheck_
    <nonce>} marker gives an end-to-end activation check: it must land in
    ~/.claude/ctf-flaghook-ok, a sentinel kept separate from ctf-flags.log so a
    routine activation check never pollutes the real flag record."""

    def test_flaghook_health_marker_writes_sentinel_not_flag_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = "bug{CodexHarnessHookCheck_regressiontest01}"
            payload = json.dumps({"tool_name": "Bash", "tool_response": marker})
            proc = run_full("flaghook.py", input_text=payload, env={"HOME": tmp})
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            sentinel = os.path.join(tmp, ".claude", "ctf-flaghook-ok")
            self.assertTrue(os.path.isfile(sentinel),
                            "flaghook did not write the health-check sentinel")
            with open(sentinel, encoding="utf-8") as fh:
                self.assertEqual(fh.read().strip(), marker)
            self.assertFalse(os.path.exists(os.path.join(tmp, ".claude", "ctf-flags.log")),
                             "a health-check marker must never be logged as a real flag")


if __name__ == "__main__":
    unittest.main()
