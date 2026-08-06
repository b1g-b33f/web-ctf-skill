#!/usr/bin/env python3
"""jsmine.py — mine JS bundles for routes, params, secrets, comments, config.

Usage:
  python3 jsmine.py <dir-or-file> [more...]
  python3 jsmine.py ~/Tools/CTF/<name>/recon/

Catches the things hand-rolled regexes miss: query-string routes, template-literal
and .concat() route building, and the client router table.
"""
import glob
import os
import re
import sys

PATH_CHARS = r"a-zA-Z0-9/_\-?=&.:{}$"


def load(args):
    blobs = []
    for a in args:
        files = []
        if os.path.isdir(a):
            for ext in ("*.js", "*.mjs", "*.map", "*.ts"):
                files += glob.glob(os.path.join(a, "**", ext), recursive=True)
        else:
            files = [a]
        for f in files:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    blobs.append((f, fh.read()))
            except OSError:
                pass
    return blobs


def section(title, items, limit=400):
    items = [i for i in items if i]
    print("\n=== %s (%d) ===" % (title, len(items)))
    for i in sorted(set(items))[:limit]:
        print("  " + str(i)[:200])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    blobs = load(sys.argv[1:])
    if not blobs:
        print("no JS found")
        return 1
    print("mined %d file(s): %s" % (len(blobs), ", ".join(os.path.basename(f) for f, _ in blobs)[:200]))
    all_js = "\n".join(b for _, b in blobs)

    # ---- routes -------------------------------------------------------------
    routes = set()
    # quoted absolute paths, INCLUDING query strings (?, =, &)
    routes |= set(re.findall(r'["\'](/(?:api|v\d+|internal|admin|graphql)[%s]*)["\']' % PATH_CHARS, all_js))
    # any quoted path with two segments — catches unprefixed APIs
    routes |= set(re.findall(r'["\'](/[a-zA-Z0-9_\-]+/[%s]+)["\']' % PATH_CHARS, all_js))
    # fetch / axios call sites
    routes |= set(re.findall(r'(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*["\']([^"\'\s]+)', all_js))
    # template literals
    routes |= set(re.findall(r'`(/[%s]+)`' % PATH_CHARS, all_js))
    section("ROUTES", routes)

    # ---- .concat() dynamic route building -----------------------------------
    # keep only the argument list, not the minified tail that follows it
    concat = re.findall(r'["\'](/[%s]*)["\']\s*\.concat\(([^;\n]{0,90})' % PATH_CHARS, all_js)
    dyn = []
    for base, tail in concat:
        arg = re.split(r'\)\s*[,)\.]|\)\)', tail)[0]
        arg = re.sub(r'\s+', ' ', arg).strip()[:60]
        dyn.append("%s{%s}" % (base, arg))
    section("DYNAMIC ROUTES (.concat)", dyn)

    # ---- HTTP methods per path ---------------------------------------------
    # bundles minify the axios instance ($o.get, a.post, ...), so match any receiver
    calls = re.findall(r'[\w$]{1,4}\.(get|post|put|delete|patch)\s*\(\s*["\']'
                       r'(/[^"\']+)["\']', all_js)
    concat_calls = re.findall(r'[\w$]{1,4}\.(get|post|put|delete|patch)\s*\(\s*["\']'
                              r'(/[^"\']+)["\']\s*\.concat', all_js)
    section("METHOD -> PATH",
            ["%-6s %s" % (m.upper(), p) for m, p in calls]
            + ["%-6s %s{...}" % (m.upper(), p) for m, p in concat_calls])

    # ---- client router (reveals pages, hence features) ----------------------
    section("ROUTER PATHS", re.findall(r'path:\s*["\']([^"\']+)["\']', all_js))

    # ---- secrets ------------------------------------------------------------
    secrets = re.findall(
        r'(?i)(?:password|passwd|secret|apikey|api_key|access_key|token|privatekey|client_secret)'
        r'\s*[:=]\s*["\'`]([^"\'`\s]{6,})["\'`]', all_js)
    section("SECRETS", [s for s in secrets if not s.startswith(("function", "undefined"))])

    # ---- comments -----------------------------------------------------------
    kw = ("todo", "fixme", "hack", "password", "admin", "debug", "flag", "secret",
          "internal", "bypass", "temporary", "remove", "xxx", "legacy", "deprecated")
    comments = [c.strip() for c in re.findall(r'//[^\n]{0,200}', all_js)
                if any(k in c.lower() for k in kw)]
    comments += [c.strip().replace("\n", " ")[:200]
                 for c in re.findall(r'/\*.{0,300}?\*/', all_js, re.S)
                 if any(k in c.lower() for k in kw)]
    section("COMMENTS", comments, limit=120)

    # ---- graphql ------------------------------------------------------------
    section("GRAPHQL", re.findall(r'(?:query|mutation|subscription)\s+\w+[^{]{0,80}\{', all_js))

    # ---- role / flag / feature strings -------------------------------------
    section("ROLE & FEATURE STRINGS", re.findall(
        r'["\']((?:admin|administrator|superuser|root|moderator|staff|owner|is_?admin|'
        r'role|internal|debug|flag)[^"\']{0,60})["\']', all_js, re.I))

    # ---- narrative hint text -------------------------------------------------
    # Prose the author wrote to explain the vuln post-exploitation (a success-screen
    # sentence, an error message) slips past every pattern above: not a // comment,
    # not a key:"value" pair, doesn't start with a role keyword. Minifiers don't
    # touch string contents, so this catches it even with no source map at all.
    #
    # Must be a real JS-string-literal match (escaped \" / \' treated as *inside* the
    # string, not a terminator) — a naive [^"']* class breaks on the first apostrophe,
    # which is fatal since prose is full of them ("Council's chamber...").
    str_lit = re.findall(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', all_js)
    HINT_KW = ("weak ", "hardcod", "backdoor", "insecure", "vulnerable", "bypass",
               "default password", "default credential", "for demo", "do not use in prod",
               "secret is", "secret was", "signing key", "private key", "master key",
               "should never", "for testing only", "not secure")
    hints = []
    for raw in str_lit:
        inner = raw[1:-1]
        if not (40 <= len(inner) <= 300) or len(inner.split()) < 5:
            continue
        if any(k in inner.lower() for k in HINT_KW):
            hints.append(inner)
    section("HINT TEXT (narrative strings, not code)", hints, limit=60)

    # ---- flags already present ---------------------------------------------
    hits = re.findall(r'(?:HTB|bug|flag|CTF|THM|picoCTF)\{[^}]{4,80}\}', all_js, re.I)
    if hits:
        print("\n" + "!" * 60)
        print("FLAG PATTERN IN BUNDLE: %s" % set(hits))
        print("!" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
