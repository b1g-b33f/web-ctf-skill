#!/usr/bin/env python3
"""jsmine.py — mine JS bundles and rendered HTML for routes and methods.

Usage:
  python3 jsmine.py <dir-or-file> [more...]
  python3 jsmine.py ~/Tools/CTF/<name>/recon/

Catches the things hand-rolled regexes miss: query-string routes, template-literal
and .concat() route building, and the client router table.
"""
import ast
import glob
import os
import re
import sys

PATH_CHARS = r"a-zA-Z0-9/_\-?=&.:{}$"


def parse_call_args(tail):
    """Return the top-level arguments from text immediately after ``concat(``.

    Minified bundles commonly build routes as ``.concat(id,"/comments")``.
    A regex split on the first closing parenthesis loses nested expressions such
    as ``encodeURIComponent(id)``, so keep a tiny quote/depth-aware scanner here.
    """
    args, buf, depth = [], [], 0
    quote, escaped = None, False
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    for ch in tail:
        if quote:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
            buf.append(ch)
        elif ch in pairs:
            depth += 1
            buf.append(ch)
        elif ch in closers:
            if ch == ")" and depth == 0:
                break
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf or args:
        args.append("".join(buf).strip())
    return [arg for arg in args if arg]


def literal_string(expr):
    expr = expr.strip()
    if len(expr) < 2 or expr[0] not in "'\"`" or expr[-1] != expr[0]:
        return None
    if expr[0] == "`":
        return None if "${" in expr else expr[1:-1]
    try:
        value = ast.literal_eval(expr)
        return value if isinstance(value, str) else None
    except (SyntaxError, ValueError):
        return None


def concat_route(base, tail, named=False):
    """Reconstruct a route from a minified ``.concat(...)`` call.

    The diagnostic DYNAMIC ROUTES section retains simple argument names because
    they help an analyst correlate adjacent call sites. METHOD -> PATH stays
    directly probeable by using ``{...}`` and ``probe`` placeholders.
    """
    route = base
    args = parse_call_args(tail)
    if not args:
        return route + "{...}"
    for arg in args:
        literal = literal_string(arg)
        if literal is not None:
            route += literal
        elif named:
            dynamic = re.sub(r'\s+', ' ', arg).strip()[:60]
            route += "{%s}" % dynamic
        elif re.search(r'(?:\?|&)[a-zA-Z0-9_.-]+=$', route):
            route += "probe"
        else:
            route += "{...}"
    return route


def template_route(path):
    return re.sub(r'\$\{[^}]+\}', '{...}', path)


def load(args):
    blobs = []
    for a in args:
        files = []
        if os.path.isdir(a):
            for ext in ("*.js", "*.mjs", "*.map", "*.ts", "*.html", "*.htm"):
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
    items = sorted(set(i for i in items if i))
    print("\n=== %s (%d) ===" % (title, len(items)))
    for i in items[:limit]:
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
    # Keep the tail in a zero-width lookahead so adjacent minified calls are not
    # swallowed. Reconstruct literal suffix arguments such as "/comments".
    concat = re.findall(r'["\'](/[%s]*)["\']\s*\.concat\((?=([^;\n]{0,90}))' % PATH_CHARS, all_js)
    dyn = [concat_route(base, tail, named=True) for base, tail in concat]
    section("DYNAMIC ROUTES (.concat)", dyn)

    # ---- HTTP methods per path ---------------------------------------------
    # Bundles minify the axios instance ($o.get, a.post, ...), while exploded
    # source maps retain longer names such as axios. Mine ordinary quoted calls
    # and template literals; exclude quoted bases immediately followed by
    # .concat(), which are reconstructed below.
    calls = re.findall(r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*(["\'])'
                       r'(/[^"\']+)\2(?!\s*\.concat\()', all_js)
    call_lines = ["%-6s %s" % (method.upper(), path) for method, _, path in calls]
    template_calls = re.findall(
        r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*`(/[^`]+)`', all_js)
    template_lines = ["%-6s %s" % (method.upper(), template_route(path))
                      for method, path in template_calls]
    # Capture the concat() argument too. A base path with no trailing "/" is
    # a query-string builder when its tail contains a quoted ?param= literal;
    # resolve that shape now so probe.py does not substitute its path id into
    # the bare word (/api/admin/posts{...} -> /api/admin/posts1).
    # Keep the tail in a zero-width lookahead: consuming it can swallow a nearby
    # minified call site and silently drop the next route from re.findall().
    concat_calls = re.findall(r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*["\']'
                              r'(/[^"\']+)["\']\s*\.concat\((?=([^;\n]{0,90}))', all_js)
    concat_lines = ["%-6s %s" % (method.upper(), concat_route(path, tail))
                    for method, path, tail in concat_calls]

    # Server-rendered apps often expose their complete route map as ordinary
    # HTML forms even when every linked JS asset is unavailable. Attribute order
    # is deliberately irrelevant here; method defaults to GET per HTML.
    forms = []
    for tag in re.findall(r'<form\b[^>]*>', all_js, re.I):
        attrs = dict((k.lower(), v) for k, _, v in re.findall(
            r'([:\w-]+)\s*=\s*(["\'])(.*?)\2', tag, re.I | re.S))
        action = attrs.get("action", "")
        if action.startswith("/"):
            forms.append("%-6s %s" % (attrs.get("method", "GET").upper(), action))

    section("METHOD -> PATH",
            call_lines
            + template_lines
            + concat_lines
            + forms)

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
