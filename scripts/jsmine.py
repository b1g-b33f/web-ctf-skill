#!/usr/bin/env python3
"""jsmine.py — mine JS bundles and rendered HTML for routes and methods.

Usage:
  python3 jsmine.py <dir-or-file> [more...]
  python3 jsmine.py ~/Offsec/Web_CTF/CTF/<name>/recon/

Catches the things hand-rolled regexes miss: query-string routes, template-literal
and .concat() route building, and the client router table.
"""
import ast
import glob
import json
import os
import re
import sys

PATH_CHARS = r"a-zA-Z0-9/_\-?=&.:{}$"
STATIC_EXT = re.compile(r'\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip)(?:[?#]|$)', re.I)
ACTION_ROUTE = re.compile(
    r'/(?:[^/?#]+/)*(magic(?:-link)?|passwordless|inbox|outbox|emails?|mail|claim|'
    r'activation|activate|enrollment|enroll|invite|callback|session|password|recover|reset|'
    r'verify|forgot|search|filter|query|graphql|login|register|signup)'
    r'(?:[/?#-]|$)', re.I)
VENDOR_BASENAME = re.compile(
    r'^(?:socket\.io|engine\.io|react(?:-dom)?|runtime|polyfills?|vendors?)(?:[.\-_]|$)', re.I)
VENDOR_SOURCE = re.compile(
    r'(?:^|/)(?:node_modules|vendor|vendors)/(?:.*)|'
    r'webpack://(?:engine\.io|socket\.io|react(?:-dom)?|webpack)(?:[./@-]|$)', re.I)


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


def source_is_vendor(path):
    """Classify sources that should be retained as raw evidence but not mined.

    Some vendor source maps use webpack package namespaces instead of a literal
    node_modules/ path (Socket.IO is a common example), so path-segment checks
    alone are not sufficient.
    """
    norm = path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    return (bool(VENDOR_SOURCE.search(norm))
            or any(p in ("node_modules", "vendor", "vendors") for p in parts)
            or bool(parts and VENDOR_BASENAME.search(parts[-1])))


def sourcemap_blobs(path):
    """Load only application sourcesContent from a raw source map."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if len(sources) != len(contents):
        return []
    out = []
    for source, content in zip(sources, contents):
        if content is None or source_is_vendor(source):
            continue
        out.append(("%s!%s" % (path, source), content))
    return out


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


def route_from_expr(expr):
    """Turn a first request argument into a probe-ready route when possible."""
    expr = expr.strip()
    literal = literal_string(expr)
    if literal is not None:
        return literal if literal.startswith("/") else None
    if len(expr) >= 2 and expr[0] == "`" and expr[-1] == "`":
        path = template_route(expr[1:-1])
        return path if path.startswith("/") else None
    m = re.match(r'(["\'])(/[^"\']+)\1\s*\.concat\((.*)', expr, re.S)
    if m:
        return concat_route(m.group(2), m.group(3))
    return None


def object_property(expr, name):
    """Read a quoted or bare string-valued property from a JS object literal."""
    m = re.search(r'(?:^|[,{}])\s*["\']?%s["\']?\s*:\s*(["\'`])(.+?)\1'
                  % re.escape(name), expr, re.I | re.S)
    return m.group(2).strip() if m else None


def discover_request_wrappers(js):
    """Find helper names whose definitions delegate to fetch/axios.

    This deliberately identifies the helper definition first instead of treating
    every function named ``request`` as an HTTP call. It covers declarations,
    assigned arrow functions, and object/class method syntax.
    """
    names = {"fetch", "apiRequest", "apiFetch", "fetchJson", "requestJson"}
    definitions = [
        r'\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{',
        r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{',
        r'\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{',
    ]
    keywords = {"if", "for", "while", "switch", "catch", "with"}
    for pattern in definitions:
        for match in re.finditer(pattern, js):
            if match.group(1) in keywords:
                continue
            # Stop at the matching function brace so a later, unrelated fetch
            # does not cause every preceding function to look like a wrapper.
            body, depth = [], 1
            quote, escaped = None, False
            for ch in js[match.end():match.end() + 12000]:
                if quote:
                    body.append(ch)
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == quote:
                        quote = None
                    continue
                if ch in "'\"`":
                    quote = ch
                    body.append(ch)
                elif ch == "{":
                    depth += 1
                    body.append(ch)
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                    body.append(ch)
                else:
                    body.append(ch)
            if re.search(r'\b(?:fetch\s*\(|axios(?:\.|\s*\())', "".join(body)):
                names.add(match.group(1))
    return names


def generic_request_lines(js, wrapper_names):
    """Extract methods from fetch/custom-wrapper call sites with balanced args."""
    lines = []
    call = re.compile(r'(?<![\w$])((?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*))\s*\(')
    for match in call.finditer(js):
        full_name, terminal = match.group(1), match.group(2)
        if terminal not in wrapper_names and full_name != "axios.request":
            continue
        args = parse_call_args(js[match.end():])
        if not args:
            continue
        route = route_from_expr(args[0])
        options = args[1] if len(args) > 1 else ""
        if route is None and args[0].lstrip().startswith("{"):
            raw_url = object_property(args[0], "url")
            if raw_url:
                route = template_route(raw_url)
            options = args[0]
        if not route or not route.startswith("/") or STATIC_EXT.search(route):
            continue
        method = object_property(options, "method") or "GET"
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            continue
        lines.append("%-6s %s" % (method, route))
    return lines


def extract_method_lines(js, wrapper_names):
    """Return every probe-ready HTTP method/path line from one source blob."""
    calls = re.findall(r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*(["\'])'
                       r'(/[^"\']+)\2(?!\s*\.concat\()', js)
    call_lines = ["%-6s %s" % (method.upper(), path) for method, _, path in calls]
    template_calls = re.findall(
        r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*`(/[^`]+)`', js)
    template_lines = ["%-6s %s" % (method.upper(), template_route(path))
                      for method, path in template_calls]
    concat_calls = re.findall(r'[\w$]{1,32}\.(get|post|put|delete|patch)\s*\(\s*["\']'
                              r'(/[^"\']+)["\']\s*\.concat\((?=([^;\n]{0,90}))', js)
    concat_lines = ["%-6s %s" % (method.upper(), concat_route(path, tail))
                    for method, path, tail in concat_calls]
    forms = []
    for tag in re.findall(r'<form\b[^>]*>', js, re.I):
        attrs = dict((k.lower(), v) for k, _, v in re.findall(
            r'([:\w-]+)\s*=\s*(["\'])(.*?)\2', tag, re.I | re.S))
        action = attrs.get("action", "")
        if action.startswith("/"):
            forms.append("%-6s %s" % (attrs.get("method", "GET").upper(), action))
    return call_lines + template_lines + concat_lines + forms + generic_request_lines(js, wrapper_names)


# The name is optional: `query { ... }` is a valid anonymous operation and is
# common in hand-written clients. The name must still be whitespace-separated
# from the keyword, or minified `document.querySelector(...)` splits into the
# keyword `query` plus the name `Selector` and mines as an operation.
# Groups: keyword, name, args.
GRAPHQL_START = re.compile(
    r'\b(query|mutation|subscription)(?:[ \t\r\n]+([A-Za-z_]\w*))?[ \t\r\n]*'
    r'(\([^{}]{0,1000}\))?[ \t\r\n]*\{')
# `gql`{ viewer { id } }`` — shorthand has no keyword at all, so only trust it
# inside a GraphQL template tag. A bare `{` anywhere else is just JavaScript.
GRAPHQL_TAG_SHORTHAND = re.compile(r'\b(?:gql|graphql)\s*`\s*\{')
# GraphQL selection sets contain none of these; JS bodies almost always do. Used
# only to vet anonymous matches, where the keyword alone is weak evidence.
JS_BODY_MARKER = re.compile(r'=>|;|&&|\|\||`|\+\+|\breturn\b|\bfunction\b|\bvar\b')


def anonymous_match_is_graphql(args, body):
    """Vet a nameless ``query|mutation|subscription`` match against JS lookalikes.

    ``function query() {`` and ``async query(a, b) {`` are ordinary JavaScript
    that the nameless pattern would otherwise mine. Two cheap discriminators:
    a GraphQL variable list always opens with ``$``, and a selection set never
    contains JS statement syntax.
    """
    if args and not re.match(r'\(\s*\$', args):
        # `query(selector) {` is a function, not an operation. A nameless
        # GraphQL operation that takes arguments always declares `$vars` --
        # and requiring `$` *first* also rejects a minified span that merely
        # happens to contain one further along.
        return False
    return not JS_BODY_MARKER.search(body)


def graphql_comment_end(text, index):
    """Index just past a GraphQL ``#`` comment that starts at ``index``.

    A comment runs to end of line, but the line may end either with a real
    newline (source maps, unminified bundles) or with the two characters
    ``\\n`` that a minified JS string literal uses instead.
    """
    for cursor in range(index, len(text)):
        char = text[cursor]
        if char in "\r\n":
            return cursor
        if char == "\\" and text[cursor + 1:cursor + 2] in ("n", "r"):
            return cursor
    return len(text)


def scan_graphql(text, start, limit=None):
    """Yield ``(index, char)`` over a GraphQL document, skipping strings/comments.

    Inside a GraphQL document only ``"`` opens a string — an apostrophe is
    ordinary prose, so treating it as a JS quote used to swallow the rest of the
    operation. ``#`` comments are skipped outright, since a brace mentioned in a
    comment is not structure.
    """
    stop = len(text) if limit is None else min(len(text), limit)
    index = start
    while index < stop:
        char = text[index]
        if char == "#":
            index = graphql_comment_end(text, index)
            continue
        if char == '"':
            index += 1
            while index < stop:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    break
                index += 1
            index += 1
            continue
        yield index, char
        index += 1


def strip_graphql_comments(text):
    return "".join(char for _, char in scan_graphql(text, 0))


def extract_graphql_operations(js):
    """Extract complete named GraphQL operations with balanced selection braces.

    The old one-line regex stopped at the opening brace, hiding the root resolver,
    selection fields, and identity-shaped variables that make an IDOR lead valuable.
    Keep this parser intentionally GraphQL-shaped rather than trying to parse all JS:
    start at an operation, then balance braces while skipping GraphQL strings and
    ``#`` comments. Named operations are trusted on sight; nameless ones are vetted
    against JS lookalikes first, and bare shorthand only inside a gql`` tag.
    """
    starts = [(match.start(), match.group(1), match.group(2), match.group(3),
               js.find("{", match.start(), match.end()))
              for match in GRAPHQL_START.finditer(js)]
    # Shorthand carries no keyword, so it is only mined inside a gql`` tag and is
    # a query by definition.
    starts += [(match.end() - 1, "query", None, None, match.end() - 1)
               for match in GRAPHQL_TAG_SHORTHAND.finditer(js)]

    operations = []
    for start, keyword, name, args, brace in sorted(starts):
        depth = 0
        end = None
        for index, char in scan_graphql(js, brace, brace + 20000):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            continue
        if not name and not anonymous_match_is_graphql(
                args, strip_graphql_comments(js[brace:end])):
            continue
        raw = js[start:end]
        # A minified JS string carries GraphQL newlines as the two characters
        # ``\\n``, while sourcesContent carries real newlines. Normalize both so
        # the bundle and its source map collapse to one operation/provenance row.
        semantic = re.sub(r'\\[nrt]', ' ', raw)
        normalized = " ".join(semantic.split())
        # Comments are kept in the emitted operation (they carry lab hints) but
        # never drive parsing: a leading comment would otherwise hide the root.
        analysed = re.sub(r'\\[nrt]', ' ', strip_graphql_comments(raw))
        header = analysed[:analysed.find("{")]
        variables = list(dict.fromkeys(re.findall(r'\$([A-Za-z_]\w*)', header)))
        identity_variables = [name for name in variables if name.lower().endswith("id")]
        body = analysed[analysed.find("{") + 1:]
        root_match = re.match(
            r'\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_]\w*)', body)
        roots = [root_match.group(1)] if root_match else []
        operations.append({
            "type": keyword,
            "name": name or "(anonymous)",
            "variables": variables,
            "identity_variables": identity_variables,
            "roots": roots,
            "operation": normalized,
        })
    return operations


def format_graphql_operation(operation, sources=None):
    bits = ["%s %s" % (operation["type"], operation["name"])]
    if operation["variables"]:
        bits.append("vars=" + ",".join(operation["variables"]))
    if operation["identity_variables"]:
        bits.append("identity-vars=" + ",".join(operation["identity_variables"]))
    if operation["roots"]:
        bits.append("roots=" + ",".join(operation["roots"]))
    if sources:
        bits.append("sources=" + ",".join(sorted(sources)))
    return " ".join(bits) + " :: " + operation["operation"]


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
            norm = f.replace("\\", "/")
            if source_is_vendor(norm):
                continue
            if f.lower().endswith(".map"):
                blobs.extend(sourcemap_blobs(f))
                continue
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    blobs.append((f, fh.read()))
            except OSError:
                pass
    return blobs


def section(title, items, limit=400, width=200):
    items = sorted(set(i for i in items if i))
    print("\n=== %s (%d) ===" % (title, len(items)))
    for i in items[:limit]:
        print("  " + str(i)[:width])


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
    wrapper_names = discover_request_wrappers(all_js)
    physical = [name.split("!", 1)[0] for name, _ in blobs]
    try:
        source_root = os.path.commonpath(physical)
        if not os.path.isdir(source_root):
            source_root = os.path.dirname(source_root)
    except ValueError:
        source_root = ""

    def source_label(filename):
        physical_name, sep, embedded = filename.partition("!")
        label = os.path.relpath(physical_name, source_root) if source_root else physical_name
        return label + ("!" + embedded if sep else "")

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
    routes = {r for r in routes if not STATIC_EXT.search(r)}
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
    method_lines = extract_method_lines(all_js, wrapper_names)
    section("METHOD -> PATH", method_lines)
    if routes and not method_lines:
        print("\n[!] HIGH PRIORITY: routes were found but no HTTP methods were mapped")
        print("[!] Run wrapper/OPTIONS/POST fallback discovery before treating routes as absent")

    # Keep the probe-ready section above annotation-free, then provide analyst
    # provenance separately so a high-value application call is not buried under
    # a large bundle corpus.
    provenance = {}
    for filename, blob in blobs:
        label = source_label(filename).replace("\\", "/")
        for line in extract_method_lines(blob, wrapper_names):
            provenance.setdefault(line, set()).add(label)
    provenance_lines = ["%s [%s; high]" % (line, ", ".join(sorted(paths)))
                        for line, paths in provenance.items()]
    section("METHOD PROVENANCE", provenance_lines)

    high_value = []
    for line in sorted(set(method_lines)):
        match = ACTION_ROUTE.search(line)
        if not match:
            continue
        keyword = match.group(1).lower()
        if keyword in ("inbox", "outbox", "email", "emails", "mail"):
            score = 110
        elif keyword in (
                "magic", "magic-link", "passwordless", "claim", "activation", "activate",
                "enrollment", "enroll", "invite", "password", "recover", "reset",
                "verify", "forgot"):
            score = 100
        else:
            score = 80
        if keyword in ("login", "register", "signup"):
            score = 60
        sources = ", ".join(sorted(provenance.get(line, [])))
        high_value.append("score=%d %s [%s]" % (score, line, sources or "unknown source"))
    section("HIGH-VALUE ACTION ROUTES", high_value)

    # ---- client router (reveals pages, hence features) ----------------------
    section("ROUTER PATHS", re.findall(r'path:\s*["\']([^"\']+)["\']', all_js))

    # ---- secrets ------------------------------------------------------------
    secrets = re.findall(
        r'(?i)(?:password|passwd|secret|apikey|api_key|access_key|token|privatekey|client_secret)'
        r'\s*[:=]\s*["\'`]([^"\'`\s]{6,})["\'`]', all_js)
    library_secret_noise = re.compile(
        r'(?:SECRET_)?DO_NOT_(?:PASS_THIS|USE)_OR_YOU_WILL_BE_FIRED', re.I)
    section("SECRETS", [s for s in secrets
                        if not s.startswith(("function", "undefined"))
                        and not library_secret_noise.fullmatch(s)])

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
    graphql_operations = {}
    graphql_sources = {}
    for filename, blob in blobs:
        label = source_label(filename).replace("\\", "/")
        for operation in extract_graphql_operations(blob):
            key = (operation["type"], operation["name"], operation["operation"])
            graphql_operations[key] = operation
            graphql_sources.setdefault(key, set()).add(label)
    graphql_lines = [format_graphql_operation(operation, graphql_sources[key])
                     for key, operation in graphql_operations.items()]
    section("GRAPHQL OPERATIONS", graphql_lines, width=600)
    identity_lines = [line for line in graphql_lines if "identity-vars=" in line]
    section("GRAPHQL IDENTITY SIGNALS", identity_lines, width=600)

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
    hits = re.findall(r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|picoCTF)\{[^}]{4,80}\}', all_js, re.I)
    if hits:
        print("\n" + "!" * 60)
        print("FLAG PATTERN IN BUNDLE: %s" % set(hits))
        print("!" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
