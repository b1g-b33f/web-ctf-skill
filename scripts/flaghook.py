#!/usr/bin/env python3
"""flaghook.py — PostToolUse hook: shout when a flag appears in any tool output.

Ports the flag-catcher Burp regex to the agent's own traffic. Flags land in
response *headers* on otherwise-normal 403s, and in fields nobody reads twice
(a user's full_name), so every tool result gets scanned rather than trusting
the eyeball pass.

Reads the hook JSON payload on stdin and scans the whole blob as text — no
dependency on a specific field layout. Exit 2 surfaces stderr back to Claude.
Appends every hit to ~/.claude/ctf-flags.log with a UTC timestamp. A dedicated
`bug{CodexHarnessHookCheck_<nonce>}` marker writes ~/.claude/ctf-flaghook-ok
instead, allowing an end-to-end hook activation check without logging a fake flag.
"""
import datetime
import os
import re
import sys

# Deliberately specific: platform-prefixed braces only. A bare {...} would fire
# on every JS object in a bundle.
FLAG_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:HTB|bug|flag|CTF|THM|PLab|picoCTF|RM|WEBVERSE)\{[A-Za-z0-9_\-!?.@#$%^&*+=/]{3,90}\}')
HOOK_CHECK_RE = re.compile(r'bug\{CodexHarnessHookCheck_[A-Za-z0-9_-]{4,40}\}')

# Don't fire on our own log line, on regex literals we ship, or on placeholders.
IGNORE = re.compile(r'(?:flag\{[^}]*(?:\.\.\.|xxx|your|example|placeholder|\[)[^}]*\}'
                    r'|FLAG_RE|flaghook|ctf-flags\.log)', re.I)

LOG = os.path.join(os.path.expanduser("~"), ".claude", "ctf-flags.log")
HOOK_CHECK_LOG = os.path.join(os.path.expanduser("~"), ".claude", "ctf-flaghook-ok")


def main():
    try:
        blob = sys.stdin.read()
    except Exception:
        return 0
    if not blob:
        return 0

    # An ordinary unit test proves this script works; this marker proves Claude
    # actually invoked it after a tool call. Keep it out of the real flag log.
    hook_check = HOOK_CHECK_RE.search(blob)
    if hook_check:
        try:
            os.makedirs(os.path.dirname(HOOK_CHECK_LOG), exist_ok=True)
            with open(HOOK_CHECK_LOG, "w", encoding="utf-8") as fh:
                fh.write(hook_check.group(0) + "\n")
        except OSError:
            pass

    # Self-reference guard: if this payload touches the flag log or this script,
    # we're inspecting our own bookkeeping, not discovering a flag. Without this,
    # `cat ctf-flags.log` re-announces every flag in it — and if the same command
    # also removes the log, the dedupe check can't suppress the repeat.
    if os.path.basename(LOG) in blob or "flaghook" in blob:
        return 0

    hits = []
    for m in FLAG_RE.findall(blob):
        if HOOK_CHECK_RE.fullmatch(m):
            continue
        if IGNORE.search(m):
            continue
        if m not in hits:
            hits.append(m)
    if not hits:
        return 0

    # de-dupe against flags already reported this session
    seen = set()
    try:
        if os.path.exists(LOG):
            with open(LOG, encoding="utf-8", errors="replace") as fh:
                seen = {ln.strip().split("\t")[-1] for ln in fh}
    except OSError:
        pass

    fresh = [h for h in hits if h not in seen]

    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as fh:
            ts = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
            for h in fresh:
                fh.write("%s\t%s\n" % (ts, h))
    except OSError:
        pass

    if not fresh:
        return 0

    sys.stderr.write(
        "FLAG PATTERN DETECTED in tool output: %s\n"
        "Verify it against a fresh independent request before submitting "
        "(labs serve decoy flags), then record it and stop working the surface.\n"
        % ", ".join(fresh))
    return 2


if __name__ == "__main__":
    sys.exit(main())
