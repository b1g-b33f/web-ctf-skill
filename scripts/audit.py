#!/usr/bin/env python3
"""audit.py — consistency checks for this skill repo. Runs as a pre-commit hook.

Every problem this checks for was found by hand at least once:
  * a script added to scripts/ but never listed in the README
  * the README's SKILL.md token figure drifting as SKILL.md grows (it is the one
    file loaded on EVERY invocation, so that budget is the one that matters)
  * the porting table naming 4 files when 9 carried hardcoded host paths, so a
    port to another machine would silently leave stale Windows paths
  * a reference documenting the old, broken usage of a tool that was just fixed
  * a real flag pasted into a doc as an example

Usage:
  python3 scripts/audit.py            # check, exit 1 on failure
  python3 scripts/audit.py --quiet    # only print failures

Install as a hook (not versioned by git, so do this per clone):
  printf '#!/bin/sh\\nexec python3 "$(git rev-parse --show-toplevel)/scripts/audit.py"\\n' \\
    > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

FAILS, WARNS = [], []


def fail(msg):
    FAILS.append(msg)


def warn(msg):
    WARNS.append(msg)


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


scripts = sorted(os.path.basename(p) for p in
                 glob.glob("scripts/*.py") + glob.glob("scripts/*.sh")
                 + glob.glob("scripts/*/*.py"))
refs = sorted(os.path.basename(p) for p in glob.glob("references/*.md"))
readme, skill = read("README.md"), read("SKILL.md")
docs = ["README.md", "SKILL.md"] + ["references/" + r for r in refs]

# 1. every script is documented ------------------------------------------------
for s in scripts:
    if s == "audit.py":
        continue                       # tooling for the repo, not for a solve
    if s not in readme:
        fail("scripts/%s exists but is not in README.md" % s)

# 2. every reference is reachable from the routing table -----------------------
for r in refs:
    if r not in skill:
        fail("references/%s is orphaned - nothing in SKILL.md routes to it" % r)

# 3. no doc points at a script that does not exist -----------------------------
for d in docs:
    for m in set(re.findall(r'scripts/([a-z0-9_]+\.py)', read(d))):
        if m not in scripts:
            fail("%s references scripts/%s which does not exist" % (d, m))

# 4. README's reference count ---------------------------------------------------
m = re.search(r'references/\*\.md\s+(\d+) files', readme)
if not m:
    warn("README no longer states a reference count")
elif int(m.group(1)) != len(refs):
    fail("README says %s reference files, there are %d" % (m.group(1), len(refs)))

# 5. README's SKILL.md token estimate (chars/3.6, same basis as the original) ---
m = re.search(r'SKILL\.md\s+~([\d.]+)k tokens', readme)
if not m:
    warn("README no longer states a SKILL.md token figure")
else:
    actual, claimed = len(skill) / 3.6 / 1000, float(m.group(1))
    if abs(actual - claimed) / max(claimed, 0.1) > 0.15:
        fail("README claims SKILL.md is ~%.1fk tokens, it is ~%.1fk - update it, or move "
             "the addition into a reference" % (claimed, actual))

# 6. porting table vs files that actually carry host paths ---------------------
# Windows roots kept for regression safety even though the current baseline is
# macOS; ~/Offsec/Web_CTF, /opt/security-tools, and ~/Obsidian (or $HOME-spelled)
# are this baseline's equivalent of a hardcoded host path and need repointing on
# a machine with a different layout.
HOSTPATH = re.compile(
    r'(?:C:\\|C:/|/c/)(?!Program Files/Git)[A-Za-z0-9_]'
    r'|(?:~|\$HOME)/(?:Offsec/Web_CTF|Obsidian)/[A-Za-z]'
    r'|/opt/security-tools/[A-Za-z]')
have_paths = {d for d in docs if d != "README.md" and HOSTPATH.search(read(d))}

porting = readme.split("## Porting")[-1] if "## Porting" in readme else ""
listed = set()
for line in porting.splitlines():
    if line.strip().startswith("|"):
        cell = re.search(r'`([^`]+\.md)`', line)
        if cell:
            listed.add(cell.group(1) if "/" in cell.group(1) else cell.group(1))
for f in sorted(have_paths - listed):
    fail("%s contains host paths but is not in the README porting table" % f)
for f in sorted(listed - have_paths):
    warn("%s is in the porting table but no longer contains host paths" % f)

# 7. no real flags, tokens or lab hostnames in tracked content -----------------
FLAG = re.compile(r'(?:HTB|bug|flag|CTF|THM|picoCTF)\{([^}]{3,90})\}', re.I)
# The trailing `_<...>` alternative covers documented sentinel/marker literals like
# flaghook.py's health-check pattern bug{CodexHarnessHookCheck_<nonce>}: a literal,
# human-readable prefix ending in an angle-bracketed placeholder name. A real flag
# never ends in that shape, so this can't hide an actual leaked flag.
PLACEHOLDER = re.compile(r'^[.…]{0,3}$|^\s*$|^<|^\$|^[A-Z_]+$|.*_<[^{}]*>$')
for d in docs:
    body = read(d)
    for inner in FLAG.findall(body):
        if not PLACEHOLDER.match(inner):
            fail("%s contains what looks like a real flag: {%s}" % (d, inner[:40]))
    if re.search(r'eyJ[A-Za-z0-9_-]{20,}', body):
        fail("%s contains a JWT" % d)
    for h in set(re.findall(r'[a-z0-9-]{6,}\.(?:labs-app\.bugforge\.io|htb|thm)', body)):
        fail("%s contains a live lab hostname: %s" % (d, h))

# 8. scripts parse --------------------------------------------------------------
import py_compile
import subprocess
paths = (glob.glob("scripts/*.py") + glob.glob("scripts/*/*.py")
         + glob.glob("scripts/*.sh"))
for p in paths:
    if p.endswith(".py"):
        try:
            py_compile.compile(p, doraise=True)
        except py_compile.PyCompileError as e:
            fail("%s does not compile: %s" % (p, str(e).splitlines()[0]))
    else:
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        if r.returncode:
            fail("%s has a syntax error: %s" % (p, r.stderr.strip().splitlines()[0]))

# 9. shell scripts invoked as direct executables must carry the exec bit -------
# Only .sh files are checked: every .py script here is invoked as `python3 script.py`,
# so its own exec bit is irrelevant. A .sh script that loses 100755 (Edit/sed don't
# reliably preserve file mode) fails with a bare permission-denied on a fresh clone,
# even though the documented `bash script.sh ...` invocation still works fine -
# this exact drift shipped once and broke every /web-ctf run until a live test caught it.
for p in [p for p in paths if p.endswith(".sh")]:
    r = subprocess.run(["git", "ls-files", "-s", p], capture_output=True, text=True)
    mode = r.stdout.split()[0] if r.stdout.strip() else None
    if mode and mode != "100755":
        fail("%s is tracked as mode %s, not 100755 - lost its executable bit" % (p, mode))

# 10. bundled scripts must not hardcode host paths (they ship with the repo) ----
for p in paths:
    body = read(p)
    for m in set(re.findall(
            r'(?<![:${])(?:/c/Tools|C:/Tools|C:\\Tools|/Users/[^/\s]+/Offsec/Web_CTF'
            r'|/home/[^/\s]+/Offsec/Web_CTF|/opt/security-tools)/[A-Za-z]\S*',
            body)):
        context = body[max(0, body.find(m) - 60):body.find(m)]
        if ":-" in context or "environ.get(" in context:
            continue                    # ${VAR:-...} or os.environ.get(VAR, ...) default, fine
        warn("%s hardcodes %s - prefer an env override with that as the default" % (p, m))

quiet = "--quiet" in sys.argv
if WARNS and not quiet:
    for w in WARNS:
        print("  warn: %s" % w)
if FAILS:
    print("\naudit FAILED (%d):" % len(FAILS))
    for f in FAILS:
        print("  - %s" % f)
    print("\nfix, or commit with --no-verify if intentional.")
    sys.exit(1)
if not quiet:
    print("audit OK - %d scripts, %d references, %d docs checked"
          % (len(scripts), len(refs), len(docs)))
sys.exit(0)
