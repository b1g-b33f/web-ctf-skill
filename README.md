# web-ctf — a web CTF harness for Claude Code

A progressive-disclosure skill for challenges against a **running web application**: recon, auth,
endpoint probing, exploitation, flag extraction. Invoke it with `/web-ctf`.

```
/web-ctf [platform] <target> [challenge-name] [username] [password]
```

`target` is a URL or IP; the workspace is created at `$CTF_ROOT/<challenge-name>/`. `platform` is
optional and only sets the expected flag wrapper (`htb` → `HTB{}`, `bugforge` → `bug{}`,
`picoctf` → `picoCTF{}`, otherwise `flag{}`) — any platform works, including none.

**Scope: web only, deliberately.** The bug classes it routes to are broken access control,
injection, SSTI, path traversal and upload, SSRF, XSS with an admin bot, CORS, GraphQL, JWT and
session flaws, business logic and race conditions, and anti-bot layers.

It is not a crypto, pwn, forensics or reversing playbook, and its skill description says so
explicitly, so it won't hijack those requests — leaving room for a companion skill to own
full-scope boxes (enumeration, privesc, pivoting) without either one diluting the other. Keeping
the always-loaded routing table narrow is what makes it fast; a general-purpose CTF skill is a
different shape, not a superset of this one.

## How it is organised

```
SKILL.md            ~3.3k tokens, always loaded: routing + order of operations
references/*.md     15 files, loaded one at a time when a signal fires
scripts/*.py        real tooling (env-overridable paths — portable as-is)
```

The design goal is that the always-loaded file stays small. `SKILL.md` carries only the order of
operations and a **signal → reference** routing table; the depth for any one bug class lives in a
reference that gets read only when the app actually shows you that signal. A payload catalogue you
load on every invocation is a payload catalogue you pay for on every invocation.

**Watch the SKILL.md figure.** It is the one file loaded on *every* invocation, so it is the
budget that matters. When a lesson can live in a reference, put it there — SKILL.md should only
carry what changes which reference you open. `scripts/audit.py` fails the build if the figure in
this README drifts from reality by more than 15%.

The methodology is app-first: log in, read the app's own JavaScript and seeded documents, probe
every endpoint, and exploit what the app's behaviour points at. Scanners are step 8, not step 1.

`references/browser.md` covers driving a real browser: a supplement to curl for the cases where
JS execution or browser URL-parsing matters (DOM/reflected XSS, client-side traversal/redirect
chains) — explicitly *not* the tool for admin-bot XSS, where the exploit must fire in the lab's
browser and exfiltrate to a listener you control.

## Scripts

| Script | Purpose |
|---|---|
| `jwtquick.py` | The whole cheap JWT surface in one ~1s foreground call: decode, dictionary-crack the HS256 secret (104k JWT-specific secrets, 0.8s worst case), mint `alg:none` ×4 plus privilege-escalated and id-swapped forgeries, fire them all at a route that refuses you, scan status/headers/body for a flag. Emits a re-sign-only control so a win is attributable to escalation rather than to re-signing |
| `jsmine.py` | Bundle → routes (incl. query-string and `.concat()` forms), method map, router table, secrets, comments |
| `probe.py` | Every endpoint with auth **and** without, **per method**; calibrates the not-found body (and detects framework 404s) so status jitter can't hide routes; scans headers + bodies for flags |
| `ssrfget.py` | Drives a stored-response SSRF as an arbitrary read: trigger, then fetch the artifact the app saved. `--sweep` finds internal services and probes admin paths on each |
| `oob.py` | OOB collector + public tunnel in one command, for admin-bot labs — own the exfil channel instead of trusting the app's. Logs method/path/query/body/UA/`Origin`/`Referer`; answers every method with permissive CORS and a 1x1 GIF so `fetch`, `sendBeacon` and `<img>` all settle; matches flags through URL-encoding and base64 (incl. base64-wrapped JSON). cloudflared by default, `--tunnel ngrok\|none` |
| `ctf-init.sh` | Parallel background recon: scaffolds the workspace, then headers / meta files / quick paths / feroxbuster / nuclei at once |
| `forgeflare/` | `forgeflare.py` (session that auto-re-clears a Forgeflare-style anti-bot challenge, `solve_pow()`, WordPress helpers) and `ffproxy.py` (reverse proxy that injects headers + clearance so unmodified third-party tools work through it) |
| `flaghook.py` | `PostToolUse` hook — scans every Bash result for flag patterns and logs hits |
| `audit.py` | Repo consistency check, see below |

```bash
# run this the moment you hold a token — foreground, ~1s, not a background job
python ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" --base <target> --test /api/admin/stats

python ~/.claude/skills/web-ctf/scripts/jsmine.py $CTF_ROOT/<name>/recon/

# pipe the METHOD -> PATH section so POST-only routes are probed as POST
python ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths - --methods

python ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep

# start this BEFORE the first payload on any admin-bot lab
python ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge>
```

## Install

1. Copy this directory to `~/.claude/skills/web-ctf/`.
2. Set `CTF_ROOT` to where you want challenge workspaces (defaults to a Windows path, see below).
3. Optionally wire the flag hook (next section).

Scripts need no edits — they take paths as arguments and read `CTF_ROOT`, `SECLISTS`,
`CLOUDFLARED`, `NGROK` and `NOTES_VAULT` from the environment.

| Variable | Purpose |
|---|---|
| `CTF_ROOT` | where challenge workspaces are created |
| `SECLISTS` | SecLists tree used by the fuzzing steps |
| `CLOUDFLARED` / `NGROK` | tunnel binaries for `oob.py` |
| `NOTES_VAULT` | optional personal writeup vault, see below |

### On Windows, run it from Git Bash

The Python tooling is cross-platform and runs from any shell, but the shell snippets throughout
`SKILL.md` and the references are POSIX — `${VAR:-default}` fallbacks, `seq`, `sed -n`, `grep -a`,
pipelines into python — and `ctf-init.sh` is a bash script. Several default paths also use the
MSYS `/c/...` form, which only resolves under Git Bash. Install
[Git for Windows](https://gitforwindows.org/) and point the agent's shell at it.

Two Windows-specific gotchas worth knowing up front:

- **Windows PowerShell 5.1 aliases `curl` to `Invoke-WebRequest`**, which takes different flags
  and different quoting. Every recon snippet here is `curl -si`, so in PowerShell they fail or
  behave differently rather than erroring cleanly. (PowerShell 7+ dropped the alias.)
- **Git Bash rewrites URL-looking arguments**: `/admin/config` becomes
  `C:/Program Files/Git/admin/config`. Prefix `MSYS_NO_PATHCONV=1` for those calls — see the
  Environment section of `SKILL.md`.

**External dependencies.** A fresh clone does not carry these, and the sections naming them are
dead ends without them: a [SecLists](https://github.com/danielmiessler/SecLists) tree
(`SECLISTS`), `cloudflared` or `ngrok` for OOB callbacks, and the CLI tools the references invoke
(`jwt_tool`, `sqlmap`, `ffuf`, `feroxbuster`, `nuclei`). The skill degrades gracefully — each sits
behind a specific signal.

**The notes vault is optional.** `references/vault-index.md` describes looking up your own prior
writeups when you have a *named* hypothesis — on re-provisioned labs a past writeup is often the
whole method. Set `NOTES_VAULT` to point at your own markdown tree; if you don't, the lookups
return nothing and every other step is unaffected. The folder map in that file is the author's
own index, kept as a worked example of how to organise one.

## Flag hook

`flaghook.py` scans Bash output for flag patterns so a flag can't scroll past unnoticed. Wire it
in **project** settings rather than user settings, so it only runs in your CTF workspace:

```json
{ "hooks": { "PostToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command",
    "command": "python \"<path-to>/.claude/skills/web-ctf/scripts/flaghook.py\"",
    "timeout": 15 } ] } ] } }
```

Exit 2 is intentional — it surfaces the hit back to the model. Do not wrap the command in
`|| true`, which would swallow it.

## Consistency audit

`scripts/audit.py` checks the repo against itself: every script documented, every reference
routed to from `SKILL.md`, no doc pointing at a script that doesn't exist, this README's
reference count and SKILL.md token figure still true, the porting table matching the files that
actually carry host paths, no real flag / JWT / lab hostname committed, and every script
compiling. Each check exists because that exact drift happened at least once.

**Git hooks aren't versioned — install it per clone:**

```bash
printf '#!/bin/sh\nexec python "$(git rev-parse --show-toplevel)/scripts/audit.py"\n' \
  > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Run it directly any time with `python scripts/audit.py`. It blocks the commit on failure;
`git commit --no-verify` overrides when a change is deliberate.

## Porting to another platform

The scripts are portable as-is, and the shell snippets assume a POSIX shell — which on Linux and
macOS is the default, and on Windows means Git Bash (see above). These docs contain host paths
from the environment they were written in, and need repointing if you don't share that layout:

| File | What needs repointing |
|---|---|
| `SKILL.md` | workspace and source-code roots; the Git-Bash argv-mangling note is Windows-only and can be dropped |
| `references/auth-jwt.md` | `jwt_tool.py`, SecLists password lists |
| `references/injection.md` | `sqlmap.py` |
| `references/source-review.md` | local source-code root |
| `references/traversal-upload.md` | workspace root |
| `references/vault-index.md` | notes-vault root (**and the vault itself must be present**) |
| `references/web-recon.md` | SecLists wordlists (or set `SECLISTS`) |
| `references/xss-ssrf.md` | `cloudflared` binary |

## Contributing

The references are deliberately written as *decision rules with the evidence behind them*, not as
payload dumps — each one exists because a specific failure cost real time. If you add a lesson,
put it in the reference its signal routes to, keep `SKILL.md` unchanged unless the lesson changes
*which* reference you open, and make sure `python scripts/audit.py` passes.
