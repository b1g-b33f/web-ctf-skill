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
SKILL.md            ~4.2k tokens, always loaded: routing + order of operations
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
| `jwtquick.py` | The whole cheap JWT surface in one ~1s foreground call: decode, dictionary-crack the HS256 secret (104k JWT-specific secrets, 0.8s worst case), mint `alg:none` ×4 plus privilege-escalated and id-swapped forgeries, fire them all at a route that refuses you, scan status/headers/body for a flag. Emits a re-sign-only control so a win is attributable to escalation rather than to re-signing. Tags each candidate `rejected` / `POSSIBLE BYPASS` / `FLAG` off exact status+body, never off a reworded rejection message |
| `jsmine.py` | Bundle → routes (incl. query-string and `.concat()` forms), method map, router table, secrets, comments |
| `jsharvest.py` | Fetches the root page, resolves and downloads every `<script src>` bundle (plus non-inline source maps), runs `jsmine.py` over the lot, and writes `recon/jsmine.txt` + a probe-ready `recon/methods.txt`. `ctf-init.sh` runs it once pre-auth; re-run it with `--token`/`--cookie` after login since some apps ship different bootstrap data once authenticated |
| `quickrecon.py` | SPA-fallback-aware existence check: calibrates the not-found signature (size + content-type + body hash, status ignored) from one randomized nonexistent path, then checks a candidate list against it and against framework 404 bodies, saving every response and printing only real hits as `status size content-type URL` |
| `probe.py` | Every endpoint with auth **and** without, **per method**; calibrates the not-found body (and detects framework 404s) so status jitter can't hide routes; scans headers + bodies for flags. Verdicts: `not-a-route`, `auth-required`, `public-error` (same non-fallback error regardless of auth, on a status other than 401/403 — not a leak), `NO-AUTH LEAK`, `NO-AUTH DATA` |
| `sqlquick.py` | Low-volume SQLi fast-track for one GET parameter, meant to run *before* sqlmap: seed → quote → boolean true/false across a few closing forms, stopping at the first strong differential; never claims SQLi from a quote error alone. Binary-searches the `ORDER BY` column boundary, verifies with a numbered `UNION SELECT`, then dumps priority-matching SQLite tables through it (stops at the first flag). Rate-limit aware — 0.55s default delay, two `429` backoff retries (~3s, ~6s), aborts as inconclusive rather than reporting a false negative if throttling persists |
| `ssrfget.py` | Drives a stored-response SSRF as an arbitrary read: trigger, then fetch the artifact the app saved. `--sweep` finds internal services and probes admin paths on each |
| `oob.py` | OOB collector + public tunnel in one command, for admin-bot labs — own the exfil channel instead of trusting the app's. Logs method/path/query/body/UA/`Origin`/`Referer`; answers every method with permissive CORS and a 1x1 GIF so `fetch`, `sendBeacon` and `<img>` all settle; matches flags through URL-encoding and base64 (incl. base64-wrapped JSON). cloudflared by default, `--tunnel ngrok\|none` |
| `ctf-init.sh` | Recon launcher: fetches the root page and runs `jsharvest.py` over it *first* (sequential, so `recon/methods.txt` exists before anything else finishes), then backgrounds `quickrecon.py` (meta files, admin/API quick paths), feroxbuster, and nuclei in parallel |
| `forgeflare/` | `forgeflare.py` (session that auto-re-clears a Forgeflare-style anti-bot challenge, `solve_pow()`, WordPress helpers) and `ffproxy.py` (reverse proxy that injects headers + clearance so unmodified third-party tools work through it) |
| `flaghook.py` | `PostToolUse` hook — scans every Bash result for flag patterns and logs hits |
| `audit.py` | Repo consistency check, see below |

```bash
# run this the moment you hold a token — foreground, ~1s, not a background job
python3 ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" --base <target> --test /api/admin/stats

python3 ~/.claude/skills/web-ctf/scripts/jsmine.py $CTF_ROOT/<name>/recon/

# re-harvest JS once authenticated — some apps bootstrap differently post-login
python3 ~/.claude/skills/web-ctf/scripts/jsharvest.py --base <target> --out recon/ --token "$TOKEN"

# pipe the METHOD -> PATH section so POST-only routes are probed as POST
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths - --methods

# low-volume SQLi fast-track, before sqlmap
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/search?q=1" --token "$TOKEN"

python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep

# start this BEFORE the first payload on any admin-bot lab
python3 ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge>
```

## Install

1. Symlink this directory to `~/.claude/skills/web-ctf/` (don't copy — keep the git clone the
   single source of truth so edits and `gh`-based maintenance stay in one place):
   ```bash
   ln -s ~/Tools/web-ctf-skill ~/.claude/skills/web-ctf
   ```
2. Set `CTF_ROOT` to where you want challenge workspaces (defaults to `~/Tools/CTF`, see below).
3. Optionally wire the flag hook (next section).

Scripts need no edits — they take paths as arguments and read `CTF_ROOT`, `SECLISTS`,
`CLOUDFLARED`, `NGROK` and `NOTES_VAULT` from the environment.

| Variable | Purpose | macOS default |
|---|---|---|
| `CTF_ROOT` | where challenge workspaces are created | `~/Tools/CTF` |
| `SECLISTS` | SecLists tree used by the fuzzing steps | `~/Tools/SecLists` |
| `ROCKYOU` | wordlist `jwtquick.py` escalates to on a miss | `$SECLISTS/Passwords/Leaked-Databases/rockyou.txt` |
| `CLOUDFLARED` / `NGROK` | tunnel binaries for `oob.py` | `cloudflared` / `ngrok` (on `PATH` via brew) |
| `NOTES_VAULT` | optional personal writeup vault, see below | `~/Obsidian/Pentesting notes/02-AppSec` |

### macOS setup

The Python tooling and the POSIX shell snippets throughout `SKILL.md` and the references run
natively — Terminal.app opens a login shell, `ctf-init.sh` is a plain bash script, no path
mangling to work around. One real gotcha:

- **macOS ships no bare `python` command, only `python3`.** Every invocation in this skill uses
  `python3` for that reason — translate any `python ...` one-liner pasted in from an external
  writeup before running it.

External dependencies, installed via Homebrew where a formula exists:

```bash
brew install feroxbuster nuclei sqlmap ffuf cloudflared pipx
```

`jwt_tool` and `SecLists` have no brew package — they're tracked as plain git clones instead:

```bash
git clone https://github.com/ticarpi/jwt_tool.git ~/Tools/jwt_tool
python3 -m pip install --user -r ~/Tools/jwt_tool/requirements.txt

git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/Tools/SecLists
tar -xzf ~/Tools/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
  -C ~/Tools/SecLists/Passwords/Leaked-Databases/
```

The skill degrades gracefully if any of these are missing — each sits behind a specific signal,
named in `SKILL.md`'s routing table.

**The notes vault is optional.** `references/vault-index.md` describes looking up your own prior
writeups when you have a *named* hypothesis — on re-provisioned labs a past writeup is often the
whole method. Set `NOTES_VAULT` to point at your own markdown tree; if you don't, the lookups
return nothing and every other step is unaffected. The folder map in that file is the author's
own index, kept as a worked example of how to organise one.

## Flag hook

`flaghook.py` scans Bash output for flag patterns so a flag can't scroll past unnoticed. Wire it
in **project** settings rather than user settings, so it's scoped to CTF work rather than every
session everywhere.

**Placement matters and is easy to get wrong.** Claude Code resolves project settings by walking
*up* from the session's actual working directory — never down into subdirectories. Put
`.claude/settings.json` at (or above) wherever your `/web-ctf` sessions actually start, **not**
inside `$CTF_ROOT` or a per-challenge folder underneath it. A copy nested one level too deep sits
there validly formed and silently never loads — this shipped once, ran an entire live session
with the hook dark, and was only caught because the flag happened to also print to stdout
directly. If sessions start from `~/Tools`, the file belongs at `~/Tools/.claude/settings.json`.
**Verify it, don't assume it:** after wiring it, run a Bash command that echoes a fake flag
pattern (`echo 'bug{TEST}'`) and confirm a line actually lands in `~/.claude/ctf-flags.log`
before trusting it in a real run.

```json
{ "hooks": { "PostToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command",
    "command": "python3 \"<path-to>/.claude/skills/web-ctf/scripts/flaghook.py\"",
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
printf '#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/scripts/audit.py"\n' \
  > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Run it directly any time with `python3 scripts/audit.py`. It blocks the commit on failure;
`git commit --no-verify` overrides when a change is deliberate.

## Porting to another platform

The scripts are portable as-is, and the shell snippets assume a POSIX shell — the default on
Linux and macOS (this repo's current baseline), and available on Windows via Git Bash. These
docs contain host paths from the environment they were written in (currently `~/Tools/...` on
macOS), and need repointing if you don't share that layout:

| File | What needs repointing |
|---|---|
| `SKILL.md` | workspace and source-code roots |
| `references/auth-jwt.md` | `jwt_tool.py` clone location, SecLists password lists |
| `references/injection.md` | sqlmap output/exploits directory (the `sqlmap` binary itself is on `PATH`) |
| `references/source-review.md` | local source-code root |
| `references/traversal-upload.md` | workspace root |
| `references/vault-index.md` | notes-vault root (**and the vault itself must be present**) |
| `references/web-recon.md` | SecLists wordlists (or set `SECLISTS`) |

**Porting to Kali or another Linux box:** the scripts and POSIX shell snippets need no changes —
only the literal `~/Tools/...` example paths above, if your layout differs, and `python3` should
already be present. **Porting back to Windows:** see this repo's git history prior to the macOS
port for the Git Bash-specific notes (MSYS path mangling, the PowerShell `curl` alias) that were
dropped from the current docs since they no longer apply to the primary platform.

## Contributing

The references are deliberately written as *decision rules with the evidence behind them*, not as
payload dumps — each one exists because a specific failure cost real time. If you add a lesson,
put it in the reference its signal routes to, keep `SKILL.md` unchanged unless the lesson changes
*which* reference you open, and make sure `python3 scripts/audit.py` passes.
