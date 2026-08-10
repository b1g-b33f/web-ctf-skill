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
SKILL.md            ~4.9k tokens, always loaded: routing + order of operations
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
| `graphqlquick.py` | Bounded post-auth, read-only GraphQL fast track: anonymous/auth reachability, Query introspection, validation-error schema oracle when introspection is disabled, ID `1`/self checks, independent sensitive-field probes, header/body flag scanning, and hard stops on a flag, rate limit, gateway failure, or request budget. Never generates mutations |
| `jsmine.py` | Bundles and rendered HTML → routes, direct calls, native `fetch`, discovered request wrappers, HTML form methods, and complete named GraphQL operations with roots, variables, identity signals, and provenance. Keeps probe-ready output annotation-free, then adds provenance and high-value action-route ranking; warns loudly when routes exist but no methods map |
| `jsharvest.py` | Fetches pages and valid `<script src>` bundles plus source maps, quarantines literal JS/template hrefs and vendor bundles, rejects error/HTML bodies masquerading as JavaScript, runs `jsmine.py`, and writes `jsmine.txt`, `methods.txt`, `dynamic-links.txt`, and `source-provenance.tsv` |
| `quickrecon.py` | SPA-fallback-aware existence check with optional action-route method fallback: calibrated GET/POST bodies, route-specific `Allow`, and safe `POST {}` validation probes. A 429 is inconclusive; gateway failures trip a circuit breaker |
| `probe.py` | Every endpoint with auth **and** without, **per method**; calibrates the not-found body (and detects framework 404s) so status jitter can't hide routes; scans headers + bodies for flags. Verdicts: `not-a-route`, `auth-required`, `public-error` (same non-fallback error regardless of auth, on a status other than 401/403 — not a leak), `NO-AUTH LEAK`, `NO-AUTH DATA` |
| `sqlquick.py` | Low-volume SQLi fast-track for one GET parameter, meant to run *before* sqlmap: seed → quote → boolean true/false across a few closing forms, stopping at the first strong differential; never claims SQLi from a quote error alone. Binary-searches the `ORDER BY` column boundary, verifies with a numbered `UNION SELECT`, then dumps priority-matching SQLite tables through it (stops at the first flag). Rate-limit aware — 0.55s default delay, two `429` backoff retries (~3s, ~6s), aborts as inconclusive rather than reporting a false negative if throttling persists |
| `nosqlquick.py` | Guarded JSON/Mongo operator oracle for an explicit endpoint and field allowlist: scalar/single/paired `$ne`, query-shape mapping, `$gt` identity enumeration, and variable-length printable-ASCII `$regex`/`$eq` extraction. Refuses login/register/password probes without `--dangerous-auth`; aborts on 429/gateway failures |
| `ssrfget.py` | Drives a stored-response SSRF as an arbitrary read: trigger, then fetch the artifact the app saved. `--sweep` finds internal services and probes admin paths on each |
| `oob.py` | OOB collector + public tunnel in one command, for admin-bot labs — own the exfil channel instead of trusting the app's. Logs method/path/query/body/UA/`Origin`/`Referer`; answers every method with permissive CORS and a 1x1 GIF so `fetch`, `sendBeacon` and `<img>` all settle; matches flags through URL-encoding and base64 (incl. base64-wrapped JSON). cloudflared by default, `--tunnel ngrok\|none` |
| `ctf-init.sh` | Resumable recon launcher: preserves `WORKLOG.md`, namespaces each reprovision under `instances/<hostname>/`, updates an atomic `current` pointer, runs JS harvest first, then quick paths, feroxbuster, and nuclei in parallel. Emits a hook-health sentinel for next-call verification |
| `forgeflare/` | `forgeflare.py` (session that auto-re-clears a Forgeflare-style anti-bot challenge, `solve_pow()`, WordPress helpers) and `ffproxy.py` (reverse proxy that injects headers + clearance so unmodified third-party tools work through it) |
| `flaghook.py` | `PostToolUse` hook — scans every Bash result for flag patterns and logs hits |
| `audit.py` | Repo consistency check, see below |

```bash
# run this the moment you hold a token — foreground, ~1s, not a background job
python3 ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" --base <target> --test /api/admin/stats

python3 ~/.claude/skills/web-ctf/scripts/jsmine.py $CTF_ROOT/<name>/recon/

# run this in the same authenticated parallel burst as jwtquick.py when GraphQL is mapped
python3 ~/.claude/skills/web-ctf/scripts/graphqlquick.py \
  --url <target>/api/graphql --token "$TOKEN" --id "$YOUR_ID" --out recon/graphqlquick

# re-harvest bundles and rendered forms once authenticated
python3 ~/.claude/skills/web-ctf/scripts/jsharvest.py --base <target> --out recon/ \
  --cookie-file <curl-cookie-jar> --page /dashboard --crawl-pages

# pipe the METHOD -> PATH section so POST-only routes are probed as POST
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths - --methods

# low-volume SQLi fast-track, before sqlmap
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/search?q=1" --token "$TOKEN"

# guarded NoSQL operator probe; action/recovery fields only unless dangerous auth is explicit
python3 ~/.claude/skills/web-ctf/scripts/nosqlquick.py \
  --url "<target>/api/account/recover" --field email --field backupCode \
  --baseline email=none@example.test --baseline backupCode=invalid \
  --success-json status=verified --probe --map-query-shape

python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep

# start this BEFORE the first payload on any admin-bot lab
python3 ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge>
```

## Install

1. Symlink this directory to `~/.claude/skills/web-ctf/` (don't copy — keep the git clone the
   single source of truth so edits and `gh`-based maintenance stay in one place):
   ```bash
   ln -s ~/Offsec/Web_CTF/web-ctf-skill ~/.claude/skills/web-ctf
   ```
2. Set `CTF_ROOT` to where you want challenge workspaces (defaults to `~/Offsec/Web_CTF/CTF`, see below).
3. Optionally wire the flag hook (next section).

Scripts need no edits — they take paths as arguments and read `CTF_ROOT`, `SECLISTS`,
`CLOUDFLARED`, `NGROK` and `NOTES_VAULT` from the environment.

| Variable | Purpose | macOS default |
|---|---|---|
| `CTF_ROOT` | where challenge workspaces are created | `~/Offsec/Web_CTF/CTF` |
| `SECLISTS` | SecLists tree used by the fuzzing steps | `/opt/security-tools/SecLists` |
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
git clone https://github.com/ticarpi/jwt_tool.git /opt/security-tools/jwt_tool
python3 -m pip install --user -r /opt/security-tools/jwt_tool/requirements.txt

git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/security-tools/SecLists
tar -xzf /opt/security-tools/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
  -C /opt/security-tools/SecLists/Passwords/Leaked-Databases/
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
directly. If sessions start from `~/Offsec/Web_CTF`, the file belongs at `~/Offsec/Web_CTF/.claude/settings.json`.
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
docs contain host paths from the environment they were written in: the workspace root
(currently `~/Offsec/Web_CTF/...`) and, separately, third-party tool installs kept outside the
workspace (currently `/opt/security-tools/...` — SecLists, jwt_tool). Both are macOS-specific
and need repointing if you don't share that layout:

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
only the literal `~/Offsec/Web_CTF/...` and `/opt/security-tools/...` example paths above, if your
layout differs, and `python3` should already be present. **Porting back to Windows:** see this
repo's git history prior to the macOS port for the Git Bash-specific notes (MSYS path mangling,
the PowerShell `curl` alias) that were dropped from the current docs since they no longer apply to
the primary platform.

## Contributing

The references are deliberately written as *decision rules with the evidence behind them*, not as
payload dumps — each one exists because a specific failure cost real time. If you add a lesson,
put it in the reference its signal routes to, keep `SKILL.md` unchanged unless the lesson changes
*which* reference you open, and make sure `python3 scripts/audit.py` passes.
