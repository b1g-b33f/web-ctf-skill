# ctf skill — CTF/lab harness

Progressive-disclosure replacement for the old monolithic `~/.claude/commands/ctf.md`
(36 KB, ~8.9k tokens loaded on every invocation).

```
SKILL.md            ~2.7k tokens, always loaded: routing + order of operations
references/*.md     14 files, loaded one at a time when a signal fires
scripts/*.py        real tooling (no hardcoded paths — portable as-is)
```

**Watch the SKILL.md figure.** It was ~1.6k tokens at creation and is the one file loaded on
*every* invocation, so it is the budget that matters. When a lesson can live in a reference,
put it there — SKILL.md should only carry what changes which reference you open.

`references/browser.md` covers the in-app browser pane: a supplement to curl for the specific
cases where JS execution or browser URL-parsing matters (DOM/reflected XSS, client-side
traversal/redirect chains, clean-tier requests on anti-bot labs) — explicitly *not* the tool for
admin-bot XSS, where the exploit must fire in the lab's browser and exfiltrate to a listener.

## Scripts

| Script | Purpose |
|---|---|
| `jsmine.py` | Bundle → routes (incl. query-string and `.concat()` forms), method map, router table, secrets, comments |
| `probe.py` | Every endpoint with auth **and** without, **per method**; calibrates the not-found body (and detects framework 404s) so status jitter can't hide routes; scans headers + bodies for flags |
| `ssrfget.py` | Drives a stored-response SSRF as an arbitrary read: trigger, then fetch the artifact the app saved. `--sweep` finds internal services and probes admin paths on each |
| `ctf-init.sh` | Parallel background recon: scaffolds the workspace, then headers / meta files / quick paths / feroxbuster / nuclei (htb only) at once. `CTF_ROOT` and `SECLISTS` override the Windows defaults |
| `forgeflare/` | `forgeflare.py` (session that auto-re-clears a Forgeflare challenge, `solve_pow()`, WordPress helpers) and `ffproxy.py` (reverse proxy on 127.0.0.1:8899 that injects headers + clearance so unmodified third-party tools work) |
| `flaghook.py` | `PostToolUse` hook — scans every Bash result for flag patterns, logs to `~/.claude/ctf-flags.log` |

```bash
python ~/.claude/skills/ctf/scripts/jsmine.py /c/Tools/CTF/<name>/recon/

# pipe the METHOD -> PATH section so POST-only routes are probed as POST
python ~/.claude/skills/ctf/scripts/jsmine.py recon/ | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths - --methods

python ~/.claude/skills/ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep
```

## Consistency audit

`scripts/audit.py` checks this repo against itself: every script documented, every
reference routed to from `SKILL.md`, no doc pointing at a script that doesn't exist, the
README's reference count and SKILL.md token figure still true, the porting table matching
the files that actually carry host paths, no real flag / JWT / lab hostname committed, and
every script compiling. Each check exists because that exact drift happened at least once.

**Git hooks aren't versioned — install it per clone:**

```bash
printf '#!/bin/sh\nexec python "$(git rev-parse --show-toplevel)/scripts/audit.py"\n' \
  > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Run it directly any time with `python scripts/audit.py`. It blocks the commit on failure;
`git commit --no-verify` overrides when a change is deliberate.

## Hook wiring

The flag hook lives in **project** settings (`C:\Tools\.claude\settings.json`), so it only
runs in the tools/CTF workspace rather than on every Bash call in every project:

```json
{ "hooks": { "PostToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command",
    "command": "python \"C:/Users/shawn/.claude/skills/ctf/scripts/flaghook.py\"",
    "timeout": 15 } ] } ] } }
```

Exit 2 is intentional — it surfaces the hit back to the model. Do not wrap the command
in `|| true`, which would swallow it.

## Porting to another machine (Kali VM)

1. Copy this directory to `~/.claude/skills/ctf/`.
2. `scripts/*.py` need no changes — they take paths as arguments and use `expanduser`.
   (`ssrfget.py` contains Windows Git-Bash paths only as argv-demangling *fallbacks*;
   they simply never match on Linux.)
3. Fix tool paths in these **nine** files, which reference the Windows layout:

   | File | What needs repointing |
   |---|---|
   | `SKILL.md` | `/c/Tools/CTF/`, `/c/Tools/Source Code/`; the Git-Bash argv-mangling note is Windows-only and can be dropped |
   | `references/auth-jwt.md` | `jwt_tool.py`, SecLists password lists |
   | `references/injection.md` | `sqlmap.py` |
   | `references/source-review.md` | `/c/Tools/Source Code/` |
   | `references/traversal-upload.md` | `C:/Tools/CTF/` |
   | `references/vault-index.md` | Obsidian vault root (**and the vault itself must be present**) |
   | `references/web-recon.md` | SecLists wordlists (`ctf-init.sh` is bundled now — set `CTF_ROOT`/`SECLISTS` instead of editing it) |
   | `references/xss-ssrf.md` | `cloudflared.exe` |

4. Re-wire the hook in that machine's project settings with the new script path.
5. **Remaining external dependencies** — a fresh clone does not carry these: the **SecLists
   tree** (`SECLISTS` env var), the **Obsidian vault**, and the tools in `C:\Tools\CLAUDE.md`
   (jwt_tool, sqlmap, cloudflared). The skill degrades gracefully without them — each sits
   behind a specific signal — but the sections naming them will be dead ends.
   `ctf-init.sh` and `forgeflare/` used to be on this list; they are bundled in `scripts/` now.

## Provenance

This skill replaced a 937-line / 36 KB monolithic command that loaded ~8.9k tokens on every
invocation. That command was retired on 2026-07-30 once the skill had been proven on live
labs; `archive/ctf-legacy.md` is the verbatim copy.

**It is history, not a rollback path.** The `/ctf-legacy` slash command no longer exists, and
the archive is not maintained — it references `/c/Tools/ctf-init.sh` and
`/c/Tools/Python/forgeflare/`, which have moved into `scripts/`. Read it to recover a payload
or a phrasing the decomposition dropped; don't run it.

Every section of it maps onto a reference: IDOR/mass-assignment → `access-control.md`,
SQLi → `injection.md`, SSTI → `ssti.md`, traversal → `traversal-upload.md`,
JWT → `auth-jwt.md`, JS harvest and probing → `web-recon.md`.
