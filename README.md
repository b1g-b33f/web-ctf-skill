# ctf skill — CTF/lab harness

Progressive-disclosure replacement for the old monolithic `~/.claude/commands/ctf.md`
(36 KB, ~8.9k tokens loaded on every invocation).

```
SKILL.md            ~1.6k tokens, always loaded: routing + order of operations
references/*.md     14 files, loaded one at a time when a signal fires
scripts/*.py        real tooling (no hardcoded paths — portable as-is)
```

`references/browser.md` covers the in-app browser pane: a supplement to curl for the specific
cases where JS execution or browser URL-parsing matters (DOM/reflected XSS, client-side
traversal/redirect chains, clean-tier requests on anti-bot labs) — explicitly *not* the tool for
admin-bot XSS, where the exploit must fire in the lab's browser and exfiltrate to a listener.

## Scripts

| Script | Purpose |
|---|---|
| `jsmine.py` | Bundle → routes (incl. query-string and `.concat()` forms), method map, router table, secrets, comments |
| `probe.py` | Every endpoint with auth **and** without; calibrates the not-found body so status jitter can't hide routes; scans headers + bodies for flags |
| `flaghook.py` | `PostToolUse` hook — scans every Bash result for flag patterns, logs to `~/.claude/ctf-flags.log` |

```bash
python ~/.claude/skills/ctf/scripts/jsmine.py /c/Tools/CTF/<name>/recon/
python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths paths.txt --methods
```

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
3. Fix tool paths in these four files, which reference the Windows layout:
   `references/auth-jwt.md` (jwt_tool), `references/traversal-upload.md`,
   `references/web-recon.md` (ctf-init.sh), `references/vault-index.md` (Obsidian vault root).
4. Re-wire the hook in that machine's project settings with the new script path.
5. `ctf-init.sh` still lives at `C:\Tools\ctf-init.sh` (canonical) — it is referenced, not bundled.

## Rollback

The original monolith is preserved at `~/.claude/commands/ctf-legacy.md` (renamed from
`ctf.md` so it no longer collides with this skill's `/ctf`). It's reachable as `/ctf-legacy`.
To fully revert: delete this skill directory and `mv ctf-legacy.md ctf.md`. Once `/ctf` is
confirmed loading the skill in a fresh session, `ctf-legacy.md` can be deleted.
