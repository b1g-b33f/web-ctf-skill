# web-ctf

A practical harness for solving web CTFs with Codex or Claude Code. It helps an agent move from
reconnaissance through authentication, endpoint testing, exploitation, and flag extraction while
keeping evidence and reproducible commands.

Use `$web-ctf` in Codex or `/web-ctf` in Claude Code:

```text
$web-ctf [platform] <target> [challenge-name] [username] [password]
```

`platform` is optional. It selects the expected flag wrapper for HTB, BugForge, and picoCTF;
other platforms work without one. This skill is for running web applications, not crypto, pwn,
forensics, or reversing challenges.

## Quick start

1. Make the canonical checkout available to Codex:

   ```bash
   ln -s ~/Offsec/Web_CTF/web-ctf-skill ~/.codex/skills/web-ctf
   ```

2. Optionally choose where challenge workspaces are stored:

   ```bash
   export CTF_ROOT=~/Offsec/Web_CTF/CTF
   ```

3. Start a task:

   ```text
   $web-ctf bugforge https://target.example challenge-name
   ```

The harness creates a resumable workspace, records a worklog, saves recon and probe evidence, and
keeps each reprovisioned lab instance separate.

## How it works

The methodology is app-first: read the application, establish real baselines, test authenticated
and anonymous behavior, and follow the strongest live signal before reaching for broad scanners.

```text
SKILL.md           ~2.8k tokens: workflow and signal routing
references/*.md    16 files: focused guidance loaded when needed
scripts/           bounded helpers for repeatable recon and testing
```

Detailed techniques live in the references so every task does not pay the context cost of a full
payload catalog. `scripts/audit.py` checks that the routing, documentation, and tooling stay in
sync.

## Included tools

| Tool | What it does |
|---|---|
| `ctf-init.sh` | Creates or resumes a challenge workspace and launches the initial recon jobs |
| `jsharvest.py`, `jsmine.py` | Harvest application JavaScript, source maps, routes, methods, fields, and GraphQL operations |
| `quickrecon.py`, `probe.py` | Check routes with calibrated fallback detection and authenticated/anonymous comparisons |
| `authquick.py`, `jwtquick.py` | Test first-use account flows and the bounded JWT attack surface |
| `sqlquick.py`, `nosqlquick.py` | Run guarded SQL and document-query injection fast tracks |
| `cmdiquick.py` | Detect command injection across POSIX, cmd.exe, and PowerShell contexts |
| `lfiquick.py` | Test bounded Linux and Windows traversal/LFI paths and bypass families |
| `graphqlquick.py` | Map and probe high-value read-only GraphQL operations |
| `templatequick.py` | Test controllable response-only template fields |
| `ssrfget.py` | Turn stored-response SSRF into a repeatable read primitive |
| `oob.py` | Start a local callback collector and optional public tunnel for admin-bot labs |
| `forgeflare.py`, `ffproxy.py` | Maintain Forgeflare-style clearance and proxy other tools through it |
| `flaghook.py` | Scan command output for supported flag patterns |
| `audit.py`, `sync-claude-mirror.py` | Validate the canonical checkout and build the Claude Code mirror |

Each helper has `--help`. The relevant file under [`references/`](references/) explains when to
use it and what constitutes a real result.

### A few common commands

```bash
# initialize recon
bash ~/.codex/skills/web-ctf/scripts/ctf-init.sh <target> <name> <platform>

# test a JWT against a route that genuinely refuses the original token
python3 ~/.codex/skills/web-ctf/scripts/jwtquick.py \
  --token "$TOKEN" --base <target> --test /api/admin/stats

# test one known-valid file parameter for traversal/LFI
python3 ~/.codex/skills/web-ctf/scripts/lfiquick.py \
  --url "<target>/api/image?file=/uploads/known.png" --param file \
  --token "$TOKEN" --out recon/lfiquick

# start the callback collector before testing an admin bot
python3 ~/.codex/skills/web-ctf/scripts/oob.py --name <challenge>
```

## Requirements

The harness expects Python 3 and a POSIX shell. Individual techniques can also use feroxbuster,
nuclei, sqlmap, ffuf, cloudflared, ngrok, SecLists, and `jwt_tool`. Missing optional tools do not
prevent unrelated parts of the workflow from running.

| Variable | Purpose | Default |
|---|---|---|
| `CTF_ROOT` | Challenge workspaces | `~/Offsec/Web_CTF/CTF` |
| `SECLISTS` | SecLists checkout | `/opt/security-tools/SecLists` |
| `ROCKYOU` | Large fallback password list | `$SECLISTS/Passwords/Leaked-Databases/rockyou.txt` |
| `CLOUDFLARED`, `NGROK` | Tunnel binaries used by `oob.py` | Commands on `PATH` |
| `NOTES_VAULT` | Optional personal writeup vault | `~/Obsidian/Pentesting notes/02-AppSec` |

On macOS, use `python3`; there is no default `python` command. Linux and macOS run the scripts
natively. Windows needs a POSIX-compatible shell such as Git Bash.

## Porting

Most paths are configurable, but these documentation files contain examples tied to the current
workspace and tool layout:

| File | Local assumption |
|---|---|
| `SKILL.md` | Workspace and source-code roots |
| `references/auth-jwt.md` | `jwt_tool` and password-list locations |
| `references/injection.md` | sqlmap output directory |
| `references/source-review.md` | Local source-code root |
| `references/traversal-upload.md` | Workspace root |
| `references/vault-index.md` | Optional notes-vault root |
| `references/web-recon.md` | SecLists wordlists |

Repoint those examples when using a different filesystem layout. The helpers themselves prefer
arguments and environment variables over embedded host paths.

## Contributing

The canonical checkout, validation sequence, flag-hook setup, Claude mirror workflow, and
attribution policy are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

Created and owned by Shawn Szczepkowski.

The canonical harness is maintained collaboratively with OpenAI Codex. Anthropic Claude
contributed substantially to its earlier development and is supported through the generated
Claude Code mirror.
