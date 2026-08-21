# Contributing

Thanks for helping improve `web-ctf`. Changes should make the harness faster, clearer, or more
reliable on real web challenges without turning the skill into an always-loaded payload catalog.

## Repository ownership

This git checkout is the canonical source. Codex runs it directly through
`~/.codex/skills/web-ctf`; Claude Code runs a generated mirror at
`~/.claude/skills/web-ctf`.

Make changes here, not in the Claude mirror. Build the mirror only after the canonical checkout
passes validation.

## Where changes belong

- Put routing and order-of-operations decisions in `SKILL.md`.
- Put technique depth and evidence rules in the relevant file under `references/`.
- Put repeated or mechanically sensitive work in `scripts/`.
- Add regression coverage for behavior that could silently fail or produce a false result.
- Keep the README useful to a new human reader; implementation detail belongs here or in a focused
  reference.

The references should explain decisions and proof standards, not duplicate generic payload lists.
Live solve evidence is a reason to improve the harness, but one lab-specific quirk should not
become a universal rule without a reusable signal.

## Validation and handoff

Run the canonical checks from the repository root:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/audit.py
```

Then refresh and test the Claude mirror:

```bash
python3 scripts/sync-claude-mirror.py
cd ~/.claude/skills/web-ctf
python3 -m unittest discover -s tests -p 'test_*.py'
```

Return to the canonical checkout and confirm that the working tree contains only the intended
changes. A maintenance handoff is complete when both suites pass, the audit passes, and
`python3 scripts/sync-claude-mirror.py --check` reports no drift.

The sync script intentionally rewrites Codex paths, hook language, and invocation frontmatter for
Claude Code. Do not flatten those platform differences by copying files over the mirror manually.
It retains the two newest previous mirrors under `~/.claude/skill-backups/web-ctf`, outside
Claude's skill-discovery directory, and prunes older backups only after a successful swap.

## Consistency audit

`scripts/audit.py` checks script documentation, reference routing, token and reference counts,
host-path portability notes, leaked flags or tokens, source syntax, and executable bits.

To run it automatically before commits, install this hook in each clone:

```bash
printf '#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/scripts/audit.py"\n' \
  > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Run the audit directly when diagnosing a failure. Avoid `git commit --no-verify` unless the failed
check is understood and the exception is deliberate.

## Flag hook

`flaghook.py` scans command output for flags. Keep it in project configuration so it runs only for
CTF work. For a project rooted at `~/Offsec/Web_CTF`, place the Codex configuration in
`~/Offsec/Web_CTF/.codex/config.toml`:

```toml
[features]
hooks = true

[[hooks.PostToolUse]]
matcher = ".*"

[[hooks.PostToolUse.hooks]]
type = "command"
command = 'python3 "/Users/<user>/.codex/skills/web-ctf/scripts/flaghook.py"'
timeout = 15
```

After an application restart or tool-surface change, print a unique
`bug{CodexHarnessHookCheck_<nonce>}` marker in one tool call and verify in the next that it reached
`~/.codex/ctf-flaghook-ok`. The health-check marker is not recorded as a real flag. Directly
invoking `flaghook.py` tests the script but does not prove the `PostToolUse` hook fired.

The hook exits with status 2 when it sees a real flag so the result is surfaced to the agent. Do
not append `|| true` to its configuration.

## Porting

The scripts use Python 3 and POSIX shell conventions. Host-specific examples currently assume:

- challenge work under `~/Offsec/Web_CTF`;
- third-party tools and wordlists under `/opt/security-tools`;
- an optional Obsidian vault under `~/Obsidian`.

The README lists every documentation file that carries one of these assumptions. Repoint the
examples or set the corresponding environment variables when moving the harness. On Windows, use
Git Bash and account for MSYS argument conversion when a command-line value looks like a path.

## Attribution

Shawn Szczepkowski remains the repository owner and git author. The README acknowledges both
OpenAI Codex and Anthropic Claude where they have materially assisted development.

Do not invent an email address to force an AI tool into GitHub's contributor graph. Use a normal
commit message and, when useful, add a plain-text trailer such as:

```text
Assisted-By: OpenAI Codex
```

Use `Co-Authored-By` only for a real identity with a verified address. Do not rewrite published
history solely to change AI attribution.
