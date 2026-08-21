#!/usr/bin/env python3
"""Build the Claude Code mirror from the canonical Codex web-ctf checkout.

The canonical git checkout is never modified. The mirror is staged beside its
destination, platform-specific paths/frontmatter are rewritten, and the old
destination is moved to a timestamped backup before the staged tree is swapped
in. Run the canonical regression suite and audit before this command, then run
the mirror regression suite afterward.
"""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent.parent
def ignored(_directory, names):
    return {name for name in names
            if name in {".git", "__pycache__", ".DS_Store"}
            or name.endswith((".pyc", ".pyo"))}


def rewrite(path, replacements):
    body = path.read_text(encoding="utf-8")
    changed = body
    for old, new in replacements:
        changed = changed.replace(old, new)
    if changed != body:
        path.write_text(changed, encoding="utf-8")


def render(stage):
    shutil.copytree(ROOT, stage, dirs_exist_ok=True, ignore=ignored)
    shutil.rmtree(stage / "agents", ignore_errors=True)

    skill = stage / "SKILL.md"
    rewrite(skill, [
        ("description: Web CTF", "user-invocable: true\ndescription: Web CTF"),
        ("~/.codex/skills/web-ctf", "~/.claude/skills/web-ctf"),
        ("~/Offsec/Web_CTF/.codex/config.toml", "~/Offsec/Web_CTF/.claude/settings.json"),
        ("~/.codex/ctf-", "~/.claude/ctf-"),
        ("# $web-ctf", "# /web-ctf"),
        ("`AGENTS.md`", "`CLAUDE.md`"),
        ("AGENTS.md", "CLAUDE.md"),
    ])

    for path in (stage / "references").glob("*.md"):
        rewrite(path, [("~/.codex/skills/web-ctf", "~/.claude/skills/web-ctf")])

    rewrite(stage / "scripts" / "flaghook.py", [
        ('".codex", "ctf-', '".claude", "ctf-'),
        ("stderr back to Codex", "stderr back to Claude"),
        ("proves Codex", "proves Claude"),
    ])
    rewrite(stage / "scripts" / "oob.py", [
        ("~/.codex/skills/web-ctf", "~/.claude/skills/web-ctf"),
    ])
    rewrite(stage / "tests" / "test_regression.py", [
        ("~/.codex/ctf-", "~/.claude/ctf-"),
        ('".codex", "ctf-', '".claude", "ctf-'),
        ("stderr back to Codex", "stderr back to Claude"),
    ])


def manifest(root):
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ("__pycache__" in relative.parts or ".git" in relative.parts
                or path.name == ".DS_Store" or path.suffix in {".pyc", ".pyo"}):
            continue
        if path.is_file() and not path.is_symlink():
            result[str(relative)] = path.read_bytes()
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Refresh the managed Claude web-ctf mirror")
    parser.add_argument(
        "--target", type=Path,
        default=Path.home() / ".claude" / "skills" / "web-ctf")
    parser.add_argument(
        "--replace-symlink", action="store_true",
        help="allow the initial handoff from a symlink to a managed directory")
    parser.add_argument(
        "--check", action="store_true",
        help="compare the rendered mirror with the target without changing it")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    target = args.target.expanduser().absolute()
    if not (ROOT / ".git").is_dir():
        print("refusing to sync: run this script from the canonical git checkout", file=sys.stderr)
        return 2
    if target == ROOT.absolute() or (not target.is_symlink() and target.resolve() == ROOT.resolve()):
        print("refusing to replace the canonical checkout", file=sys.stderr)
        return 2
    if target.is_symlink() and not args.replace_symlink and not args.check:
        print("target is a symlink; use --replace-symlink for the initial handoff", file=sys.stderr)
        return 2
    if not target.is_symlink() and (target / ".git").exists():
        print("refusing to replace a git checkout at %s" % target, file=sys.stderr)
        return 2

    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".web-ctf-claude-stage-", dir=target.parent))
    backup = None
    try:
        render(stage)
        if args.check:
            if not target.exists() and not target.is_symlink():
                print("mirror is absent: %s" % target)
                return 1
            if manifest(stage) != manifest(target):
                print("mirror drift detected: %s" % target)
                return 1
            print("mirror matches canonical platform rendering: %s" % target)
            return 0

        if target.exists() or target.is_symlink():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = target.with_name(target.name + ".backup-" + stamp)
            if backup.exists() or backup.is_symlink():
                print("backup path already exists: %s" % backup, file=sys.stderr)
                return 2
            target.rename(backup)
        stage.rename(target)
        stage = None
        print("Claude mirror refreshed: %s" % target)
        if backup:
            print("previous install preserved: %s" % backup)
        return 0
    finally:
        if stage and stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    sys.exit(main())
