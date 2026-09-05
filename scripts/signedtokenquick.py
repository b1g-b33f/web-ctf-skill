#!/usr/bin/env python3
"""Generate a bounded structural differential for a custom signed token.

This helper is intentionally offline: it writes token variants for replay through
the application's real consumer without guessing request placement or declaring a
bypass from decoding alone. Output is mode 0600 because it contains live tokens.

Exit codes: 0 variants written, 4 invalid arguments or token structure.
"""
import argparse
import json
import os
import sys


def changed_tag(tag):
    """Change a high-order character while preserving the tag's length."""
    replacement = "A" if tag[0] != "A" else "B"
    return replacement + tag[1:]


def build_variants(token, delimiter):
    parts = token.split(delimiter)
    if len(parts) != 2 or not all(parts):
        raise ValueError("known-valid token must have exactly two nonempty segments")
    payload, tag = parts
    return {
        "valid-control": token,
        "invalid-tag-control": payload + delimiter + changed_tag(tag),
        "missing-tag": payload,
        "empty-tag": payload + delimiter,
        "extra-segment": token + delimiter + "x",
    }


def read_token(args):
    if args.token_file:
        try:
            with open(args.token_file, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise ValueError("cannot read --token-file: %s" % exc) from exc
    return (args.token or "").strip()


def main():
    parser = argparse.ArgumentParser(
        description="Generate valid/invalid/missing/empty/extra-segment signed-token controls")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--token", help="known-valid two-segment token")
    source.add_argument("--token-file", help="file containing a known-valid token")
    parser.add_argument("--delimiter", default=".", help="segment delimiter (default: .)")
    parser.add_argument("--out", default="signedtokenquick_out", help="evidence directory")
    args = parser.parse_args()

    if not args.delimiter:
        print("INVALID ARGUMENT: delimiter must not be empty", file=sys.stderr)
        return 4
    try:
        token = read_token(args)
        variants = build_variants(token, args.delimiter)
    except ValueError as exc:
        print("INVALID ARGUMENT: %s" % exc, file=sys.stderr)
        return 4

    try:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "variants.json")
        record = {
            "delimiter": args.delimiter,
            "variant_order": list(variants),
            "variants": variants,
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        print("INVALID ARGUMENT: cannot write evidence: %s" % exc, file=sys.stderr)
        return 4

    print("wrote 5 structural variants to %s (mode 0600)" % path)
    print("replay in order: " + ", ".join(variants))
    print("a parse or state echo is only a lead; verify a protected objective independently")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
