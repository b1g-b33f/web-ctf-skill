#!/usr/bin/env bash
# ctf-init.sh — parallel web recon launcher
# Usage: ctf-init.sh <target> <challenge-name> [platform]
# Example: ctf-init.sh http://10.10.10.1:8080 my-challenge htb

TARGET="$1"
NAME="$2"
PLATFORM="${3:-htb}"

if [[ -z "$TARGET" || -z "$NAME" ]]; then
  echo "Usage: ctf-init.sh <target> <challenge-name> [platform]"
  echo "  target: IP, IP:port, or full URL"
  echo "  platform: htb (default) or bugforge"
  exit 1
fi

# Normalize target to URL
if [[ "$TARGET" != http* ]]; then
  TARGET="http://$TARGET"
fi
TARGET="${TARGET%/}"

# Sanitize name
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')

# Overridable so this works off any machine's layout without editing the script.
CTF_ROOT="${CTF_ROOT:-$HOME/Offsec/Web_CTF/CTF}"
SECLISTS="${SECLISTS:-/opt/security-tools/SecLists}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORKDIR="$CTF_ROOT/$NAME"
INSTANCE_ID=$(python3 - "$TARGET" <<'PY'
import re, sys
from urllib.parse import urlsplit
p = urlsplit(sys.argv[1])
host = (p.hostname or "target").lower()
if p.port:
    host += "-%d" % p.port
path = p.path.strip("/")
if path:
    host += "-" + path
print(re.sub(r"[^a-z0-9._-]+", "-", host).strip("-") or "target")
PY
)
INSTANCE_DIR="$WORKDIR/instances/$INSTANCE_ID"
RECON="$INSTANCE_DIR/recon"
EXPLOITS="$INSTANCE_DIR/exploits"
LOOT="$INSTANCE_DIR/loot"
AUTH_DIR="$INSTANCE_DIR/auth"
STATE_DIR="$WORKDIR/state"
CURRENT_STATE="$STATE_DIR/current.json"

line_count() {
  if [[ -f "$1" ]]; then
    awk 'END { print NR + 0 }' "$1"
  else
    echo 0
  fi
}

match_count() {
  local pattern="$1"
  local file="$2"
  local count
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  count=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
  echo "${count:-0}"
}

echo "[*] Target:    $TARGET"
echo "[*] Name:      $NAME"
echo "[*] Platform:  $PLATFORM"
echo "[*] Workspace: $WORKDIR"
echo "[*] Instance:  $INSTANCE_ID"
echo ""

# Scaffold
mkdir -p "$RECON" "$EXPLOITS" "$LOOT" "$AUTH_DIR" "$STATE_DIR"

PREVIOUS_TARGET=""
if [[ -f "$CURRENT_STATE" ]]; then
  PREVIOUS_TARGET=$(python3 - "$CURRENT_STATE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        print(json.load(fh).get("target", ""))
except (OSError, ValueError):
    pass
PY
)
fi

# A stable current pointer avoids mixing tokens/cookies/recon across reprovisions.
ln -sfn "instances/$INSTANCE_ID" "$WORKDIR/current"
for alias in recon exploits loot auth; do
  if [[ -L "$WORKDIR/$alias" || ! -e "$WORKDIR/$alias" ]]; then
    ln -sfn "current/$alias" "$WORKDIR/$alias"
  else
    echo "[!] Preserving legacy $WORKDIR/$alias; use $WORKDIR/current/$alias for this instance"
  fi
done

# Flag format
case "$PLATFORM" in
  bugforge) FLAG_FMT="bug{}" ;;
  *) FLAG_FMT="HTB{}" ;;
esac

# Initialize the durable worklog once. Rerunning recon must never erase live leads.
if [[ ! -f "$WORKDIR/WORKLOG.md" ]]; then
cat > "$WORKDIR/WORKLOG.md" << EOF
# $NAME

**Platform:** $PLATFORM
**Target:** $TARGET
**Flag format:** $FLAG_FMT
**Started:** $(date '+%Y-%m-%d %H:%M')

## Recon

## Auth

## Attack surface

## Exploitation log

## Flag

EOF
else
  echo "[*] Preserving existing $WORKDIR/WORKLOG.md"
fi

if [[ -n "$PREVIOUS_TARGET" && "$PREVIOUS_TARGET" != "$TARGET" ]]; then
cat >> "$WORKDIR/WORKLOG.md" << EOF

## Reprovisioned — $(date '+%Y-%m-%d %H:%M')

**Previous target:** $PREVIOUS_TARGET
**Current target:** $TARGET
**Current evidence:** instances/$INSTANCE_ID/

EOF
  echo "[*] Recorded target change without overwriting prior evidence"
fi

python3 - "$CURRENT_STATE" "$TARGET" "$INSTANCE_ID" "$PLATFORM" <<'PY'
import datetime, json, os, sys
dest, target, instance, platform = sys.argv[1:]
tmp = dest + ".tmp.%d" % os.getpid()
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump({
        "target": target,
        "instance": instance,
        "platform": platform,
        "updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "recon": "instances/%s/recon" % instance,
        "auth": "instances/%s/auth" % instance,
    }, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp, dest)
PY

echo "[*] Workspace scaffolded"
echo ""

# ── Step 1: root page + JS harvest — sequential, blocking, fast ─────────────
# Everything below this backgrounds. Doing this first means probe.py has a
# METHOD -> PATH list to work from before feroxbuster/nuclei even finish.
echo "[*] Fetching root page + harvesting client-side JS..."
curl -sk -D "$RECON/headers.txt" "$TARGET/" -o "$RECON/root.html" \
  --max-time 15 --connect-timeout 8
# Also try HTTPS if HTTP connects but looks wrong
if grep -q "400 Bad Request\|plain HTTP" "$RECON/root.html" 2>/dev/null; then
  HTTPS_TARGET="${TARGET/http:/https:}"
  curl -sk -D "$RECON/headers_https.txt" "$HTTPS_TARGET/" -o "$RECON/root_https.html" \
    --max-time 15 --connect-timeout 8
  echo "[*] also tried HTTPS"
fi
if ! python3 "$SCRIPT_DIR/jsharvest.py" --base "$TARGET" --out "$RECON" \
  --root "$RECON/root.html" --crawl-pages > "$RECON/jsharvest.log" 2>&1; then
  echo "[!] JS/HTML harvest failed; see recon/jsharvest.log"
  tail -5 "$RECON/jsharvest.log" 2>/dev/null
fi
METHOD_COUNT=$(line_count "$RECON/methods.txt")
ROUTE_COUNT=$(sed -n 's/^=== ROUTES (\([0-9][0-9]*\)) ===$/\1/p' "$RECON/jsmine.txt" 2>/dev/null | head -1)
ROUTE_COUNT="${ROUTE_COUNT:-0}"
echo "[*] JS harvest done — $METHOD_COUNT METHOD -> PATH entries ($RECON/methods.txt, $RECON/jsmine.txt)"
if [[ "$ROUTE_COUNT" -gt 0 && "$METHOD_COUNT" -eq 0 ]]; then
  echo "[!] HIGH PRIORITY: $ROUTE_COUNT route(s) found but zero HTTP methods mapped"
  echo "[!] POST-only endpoints remain unknown; quickcheck will run method fallback discovery"
fi
echo ""

echo "[*] Firing background recon in parallel..."
echo ""

# ── Job 1: meta files — SPA-fallback-aware ───────────────────────────────────
# quickrecon.py calibrates the SPA/framework fallback signature from a
# randomized nonexistent path first, so a lab whose unknown paths all answer
# 200 with the same shell doesn't get reported as seven hits.
(
  echo "[job:meta] starting"
  python3 "$SCRIPT_DIR/quickrecon.py" --base "$TARGET" --out "$RECON/meta_probe" \
    --hitfile "$RECON/meta_hits.txt" --paths \
    robots.txt sitemap.xml .well-known/security.txt crossdomain.xml \
    humans.txt security.txt favicon.ico \
    > "$RECON/meta_probe.log" 2>&1
  echo "[job:meta] done"
) &
JOB_META=$!

# ── Job 2: admin / protected API leaves — SPA-fallback-aware ─────────────────
# Direct nested guesses matter: a fallback/404 at /api prevents recursive
# fuzzers from ever reaching a protected leaf whose unauthenticated 401/403 is
# the only existence oracle.
(
  echo "[job:quickcheck] starting"
  python3 "$SCRIPT_DIR/quickrecon.py" --base "$TARGET" --out "$RECON/quickcheck_probe" \
    --hitfile "$RECON/quickcheck_hits.txt" --discover-methods \
    --methodfile "$RECON/methods.txt" --paths \
    admin api graphql api/graphql v1 v2 api/v1 api/v2 \
    swagger swagger-ui swagger.json api-docs openapi.json \
    console debug phpinfo.php .git/HEAD .env admin/login \
    api/admin dashboard panel management \
    api/me api/profile api/users api/search api/stocks api/stocks/search \
    api/items/search api/account api/account/reset api/account/verify \
    api/account/recover api/review-requests api/reset-password \
    api/password-reset api/flag api/admin/flag api/admin/stats api/admin/users \
    > "$RECON/quickcheck_probe.log" 2>&1
  echo "[job:quickcheck] done"
) &
JOB_QUICK=$!

# ── Job 3: feroxbuster directory brute-force ─────────────────────────────────
(
  echo "[job:ferox] starting"
  if feroxbuster -u "$TARGET" \
    -w "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" \
    --depth 2 -t 20 --timeout 8 -q \
    -o "$RECON/ferox.txt" > "$RECON/ferox.log" 2>&1; then
    echo "[job:ferox] done — $(match_count '^[0-9]{3} ' "$RECON/ferox.txt") hits"
  else
    echo "[job:ferox] failed — see recon/ferox.log"
    tail -5 "$RECON/ferox.log" 2>/dev/null
  fi
) &
JOB_FEROX=$!

# ── Job 4: nuclei (skipped on bugforge) ─────────────────────────────────────────────────
if [[ "$PLATFORM" != "bugforge" ]]; then
  (
    echo "[job:nuclei] starting"
    nuclei -u "$TARGET" -severity medium,high,critical \
      -timeout 5 -silent \
      -o "$RECON/nuclei.txt" 2>/dev/null
    echo "[job:nuclei] done — $(line_count "$RECON/nuclei.txt") findings"
  ) &
  JOB_NUCLEI=$!
else
  JOB_NUCLEI=""
  echo "[*] Skipping nuclei (bugforge)"
fi

# ── Wait and report ──────────────────────────────────────────────────────────
echo "[*] Jobs running: meta, quickcheck, feroxbuster${JOB_NUCLEI:+, nuclei}"
echo "[*] Waiting for all jobs to finish..."
echo ""

wait $JOB_META $JOB_QUICK $JOB_FEROX ${JOB_NUCLEI:+$JOB_NUCLEI}

echo ""
echo "════════════════════════════════════════"
echo " RECON COMPLETE — $NAME"
echo "════════════════════════════════════════"
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "── Headers ─────────────────────────────"
cat "$RECON/headers.txt" 2>/dev/null | grep -E "^(HTTP|Server|X-Powered|Set-Cookie|Content-Type|Location|X-)" | head -20

echo ""
echo "── JS harvest — METHOD -> PATH (recon/methods.txt) ─────"
cat "$RECON/methods.txt" 2>/dev/null || echo "  none"

echo ""
echo "── Meta file hits — status size content-type URL (SPA fallback suppressed) ──"
cat "$RECON/meta_hits.txt" 2>/dev/null || echo "  none"

echo ""
echo "── Quick path hits — status size content-type URL (SPA fallback suppressed) ──"
cat "$RECON/quickcheck_hits.txt" 2>/dev/null || echo "  none"

echo ""
echo "── Feroxbuster (top 30) ─────────────────"
grep -E '^[0-9]{3} ' "$RECON/ferox.txt" 2>/dev/null | head -30 || echo "  none"

if [[ -n "$JOB_NUCLEI" ]]; then
  echo ""
  echo "── Nuclei findings ──────────────────────"
  cat "$RECON/nuclei.txt" 2>/dev/null || echo "  none"
fi

echo ""
echo "── Flag check ───────────────────────────"
grep -rE 'HTB\{|bug\{|flag\{' "$RECON/" 2>/dev/null && echo "  FLAG FOUND ^^^" || echo "  none in recon output"

echo ""
echo "[*] All output saved to: $WORKDIR"
echo "[*] Current instance evidence: $INSTANCE_DIR"

# Emit an end-to-end hook sentinel. The PostToolUse hook handles this only after
# ctf-init exits, so the exact marker must be verified on the next tool call.
PREVIOUS_HOOK_SENTINEL=""
if [[ -f "$STATE_DIR/flaghook-expected.txt" ]]; then
  PREVIOUS_HOOK_SENTINEL=$(head -1 "$STATE_DIR/flaghook-expected.txt")
fi
if [[ -n "$PREVIOUS_HOOK_SENTINEL" ]]; then
  PREVIOUS_HOOK_VERIFIED=""
  for marker in "${CTF_FLAGHOOK_MARKER:-}" "$HOME/.codex/ctf-flaghook-ok" "$HOME/.claude/ctf-flaghook-ok"; do
    if [[ -n "$marker" && -f "$marker" ]] && grep -Fq "$PREVIOUS_HOOK_SENTINEL" "$marker" 2>/dev/null; then
      PREVIOUS_HOOK_VERIFIED="$marker"
    fi
  done
  if [[ -n "$PREVIOUS_HOOK_VERIFIED" ]]; then
    echo "[*] Previous flag-hook sentinel verified in $PREVIOUS_HOOK_VERIFIED"
  else
    echo "[!] Previous flag-hook sentinel was not observed; PostToolUse may be inactive"
  fi
fi
HOOK_NONCE=$(printf '%s' "$NAME-$TARGET-$$-$(date +%s)" | shasum -a 256 | cut -c1-16)
HOOK_SENTINEL="bug{CodexHarnessHookCheck_$HOOK_NONCE}"
printf '%s\n' "$HOOK_SENTINEL" > "$STATE_DIR/flaghook-expected.txt"
echo "[!] Flag hook activation for this run is pending; inspect responses manually until verified"
echo "[!] Next-call sentinel check: $HOOK_SENTINEL"
echo "[*] Now run: /web-ctf $PLATFORM $TARGET $NAME"
