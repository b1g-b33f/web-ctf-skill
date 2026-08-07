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

# Sanitize name
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')

# Overridable so this works off any machine's layout without editing the script.
CTF_ROOT="${CTF_ROOT:-$HOME/Tools/CTF}"
SECLISTS="${SECLISTS:-$HOME/Tools/SecLists}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORKDIR="$CTF_ROOT/$NAME"
RECON="$WORKDIR/recon"
EXPLOITS="$WORKDIR/exploits"
LOOT="$WORKDIR/loot"

echo "[*] Target:    $TARGET"
echo "[*] Name:      $NAME"
echo "[*] Platform:  $PLATFORM"
echo "[*] Workspace: $WORKDIR"
echo ""

# Scaffold
mkdir -p "$RECON" "$EXPLOITS" "$LOOT"

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
echo "[*] JS harvest done — $(grep -c '^' "$RECON/methods.txt" 2>/dev/null || echo 0) METHOD -> PATH entries (recon/methods.txt, recon/jsmine.txt)"
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

# ── Job 2: admin / API quick paths — SPA-fallback-aware ──────────────────────
(
  echo "[job:quickcheck] starting"
  python3 "$SCRIPT_DIR/quickrecon.py" --base "$TARGET" --out "$RECON/quickcheck_probe" \
    --hitfile "$RECON/quickcheck_hits.txt" --paths \
    admin api graphql api/graphql v1 v2 api/v1 api/v2 \
    swagger swagger-ui swagger.json api-docs openapi.json \
    console debug phpinfo.php .git/HEAD .env admin/login \
    api/admin dashboard panel management \
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
    echo "[job:ferox] done — $(grep -cE '^[0-9]{3} ' "$RECON/ferox.txt" 2>/dev/null || echo 0) hits"
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
    echo "[job:nuclei] done — $(wc -l < "$RECON/nuclei.txt" 2>/dev/null || echo 0) findings"
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
echo "[*] Now run: /web-ctf $PLATFORM $TARGET $NAME"
