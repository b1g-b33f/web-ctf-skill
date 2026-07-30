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

# Overridable so this works off the Windows layout without editing the script.
CTF_ROOT="${CTF_ROOT:-/c/Tools/CTF}"
SECLISTS="${SECLISTS:-/c/Tools/SecLists}"

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

# Write notes.md
cat > "$WORKDIR/notes.md" << EOF
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

echo "[*] Workspace scaffolded"
echo "[*] Firing recon in parallel..."
echo ""

# ── Job 1: HTTP headers + root page ──────────────────────────────────────────
(
  echo "[job:headers] starting"
  curl -sk -D "$RECON/headers.txt" "$TARGET/" -o "$RECON/root.html" \
    --max-time 15 --connect-timeout 8
  # Also try HTTPS if HTTP connects but looks wrong
  if grep -q "400 Bad Request\|plain HTTP" "$RECON/root.html" 2>/dev/null; then
    HTTPS_TARGET="${TARGET/http:/https:}"
    curl -sk -D "$RECON/headers_https.txt" "$HTTPS_TARGET/" -o "$RECON/root_https.html" \
      --max-time 15 --connect-timeout 8
    echo "[job:headers] also tried HTTPS"
  fi
  echo "[job:headers] done"
) &
JOB_HEADERS=$!

# ── Job 2: robots.txt, sitemap, common meta files ────────────────────────────
(
  echo "[job:meta] starting"
  for path in robots.txt sitemap.xml .well-known/security.txt crossdomain.xml \
               humans.txt security.txt favicon.ico; do
    code=$(curl -sk -o "$RECON/meta_$(echo $path | tr '/' '_')" \
      -w "%{http_code}" --max-time 8 "$TARGET/$path")
    [[ "$code" != "404" ]] && echo "$code $TARGET/$path" >> "$RECON/meta_hits.txt"
  done
  echo "[job:meta] done"
) &
JOB_META=$!

# ── Job 3: Common admin / API paths quick-check ──────────────────────────────
(
  echo "[job:quickcheck] starting"
  for path in admin api graphql api/graphql v1 v2 api/v1 api/v2 \
               swagger swagger-ui swagger.json api-docs openapi.json \
               console debug phpinfo.php .git/HEAD .env admin/login \
               api/admin dashboard panel management; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$TARGET/$path")
    [[ "$code" != "404" && "$code" != "000" ]] && \
      echo "$code $TARGET/$path" >> "$RECON/quickcheck_hits.txt"
  done
  echo "[job:quickcheck] done"
) &
JOB_QUICK=$!

# ── Job 4: feroxbuster directory brute-force ─────────────────────────────────
(
  echo "[job:ferox] starting"
  feroxbuster -u "$TARGET" \
    -w "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" \
    --depth 2 -t 20 --timeout 8 -q \
    -o "$RECON/ferox.txt" 2>/dev/null
  echo "[job:ferox] done — $(wc -l < "$RECON/ferox.txt" 2>/dev/null || echo 0) hits"
) &
JOB_FEROX=$!

# ── Job 5: nuclei (HTB only) ─────────────────────────────────────────────────
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
echo "[*] Jobs running: headers, meta, quickcheck, feroxbuster${JOB_NUCLEI:+, nuclei}"
echo "[*] Waiting for all jobs to finish..."
echo ""

wait $JOB_HEADERS $JOB_META $JOB_QUICK $JOB_FEROX ${JOB_NUCLEI:+$JOB_NUCLEI}

echo ""
echo "════════════════════════════════════════"
echo " RECON COMPLETE — $NAME"
echo "════════════════════════════════════════"
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "── Headers ─────────────────────────────"
cat "$RECON/headers.txt" 2>/dev/null | grep -E "^(HTTP|Server|X-Powered|Set-Cookie|Content-Type|Location|X-)" | head -20

echo ""
echo "── Meta file hits ───────────────────────"
cat "$RECON/meta_hits.txt" 2>/dev/null || echo "  none"

echo ""
echo "── Quick path hits ──────────────────────"
cat "$RECON/quickcheck_hits.txt" 2>/dev/null | sort -k1 -n || echo "  none"

echo ""
echo "── Feroxbuster (top 30) ─────────────────"
cat "$RECON/ferox.txt" 2>/dev/null | head -30 || echo "  none"

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
echo "[*] Now run: /ctf $PLATFORM $TARGET $NAME"
