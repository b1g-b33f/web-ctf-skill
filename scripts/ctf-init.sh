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
awk '
  /^=== COMMAND-INJECTION FIELD SIGNALS / { inside=1; next }
  /^=== / { inside=0 }
  inside && /^  / { sub(/^  /, ""); print }
' "$RECON/jsmine.txt" 2>/dev/null > "$RECON/cmdi-signals.txt"
if [[ -s "$RECON/cmdi-signals.txt" ]]; then
  echo "[!] Command-injection-shaped request fields mined — candidates, not findings:"
  sed 's/^/    /' "$RECON/cmdi-signals.txt"
  echo "[!] Reconstruct one known-valid request, then run cmdiquick.py against one explicit location."
fi
awk 'toupper($1) == "POST" && tolower($2) ~ "(^|/)graphql($|[?/])" { print $2 }' \
  "$RECON/methods.txt" 2>/dev/null | sort -u > "$RECON/graphql-endpoints.txt"
GRAPHQL_PATH=$(head -1 "$RECON/graphql-endpoints.txt" 2>/dev/null)
if [[ -n "$GRAPHQL_PATH" ]]; then
  echo "[!] GraphQL route mapped: $GRAPHQL_PATH"
  echo "[!] After auth, run graphqlquick.py in parallel with jwtquick.py:"
  echo "    python3 $SCRIPT_DIR/graphqlquick.py --url $TARGET$GRAPHQL_PATH --token \"\$TOKEN\" --id \"\$YOUR_ID\" --out $RECON/graphqlquick"
fi
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
    dev/inbox api/auth/inbox api/auth/magic-link api/auth/magic-link/request \
    api/auth/magic-link/verify api/auth/claim api/auth/activate api/auth/invite \
    api/profile/password \
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

# ── Job 4: SQLi triage on every path parameter ──────────────────────────────
# A REST id lives in the path, so there is no query param to name and a quote
# probe against it is meaningless: /api/products/1' returning "not found" is
# exactly what a bound integer does. Only a boolean differential separates the
# two, and it costs 3-5 requests per position. This is the cheapest question in
# the whole run and it is the one that has been skipped.
(
  echo "[job:sqlisweep] starting"
  if [[ -s "$RECON/methods.txt" ]]; then
    python3 "$SCRIPT_DIR/sqlquick.py" --sweep --base "$TARGET" \
      --methods "$RECON/methods.txt" --out "$RECON/sqlisweep_probe" --delay 0.25 \
      > "$RECON/sqlisweep.txt" 2>&1
    echo "[job:sqlisweep] done — $(match_count 'INJECTABLE' "$RECON/sqlisweep.txt") injectable, $(match_count 'UNTESTED' "$RECON/sqlisweep.txt") untested"
  else
    echo "no methods.txt — nothing to sweep" > "$RECON/sqlisweep.txt"
    echo "[job:sqlisweep] skipped — methods.txt empty"
  fi
) &
JOB_SQLI=$!

# ── Job 5: nuclei (skipped on bugforge) ─────────────────────────────────────────────────
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
echo "[*] Jobs running: meta, quickcheck, feroxbuster, sqlisweep${JOB_NUCLEI:+, nuclei}"
echo "[*] Waiting for all jobs to finish..."
echo ""

wait $JOB_META $JOB_QUICK $JOB_FEROX $JOB_SQLI ${JOB_NUCLEI:+$JOB_NUCLEI}

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

if [[ -s "$RECON/cmdi-signals.txt" ]]; then
  echo ""
  echo "── Command-injection field signals (recon/cmdi-signals.txt) ──"
  cat "$RECON/cmdi-signals.txt"
  echo "  Candidate only: do not spray malformed requests. Preserve a known-valid baseline."
  echo "  JSON: python3 $SCRIPT_DIR/cmdiquick.py --url <full-url> --method POST --json '<valid-body>' --field <field> --out $RECON/cmdiquick"
  echo "  Form: python3 $SCRIPT_DIR/cmdiquick.py --url <full-url> --method POST --form '<valid-body>' --field <field> --out $RECON/cmdiquick"
  echo "  Other: use --param, --path-marker, --inject-header, or --request-file/--marker."
fi

AUTH_LIFECYCLE_RE='magic|passwordless|inbox|outbox|claim|activat|enroll|invite|/api/(email|emails|mail)([/?[:space:]]|$)'
{
  grep -Ei "$AUTH_LIFECYCLE_RE" "$RECON/methods.txt" 2>/dev/null || true
  grep -Ei "$AUTH_LIFECYCLE_RE" "$RECON/quickcheck_hits.txt" 2>/dev/null || true
} | awk '!seen[$0]++' > "$RECON/auth-lifecycle-signals.txt"
if [[ -s "$RECON/auth-lifecycle-signals.txt" ]]; then
  echo ""
  echo "── Auth lifecycle / artifact fast track ─"
  cat "$RECON/auth-lifecycle-signals.txt"
  echo "  [!] Reserve at least one untouched seeded identity. Test a live token against"
  echo "      claim/register fields before redeeming it through the intended flow."
  echo "  python3 $SCRIPT_DIR/authquick.py --base $TARGET \\"
  echo "    --account '<email>=<name>' --password '<chosen-password>' \\"
  echo "    --register-field '<required-key>=<value>' --objective-path '<protected-path>'"
fi

if [[ -s "$RECON/graphql-endpoints.txt" ]]; then
  echo ""
  echo "── GraphQL post-auth fast track ─────────"
  while IFS= read -r path; do
    echo "python3 $SCRIPT_DIR/graphqlquick.py --url $TARGET$path --token \"\$TOKEN\" --id \"\$YOUR_ID\" --out $RECON/graphqlquick"
  done < "$RECON/graphql-endpoints.txt"
fi

echo ""
echo "── Path-parameter SQLi triage (recon/sqlisweep.txt) ─────"
if grep -q 'INJECTABLE' "$RECON/sqlisweep.txt" 2>/dev/null; then
  echo "  *** INJECTABLE PATH PARAMETER — this outranks everything else below ***"
  grep -E 'INJECTABLE|python3 ' "$RECON/sqlisweep.txt" 2>/dev/null
else
  grep -E 'no differential|UNTESTED|nothing to sweep|THROTTLED' "$RECON/sqlisweep.txt" 2>/dev/null \
    | head -12 || echo "  none"
  echo "  (GET path params only — query params, POST bodies and headers are NOT cleared)"
  if grep -q 'UNTESTED' "$RECON/sqlisweep.txt" 2>/dev/null; then
    echo ""
    echo "  [!] UNTESTED means NOT CLEARED. On an auth-gated API every id 401s before"
    echo "      login, so this sweep proves nothing until you re-run it with a token."
    echo "      Do it in the same burst as the authenticated jsharvest re-run:"
    echo "      python3 $SCRIPT_DIR/sqlquick.py --sweep --base $TARGET \\"
    echo "        --methods $RECON/methods.txt --token \"\$TOKEN\" --out $RECON/sqlisweep_auth"
  fi
fi

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
