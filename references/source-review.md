# Source code review (HTB only)

If platform is `htb`, check for source before anything else:

```bash
ls "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null || echo "no source"
ls "/c/Tools/Source Code/" | grep -i "<challenge-name>"   # zip names don't always match
```

If source is found, read it immediately — it replaces most of the guesswork in recon/probing.

## What to extract

**1. File tree** — structure before individual files:
```bash
find "/c/Tools/Source Code/<challenge-name>" -type f | sort
```

**2. Entry point and routes** — `app.js`, `index.js`, `app.py`, `main.py`, `routes/`, `controllers/`:
- Every route definition → complete endpoint list, skip JS harvest for discovery
- HTTP methods per route → know exactly what's POST-able vs GET-only
- Any route that reads a file, runs a command, or renders a template → immediate SSTI/traversal/RCE candidate

**3. Auth and JWT config:**
```bash
grep -rE '(secret|SECRET|JWT_SECRET|SESSION_SECRET|key)\s*[=:]\s*["\x27][^"]{4,}' \
  "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null
```
A hardcoded JWT secret → go straight to forging, skip cracking.

**4. Flag location:**
```bash
grep -rE '(flag|FLAG|HTB\{)' "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null | grep -v '.min.js'
```
Note the exact route and condition that returns it.

**5. Dangerous sinks:**
```bash
grep -rE '(exec|eval|system|popen|render_template_string|subprocess|child_process|fs\.read|path\.join|file\.save|move_uploaded_file|shutil\.move)' \
  "/c/Tools/Source Code/<challenge-name>/" 2>/dev/null
```
`file.save` / `move_uploaded_file` with an unsanitized filename → write traversal (`traversal-upload.md`).

**6. Database schema** — `schema.sql`, `models/`, `migrations/`: table names, column names, seed data containing flags or admin creds.

**7. Dockerfile / docker-compose.yml** — flag path, env vars, exposed ports, base image.

## After reading source

- Update `AUTH_HEADER` state with any known secret/algorithm
- Build the endpoint list directly from routes
- Note the exact vuln class the source points to and go straight to that reference
- Record findings in `WORKLOG.md ## Attack surface`

**Check the schema for where the flag actually lives.** It is not always a dedicated `flag` column — on Tanuki it was stored in the admin user's `full_name`, visible in ordinary `/api/verify-token` output once authenticated as that user.
