# Web recon — background scan, JS harvest, endpoint probing, fuzzing

## 1. Launch recon in the background

Feroxbuster and nuclei take 1–5 minutes. **Do not block.** Launch and go straight to auth — login/register endpoints are known guesses, not something recon must discover first.

```bash
mkdir -p /c/Tools/CTF/<challenge-name>/{recon,exploits,loot}
nohup bash /c/Tools/ctf-init.sh <target> <challenge-name> <platform> > /c/Tools/CTF/<challenge-name>/recon/_init.log 2>&1 &
```

Produces in `recon/`: `headers.txt`, `root.html`, `meta_hits.txt`, `quickcheck_hits.txt`, `ferox.txt`, `nuclei.txt` (htb only).

When you check back:
- `Server` / `X-Powered-By` → framework. **Treat as untrusted** — some labs rotate it per response to poison fingerprinting.
- `Set-Cookie` → cookie names, flags, session format
- Ferox hits that look like API routes, admin panels, upload dirs

**Build a running endpoint list** from `meta_hits.txt`, `quickcheck_hits.txt`, `ferox.txt` — every non-404 path is a candidate. Merge with JS findings. Do not let recon hits get dropped on the floor.

If the script reports a flag match already, record it and stop.

## 2. JS harvest

```bash
curl -sk <target>/ $AUTH_HEADER -o /c/Tools/CTF/<challenge-name>/recon/root_auth.html
```

Extract script srcs and download every bundle, then **use the script** — it already handles query-string routes, `.concat()` route building, minified axios aliases, and the router table:

```bash
python ~/.claude/skills/ctf/scripts/jsmine.py /c/Tools/CTF/<challenge-name>/recon/
```

The inline version below is the fallback if the script is unavailable:

```bash
python3 -c "
import re, glob
all_content = ''
for f in glob.glob('C:/Tools/CTF/<challenge-name>/recon/*.js'):
    with open(f, encoding='utf-8', errors='replace') as fh: all_content += fh.read() + '\n'

# API endpoints — note the trailing char class INCLUDES ? so query-string routes aren't missed
endpoints  = set(re.findall(r'[\"\'](/api/[a-zA-Z0-9/_\-?=&{}.]+)[\"\']', all_content))
endpoints |= set(re.findall(r'[\"\'](/v[0-9]+/[a-zA-Z0-9/_\-?=&{}.]+)[\"\']', all_content))
endpoints |= set(re.findall(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[\"\']([^\"\' ]+)', all_content))
# template-literal and .concat() routes
endpoints |= set(re.findall(r'\`(/[a-zA-Z0-9/_\-\$\{\}.]+)\`', all_content))
print('=== ENDPOINTS ==='); [print(e) for e in sorted(endpoints)]

print('\n=== SECRETS ===')
for s in set(re.findall(r'(?i)(?:password|secret|apikey|api_key|token|key)\s*[:=]\s*[\"\'\`]([^\"\'\`]{4,})[\"\'\`]', all_content)): print(s[:120])

print('\n=== COMMENTS ===')
for c in re.findall(r'//[^\n]{0,200}', all_content):
    if any(k in c.lower() for k in ['todo','fixme','password','admin','debug','flag','secret','hack','internal','bypass','note']): print(c[:200])

print('\n=== GRAPHQL ===')
for g in set(re.findall(r'(?:query|mutation|subscription)\s+\w+[^{]*\{', all_content)): print(g[:200])

print('\n=== OTHER ===')
for s in set(re.findall(r'[\"\']((?:admin|root|superuser|internal|debug|flag|/admin|/internal|/debug)[^\"\']{0,80})[\"\'\`]', all_content, re.I)): print(s[:150])
"
```

**A route with a query string is easy to miss.** On Tanuki, `/api/ai-log?format=json` was invisible to a `"/api/[\w/-]+"` pattern and it turned out to be the whole exploit. Always run a second pass for `?` and for `.concat(` / template-literal route building.

Also extract the client-side **router** table — it reveals pages (and therefore features) that the API list alone doesn't:
```bash
grep -oE 'path:"[^"]*"' recon/main.js | sort -u
```

Flag any interesting app content — user data, bios, descriptions, config values referencing endpoints. Follow those up first.

## 3. Probe every endpoint

Hit everything found, **with `$AUTH_HEADER` and again without it.** Use the script — it does the paired requests, calibrates the fallback body so jittered status codes can't fool it, saves every response, and scans headers as well as bodies:

```bash
python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" \
  --paths paths.txt --methods --out recon/probe
```

Manual equivalent:

```bash
curl -si <target>/api/<endpoint> $AUTH_HEADER -o recon/<endpoint-name>.json   # with auth
curl -si <target>/api/<endpoint>                                              # without
curl -si -X OPTIONS <target>/api/<endpoint> $AUTH_HEADER                       # allowed methods
```

The no-auth pass is not optional. On Tanuki the mailcatcher at `/api/email` needed no authentication at all — found by accident when a shell error sent an empty bearer token. Do it deliberately, for every endpoint.

Record per response: status, content-type, **all** body fields (especially ones the UI never shows), numeric ids, UUIDs, role strings, org ids, permission arrays, anything writable-looking.

Then:
```bash
grep -rE 'HTB\{|bug\{|flag\{' /c/Tools/CTF/<challenge-name>/recon/ 2>/dev/null
```

## 4. Fuzzing (only after exploitation is exhausted)

`ctf-init.sh` already ran ferox/nuclei — check `recon/ferox.txt` and `recon/nuclei.txt` for unexplored hits before re-scanning.

```bash
feroxbuster -u <target>/<subpath> -w /c/Tools/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  --depth 2 -t 20 --timeout 5 -q 2>&1 | head -100

python -m arjun -u <target>/api/<endpoint> -m GET -q 2>&1 | head -40
python -m arjun -u <target>/api/<endpoint> -m POST -q 2>&1 | head -40
```

**ffuf against a jittering target:** default matchers drop non-standard 2xx, so a lab that rewrites every status to 200/201/202 makes ffuf report *zero hits* while everything looks alive. Always:
```bash
ffuf -u <target>/api/FUZZ -w <wordlist> -mc all -fs <fallback-size> -t 8
```
Get `<fallback-size>` by requesting a guaranteed-bogus path first. Verify with a canary wordlist containing one known-good entry before trusting an empty result set — and never pipe ffuf through a grep that can swallow the results table.

If fuzzing finds new endpoints → back to probing.
