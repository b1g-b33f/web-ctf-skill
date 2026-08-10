# Web recon — background scan, JS harvest, endpoint probing, fuzzing

## 1. Launch recon in the background

Feroxbuster and nuclei take 1–5 minutes. **Do not block.** Launch and go straight to auth — login/register endpoints are known guesses, not something recon must discover first.

```bash
bash ~/.claude/skills/web-ctf/scripts/ctf-init.sh <target> <challenge-name> <platform>
```

Run that command in a retained execution session and let the tool yield a session id while
you continue with auth. Do not add `nohup` or shell `&`: command runners may terminate detached
children when the parent call returns. `ctf-init.sh` already parallelizes its slow jobs internally.

`ctf-init.sh` scaffolds the whole workspace itself. Each target is isolated under
`instances/<hostname>/` with its own `recon/`, `exploits/`, `loot/`, and `auth/`; an atomic
`current` pointer selects the active reprovision and fresh workspaces expose compatibility links
such as `recon/`. The durable `WORKLOG.md` remains in the challenge root and receives an immutable
target-change entry — no separate `mkdir` needed. That stub means
`WORKLOG.md` already exists by the time you write to it: `Read` it first, or the edit tool
will refuse the write as an unread file.

Before anything else backgrounds, `ctf-init.sh` fetches the root page and runs `jsharvest.py`
against it — see §2. Produces in `recon/`:

| File(s) | From | What it is |
|---|---|---|
| `headers.txt`, `root.html` | root fetch | the unauthenticated root page and its response headers |
| `<bundle>.js`/`.mjs`, `<bundle>.map`, `vendor/` | `jsharvest.py` | application bundles/maps; known vendor/runtime bundles are retained under `vendor/` and excluded from mining |
| `jsmine.txt` | `jsharvest.py` → `jsmine.py` | the full mined-routes report over everything downloaded |
| `methods.txt` | `jsharvest.py` | just the `METHOD -> PATH` lines, ready to pipe into `probe.py` |
| `dynamic-links.txt`, `source-provenance.tsv` | `jsharvest.py` | literal JS/template hrefs that were not requested, plus app/vendor source classification |
| `fallback.txt`, `fallback_post.txt` | `quickrecon.py` | per-method calibration responses used by the meta/quickcheck jobs |
| `meta_hits.txt`, `quickcheck_hits.txt` | `quickrecon.py` | real hits only, as `status size content-type URL`, including direct protected API-leaf guesses whose 401/403 existence oracle cannot be reached by recursive fuzzing; SPA fallback and framework-404s already suppressed |
| `ferox.txt`, `ferox.log`, `nuclei.txt` | feroxbuster/nuclei | Results stay in `ferox.txt`; live progress/errors stay in `ferox.log` so retained sessions remain readable. Nuclei is skipped on BugForge, whose labs are anti-bot instrumented. |

When you check back:
- `Server` / `X-Powered-By` → framework. **Treat as untrusted** — some labs rotate it per response to poison fingerprinting.
- `Set-Cookie` → cookie names, flags, session format
- Ferox hits that look like API routes, admin panels, upload dirs

**Build a running endpoint list** from `methods.txt`, `meta_hits.txt`, `quickcheck_hits.txt`, `ferox.txt` — every survivor is a candidate. Do not let recon hits get dropped on the floor.

If the script reports a flag match already, record it and stop.

## 2. JS harvest

`ctf-init.sh` already ran this once, pre-login, via `jsharvest.py`: it pulls every `<script src>`
off the root page (resolving absolute, protocol-relative, root-relative and ordinary relative URLs
the same way), downloads `.js`/`.mjs` bundles plus any non-inline `sourceMappingURL` they advertise,
mines the lot, and writes `recon/jsmine.txt` + `recon/methods.txt`. Check those two files before
hand-mining anything.

**Re-run it authenticated.** Some apps ship different bootstrap data once you're logged in — that's
the one thing the automatic pre-auth pass can't see:

```bash
python3 ~/.claude/skills/web-ctf/scripts/jsharvest.py --base <target> --out recon/ \
  --cookie-file <curl-cookie-jar> --page /dashboard --crawl-pages
```

This safely GET-crawls same-origin HTML pages from the dashboard, mines rendered form actions
as well as bundles, rejects non-2xx/error-page assets, and quarantines literal template/JS hrefs
such as `/jobs/${job.id}` in `dynamic-links.txt` instead of requesting them. Known vendor bundles
and package-namespace source maps (including Socket.IO maps without a `node_modules/` segment)
remain available as raw evidence under `vendor/` but are excluded from application mining. It overwrites
`jsmine.txt`/`methods.txt` with the union — nothing from the first pass is lost.

`jsmine.py` recognizes native `fetch(url, {method: ...})` and request helpers whose definitions
delegate to `fetch`/Axios, including qualified calls such as `FurHire.apiRequest(...)`. Its plain
`METHOD -> PATH` section remains probe-ready; `METHOD PROVENANCE` and `HIGH-VALUE ACTION ROUTES`
show where each method came from and rank recovery/reset/verify/search-style surfaces. If routes
exist but zero methods map, both harvest tools raise a high-priority warning and `ctf-init.sh`
runs action-shaped GET misses through route-specific `Allow` plus a calibrated `POST {}` fallback.
Never interpret that invariant as “GET only.”

**A component can "exist in the browser" and not exist on the server.** DevTools' Sources
panel reconstructs a full original-file tree (`components/AdminPanel.js`, `Dashboard.js`, ...)
purely client-side from a source map's `sources`/`sourcesContent` arrays — no per-file network
request happens. Hitting that path directly with curl gets the SPA fallback, indistinguishable
by status/size from a totally bogus URL; do not burn requests probing it as if it might be a
real route. `jsharvest.py` now explodes every map's `sourcesContent` into `recon/src/<path>`
automatically (vendor/`node_modules` excluded — typically 90%+ of a CRA/webpack map's `sources`
list), reconstructing the same tree DevTools shows you. **Read `recon/src/` directly** — it's
already the signal-only slice, worth checking before grepping the raw bundle at all.

Necromancer: the flag-gate's JWT secret (`pumpkin`) was spelled out verbatim in
`recon/src/components/AdminPanel.js` — a plain-English success-screen sentence ("The weak
signing key \"pumpkin\" has revealed its true nature"), sitting in the *minified bundle itself*,
no source map needed. It survived because minifiers don't touch string contents. It was missed
on the first pass because it's prose: not a `//` comment, not a `key:"value()"` pair, doesn't
start with a role keyword — every existing pattern assumes code shape. `jsmine.py`'s
`HINT TEXT` section now catches this class directly: a real JS-string-literal match (escaped
`\"`/`\'` treated as inside the string, not a terminator — a naive `[^"']*` class breaks on the
first apostrophe, which prose is full of) filtered to sentence-length strings containing a
vuln-narrative keyword (`weak `, `hardcod`, `backdoor`, `signing key`, `secret is`, ...).

To mine a directory of bundles you already have on disk directly — it already handles
query-string routes, `.concat()` route building, minified axios aliases, and the router table:

```bash
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py ~/Offsec/Web_CTF/CTF/<challenge-name>/recon/
```

The inline version below is the fallback if the script is unavailable:

```bash
python3 -c "
import re, glob
all_content = ''
for f in glob.glob('~/Offsec/Web_CTF/CTF/<challenge-name>/recon/*.js'):
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

**Also flag request paths built by string concatenation from `location.search` / `location.hash`** — that one pattern is the tell for client-side path traversal (CSPT):

```bash
grep -oE "(?:'|\")/api/[^'\"]*(?:'|\")\s*\+\s*\w+" recon/main.js | sort -u
grep -nE 'location\.(search|hash)|URLSearchParams' recon/main.js | head
```

When a path is concatenated from **more than one** attacker-controlled value, both may be injectable but only one reaches the target — it's segment arithmetic, so count before picking. Prefer the **last** interpolated parameter: nothing follows it, so the payload ends the URL cleanly, whereas an earlier one leaves the fixed suffix trailing into the query string and corrupting the value. Traversal that overshoots clamps at root instead of erroring, so a wrong count fails *silently*. The sink decides whether the gadget is worth anything — a bodyless `PUT` is inert unless the target endpoint reads query params, so check that (see §5) before writing it off. Full worked chain: `vault-index.md` → CSPT.

Flag any interesting app content — user data, bios, descriptions, config values referencing endpoints. Follow those up first.

## 3. Probe every endpoint

Hit everything found, **with `$AUTH_HEADER` and again without it.** Use the script — it does the paired requests, calibrates the fallback body so jittered status codes can't fool it, saves every response, and scans headers as well as bodies:

```bash
# feed it jsmine's METHOD -> PATH section, not just the path list: probing a
# POST-only route with GET returns the SPA index, which matches the 404
# calibration exactly and reports not-a-route
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ \
  | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" \
      --paths - --methods --out recon/probe
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
grep -rE 'HTB\{|bug\{|flag\{' ~/Offsec/Web_CTF/CTF/<challenge-name>/recon/ 2>/dev/null
```

## 4. Fuzzing (only after exploitation is exhausted)

`ctf-init.sh` already ran ferox/nuclei — check `recon/ferox.txt` and `recon/nuclei.txt` for unexplored hits before re-scanning.

```bash
feroxbuster -u <target>/<subpath> -w /opt/security-tools/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  --depth 2 -t 20 --timeout 5 -q 2>&1 | head -100

python3 -m arjun -u <target>/api/<endpoint> -m GET -q 2>&1 | head -40
python3 -m arjun -u <target>/api/<endpoint> -m POST -q 2>&1 | head -40
```

**ffuf against a jittering target:** default matchers drop non-standard 2xx, so a lab that rewrites every status to 200/201/202 makes ffuf report *zero hits* while everything looks alive. Always:
```bash
ffuf -u <target>/api/FUZZ -w <wordlist> -mc all -fs <fallback-size> -t 8
```
Get `<fallback-size>` by requesting a guaranteed-bogus path first. Verify with a canary wordlist containing one known-good entry before trusting an empty result set — and never pipe ffuf through a grep that can swallow the results table.

If fuzzing finds new endpoints → back to probing.

## 5. Where wordlist brute force structurally fails

A 39k-entry merged wordlist (SecLists `api-endpoints` + `objects` + `api-seen-in-wild` +
`actions-lowercase` + `raft-medium-directories`) against Deskly's `/api/` found **5 of 8**
real endpoints. Reading the client JS found 7 of 8 in two curl calls. The three misses were
not bad luck — each is a shape wordlists cannot reach:

| Blind spot | Why brute force misses it | Fix |
|---|---|---|
| **Hyphenated compounds** (`/api/review-requests`) | no SecLists API wordlist contains them | hand-written list: `review-requests`, `reset-password`, `password-reset`, `gift-cards` |
| **Nested under a 404-ing parent** (`/api/account/recover`) | `GET /api/account` 404s, so feroxbuster never recurses — recursion needs a non-404 parent | explicit nested guesses: `account/reset`, `account/verify`, `account/recover` |
| **PUT/PATCH-only routes** (`PUT /api/account`) | Express returns an identical 404 for a method mismatch, so a GET,POST scan filters the hit away | fuzz the method matrix |

```bash
# method matrix beats a 39k wordlist for this shape: ~15 names x 5 methods = ~75 requests
for n in me account profile settings users/me user preferences notifications; do
  for m in GET POST PUT PATCH DELETE; do
    printf '%-6s /api/%-16s ' "$m" "$n"
    curl -s -o /dev/null -w '%{http_code}\n' -X $m "<target>/api/$n" $AUTH_HEADER
  done
done
```

**Auth middleware is a free existence oracle.** Unauthenticated, `401` = the route exists,
`404` = it doesn't. You can map a protected API surface with no account at all.

**Probe `?param=` on PUT/PATCH, not just JSON bodies.** `PUT /api/account?email=x@y.com`
returned `{"message":"Account updated"}` with an empty body — that's what makes the endpoint
reachable from a bodyless cross-origin `fetch`, so it's a security-relevant property rather
than a trivium.

**Verify every fuzzer hit with curl.** ffuf `-s` attributed three Deskly hits to the GET run
when all three were POST-only — the fuzzer's own labeling was wrong.

Express fingerprint: unknown path → `404` + HTML `Cannot GET /path`; real route → JSON.
Clean discriminator (`probe.py` keys off it). Express routes are case-insensitive by default,
so `/api/Account` hits are noise, not findings.
