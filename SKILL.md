---
name: web-ctf
description: Web CTF and web-application lab methodology — recon, auth, endpoint probing, exploitation and flag extraction against a running web app, on any platform (HTB, BugForge, picoCTF, PortSwigger-style labs, self-hosted, or an unnamed target URL). Covers broken access control, injection, SSTI, path traversal and upload, SSRF, XSS with an admin bot, CORS, GraphQL, JWT and session flaws, business logic and race conditions, and anti-bot layers. Use when given a web target and asked to solve it, test it, or find the flag. Not for crypto, pwn, forensics or reversing.
user-invocable: true
---

# /web-ctf — web CTF & web-app lab methodology

For challenges against a **running web application**, on any platform. Not a crypto/pwn/forensics/
reversing playbook — if the target isn't a web app, this is the wrong file.

Arguments: `$ARGUMENTS` → `/web-ctf [platform] <target> [challenge-name] [username] [password]`

- `platform` — optional, any name. Sets the expected flag wrapper: `htb` → `HTB{}`,
  `bugforge` → `bug{}`, `picoctf` → `picoCTF{}`, otherwise `flag{}` — and whatever the brief
  states beats all of these. Unknown or omitted is fine; match on `\w+\{.*\}` and move on.
- `target` — URL, IP, or IP:port (prepend `http://` if missing)
- `challenge-name` — sanitize to lowercase-hyphens; workspace is `~/Tools/CTF/<challenge-name>/`

If args are missing, infer from the conversation. Don't stop to ask for a challenge name — derive one from the hostname.

---

## Core principle: app-first

**Login → read the JS → probe every endpoint → exploit what the app's own behavior points at.**

Scanners are step 7, not step 1. On GalaxyDash-011 a scanner-first run cost first blood by ~1 minute; the flag was in the first authenticated endpoint probe. Read the data the app returns before reaching for a tool.

**Exception — a named CVE or technique jumps the queue.** If the brief, a hint, or the user
names something specific (a CVE id, "wp2shell", a technique by name), search for and read
that writeup *before* probing. Don't re-derive the mechanism from a PoC script and don't
substitute a generic playbook. Details and the failure it's drawn from: `references/vault-index.md`.

Two rules that repeatedly decide solves:

- **Use `curl -si` always.** Flags land in response *headers* (`X-Flag` on an otherwise-normal 403). Body-only checks make live endpoints look dead — and so does status-only reading: a 401/403 is never a reason to skip the headers (`references/cors.md`). A **200 whose body is exactly what you expected** needs the same treatment — on Cheesy-007 the flag rode `X-Flag` on a normal-looking `/api/admin/stats` 200.
- **Never trust status codes for discovery.** Labs jitter them. Discriminate on body size + content-type. If a fuzzer reports nothing, check that it isn't filtering jittered 2xx (`ffuf` needs `-mc all` plus a size filter). If it reports *everything*, the filter didn't apply — `ffuf -fs` takes comma-separated values, **not ranges**. Prefer a body regex: `-fr 'could not be found'`.

---

## Order of operations

1. **Source review** — if the challenge ships source (a download, a repo, `~/Tools/Source Code/<name>/`), read it first; it replaces most guesswork → `references/source-review.md`
2. **Launch recon in a retained execution session** — let the tool yield while it runs; do not
   detach it with `nohup ... &` → `references/web-recon.md`. `ctf-init.sh`
   mines JS and calibrates the SPA-fallback signature *before* backgrounding anything else, so
   `recon/methods.txt` exists by step 3 — check it before hand-mining.
2b. **Identity check** (skip if you keep no notes vault) — as soon as the app names itself (page
   `<title>`, header, slug), search vault *filenames* for its shortest distinctive **stem**
   (`*cafe*`, not `*cafeclub*` — spacing varies):
   `find "${NOTES_VAULT:-$HOME/Obsidian/Pentesting notes/02-AppSec}" -iname "*<stem>*.md"`
   (env is not inherited between Bash calls — always inline the fallback). Hosted labs get
   re-provisioned with a new flag and host but the same bug (BugForge especially) — a prior
   writeup is the method, free. **Read the hit count first:** *one* note = the same challenge
   re-provisioned, method transfers. *Several* = an app **family**, and only the endpoint map
   and already-hardened list transfer, never the bug. One `find`, then move on
   → `references/vault-index.md`
3. **Get an account** — login with given creds, else open registration → `references/auth-jwt.md`
   **Hold a JWT? Run `jwtquick.py` foreground — ~1s, not a background job.** Crack + alg:none
   + forge + fire at a refusing route, one call. Never defer it → `references/auth-jwt.md` §2
4. **Read the seeded corpus — first authenticated action, before any probing.** If the app stores
   documents/files/notes/tickets, dump them all now, in the same parallel burst as steps 5–6;
   labs plant the brief in one of them (Vaultly-010 named its own vulnerable endpoint there).
   ```bash
   for i in $(seq 1 40); do echo "== $i"; curl -s -b jar "$BASE/api/files/$i/preview" | head -c 400; done
   ```
   Read the status boundary too: the one id returning **403 to an account that owns everything
   else** is the target object, free.
5. **Harvest JS again, authenticated** — apps sometimes bootstrap differently post-login; re-run
   `jsharvest.py` with `$AUTH_HEADER` now → `references/web-recon.md`
6. **Probe every endpoint** — with auth *and* without auth, save every response to disk
7. **Route to an exploit reference** — see the signal table below
8. **Fuzz** — only after 5–7 are exhausted → `references/web-recon.md`
9. **Loop gate** — status table, pick the strongest untested vector, keep going

Maintain `WORKLOG.md` in the challenge dir throughout: target, creds, `AUTH_HEADER`, endpoint list, **hypotheses killed** (with the evidence that killed them), live leads. This is what survives context compaction — write to it as you go, not at the end.

Track auth state for the whole session: `AUTH_HEADER` (`-H "Authorization: Bearer $TOKEN"` or `-b "session=<cookie>"`), `TOKEN`, `COOKIE`, `YOUR_ID`. Update on every new token.

---

## Signal → reference routing

Route on what the app actually did, not on a checklist sweep. Read **one** reference file when its signal fires.

**When several signals fire at once, break the tie this way:**

> A parameter that makes the server **act** — fetch a URL, render a template, read a
> path, deserialize, import a file — outranks a parameter that makes the server
> **compute** — price, quantity, points, balance, voucher.

Action params are rare and usually the planted bug; arithmetic surfaces are the most
commonly hardened thing in a commerce lab. On CafeClub the JS mine fired `logic-race`,
`xss-ssrf` and `json-type-confusion` simultaneously; the gift-card/points logic was
hardened at every point (amount allowlist, redeem not racy, balances checked server
side) and burned half the solve, while the one URL-taking endpoint was the answer.

| Observed signal | Read |
|---|---|
| JWT in response; session cookie; reset/forgot-password flow; login oracle | `references/auth-jwt.md` |
| Numeric/UUID ids in responses; `role`/`isAdmin`/`permissions` fields; 401/403 endpoints | `references/access-control.md` |
| Search/filter/id param; DB error on odd input; Mongo/mongoose in use | `references/injection.md` |
| Input echoed back into a rendered page or document | `references/ssti.md` |
| Filename or path parameter; file upload accepting a filename | `references/traversal-upload.md` |
| `/graphql` endpoint or introspection available | `references/graphql.md` |
| "Admin reviews your submission" workflow; **any param taking a URL** — import/fetch/callback/webhook/avatar-from-URL | `references/xss-ssrf.md` |
| `Access-Control-Allow-Origin` on any response; `Vary: Origin`; app documents a widget/embed/sandbox/connected-app story; a `403` route no role you hold can reach | `references/cors.md` |
| Payload must **execute** in client JS (DOM/reflected XSS, flag in DOM/localStorage); browser URL-parsing quirk; want a clean-tier client on an anti-bot lab | `references/browser.md` |
| Prices, quantities, vouchers, multi-step workflows, balances | `references/logic-race.md` |
| Any JSON body endpoint (cheap, no prerequisites) | `references/json-type-confusion.md` |
| Rotating `Server`/status codes; canary/injection headers; bot scoring | `references/anti-bot.md` |
| Out of payload ideas on a **named** hypothesis | `references/vault-index.md` |

After every attempt: check the response — headers included — for the flag pattern before moving on.

---

## Loop gate (no flag yet)

1. Update `WORKLOG.md` with what was tried and what each returned
2. Print the status table (surface / tested / result)
3. Pick the single most promising untested vector and pursue it — don't ask, go
4. Only if genuinely out of ideas on that vector: `references/vault-index.md`
5. Loop back to routing

**A negative from behind a tripped guard is *unknown*, not *killed*.** When an endpoint
leaks state in a validation error, it's tempting to farm that oracle by holding one field
deliberately wrong across a whole matrix of probes — but the guard producing the oracle
runs *first*, so every other variable in the matrix dies on the same check and reads as
inert. On cheesy-006 this hid the flag: `tip:-100` was probed in the very first sweep but
always against a deliberately-wrong `paid`, so it 400'd on the total check and looked
clamped. Paid correctly, a negative tip returns the flag as the order's `order_number`.

An error oracle is a **measurement** tool, not an **exploitation** tool. After farming one,
re-run every interesting variant with everything else valid so each request reaches the
deepest code path — and record oracle-run negatives in `WORKLOG.md` as untested, never as
hypotheses killed.

**Substantial `429` responses invalidate a scanner's negative conclusion, they don't confirm one.**
"No injection found" under heavy throttling means the check never actually ran. `sqlquick.py`
already self-aborts as inconclusive rather than reporting that as a negative — read sqlmap and
every other scanner's output the same way before crossing a vector off.

**A silent channel is an *unknown*, not a negative — and never worth more than 60s.** Waiting on
something you don't control (a bot visit, a queued job, a callback), an empty channel conflates
"never ran" with "wrong receiver." Own the receiver (`scripts/oob.py`), fire every transport at
once with an `alive` beacon first, and change the channel rather than extending the wait →
`references/xss-ssrf.md`.

**The goal is the flag. Do not stop, do not ask for direction, do not summarise and wait** until the flag is in hand or every surface is marked exhausted.

---

## Harness scripts

Use these instead of retyping one-liners — they encode fixes for mistakes that have cost real time.

```bash
# the whole cheap JWT surface, FOREGROUND: crack (JWT-specific list, then auto-escalates
# to rockyou on a miss — ~1s typical, ~40s worst case) + alg:none + forge + fire at a
# refusing route + scan headers/body for the flag. Run it the moment you hold a token.
python3 ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" --base <target> --test /api/admin/stats

# mine bundles and rendered HTML: routes (incl. query strings + .concat), form methods,
# comments, and narrative hint text (flavor-text sentences revealing the bug, e.g. a
# success-screen message that spells out a weak secret in plain English)
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py ~/Tools/CTF/<name>/recon/

# ctf-init.sh already ran this pre-auth; re-run authenticated, apps sometimes
# bootstrap different data post-login — writes recon/jsmine.txt + methods.txt, and
# explodes every source map's sourcesContent into recon/src/<path> (vendor excluded) —
# the same file tree DevTools' Sources panel shows you, reconstructed to disk. A file
# that "exists in the browser" but 404s/SPA-falls-back over direct HTTP is exactly this:
# embedded in the map, never actually served — check recon/src/ before probing it as a URL.
python3 ~/.claude/skills/web-ctf/scripts/jsharvest.py --base <target> --out recon/ \
  --cookie-file <curl-cookie-jar> --page /dashboard --crawl-pages

# probe every endpoint with auth AND without, auto-calibrating the not-found body
# so status-code jitter can't hide real routes; scans headers + bodies for flags
python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths paths.txt

# chain them — pipe the METHOD -> PATH section so POST routes are probed as POST
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ \
  | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths -

# low-volume SQLi fast-track — run this BEFORE sqlmap → references/injection.md §C
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/search?q=1" --token "$TOKEN"

# stored-response SSRF as an arbitrary read: --sweep finds internal services and
# probes admin paths on each; or name paths directly
python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep
python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" /admin/config

# OOB collector + public tunnel in one command. Run it (run_in_background) the moment a lab
# mentions an admin/operator/reviewer opening your submission — BEFORE the first payload.
python3 ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge-name>   # prints OOB_URL=
grep -a 'HIT\|FLAG' ~/Tools/CTF/<challenge-name>/oob.log
```

`probe.py` verdicts: `not-a-route` (calibrated fallback body, per method, or a framework 404),
`auth-required` (401/403, or identical denial with and without a token), `public-error` (identical
non-fallback error on a status *other* than 401/403 — a real route, but not a leak), and
`NO-AUTH LEAK` / `NO-AUTH DATA` — broken access control, found deliberately rather than by accident.

`jwtquick.py` tags each candidate `rejected` (still denies — a reworded message is not progress),
`POSSIBLE BYPASS` (the baseline denial is gone), or `FLAG` (unconditional success, any status).

**Always feed probe.py the METHOD → PATH section.** Probing a POST-only route with GET returns the SPA's index.html, which matches the 404 calibration exactly and reports `not-a-route` — that's how a GET-only probe would have hidden `POST /api/profile/avatar/import`, the entire CafeClub solve. `PUT`/`PATCH`/`DELETE` are skipped unless you pass `--write`.

A `PostToolUse` hook (`scripts/flaghook.py`, wired in `~/Tools/.claude/settings.json` — project settings resolve by walking *up* from cwd, so it must live at or above wherever the session actually started, never inside `$CTF_ROOT`) scans command results for flag patterns and logs hits to `~/.claude/ctf-flags.log`. It is a safety net, not a substitute for reading responses. Verify it with a fake flag after changing tool surfaces or restarting the app; a stale matcher fails silently.

## Environment

Paths, tool invocations, and wordlists are in `~/Tools/CLAUDE.md` — that's already in context; don't re-derive it. Exploit scripts go in `~/Tools/Python/<challenge-name>/`. Recon output goes in `~/Tools/CTF/<challenge-name>/recon/`.

Two shell rules that each cost a wasted round trip per solve:

- **`cd` does not persist between Bash calls.** Save the token once to an absolute
  path and read it absolutely every time — never rely on the working directory:
  ```bash
  echo "$TOKEN" > ~/Tools/CTF/<name>/token.txt
  T=$(cat ~/Tools/CTF/<name>/token.txt)     # every subsequent call
  ```
- **macOS has no bare `python` command.** Only `python3` exists (confirm with
  `which python3`) — every invocation in this skill, its references, and its scripts
  uses `python3` for exactly this reason. If you paste a one-liner from an external
  writeup that says `python`, translate it before running.
