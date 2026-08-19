---
name: web-ctf
description: Web CTF and web-application lab methodology — recon, auth, endpoint probing, exploitation and flag extraction against a running web app, on any platform (HTB, BugForge, picoCTF, PortSwigger-style labs, self-hosted, or an unnamed target URL). Covers broken access control, SQL/NoSQL/OS command injection, SSTI, path traversal and upload, SSRF, XSS with an admin bot, CORS, GraphQL, JWT and session flaws, business logic and race conditions, and anti-bot layers. Use when given a web target and asked to solve it, test it, or find the flag. Not for crypto, pwn, forensics or reversing.
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
- `challenge-name` — sanitize to lowercase-hyphens; workspace is `~/Offsec/Web_CTF/CTF/<challenge-name>/`

If args are missing, infer from the conversation. Don't stop to ask for a challenge name — derive one from the hostname.

---

## Core principle: app-first

**Login → read the JS → probe every endpoint → exploit what the app's own behavior points at.**

Scanners are step 7, not step 1. On GalaxyDash-011 a scanner-first run cost first blood by ~1 minute; the flag was in the first authenticated endpoint probe. Read the data the app returns before reaching for a tool.

**Treat a valid JSON response as input-schema evidence.** If it adds a top-level field the
request did not send and that field contains a placeholder such as `{value}`, round-trip that
field before broad payload testing. Prove client control, then harmless interpolation, then try
high-value variables with `templatequick.py` → `references/ssti.md`.

**Exception — a named CVE or technique jumps the queue.** If the brief, a hint, or the user
names something specific (a CVE id, "wp2shell", a technique by name), search for and read
that writeup *before* probing. Don't re-derive the mechanism from a PoC script and don't
substitute a generic playbook. Details and the failure it's drawn from: `references/vault-index.md`.

Two rules that repeatedly decide solves:

- **Use `curl -si` always.** Flags land in response *headers* (`X-Flag` on an otherwise-normal 403). Body-only checks make live endpoints look dead — and so does status-only reading: a 401/403 is never a reason to skip the headers (`references/cors.md`). A **200 whose body is exactly what you expected** needs the same treatment — on Cheesy-007 the flag rode `X-Flag` on a normal-looking `/api/admin/stats` 200.
- **Never trust status codes for discovery.** Labs jitter them. Discriminate on body size + content-type. If a fuzzer reports nothing, check that it isn't filtering jittered 2xx (`ffuf` needs `-mc all` plus a size filter). If it reports *everything*, the filter didn't apply — `ffuf -fs` takes comma-separated values, **not ranges**. Prefer a body regex: `-fr 'could not be found'`.

---

## Order of operations

1. **Source review** — if the challenge ships source (a download, a repo, `~/Offsec/Web_CTF/Source Code/<name>/`), read it first; it replaces most guesswork → `references/source-review.md`
2. **Launch recon in a retained execution session** — let the tool yield while it runs; do not
   detach it with `nohup ... &` → `references/web-recon.md`. `ctf-init.sh`
   mines JS and calibrates the SPA-fallback signature *before* backgrounding anything else, so
   `recon/methods.txt` exists by step 3 — check it before hand-mining. It also writes
   `recon/cmdi-signals.txt` when direct request construction exposes command-shaped JSON/query/
   form/path/header/multipart fields; these are candidates, not findings.
2b. **Identity check** (skip if you keep no notes vault) — as soon as the app names itself (page
   `<title>`, header, slug), search vault *filenames* for its shortest distinctive **stem**
   (`*cafe*`, not `*cafeclub*` — spacing varies):
   `find "${NOTES_VAULT:-$HOME/Obsidian/Pentesting notes/02-AppSec}" -iname "*<stem>*.md"`
   (env is not inherited between Bash calls — always inline the fallback). Hosted labs get
   re-provisioned with a new flag and host but the same bug (BugForge especially) — a prior
   writeup is the method, free. **Read the hit count first:** *one* note = the same challenge
   re-provisioned, method transfers. *Several* = an app **family**, and only the endpoint map
   and already-hardened list transfer, never the bug. If a live signal later fires, narrow those
   family filenames by that signal (for example, app stem + `graphql`) and open at most one exact
   match as a hypothesis. One initial `find`, then move on
   → `references/vault-index.md`
3. **Census auth state, then get an account** — login with given creds, else open registration
   → `references/auth-jwt.md`. If recon shows seeded/pre-provisioned users, first-use activation,
   magic/passwordless login, invitations, or a dev inbox, reserve one untouched identity and run
   `authquick.py` before normally redeeming any token. Redemption can burn the vulnerable state.
   **Given privileged creds? Register a throwaway account too, in the same burst.** Handing you
   `admin:admin` makes auth-vs-anonymous the wrong axis — as admin the vulnerable call succeeds
   (correct behaviour) and anonymously it 401s, so neither identity shows a thing. The creds exist
   to show you which functions to re-run as a nobody → `references/access-control.md` §C
   **Hold a JWT? Run `jwtquick.py` foreground — ~1s, not a background job.** Crack + alg:none
   + forge + fire at a refusing route, one call. Never defer it → `references/auth-jwt.md` §2
   If recon already mapped GraphQL, run `graphqlquick.py` in the same authenticated parallel burst;
   it is read-only, bounded, and stops on a flag, throttling, or gateway failure → `references/graphql.md`
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
5b. **Re-run the path-param SQLi sweep authenticated, same burst.** `ctf-init.sh` swept
   pre-token, so on a gated API every id 401'd and every position read `UNTESTED` — *not cleared*.
   ~4 requests each; the only check that catches a concatenated REST id, which no quote probe
   ever will → `references/injection.md`
   ```bash
   python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --sweep --base <target> \
     --methods recon/methods.txt --token "$TOKEN" --out recon/sqlisweep_auth
   ```
6. **Probe every endpoint** — with auth, *without* auth, and as the throwaway low-priv account
   if you hold privileged creds; save every response to disk
7. **Route to an exploit reference** — see the signal table below
8. **Fuzz** — only after 5–7 are exhausted → `references/web-recon.md`
9. **Loop gate** — status table, pick the strongest untested vector, keep going

Maintain `WORKLOG.md` in the challenge dir throughout: target, creds, `AUTH_HEADER`, endpoint list, **hypotheses killed** (with the evidence that killed them), live leads. This is what survives context compaction — write to it as you go, not at the end.

Track auth state for the whole session: `AUTH_HEADER` (`-H "Authorization: Bearer $TOKEN"` or `-b "session=<cookie>"`), `TOKEN`, `COOKIE`, `YOUR_ID`, account state, artifact-consumption state, and session assurance. Update on every transition; keep sensitive helper state under `current/auth/`.

---

## Signal → reference routing

Route on what the app actually did, not on a checklist sweep. Read **one** reference file when its signal fires.

**When several signals fire at once, break the tie this way:**

> A parameter that makes the server **act** — fetch a URL, render a template, read a
> path, deserialize, import a file — outranks a parameter that makes the server
> **compute** — price, quantity, points, balance, voucher.

An **observed interpolation control** outranks a merely possible blind action. A response-only
`caption:"{value}"` that renders after being resubmitted is a live read primitive; run its bounded
template fast track before waiting on a webhook or callback.

Action params are rare and usually the planted bug; arithmetic surfaces are the most
commonly hardened thing in a commerce lab. On CafeClub the JS mine fired `logic-race`,
`xss-ssrf` and `json-type-confusion` simultaneously; the gift-card/points logic was
hardened at every point (amount allowlist, redeem not racy, balances checked server
side) and burned half the solve, while the one URL-taking endpoint was the answer.

**An *unhardened* compute param that yields no flag is still a decoy** — worse, because
success feels like progress. A later CafeClub took an unbounded negative `points_to_use`
(real flaw, infinite balance, worth nothing; the flag was in the DB). Exploiting an
arithmetic surface once *is* the experiment: impossible number and no flag = negative
result. Record it and leave, don't re-derive bigger versions of the same number.

| Observed signal | Read |
|---|---|
| JWT/session cookie; reset flow/login oracle; magic/passwordless login; activation/claim/invite; public inbox/outbox; seeded account; first-use or step-up gate | `references/auth-jwt.md` |
| Numeric/UUID ids in responses; `role`/`isAdmin`/`permissions` fields; 401/403 endpoints; **privileged creds handed to you**; an admin panel whose buttons fire write verbs | `references/access-control.md` |
| Scalar request field shaped like `command`/`cmd`/`args`/`options`/`flags`/`host`/`ip`/`domain`/`filename`/`path`/`binary`/`tool`; system-backed diagnostic/conversion/export/archive feature; process output or shell errors; `recon/cmdi-signals.txt` non-empty | `references/command-injection.md` |
| Search/filter/id param; **any `{...}` path segment — a REST id is an injection point, and a quote proves nothing there**; DB error on odd input; Mongo/mongoose in use | `references/injection.md` |
| Input echoed into a rendered page/document; **a valid JSON response adds a response-only placeholder field such as `caption:"{value}"`** | `references/ssti.md` |
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

**No flag in any response ⇒ the flag is at rest ⇒ switch to a read primitive.** When all three
are true in `WORKLOG.md` — (1) routes enumerated and fuzzing adds none, (2) no flag in any header
or body under any identity you hold, (3) no admin/debug surface to escalate into — the app will
never *hand* you the flag: it's a DB row, a file, an env var. Stop auditing behaviour, go get a
read (SQLi → traversal → SSRF). Past that point you're searching a space already proven empty.
On CafeClub all three held at ~15 minutes; the run spent 30 more on mass assignment, JWT forgery,
prototype pollution, a race and a 50k brute force, while the flag sat in `users.password`.

**Expensive negatives go last, after a read primitive is ruled out.** Order by information per
second: a boolean differential on an untested param is ~4 requests and decides a vector; a 50k
brute force decides nothing and teaches you nothing you can write in the status table.

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
# bounded first-use/auth-artifact fast track. Run before normal token redemption;
# generated auth payloads stay scalar and evidence lands under current/auth/.
python3 ~/.claude/skills/web-ctf/scripts/authquick.py --base <target> \
  --account '<email>=<name>' --password '<chosen-password>' \
  --register-field '<required-key>=<value>' --objective-path '<protected-path>'

# the whole cheap JWT surface, FOREGROUND: crack (JWT-specific list, then auto-escalates
# to rockyou on a miss — ~1s typical, ~40s worst case) + alg:none + forge + fire at a
# refusing route + scan headers/body for the flag. Run it the moment you hold a token.
python3 ~/.claude/skills/web-ctf/scripts/jwtquick.py --token "$TOKEN" --base <target> --test /api/admin/stats

# mine bundles/rendered HTML: direct calls, fetch(url,{method}), discovered request
# wrappers, forms, provenance, full GraphQL operations/identity signals, ranked action routes,
# comments, and narrative hints
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py ~/Offsec/Web_CTF/CTF/<name>/recon/

# a command-shaped field is a lead, not proof. Preserve one known-valid request and
# mutate exactly one JSON/query/form/path/header/cookie/raw-body/raw-request location.
# Auto mode distinguishes POSIX, cmd.exe, and PowerShell and reuses the winning
# separator/quote context; timing and verified OOB callbacks are explicit options.
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url "<target>/api/roll" --method POST \
  --json '{"dice":[{"type":"d100","count":1}],"rollOptions":"none"}' \
  --field rollOptions --out recon/cmdiquick

# bounded read-only GraphQL fast track: anonymous/auth reachability, introspection, then
# validation-error schema oracle + high-value Query fields when introspection is disabled
python3 ~/.claude/skills/web-ctf/scripts/graphqlquick.py \
  --url <target>/api/graphql --token "$TOKEN" --id "$YOUR_ID" --out recon/graphqlquick

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

# three identities at once. Register a throwaway account and pass it as --lowpriv-token
# whenever you hold privileged creds: a route the low-priv account reaches that its
# siblings refuse is a missing function-level guard → references/access-control.md §C
python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> \
  --token "$TOKEN" --lowpriv-token "$LOWPRIV_TOKEN" --write --paths paths.txt

# chain them — pipe the METHOD -> PATH section so POST routes are probed as POST
python3 ~/.claude/skills/web-ctf/scripts/jsmine.py recon/ \
  | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python3 ~/.claude/skills/web-ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths -

# low-volume SQLi fast-track — run this BEFORE sqlmap → references/injection.md §C
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/search?q=1" --token "$TOKEN"

# a valid evaluator/renderer response adds a top-level field like caption:"{value}":
# prove the response-only field is controllable, then try harmless and high-value variables
python3 ~/.claude/skills/web-ctf/scripts/templatequick.py \
  --url "<target>/api/forecast/indicator" --token "$TOKEN" \
  --data '{"stock_id":1,"formula":"10*10"}' --out recon/templatequick

# a REST id in the PATH is injectable too, and --param cannot name it. ctf-init.sh
# already swept these pre-auth; on an auth-gated API every id 401s then, so the sweep
# reports UNTESTED and proves nothing until you re-run it WITH A TOKEN. Do that in the
# same authenticated burst as jsharvest (~4 requests per position).
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --sweep --base <target> \
  --methods recon/methods.txt --token "$TOKEN" --out recon/sqlisweep_auth
# then confirm + dump the position it names (--path-param injects the last segment):
python3 ~/.claude/skills/web-ctf/scripts/sqlquick.py --url "<target>/api/products/1" \
  --path-param --token "$TOKEN"

# guarded NoSQL operator oracle — explicit endpoint/field allowlist, paired guards,
# query-shape mapping, $gt enumeration, and variable-length printable extraction.
# Login/register/password fields are refused unless --dangerous-auth is explicit.
python3 ~/.claude/skills/web-ctf/scripts/nosqlquick.py \
  --url "<target>/api/account/recover" --field email --field backupCode \
  --baseline email=none@example.test --baseline backupCode=invalid \
  --success-json status=verified --probe --map-query-shape

# stored-response SSRF as an arbitrary read: --sweep finds internal services and
# probes admin paths on each; or name paths directly
python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep
python3 ~/.claude/skills/web-ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" /admin/config

# OOB collector + public tunnel in one command. Run it (run_in_background) the moment a lab
# mentions an admin/operator/reviewer opening your submission — BEFORE the first payload.
python3 ~/.claude/skills/web-ctf/scripts/oob.py --name <challenge-name>   # prints OOB_URL=
grep -a 'HIT\|FLAG' ~/Offsec/Web_CTF/CTF/<challenge-name>/oob.log
```

`probe.py` verdicts: `not-a-route` (calibrated fallback body, per method, or a framework 404),
`auth-required` (401/403, or identical denial with and without a token), `public-error` (identical
non-fallback error on a status *other* than 401/403 — a real route, but not a leak),
`public-endpoint` (a generic login/register/reset envelope expected before authentication),
`NO-AUTH LEAK` / `NO-AUTH DATA` — broken access control, found deliberately rather than by accident —
and, with `--lowpriv-token`, `PRIVILEGE GAP` (a second authenticated identity reached a route its
siblings refuse it). With `--methods`, `Allow` is route-specific; `CORS policy` is only the server's
advertised cross-origin verb policy and does not prove that handlers exist for those verbs.

`jwtquick.py` tags each candidate `rejected` (still denies — a reworded message is not progress),
`POSSIBLE BYPASS` (the baseline denial is gone), or `FLAG` (unconditional success, any status).

**Always feed probe.py the METHOD → PATH section.** Probing a POST-only route with GET returns the SPA's index.html, which matches the 404 calibration exactly and reports `not-a-route` — that's how a GET-only probe would have hidden `POST /api/profile/avatar/import`, the entire CafeClub solve. `PUT`/`PATCH`/`DELETE` are skipped unless you pass `--write` — **always pass it on an `/admin/` prefix**, because the guard a developer forgets is on the verb behind a button, not the one they visit in a browser (Ottergram: `DELETE /api/admin/posts/:id` was the only unguarded route in its group).

**Routes > 0 with methods = 0 is a harness alarm, not an empty result.** `jsmine.py` and
`jsharvest.py` warn on that invariant; `ctf-init.sh` then runs action-shaped routes through
route-specific `Allow` and calibrated `POST {}` fallback discovery. Literal `${...}` hrefs are
saved to `dynamic-links.txt`, never requested, and known vendor bundles/maps are retained under
`recon/vendor/` but excluded from mining.

A `PostToolUse` hook (`scripts/flaghook.py`, wired in `~/Offsec/Web_CTF/.claude/settings.json` — placement rules are in CLAUDE.md) scans command results for flag patterns and logs hits to `~/.claude/ctf-flags.log`. It is a safety net, not a substitute for reading responses.

**Verify hook activation end-to-end after every app restart or tool-surface change.** In one tool call, print a unique `bug{CodexHarnessHookCheck_<nonce>}` marker; in the next tool call, verify that exact marker landed in `~/.claude/ctf-flaghook-ok`. The hook treats this marker as a health check, not a real flag, so it never touches `ctf-flags.log`. Invoking `flaghook.py` directly proves only the script is correct, not that `PostToolUse` actually fires — a stale or untrusted hook config fails silently. If the sentinel is absent, record `flag hook inactive` in `WORKLOG.md` and keep scanning every response manually.

## Environment

Paths, tool invocations, and wordlists are in `~/Offsec/Web_CTF/CLAUDE.md` — that's already in context; don't re-derive it. Exploit scripts go in `~/Offsec/Web_CTF/Python/<challenge-name>/`. `ctf-init.sh` stores each target under `~/Offsec/Web_CTF/CTF/<challenge-name>/instances/<hostname>/` and atomically repoints `current`; fresh workspaces also expose compatibility links such as `<challenge-name>/recon/`. Use `current/auth/` for tokens and cookie jars so reprovisioned instances cannot silently reuse stale credentials.

CLAUDE.md's shell gotchas (`cd` not persisting, no bare `python`) bite hardest here.
For `cd`: a `$TOKEN` set in one Bash call is gone in the next unless it's written to a
file — `echo "$TOKEN" > ~/Offsec/Web_CTF/CTF/<name>/token.txt`, then `T=$(cat ...)` per call.
For `python`: every invocation in this skill, its references, and its scripts uses
`python3` — translate any pasted one-liner that says bare `python` before running it.
