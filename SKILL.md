---
name: ctf
description: CTF and lab methodology for web, crypto, pwn, forensics and reversing challenges. Use when working an HTB box, a BugForge lab, or any CTF challenge — recon, auth, endpoint probing, exploitation, and flag extraction. Also use when the user gives a target URL/IP and asks to solve, test, or find the flag.
user-invocable: true
---

# /ctf — CTF challenge methodology

Arguments: `$ARGUMENTS` → `/ctf <platform> <target> <challenge-name> [username] [password]`

- `platform` — `htb` (default) or `bugforge`. Sets flag format: htb → `HTB{}`, bugforge → `bug{}`, else `flag{}`
- `target` — IP, IP:port, or URL (prepend `http://` if missing)
- `challenge-name` — sanitize to lowercase-hyphens; workspace is `/c/Tools/CTF/<challenge-name>/`

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

- **Use `curl -si` always.** Flags land in response *headers* (`X-Flag` on an otherwise-normal 403). Body-only checks make live endpoints look dead.
- **Never trust status codes for discovery.** Labs jitter them. Discriminate on body size + content-type. If a fuzzer reports nothing, check that it isn't filtering jittered 2xx (`ffuf` needs `-mc all` plus a size filter).

---

## Order of operations

1. **Source review** (htb only) — if `/c/Tools/Source Code/<name>/` exists, read it first; it replaces most guesswork → `references/source-review.md`
2. **Launch recon in background** — never block on it → `references/web-recon.md`
3. **Get an account** — login with given creds, else open registration → `references/auth-jwt.md`
4. **Harvest JS** — bundle → routes, params, secrets, comments → `references/web-recon.md`
5. **Probe every endpoint** — with auth *and* without auth, save every response to disk
6. **Route to an exploit reference** — see the signal table below
7. **Fuzz** — only after 5–6 are exhausted → `references/web-recon.md`
8. **Loop gate** — status table, pick the strongest untested vector, keep going

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

**The goal is the flag. Do not stop, do not ask for direction, do not summarise and wait** until the flag is in hand or every surface is marked exhausted.

---

## Harness scripts

Use these instead of retyping one-liners — they encode fixes for mistakes that have cost real time.

```bash
# mine a bundle: routes (incl. query strings + .concat), methods, router, secrets, comments
python ~/.claude/skills/ctf/scripts/jsmine.py /c/Tools/CTF/<name>/recon/

# probe every endpoint with auth AND without, auto-calibrating the not-found body
# so status-code jitter can't hide real routes; scans headers + bodies for flags
python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths paths.txt

# chain them — pipe the METHOD -> PATH section so POST routes are probed as POST
python ~/.claude/skills/ctf/scripts/jsmine.py recon/ \
  | sed -n '/METHOD -> PATH/,/ROUTER PATHS/p' \
  | python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths -

# stored-response SSRF as an arbitrary read: --sweep finds internal services and
# probes admin paths on each; or name paths directly
python ~/.claude/skills/ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" --sweep
python ~/.claude/skills/ctf/scripts/ssrfget.py --base <target> --token "$TOKEN" /admin/config
```

`probe.py` verdicts: `not-a-route` (matches the calibrated fallback body, per method, or a framework 404), `auth-required`, and `NO-AUTH LEAK` / `NO-AUTH DATA` — the second pair is broken access control, found deliberately rather than by accident.

**Always feed probe.py the METHOD → PATH section.** Probing a POST-only route with GET returns the SPA's index.html, which matches the 404 calibration exactly and reports `not-a-route` — that's how a GET-only probe would have hidden `POST /api/profile/avatar/import`, the entire CafeClub solve. `PUT`/`PATCH`/`DELETE` are skipped unless you pass `--write`.

A `PostToolUse` hook (`scripts/flaghook.py`, wired in `C:\Tools\.claude\settings.json`) scans every Bash result for flag patterns and logs hits to `~/.claude/ctf-flags.log`. It is a safety net, not a substitute for reading responses.

## Environment

Paths, tool invocations, and wordlists are in `C:\Tools\CLAUDE.md` — that's already in context; don't re-derive it. Exploit scripts go in `C:\Tools\Python\<challenge-name>\`. Recon output goes in `/c/Tools/CTF/<challenge-name>/recon/`.

Two shell rules that each cost a wasted round trip per solve:

- **`cd` does not persist between Bash calls.** Save the token once to an absolute
  path and read it absolutely every time — never rely on the working directory:
  ```bash
  echo "$TOKEN" > /c/Tools/CTF/<name>/token.txt
  T=$(cat /c/Tools/CTF/<name>/token.txt)     # every subsequent call
  ```
- **Git Bash mangles URL-paths in argv.** `/admin/config` becomes
  `C:/Program Files/Git/admin/config`. `ssrfget.py` un-mangles this itself; for
  anything else prefix `MSYS_NO_PATHCONV=1` — and note that flag does *not* fix the
  script path, so still invoke scripts as `C:/Users/.../script.py`.
