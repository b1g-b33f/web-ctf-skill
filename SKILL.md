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

| Observed signal | Read |
|---|---|
| JWT in response; session cookie; reset/forgot-password flow; login oracle | `references/auth-jwt.md` |
| Numeric/UUID ids in responses; `role`/`isAdmin`/`permissions` fields; 401/403 endpoints | `references/access-control.md` |
| Search/filter/id param; DB error on odd input; Mongo/mongoose in use | `references/injection.md` |
| Input echoed back into a rendered page or document | `references/ssti.md` |
| Filename or path parameter; file upload accepting a filename | `references/traversal-upload.md` |
| `/graphql` endpoint or introspection available | `references/graphql.md` |
| "Admin reviews your submission" workflow; URL/callback param | `references/xss-ssrf.md` |
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

# chain them
python ~/.claude/skills/ctf/scripts/jsmine.py recon/ | grep -oE '^\s+/\S+' \
  | python ~/.claude/skills/ctf/scripts/probe.py --base <target> --token "$TOKEN" --paths -
```

`probe.py` verdicts: `not-a-route` (matches the calibrated fallback body), `auth-required`, and `NO-AUTH LEAK` / `NO-AUTH DATA` — the second pair is broken access control, found deliberately rather than by accident.

A `PostToolUse` hook (`scripts/flaghook.py`, wired in `C:\Tools\.claude\settings.json`) scans every Bash result for flag patterns and logs hits to `~/.claude/ctf-flags.log`. It is a safety net, not a substitute for reading responses.

## Environment

Paths, tool invocations, and wordlists are in `C:\Tools\CLAUDE.md` — that's already in context; don't re-derive it. Exploit scripts go in `C:\Tools\Python\<challenge-name>\`. Recon output goes in `/c/Tools/CTF/<challenge-name>/recon/`.
