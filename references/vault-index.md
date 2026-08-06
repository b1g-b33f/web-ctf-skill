# Notes-vault lookup — payloads for a named hypothesis

Optional step: this reads a personal vault of prior writeups (an Obsidian tree here, but any
folder of markdown works). Set `NOTES_VAULT` to its AppSec root; every command below falls back
to the author's default, and if the path doesn't exist the `find` simply returns nothing and you
carry on. **The file map further down is specific to that vault — treat it as a worked example of
how to index your own, not as paths you are expected to have.**

```bash
export NOTES_VAULT="/path/to/your/notes/02-AppSec"
```

A mature vault runs to a thousand-plus notes. **Never crawl it and never `grep -r` the whole thing.** Use the file map below to open at most **one or two** specific notes.

## Trigger conditions — all three must hold

1. The visible attack surface is **enumerated** (endpoints probed with and without auth, JS mined, responses read)
2. You have a **named hypothesis** derived from the app's own behavior — not a category you haven't tested yet
3. You have already tried the payloads inlined in the relevant reference file and they failed

If you're reaching for this because you're out of *ideas* rather than out of *payloads*, stop — go back and re-read the responses you already have. That's where the answer usually is.

## Exception: a **named** CVE or technique overrides all three

If the brief, a hint, or the user names something specific ("did you read the latest
wp2shell?", a CVE id, a technique by name), **go read that writeup first — before probing.**
This inverts the normal order and it is correct: on WordMess-001 the hint named
CVE-2026-63030 and the PoC was already on disk. ~20 rounds went into XSS, legacy handlers
and credential guessing; one web search returned the mechanism ("an error at index 0 shifts
every subsequent handler assignment") and the exploit landed in 2 requests.

- **"The payload doesn't execute" ≠ "the bug class isn't here."** Labs re-implement real
  CVEs in a different stack (a Grafana CVE re-themed; a PHP/MySQL PoC against Node/Express).
  Port the *primitive*, not the payload.
- **A PoC shows *what* to send; the advisory explains *why*.** You need the mechanism to
  port it. Read both.
- **A 403 on the target route is not a wall when bypassing that exact check IS the CVE.**
- **Watch for effects that are shifted rather than absent** — the WordMess giveaway was a
  403 landing on a *public* route one slot after the privileged one. Verdicts moved; they
  weren't skipped.

## The one-way rule

The vault supplies **payloads for a hypothesis the target already suggested.** It must never choose the target.

Query by observed signal ("the reset token looks like a hex timestamp", "this param accepts a nested object"), never by "what could be wrong with a flashcard app." Recall competes with observation: on Tanuki, a remembered homoglyph-collision technique pulled 16 wasted requests on a lab where nothing indicated username-based authorization. If a note describes a technique the target shows no evidence for, close it.

## App families — when the identity check returns *several* notes

One note for the app = the same challenge re-provisioned; the method transfers and you are
nearly done. **Several notes for the same app = a lab family**: one codebase, numbered variants,
a *different* planted bug in each. Platforms reuse a good app shell — Cheesy Does It alone has
-003, -004, -007, -008, -009, -010 and -011 spanning business logic, SQLi, reset flows, XSS,
IDOR and JWT.

In family mode the prior notes are still worth the one `find`, but for different reasons:

- **Take:** the endpoint map, request shapes, and — most valuable — the list of surfaces
  *already hardened*. Cheesy-004's `unit_price` tampering was dead in -007, killed by a
  server-side recalculation the note predicted exactly.
- **Do not take:** the bug. Matching the closest structural variant and expecting its bug is
  the trap. On Cheesy-007 the route set matched -004's three-step checkout precisely, so the
  payment flow got ~15 tool calls; the checkout *did* yield a real logic bug (unfloored negative
  `quantity`, 10 pizzas for $0.01) and it was **not** the flag, which sat behind a weak JWT
  secret the whole time.
- Prior bug classes for the family are mild **negative** evidence — this instance is a variant
  the vault doesn't have yet, so it is likelier to be a class the notes *don't* cover.

Practical consequence: in family mode, run the cheap class-independent checks (JWT crack,
no-auth probe of every route) **in parallel with** the app-specific hypothesis, never after it.

## File map

Base: `$NOTES_VAULT/`

| Hypothesis | Note |
|---|---|
| SQLi | `07-SQL Injection/01-SQL Injection Cheat sheet.md` |
| NoSQLi, nested filter params | `20-NoSQL Injection/01-NoSQL Cheat Sheet.md` |
| IDOR / BOLA / BFLA | `13-Broken Access Control/01-Broken Access Control Cheat Sheet.md` |
| Mass assignment, business logic, race | `21-Application Logic and State Abuse/01-Application Logic and State Abuse Cheat Sheet.md` |
| Auth bypass, reset flows, oracles | `12-Broken Authentication/01-Broken Authentication Cheat Sheet.md` |
| JWT / session / cookie | `17-Session Security/01-Session Security Cheat Sheet.md` |
| SSTI, deserialization, advanced web | `14-Web Attacks/01-Web Attacks Cheat Sheet.md` |
| LFI / RFI / path traversal | `15-File Inclusion/01-File Inclusion Cheat Sheet.md` |
| Upload filters and bypasses | `09-File Upload Attacks/01-File Upload Attack Cheat Sheet.md` |
| SSRF, XXE, server-side | `10-Server-side Attacks/01-Server-side Attacks Cheat Sheet.md` |
| XSS | `06-Cross-Site Scripting (XSS)/01-XSS Cheat Sheet.md` |
| Command injection | `08-Command Injections/01-Command Injection Cheat Sheet.md` |
| REST/GraphQL/API abuse | `18-Web Service & API Attacks/01-Web Service and API Cheat Sheet.md` |
| CORS, CSP, host header | `23-Headers and CSP/Headers and CSP.md` |
| Login brute forcing | `11-Brute Forcing/01-Login Brute Forcing Cheat Sheet.md` |
| Obfuscated JS bundle | `05-JavaScript Deobfuscation/01-JavaScript Deobfuscation Cheat Sheet.md` |
| Discovery / fuzzing gaps | `04-Information Gathering and Fuzzing - Web Edition/02-Web Fuzzing Cheat Sheet.md` |
| Payload blocked by a WAF | `WAF Bypass.md` |
| Chained / exotic techniques | `22-Advanced Web Attacks/01-Advanced Attacks Cheat Sheet.md` |
| **CSPT** (client-side path traversal) | `22-Advanced Web Attacks/Bugforge Advanced Web Attacks/01-CSPT Deep Dive.md` — see `## CSPT Lab - CSPT 1` for the full chain (CSPT → reviewer-bot email rewrite → password reset → takeover) |
| WordPress target | `19-Hacking Wordpress/01-Hacking WordPress Cheat Sheet.md` |

## Prior lab writeups — check these FIRST on a BugForge target

**Labs get re-provisioned with a fresh flag and hostname but the same bug.** On CafeClub
(2026-07-30) the vault already held `Cafe Club-009 SSRF to JWT Secrets Disclosure.md` from
2026-05-31: same endpoint, same internal service, *same `jwt_secret`* — only the flag and
host had rotated. The full method was on disk the whole time.

Every topic folder has a `Bugforge <topic>/` sibling next to its cheat sheet — 91 writeups
across 13 folders (`Bugforge Web Service and API/` 18, `Bugforge Application Logic and State
Abuse/` 11, `Bugforge SQL Injection/` 10, `Bugforge Server-side Attacks/` 9 …), plus
`25-AppSec Boxes/` for HTB.

**The identity check does not violate the one-way rule.** It is keyed on a name the *target
itself* supplies — the `<title>`, the app name in the page header, the challenge slug — so it
is observation-driven, not recall-driven. Run it as soon as you know what the app is called:

```bash
# filenames only, whole AppSec tree, one pass. Use the shortest distinctive STEM.
find "${NOTES_VAULT:-$HOME/Obsidian/Pentesting notes/02-AppSec}" -iname "*cafe*.md"
```

**Search the stem, not the full name.** Note filenames are inconsistently spaced: `*cafeclub*`
returns `CafeClub SQLi UNION.md`, `CafeClub Brute Force.md` and `CafeClub Race Conditon.md`
but **misses** `Cafe Club-009 SSRF to JWT Secrets Disclosure.md` — the one that mattered.
`*cafe*` returns all four. Truncate before any word boundary the writer might have spaced
or hyphenated, and accept a few extra hits.

**Expect a family, not a single note.** One app is usually re-skinned across several labs and
bug classes (CafeClub alone: SQLi, brute force, race condition, SSRF). Read the one whose
category matches the surface you're actually on — a prior *race condition* writeup for the
same app does not mean today's bug is a race.

A hit gives you the method, **not** the answer — the flag in an old writeup is dead. Confirm
the endpoint still behaves the same before trusting the rest, since labs do get patched
between provisionings.

## If the map doesn't cover it

Search **filenames only**, scoped to one folder, and open at most two hits:

```bash
find "${NOTES_VAULT:-$HOME/Obsidian/Pentesting notes/02-AppSec}/<folder>" -iname "*<keyword>*.md"
```

Only if that fails, content-search a single folder — never `02-AppSec/` as a whole:

```bash
grep -rli "<keyword>" "${NOTES_VAULT:-$HOME/Obsidian/Pentesting notes/02-AppSec}/<folder>/"
```

Adapt every payload to the target's actual framework and language. A cheat sheet is a starting point, not a verdict.
