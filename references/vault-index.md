# Obsidian vault lookup — payloads for a named hypothesis

The vault is 1,160 notes / 522 MB. **Never crawl it and never `grep -r` the whole thing.** Use the file map below to open at most **one or two** specific notes.

## Trigger conditions — all three must hold

1. The visible attack surface is **enumerated** (endpoints probed with and without auth, JS mined, responses read)
2. You have a **named hypothesis** derived from the app's own behavior — not a category you haven't tested yet
3. You have already tried the payloads inlined in the relevant reference file and they failed

If you're reaching for this because you're out of *ideas* rather than out of *payloads*, stop — go back and re-read the responses you already have. That's where the answer usually is.

## The one-way rule

The vault supplies **payloads for a hypothesis the target already suggested.** It must never choose the target.

Query by observed signal ("the reset token looks like a hex timestamp", "this param accepts a nested object"), never by "what could be wrong with a flashcard app." Recall competes with observation: on Tanuki, a remembered homoglyph-collision technique pulled 16 wasted requests on a lab where nothing indicated username-based authorization. If a note describes a technique the target shows no evidence for, close it.

## File map

Base: `/c/Obsidian notes/Pentesting notes/02-AppSec/`

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
| WordPress target | `19-Hacking Wordpress/01-Hacking WordPress Cheat Sheet.md` |

Prior lab writeups (read only when the current target looks like a re-theme of one): `25-AppSec Boxes/`, `Bugforge NoSQL Injections/`

## If the map doesn't cover it

Search **filenames only**, scoped to one folder, and open at most two hits:

```bash
find "/c/Obsidian notes/Pentesting notes/02-AppSec/<folder>" -iname "*<keyword>*.md"
```

Only if that fails, content-search a single folder — never `02-AppSec/` as a whole:

```bash
grep -rli "<keyword>" "/c/Obsidian notes/Pentesting notes/02-AppSec/<folder>/"
```

Adapt every payload to the target's actual framework and language. A cheat sheet is a starting point, not a verdict.
