---
name: web-ctf
description: Web CTF methodology for solving authorized running web-application labs from reconnaissance through exploitation and flag extraction. Use for a target URL or IP and requests to solve, test, or find the flag across access control, authentication, injection, traversal/upload, SSRF/XSS/CORS, GraphQL, JWT/session, business logic/races, and anti-bot layers. Not for crypto, pwn, forensics, or reversing.
---

# $web-ctf — web CTF & web-app lab methodology

Use for challenges against a running web application. Arguments are `[platform] <target>
[challenge-name] [username] [password]`; infer missing values from the conversation, prepend
`http://` when needed, and derive a challenge name from the hostname rather than stopping to ask.
The brief's flag wrapper wins; otherwise expect `HTB{}`, `bug{}`, `picoCTF{}`, or a generic
`\w+\{.*\}` match.

## Core principle: app-first

**Login → read the JS → probe every endpoint → exploit what the app's behavior points at.**

Read returned data and source before broad scanning. If source is supplied, review it first. If a
brief or hint names a CVE or technique, read that exact material before probing; otherwise do not
force a remembered app-family exploit onto a fresh instance (`references/vault-index.md`).

Two discovery rules are mandatory:

- Use `curl -si` and inspect headers and bodies after every request. A flag may ride a normal 200
  or a 401/403 header.
- Classify routes by body shape, length, and content type, not status alone. Calibrate SPA/framework
  fallbacks and treat throttled or guarded results as unknown, not negative (`references/web-recon.md`).

A successful JSON response is also schema evidence. If it adds a response-only placeholder such as
`caption:"{value}"`, resubmit that field, prove literal control, then test harmless interpolation
before high-value variables with `templatequick.py` (`references/ssti.md`).

## Order of operations

1. **Review supplied source** → `references/source-review.md`.
2. **Initialize retained recon** with `ctf-init.sh` → `references/web-recon.md`. Let the execution
   session yield while the script runs; do not detach it. Check `recon/methods.txt`,
   `recon/cmdi-signals.txt`, and `recon/lfi-signals.txt` before hand-mining. Signal files contain
   candidates, not findings.
3. **Identify the app once** if a notes vault exists. Search filenames by the shortest distinctive
   stem. One exact challenge note is a method lead; several family notes transfer only endpoint and
   hardened-surface clues. Open a family note only after a matching live signal fires
   (`references/vault-index.md`).
4. **Census auth state and get an account** → `references/auth-jwt.md`. Track identity, role,
   assurance/step-up state, cookies/tokens, and whether one-use artifacts were consumed. Reserve an
   untouched seeded/invited identity and run `authquick.py` before normal redemption. If privileged
   credentials are supplied, also register a low-privilege control identity
   (`references/access-control.md`). Run `jwtquick.py` immediately when a JWT is available and
   `graphqlquick.py` when GraphQL is already mapped.
5. **Read all seeded content first.** Dump documents, notes, tickets, files, and profiles before
   mutating state. A lone 403 among otherwise owned objects can identify the target object.
6. **Re-harvest after login** with `jsharvest.py`, then re-run the path-parameter SQLi sweep with the
   valid token. Pre-auth 401s are `UNTESTED`, not clearance (`references/injection.md`).
7. **Probe every discovered method and route** with auth, without auth, and as the low-privilege
   identity when available. Include write verbs deliberately and save responses.
8. **Route the strongest live signal** using the table below, read that one reference, and use its
   bounded helper where applicable.
9. **Fuzz only after app-led probing and live signals are exhausted** → `references/web-recon.md`.
10. **Run the loop gate** until the flag is recovered or every surface has evidence-backed status.

Maintain `WORKLOG.md` throughout: target, identities, auth state, endpoints, live leads, and killed
hypotheses with the evidence that killed them. Store sensitive state under `current/auth/` so a
reprovision cannot silently reuse stale credentials.

## Signal → reference routing

Read one reference when its signal fires. Server actions (fetch, render, read, deserialize, import)
usually outrank arithmetic surfaces; an observed interpolation primitive outranks a possible blind
callback. Test an unhardened compute parameter once, record the result, and move on if it yields no
objective impact.

| Observed signal | Read |
|---|---|
| JWT/session; reset, magic, activation, claim, invite, inbox, seeded account, or step-up flow | `references/auth-jwt.md` |
| Object identifiers; role/permission fields; 401/403 routes; privileged credentials; admin write actions | `references/access-control.md` |
| Command-shaped scalar field, system-backed action, process output/error, or `cmdi-signals.txt` hit | `references/command-injection.md` |
| Search/filter/id/path parameter, database error, or Mongo/mongoose usage | `references/injection.md` |
| Reflected/rendered input or controllable response-only placeholder field | `references/ssti.md` |
| Filename/path/template/download field, dynamic resource, upload filename, or `lfi-signals.txt` hit | `references/traversal-upload.md` |
| GraphQL endpoint or operation | `references/graphql.md` |
| Realtime event reaching an HTML sink; reviewer/admin-bot workflow; or URL-taking import/fetch/callback/webhook/avatar field | `references/xss-ssrf.md` |
| ACAO/Vary-Origin, widget/embed/sandbox story, or unreachable 403 objective | `references/cors.md` |
| `DOM XSS CANDIDATES` hit; `location`/`postMessage`/referrer/window-name data reaching a DOM sink; client-side execution, DOM/localStorage flag, URL-parsing quirk, or clean browser tier needed | `references/browser.md` |
| Prices, quantities, vouchers, balances, or multi-step workflows | `references/logic-race.md` |
| Any JSON body endpoint as a cheap independent check | `references/json-type-confusion.md` |
| Rotating server/status behavior, canary instructions, or bot scoring | `references/anti-bot.md` |
| No payload ideas remain for a named, live hypothesis | `references/vault-index.md` |

After every attempt, scan all response headers and bodies for the expected flag pattern.

## Loop gate (no flag yet)

1. Update `WORKLOG.md` and print a surface / tested / result table.
2. Pursue the strongest untested vector without waiting for user direction.
3. Re-open `references/vault-index.md` only when that named vector has no remaining evidence-led
   tests, then route again.

If enumerated routes add no flag under any identity and no reachable admin/debug surface remains,
assume the flag is at rest and prioritize a read primitive: SQLi → traversal → SSRF. Cheap boolean
differentials precede brute force.

Keep these result semantics:

- A test blocked by an earlier validation guard is **untested**. Re-run the interesting variant with
  every unrelated field valid so it reaches the deepest code path.
- Substantial 429s, gateway failures, or expired/invalid baselines make scanner output
  **inconclusive**.
- A silent bot/callback channel is **unknown**, not negative. Own the receiver with `oob.py`, send an
  `alive` beacon, try transports together, and change channel rather than waiting over 60 seconds
  (`references/xss-ssrf.md`).
- A JWT candidate is a bypass only when the original token genuinely denied the target and the
  candidate removes that denial; verify the objective route, not only `/me` or token introspection.

Do not stop at a progress summary. Stop when the flag is in hand or the status table shows every
surface exhausted with valid evidence.

## Harness helpers

Helpers encode bounded request budgets, baseline gates, evidence retention, and circuit breakers.
Read the routed reference before use, then run the helper's `--help` for exact arguments. Invoke
Python helpers as `python3 ~/.codex/skills/web-ctf/scripts/<name>.py`; for example:
`python3 ~/.codex/skills/web-ctf/scripts/lfiquick.py --help`.

| Need | Helper(s) | Guidance |
|---|---|---|
| Initialize/recon and mine JS | `ctf-init.sh`, `jsharvest.py`, `jsmine.py` | `references/web-recon.md` |
| Compare anonymous/auth/low-priv routes | `probe.py` | `references/access-control.md`, `references/web-recon.md` |
| First-use auth or JWT fast track | `authquick.py`, `jwtquick.py` | `references/auth-jwt.md` |
| SQL/NoSQL differential | `sqlquick.py`, `nosqlquick.py` | `references/injection.md` |
| Command execution | `cmdiquick.py` | `references/command-injection.md` |
| File read/traversal | `lfiquick.py` | `references/traversal-upload.md` |
| GraphQL reads | `graphqlquick.py` | `references/graphql.md` |
| Response-only interpolation | `templatequick.py` | `references/ssti.md` |
| Stored-response SSRF or external callback | `ssrfget.py`, `oob.py` | `references/xss-ssrf.md` |

For every helper, preserve a known-valid baseline and mutate one location at a time. Treat
`UNTESTED`, rate limits, gateway errors, and invalid baselines as inconclusive. `probe.py` findings
matter when calibrated behavior changes across identities; always supply method-qualified routes,
and use `--write` for privileged action prefixes.

`flaghook.py` is only a safety net. Its project-scoped configuration lives at
`~/Offsec/Web_CTF/.codex/config.toml`; verify hook activation after an app restart as documented in
`CONTRIBUTING.md`. If inactive, record that in `WORKLOG.md` and continue scanning every response
manually.

## Environment

The default workspace is `~/Offsec/Web_CTF/CTF/<challenge-name>/`; `ctf-init.sh` isolates each host
under `instances/<hostname>/` and points `current` at the active instance. Keep replayable exploits
with that challenge. Project `AGENTS.md` rules apply.

Shell state does not persist across execution calls, so write tokens/cookies to `current/auth/` and
reload them per call. Use `python3`, never assume a bare `python` executable.
