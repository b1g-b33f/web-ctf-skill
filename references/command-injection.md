# OS command injection

Read this when JavaScript, HTML, or a live request exposes a scalar field shaped like
`command`, `cmd`, `args`, `options`, `flags`, `host`, `ip`, `domain`, `filename`, `path`,
`binary`, `tool`, or `target`; when a feature plausibly shells out (diagnostics, conversion,
export, archive, media, dice/formula engines); or when a response adds process output or shell
errors. A `COMMAND-INJECTION FIELD SIGNALS` line from `jsmine.py` is a prioritization lead, not
a vulnerability finding.

## Fast track: preserve one valid request

`cmdiquick.py` mutates exactly one explicit location while leaving the rest of a known-valid
request intact. Its default chain is response-only: baseline, POSIX `;id`, `;whoami` after strong
identity output, a paired execution-marker/reflection control, then a bounded separator fallback.
It scans response headers and bodies for flags and saves every probe to `probes.jsonl`.

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

# Path marker: the marker is replaced with the seed for the valid baseline
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/tools/ping/*' --path-marker '*' --seed 127.0.0.1 \
  --out recon/cmdiquick

# Header
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target/process' --header 'X-Diagnostic-Host: 127.0.0.1' \
  --inject-header X-Diagnostic-Host --out recon/cmdiquick
```

Use a raw Burp-style request for multipart fields/filenames, cookies, duplicate parameters,
nonstandard encodings, or any request whose byte shape matters. Put a unique marker at the one
location to mutate; `--seed` is substituted for the valid baseline. The helper preserves the raw
method, target, content type, boundary, headers, and body while recalculating transport headers.

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py \
  --url 'https://target' --request-file request.txt \
  --marker CMDI_INJECT --seed report.txt --out recon/cmdiquick
```

Authentication is supported through `--token`, `--cookie`, and repeatable `--header`. Those
header values are redacted in the request evidence. Run the same known-valid request under every
identity that can reach the feature; an anonymous 401 does not clear an authenticated field.

## What counts as proof

- `INJECTABLE ... new uid/gid output` is strong in-band proof because a POSIX identity signature
  absent from the baseline appeared only after a separator plus `id`.
- `INJECTABLE ... execution-only marker` requires a random marker to appear for the shell payload
  but not for the literal reflection control. Raw reflection alone is never proof.
- A flag in any response header or body stops the run immediately.
- A new `sh:`, `bash:`, `command not found`, or Windows command error is a strong lead but remains
  `INCONCLUSIVE` without execution output or a repeatable timing differential.
- `429`, gateway failures, an invalid baseline, and an exhausted budget are inconclusive. Never
  record them as “not injectable.”

## Blind timing is explicit

Default probes do not sleep, write files, make callbacks, or open shells. If the response channel
is silent and the endpoint is safe to repeat, opt in to paired timing controls:

```bash
python3 ~/.claude/skills/web-ctf/scripts/cmdiquick.py ... --blind-time 3
```

The helper sends two unchanged controls and two delayed probes and requires both delayed requests
to exceed both controls by a substantial fraction of the requested delay. Use `--os windows` for
Windows `timeout`; `auto`/`posix` uses `sleep`. Keep the delay between two and five seconds unless
the target's normal latency requires more. OOB callbacks, file writes, and reverse shells stay
manual and require an explicit reason after the bounded fast track is exhausted.

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
