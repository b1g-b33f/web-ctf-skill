# Server-side prototype pollution — paired, reversible-behavior detection

Use this path for a Node/JavaScript API when both sides of the chain are plausible:

- a JSON update/import endpoint recursively merges user-controlled objects, especially nested
  `settings`, `permissions`, `profile`, or `config`; and
- an authorization or feature check reads a property that may be absent as an own property, such
  as `is_admin`, `isAdmin`, `verified`, `isPremium`, or `role`.

The missing property is a gadget lead, not the first payload. Confirm a pollution source with an
unrelated, low-impact framework behavior before touching any authorization property.

## Safety invariants

Server-side pollution lasts for the Node process. A neutralizer changes the selected gadget to a
behaviorally inert value; it does **not** delete the inherited property. An update endpoint may
also persist the neutralized key on the target object. Therefore:

1. Start from one known-valid, preferably idempotent JSON body against a disposable/no-op object.
   Preserve every required field and re-fetch the object after the sequence.
2. Test one object level, one form, and one oracle at a time.
3. For every attack, send the matching neutralizer at the same object level in a `finally` path.
4. Confirm only `baseline normal -> attack behavior -> neutralizer -> behavior reverted`.
5. Stop on 429, gateway failure, or an unverified cleanup. On a shared instance, restart before
   continuing if the behavior does not revert.

An unchanged oracle is inconclusive for that gadget. Express version, middleware, routing, and
explicit own properties can all make a valid source invisible to a particular oracle.

## Bounded helper

`ssppquick.py` inserts at every existing JSON object level individually and records the exact JSON
Pointer that reaches the sink. Its default status oracle is the clearest paired check:

```bash
python3 ~/.codex/skills/web-ctf/scripts/ssppquick.py \
  --url <target>/api/profile --method PATCH --token "$TOKEN" \
  --data '{"profile":{"settings":{"theme":"dark"}}}' \
  --probe-url <target>/api/profile --out recon/ssppquick
```

Use `--data-file` when shell quoting would be fragile. The status check needs `--probe-url` and
`--probe-method` to identify an endpoint/method whose JSON parser returns an error for the invalid
body `{`. Use `--oracle spacing`, `options`, `exposed-headers`, or `blitz` when their prerequisite
behavior exists. If `__proto__` is filtered, rerun with `--form constructor`; `--form both` is an
explicit broader sweep. Use `--path /profile/settings` to replay only a known nesting depth.

The helper writes redacted request metadata to `probes.jsonl`, raw responses under `responses/`,
and the outcome, path, form, and cleanup state to `summary.json`. Exit 0 means a paired source was
confirmed (or a flag was observed), 2 means no source was confirmed, 3 is a request/cleanup circuit
breaker, and 4 is invalid input. A bounded miss does not exhaust prototype pollution if object
levels were truncated, the baseline was invalid, or the applicable framework gadget was absent.

## Paired oracles

Place the oracle inside a real body at the level being tested. A top-level-only probe does not reach
a sink that merges `body.settings` or `body.profile.config`.

| Oracle | Attack under `__proto__` | Neutralizer | Required differential |
|---|---|---|---|
| Status | `{"status":510}` | `{"status":0}` | A pre-calibrated invalid-JSON error changes to 510, then stops being 510 |
| JSON spacing | `{"json spaces":" "}` | `{"json spaces":""}` | Raw JSON gains one-space indentation, then returns to its baseline formatting |
| OPTIONS | `{"head":true}` | `{"head":false}` | A baseline `Allow` containing HEAD loses HEAD, then regains it |
| CORS exposed headers | `{"exposedHeaders":["f1e3f7a9"]}` | `{"exposedHeaders":null}` | The canary appears in `Access-Control-Expose-Headers`, then disappears |
| Immutable prototype | `{"__proto__":{}}` | `{"__proto__":"xyz"}` | The object form yields an immutable-prototype error and the scalar control does not |

For a filtered `__proto__`, wrap the same inner values as
`{"constructor":{"prototype":<inner>}}`. Constructor traversal is a fallback, not proof that a
filter was bypassed; it needs the same paired differential.

Status 510 is valid only when the control error did not already return 510. JSON spacing is visible
only in a raw response view and was hardened in Express 4.17.4. OPTIONS requires an implicit HEAD
baseline. `exposedHeaders` requires compatible CORS middleware. A generic 500 by itself is not an
immutable-prototype confirmation; require the paired control and a matching error signature.

These oracles and neutralizers follow PortSwigger's original
[black-box SSPP research](https://portswigger.net/research/server-side-prototype-pollution) and its
[paired status BCheck](https://portswigger.net/burp/documentation/scanner/bchecks/worked-examples/server-side-prototype-pollution).

## Escalate only after source confirmation

Reuse the confirmed form and exact JSON Pointer. Prefer the property named by source, client code,
an authorization error, or an absent-own-property check. Test one property/value pair, re-fetch
identity state, and re-probe the previously denied capability. An echoed field or a successful
update response is not privilege proof.

Do not spray `is_admin`, `isAdmin`, `admin`, `role`, `verified`, and `authenticated` together.
Simultaneous spraying obscures the gadget and leaves several inherited properties behind. If no
exact property is observable, test a short source-derived alias set one at a time and apply a
type-correct neutral value after each miss. Record the persistent prototype state in `WORKLOG.md`.

Never jump from a confirmed source to process-spawning or `NODE_OPTIONS` gadgets when an
authorization property can reach the CTF objective with lower impact.
