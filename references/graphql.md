# GraphQL — bounded post-auth fast track

Run the read-only helper as soon as JS mining or recon confirms a GraphQL endpoint. Run it in the
same authenticated parallel burst as `jwtquick.py`; do not wait for the JWT path to fail first.

```bash
python3 ~/.codex/skills/web-ctf/scripts/graphqlquick.py \
  --url <target>/api/graphql --token "$TOKEN" --id "$YOUR_ID" \
  --out recon/graphqlquick
```

It performs a bounded sequence:

1. Compare anonymous and authenticated `{ __typename }` reachability.
2. Attempt Query-type introspection.
3. If introspection is disabled, send bare read-only Query roots and parse validation errors for
   required identity arguments and server-suggested fields.
4. Try ID `1` and your own ID against independent sensitive leaf probes (`flag`, `password`,
   `token`, `secret`, API keys, identity, email, and role). Independent requests matter: one
   nonexistent GraphQL field otherwise invalidates the entire combined query.
5. Scan every response header and body for a flag and stop immediately on a hit, `429`, gateway
   failure, or the 48-request ceiling.

The helper never generates mutations. Its JSONL evidence is `recon/graphqlquick/probes.jsonl`.
Use `--root <name>` or `--leaf <name>` to prepend a client-mined or notes-derived hypothesis
without replacing the bounded defaults.

## Manual schema-oracle fallback

If the helper cannot run, preserve headers and reproduce the same sequence manually:

```bash
# Reachability and ordinary introspection
curl -si -X POST <target>/api/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}'
curl -si -X POST <target>/api/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'

# Disabled introspection: learn the required argument and return shape from validation errors
curl -si -X POST <target>/api/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ user }"}'

# Probe one leaf per request so an invalid field cannot suppress valid data
curl -si -X POST <target>/api/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id: 1) { password } }"}'
```

Mine the client first. `jsmine.py` prints complete named operations, root resolvers, variables,
source provenance, and a separate identity-signal section for variables such as `$userId`.
Caller-controlled identity variables are an IDOR lead even when the shipped client only uses a
mutation such as activity logging.

If several same-app vault notes exist, narrow their **filenames** by the confirmed signal before
opening one (`-iname '*<stem>*.md' -iname '*graphql*.md'`). The old request is a hypothesis, never
proof; validate it against the live instance.

Only after the read-only fast track is exhausted should you manually test batching, aliases,
fragments, GET query transport, `/graphql`, `/v1/graphql`, `/query`, or a specifically justified
mutation. Never automate privilege-changing mutations in the generic harness.
