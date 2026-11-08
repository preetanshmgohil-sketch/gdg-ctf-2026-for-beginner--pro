# Chronos Engine — hint ladder

These are the same three hints the scoreboard unlocks. They are sequential and
cost 10, 20, and 30 points.

## Hint 1 — 10 points

The metadata says the nonce is deterministic and epoch-derived. Ask for two
different `timeline:*` messages in the same epoch and compare their `r` values.

## Hint 2 — 20 points

Equal `r` means equal `k`. Write the two ECDSA equations, subtract them to
eliminate the private key, and solve for `k`. Then substitute back to recover
`d`.

## Hint 3 — 30 points

`k = (z1 - z2) / (s1 - s2) mod n`, then `d = (s1*k - z1) / r mod n`. Sign the
exact message `vault:admin` with a fresh nonce and POST `r` and `s` to
`/api/vault/open`.
