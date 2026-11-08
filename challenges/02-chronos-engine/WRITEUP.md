# Chronos Engine — full writeup

**Challenge:** Chronos Engine
**Level:** Experienced · Crypto / Web
**Bug:** ECDSA nonce reuse (epoch-derived deterministic nonce)
**Flag (platform):** `GDG{chronos_<20 hex>}` — unique to each team
**Flag (standalone):** `GDG{n0nc3_r3us3_1s_f4t4l}`

> Organizer/writeup material. Contains the answer and a working exploit.

---

## 1. Story and objective

Chronos Engine is a fictional temporal attestation service. It signs public
`timeline:*` snapshots. The archive vault only accepts a valid signature over
`vault:admin`, which the public signing oracle refuses to issue.

The metadata admits the fatal design choice: the ECDSA nonce is deterministic
and derived from a **60-second epoch**. Two signatures in the same epoch reuse
the same `k`, which leaks the private key.

The goal is to recover the signing key, forge `vault:admin`, and open the vault.

---

## 2. Reconnaissance

Launch the challenge from the scoreboard and open the status page. The public
metadata is the intended starting point:

```bash
curl -s http://LAN-IP:8082/api/meta | python -m json.tool
```

```json
{
  "service": "chronos-engine",
  "version": "1.4.2-audit",
  "curve": "secp256k1",
  "hash": "sha256",
  "public_key": {
    "x": "0x...",
    "y": "0x...",
    "uncompressed": "0x04..."
  },
  "signing_policy": {
    "allowed_prefix": "timeline:",
    "max_message_length": 120,
    "nonce_scheme": "deterministic, epoch-derived for reproducible audit signatures",
    "epoch_seconds": 60,
    "rate_limit": "30 signatures per 60s per source"
  },
  "required_attestation": {
    "message": "vault:admin",
    "encoding": "hex integers for r and s",
    "endpoint": "/api/vault/open"
  }
}
```

Three facts matter:

1. The oracle signs only messages starting with `timeline:`.
2. The nonce is epoch-derived, so it repeats within a 60-second window.
3. The vault wants a signature over an exact string the oracle will not sign.

If the challenge is platform-launched, the browser session carries the team
binding. Every API call must use the same cookie. Copy the launch link and use
`curl`'s cookie jar, or copy the `gdg_chronos_session` cookie from DevTools:

```bash
curl -c cookies.txt -L "http://LAN-IP:8082/?t=<launch-token>"
curl -b cookies.txt http://LAN-IP:8082/api/meta
```

---

## 3. Getting two signatures in one epoch

Ask for two different timeline messages back to back:

```bash
curl -s -b cookies.txt -X POST http://LAN-IP:8082/api/sign \
  -H 'Content-Type: application/json' \
  -d '{"message":"timeline:alpha"}'

curl -s -b cookies.txt -X POST http://LAN-IP:8082/api/sign \
  -H 'Content-Type: application/json' \
  -d '{"message":"timeline:beta"}'
```

Example responses:

```json
{"message":"timeline:alpha","r":"0x...","s":"0x...","z":"0x...","epoch":29902598}
{"message":"timeline:beta", "r":"0x...","s":"0x...","z":"0x...","epoch":29902598}
```

The important observation is:

```text
r1 == r2
```

because both signatures used the same nonce `k`. If the two calls straddle an
epoch boundary, the `r` values differ. Wait for the next epoch and repeat. The
reference solver handles this automatically.

---

## 4. The math

ECDSA signing uses:

```text
s = k^-1 * (z + r * d) mod n
```

where `z = SHA-256(message) mod n`, `k` is the nonce, and `d` is the private key.
With one nonce used twice:

```text
s1 = k^-1 * (z1 + r * d) mod n
s2 = k^-1 * (z2 + r * d) mod n
```

Subtract the equations:

```text
s1 - s2 = k^-1 * (z1 - z2) mod n
k       = (z1 - z2) * (s1 - s2)^-1 mod n
```

Now substitute `k` back into the first equation:

```text
d = (s1 * k - z1) * r^-1 mod n
```

Python's `pow(value, -1, n)` computes the modular inverse. Always reduce modulo
`n`, the secp256k1 group order.

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

k = ((z1 - z2) * pow(s1 - s2, -1, N)) % N
d = ((s1 * k - z1) * pow(r, -1, N)) % N
```

Sanity check: compute `d * G` and compare it with the public key from
`/api/meta`. If it does not match, the signatures did not share a nonce, the
wrong `z` was used, or the epoch changed between requests. The reference solver
performs this check and aborts rather than submitting a bad forgery.

---

## 5. Forging the vault attestation

With `d` recovered, the `timeline:` restriction is irrelevant. Sign the exact
string `vault:admin` locally with a fresh random nonce:

```python
import hashlib, secrets

def sign(private_key, message, nonce):
    z = int.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), "big") % N
    point = point_mul(nonce)          # nonce * G
    r = point[0] % N
    s = (pow(nonce, -1, N) * (z + r * private_key)) % N
    return r, s, z

nonce = secrets.randbelow(N - 1) + 1
r, s, z = sign(d, "vault:admin", nonce)

payload = {
    "message": "vault:admin",
    "r": f"0x{r:064x}",
    "s": f"0x{s:064x}",
}
```

`point_mul` is the secp256k1 scalar multiplication supplied with the challenge
(`ecdsa_secp256k1.py`). A standard library can produce the same signature; the
important detail is the exact ASCII message.

Submit:

```bash
curl -s -b cookies.txt -X POST http://LAN-IP:8082/api/vault/open \
  -H 'Content-Type: application/json' \
  -d '{"message":"vault:admin","r":"0x...","s":"0x..."}'
```

```json
{
  "status": "open",
  "message": "The vault accepts the engine's signature. Take the archive.",
  "flag": "GDG{chronos_...}"
}
```

Submit the flag on the scoreboard. In standalone mode it is
`GDG{n0nc3_r3us3_1s_f4t4l}`.

---

## 6. Reference solver

The repository ships a tested solver:

```bash
# Standalone
python solve.py --url http://127.0.0.1:8082

# Platform: copy the launch link from the scoreboard
python solve.py --launch "http://LAN-IP:8082/?t=<signed-token>"

# Platform: copy the cookie from DevTools
python solve.py --url http://LAN-IP:8082 \
  --cookie "gdg_chronos_session=<value>"
```

Output:

```text
[+] two signatures share nonce: r=0x...
[+] epoch: 29902598 / 29902598
[+] private key recovered and verified against /api/meta
[+] forged an attestation for vault:admin
[+] flag: GDG{chronos_...}
```

`--launch` follows the 302 that strips the token from the URL and keeps the team
session cookie in a cookie jar. `--cookie` is the manual alternative.

The solver waits for an epoch boundary if the first two signatures do not share
`r`, verifies the recovered key, and signs the exact vault message.

---

## 7. Why this works

ECDSA security depends on a unique, unpredictable nonce per signature. Reuse `k`
for two different messages and the private key falls out of two linear equations:

```text
s1 - s2 = k^-1 (z1 - z2)  =>  k known
s1      = k^-1 (z1 + r d)  =>  d known
```

Deriving `k` from a public 60-second timestamp makes the reuse reliable and
predictable. Even without seeing two signatures, an attacker knows when the
nonce changes. This is a catastrophic cryptographic failure, not a subtle leak.

The oracle's prefix check is not a security boundary once the key is known. The
attacker signs `vault:admin` offline.

---

## 8. Remediation

- **Use a CSPRNG nonce** for every signature, or **RFC 6979** deterministic
  nonces. RFC 6979 derives `k` from the private key, message, and hash, so it
  never repeats across different messages.
- Never derive a nonce from a timestamp, counter, epoch, or other public value.
- Use a maintained, constant-time crypto library. The challenge implementation
  exists only to model the flaw.
- Do not expose a signing oracle for a key that protects a higher-value action.
  If unavoidable, scope keys and message domains and monitor for repeated `r`.
- Defensive check: alert if two signatures ever share the same `r`.

---

## 9. Per-team behavior (anti-cheat)

In a live platform event, the challenge derives a different private key and
nonce seed from `FLAG_SECRET` and the team ID:

```text
d          = HMAC(FLAG_SECRET, "chronos-key:"   + team_id)
nonce_seed = HMAC(FLAG_SECRET, "chronos-nonce:" + team_id)
```

The public key in `/api/meta` is therefore different for every team. A forged
signature that works on team A's vault is invalid on team B's. Recovering a
friend's key or sharing their `r`/`s` values does not score.

The flag itself is also derived per team. There is no static answer in platform
mode.

---

## 10. Hint mapping

| Hint | What it points at |
|---|---|
| 1 | Metadata says epoch-derived nonce; request two timeline messages and compare `r` |
| 2 | Equal `r` means equal `k`; subtract the signing equations and solve |
| 3 | Exact formulas for `k` and `d`; sign `vault:admin` and POST `r`/`s` |

---

## 11. Common mistakes

- **Trying to sign `vault:admin` at the oracle.** The oracle returns `403` for
  anything outside `timeline:*`.
- **Using signatures from different epochs.** Their `r` values differ; wait and
  retry.
- **Hashing the wrong value.** It must be SHA-256 of the exact ASCII
  `vault:admin`, not of a JSON wrapper or a hex string.
- **Submitting decimal integers.** The vault parses `r` and `s` as hexadecimal.
  Prefix them with `0x`.
- **Posting to the vault before recovering the key.** Guessed `r`/`s` returns
  `403 invalid attestation`.
- **Losing the team session.** Use one cookie jar for `/api/meta`, `/api/sign`,
  and `/api/vault/open`. A different team session has a different public key.
- **Hitting the rate limit.** 30 signatures per minute per IP. The attack needs
  two; do not spam the oracle.
- **Assuming the static flag works.** In platform mode the flag is derived per
  team.
