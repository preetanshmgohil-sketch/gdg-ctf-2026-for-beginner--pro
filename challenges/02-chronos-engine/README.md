# Chronos Engine — organizer README

**Level:** Experienced · **Category:** Crypto / Web · **Points:** 300
**Bug:** ECDSA nonce reuse caused by an epoch-derived deterministic nonce

> Spoiler warning: this directory also contains `HINTS.md`, `WRITEUP.md`, and the
> reference exploit `solve.py`. Do not publish them to players.

## Story

Chronos Engine is a fictional audit service that signs public timeline
snapshots. To make audit signatures reproducible, its operators derived the
ECDSA nonce from a 60-second epoch. The archive vault only opens for a valid
signature over `vault:admin` — a message the public oracle refuses to sign.

Recover the engine key and forge the attestation.

## Player-facing prompt

> Chronos Engine signs public `timeline:*` snapshots so auditors can reproduce
> them. The vault requires a signature over `vault:admin`, which the public
> oracle will not issue. The metadata says the nonce is deterministic and
> epoch-derived. Maybe reproducibility was a bad idea.

## Flags

| Mode | Value |
|---|---|
| Platform (live event) | `GDG{chronos_<20 hex>}` — unique per team |
| Standalone | `GDG{n0nc3_r3us3_1s_f4t4l}` |

In platform mode the app also derives a **different ECDSA private key and nonce
seed per team** from `FLAG_SECRET`. A signature forged for team A does not verify
on team B's instance.

## API

| Endpoint | Method | Notes |
|---|---|---|
| `/` | GET | Status page with public key and protocol notes |
| `/api/meta` | GET | Curve, public key, signing policy, required attestation |
| `/api/sign` | POST | Signs `{"message": "timeline:..."}`; 30/min/IP |
| `/api/vault/open` | POST | Accepts `{"message": "vault:admin", "r": "0x...", "s": "0x..."}` |
| `/healthz` | GET | Health check |

The oracle refuses any message that does not start with `timeline:` and caps
messages at 120 characters.

## Running it by itself

```bash
cd challenges/02-chronos-engine
python -m pip install flask
python app.py
```

The challenge listens on <http://127.0.0.1:8082>. On each start it generates a
random private key and nonce seed unless you set `CHRONOS_PRIVATE_KEY` and
`CHRONOS_NONCE_SEED`. The static reference flag is used when
`TEAM_TOKEN_SECRET` is not set.

To exercise the per-team path without the platform:

```bash
# macOS/Linux
DEV_TEAM_ID=7 python app.py

# Windows PowerShell
$env:DEV_TEAM_ID = "7"
python app.py
```

The derived flag and key then depend on team 7 and `FLAG_SECRET`.

## Reference solver

```bash
# Standalone
python solve.py --url http://127.0.0.1:8082

# Platform: copy the launch link from the scoreboard
python solve.py --launch "http://LAN-IP:8082/?t=<signed-token>"

# Platform: copy the session cookie from DevTools instead
python solve.py --url http://LAN-IP:8082 \
  --cookie "gdg_chronos_session=<value>"
```

`solve.py`:

1. reads `/api/meta` and records the expected public key;
2. requests two different `timeline:*` signatures, retrying across an epoch
   boundary if their `r` values differ;
3. recovers `k`, then the private key `d`;
4. verifies the recovered key against the published public key;
5. signs the exact string `vault:admin` with a fresh random nonce;
6. posts `r` and `s` to `/api/vault/open` and prints the flag.

A player does not need this script; it exists as a reference and for organizer
verification.

## Intended vulnerability

```python
NONCE_SEED = os.environ.get("CHRONOS_NONCE_SEED", secrets.token_hex(32)).encode()

def _nonce_for_epoch(epoch: int, nonce_seed: bytes) -> int:
    digest = hashlib.sha256(nonce_seed + b":" + str(epoch).encode("ascii")).digest()
    return int.from_bytes(digest, "big") % (curve.N - 1) + 1
```

Every signature in the same 60-second epoch uses the same `k`. Two signatures
`(r, s1, z1)` and `(r, s2, z2)` are enough to recover the private key:

```text
k = (z1 - z2) / (s1 - s2) mod n
d = (s1 * k - z1) / r mod n
```

The oracle's prefix restriction is irrelevant once `d` is known: the attacker
can sign `vault:admin` locally.

`ecdsa_secp256k1.py` is a deliberately small, non-constant-time implementation
written for this challenge. Do not reuse it as a crypto library.

## Files

```
app.py                    Flask app, epoch nonce, signer, vault
ecdsa_secp256k1.py        small secp256k1 implementation (educational only)
solve.py                  reference exploit with cookie/launch support
templates/index.html      status page
templates/404.html        not-found page
templates/launch_required.html  shown when a platform token is missing
static/style.css          styling
HINTS.md                  exact three-step hint ladder
WRITEUP.md                full solution and remediation
```

## Verification

Standalone, with a fixed key for repeatability:

```bash
# macOS/Linux
CHRONOS_PRIVATE_KEY=1234567890abcdef CHRONOS_NONCE_SEED=seed python app.py
```

```powershell
# Windows PowerShell
$env:CHRONOS_PRIVATE_KEY = "1234567890abcdef"
$env:CHRONOS_NONCE_SEED = "seed"
python app.py
```

Then, in another terminal:

```bash
python solve.py --url http://127.0.0.1:8082
```

Expected output ends with:

```text
[+] flag: GDG{n0nc3_r3us3_1s_f4t4l}
```

## Remediation (for the debrief)

- Never derive an ECDSA nonce from public, predictable, or repeated input.
- Use a CSPRNG nonce or RFC 6979 deterministic nonces (which bind the nonce to
  the message **and** private key, not to a timestamp).
- Use a maintained crypto library and constant-time primitives.
- Do not build a signing oracle that signs attacker-chosen messages with a key
  that protects a higher-value action. If you must, scope the key and the
  message domain.
- Add monitoring for repeated `r` values across signatures.

## Safety

Chronos is fictional. The service signs only its own synthetic messages, stores
no real keys, and must not be deployed as a real signing service.
