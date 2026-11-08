# Flag reference sheet

**SPOILERS.** Organizer-only. Do not publish this file or the challenge
`WRITEUP.md` files to players.

## Standalone mode

These flags are returned when a challenge app runs by itself and
`TEAM_TOKEN_SECRET` is not set.

| Challenge | Flag |
|---|---|
| The Intern's Secret | `GDG{1d0r_1s_n0t_4_d00r}` |
| Chronos Engine | `GDG{n0nc3_r3us3_1s_f4t4l}` |

## Platform mode (live event)

The scoreboard and challenge services derive a unique flag per team:

| Challenge | Pattern | Example shape |
|---|---|---|
| The Intern's Secret | `GDG{intern_<20 hex>}` | `GDG{intern_2b964c1a2418775e7286}` |
| Chronos Engine | `GDG{chronos_<20 hex>}` | `GDG{chronos_c6ea6a21f7d9a07d538c}` |

The values above are examples, not flags for a real event. The actual hash is:

```text
HMAC-SHA256(FLAG_SECRET, "<team_id>:<challenge_slug>")[:20]
```

`FLAG_SECRET` is generated on first run in `instance/secrets.json`.

## Recompute a team's flag (organizer support)

Find the numeric team ID in `/admin`, then:

```bash
python tools/flag_lookup.py 7 interns-secret
python tools/flag_lookup.py 7 chronos-engine
```

From PowerShell, the same commands work inside the activated virtual
environment. The tool reads `instance/secrets.json`; keep that file private.

## Chronos per-team key

Chronos also derives a unique ECDSA key per team:

```text
private_key = HMAC(FLAG_SECRET, "chronos-key:"   + team_id)  mod (n-1) + 1
nonce_seed  = HMAC(FLAG_SECRET, "chronos-nonce:" + team_id)
```

A forged signature from one team's session is invalid on another team's vault.
This is intentional anti-cheat behavior; do not "fix" it by sharing one key
across the event.
