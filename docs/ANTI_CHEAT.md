# Anti-cheat design and organizer playbook

GDG CTF Lite assumes a **trusted organizer laptop** and a **small, invite-based
event**. It is not a hardened internet-facing competition platform. Within that
scope it makes flag sharing detectable and makes one team's Chronos forgery
useless on another team's instance.

- [1. Design goals](#1-design-goals)
- [2. Controls](#2-controls)
- [3. What gets logged](#3-what-gets-logged)
- [4. Detection workflow](#4-detection-workflow)
- [5. Response playbook](#5-response-playbook)
- [6. Limitations](#6-limitations)
- [7. Pre-event checklist](#7-pre-event-checklist)
- [8. Post-event checklist](#8-post-event-checklist)

---

## 1. Design goals

1. **A copied flag must not score.** Every team gets a different flag for the
   same challenge.
2. **A forged Chronos signature must not transfer.** Each team gets a different
   ECDSA private key and nonce seed.
3. **The organizer must be able to see what happened.** Registrations,
   submissions, and cross-team attempts are recorded.
4. **No containers or per-team instances.** The event must run on one laptop
   with plain Python.
5. **The controls must be honest about their limits.** No anti-cheat scheme
   stops collusion; this one detects the common "paste someone else's flag"
   behavior and raises its cost.

The platform does not store a canonical flag answer. Flags are recomputed on
demand; submitted text is recorded in the submissions table for auditing:

```text
flag = "GDG{" + prefix + "_" + HMAC-SHA256(FLAG_SECRET, team_id + ":" + slug)[:20] + "}"
```

The 20 hex characters give 80 bits of output. Guessing is infeasible, and the
submission endpoint is rate-limited.

---

## 2. Controls

| Control | Where it lives | What it stops |
|---|---|---|
| Per-team HMAC flags | `shared/team_context.py`, `scoreboard/app.py` | Copying another team's flag |
| Signed launch tokens | `make_team_token` / `parse_team_token` | Editing `team_id` in a URL |
| 12-hour token lifetime | `parse_team_token(max_age=43200)` | Indefinite reuse of an old launch URL |
| Token stripped from URL | `init_team_context` 302 redirect | Token lingering in screenshots/history |
| Separate cookie names | each Flask app config | Session collisions on one host |
| Per-team Chronos key | `challenges/02-chronos-engine/app.py` | Reusing a forged signature across teams |
| Per-team Chronos nonce seed | same | Predicting another team's nonces |
| Generic wrong-flag response | `submit_flag` | Learning that a flag belongs to someone else |
| Submission audit | `submissions.kind = flag_share_attempt` | Investigating sharing |
| Organizer-only audit page | `/admin` HTTP Basic | Players reading other teams' submissions |
| Audit CSV export | `/admin/audit.csv` | Post-event review |
| Team ban | `/admin/team/<id>/ban` | Repeated abuse after a warning |
| CSRF on scoreboard forms | `csrf_token` / `verify_csrf` | Cross-site form posts |
| Rate limits | in-memory buckets | Brute force, spam, oracle flooding |
| Parameterized SQL | all `sqlite3` calls | SQL injection into the scoreboard |
| CSP / no-store / nosniff | `after_request` on all apps | Basic browser-side leakage |

### Rate limits

| Action | Limit |
|---|---|
| Registration | 5 attempts / IP / 10 minutes |
| Login | 10 attempts / IP / 5 minutes |
| Flag submission | 12 attempts / team / 1 minute |
| Chronos signing | 30 signatures / IP / 1 minute |
| Team token lifetime | 12 hours |

These counters live in process memory. Restarting the service resets them. That
is acceptable for a short laptop event; it is not a distributed rate limiter.

### Why a copied flag is detectable

When team B submits `GDG{intern_<hash>}` that belongs to team A:

1. It does not equal B's expected HMAC output, so it is rejected.
2. The scoreboard checks the supplied value against the derived flag of every
   other active team.
3. On a match it stores the submission as `kind = flag_share_attempt` and writes
   an audit row with the source team name.
4. The player still sees the generic `"Incorrect flag."` message, so the
   endpoint does not confirm whose flag it was.

### Why a Chronos forgery does not transfer

The private key and nonce seed are derived per team:

```text
d         = HMAC(FLAG_SECRET, "chronos-key:"   + team_id)
nonce_seed = HMAC(FLAG_SECRET, "chronos-nonce:" + team_id)
k(epoch)  = SHA256(nonce_seed || ":" || epoch)
```

Team A can recover its own `d` from its own reused nonce and forge a signature
over `vault:admin`. Team B's vault verifies against team B's public key, so A's
signature fails. The solver does not need to know this; it discovers the public
key from `/api/meta` for the current session and verifies the recovered key
against it.

---

## 3. What gets logged

### `submissions`

Every flag attempt, with `challenge_id`, provided text (truncated to 200
characters), `correct`, `kind`, IP, and timestamp.

`kind` is one of:

- `correct`
- `wrong`
- `flag_share_attempt`

### `audit`

- `team_registered`
- `login`
- `failed_login`
- `logout`
- `flag_share_attempt` (with the source team name)
- `team_banned`
- `team_unbanned`

### `solves`, `hint_unlocks`, `teams`

Used for score calculation and for the admin table. `teams` stores the
registration IP and creation time.

The admin page shows the latest 200 submissions and audit rows. The CSV export
contains the full audit table.

---

## 4. Detection workflow

1. Open `http://LAN-IP:8000/admin` as `organizer` with the password from
   `instance/secrets.json`.
2. Check the **Share attempts** counter. A nonzero value means at least one
   submission exactly matched another team's derived flag.
3. Look at the highlighted rows: submitting team, challenge, source team in the
   audit detail, IP, and time.
4. Compare with the team's normal registration/login IPs. NAT can make several
   teams share an IP, so treat IP as context, not proof.
5. Export `/admin/audit.csv` before changing anything.
6. Talk to the team. A first accidental paste after a hint discussion is
   different from a repeated pattern across challenges.

Strong signals:

- multiple `flag_share_attempt` rows from the same team;
- submissions of another team's flag for both challenges;
- submission IPs that differ from the team's registration IP;
- a team that never launched the challenge but submits its flag.

Weak signals (do not act on these alone):

- two teams on the same NAT IP;
- one wrong submission immediately before the correct one;
- a correct solve shortly after a hint unlock.

---

## 5. Response playbook

### Level 1 — likely accidental

One share attempt, otherwise normal behavior.

1. Send a private warning with the event rule.
2. Record the warning in your own notes (the platform has no warning table).
3. Do not change the score; the attempt did not score.

### Level 2 — repeated or coordinated

Two or more share attempts, or a clear pattern across challenges.

1. Export the audit CSV.
2. Ban the team from `/admin` (the **Ban** button). A banned team cannot sign
   in, and its existing browser session is discarded on the next scoreboard
   request.
3. Announce only that a rules decision was made; do not publish personal data.
4. If the event is competitive, consider freezing the scoreboard while you
   review.

### Level 3 — leaked launch URL or session

A launch URL is a bearer credential. Anyone who has it can act as that team.
Signs: a team's actions come from an IP or device the team does not use, or the
team reports that its link was posted.

1. Tell the team to stop sharing the link; relaunching creates a fresh signed
   token but does not invalidate old tokens before their 12-hour expiry.
2. Review the team's submissions for changes you did not expect.
3. If necessary, ban the team and create a replacement team for the innocent
   players (manual organizer action).
4. Remember: this is account sharing, not cross-team flag copying. Per-team
   flags do not prevent it.

### Do not

- Do not ban on a single ambiguous row without talking to the team.
- Do not publish IP addresses or flags in the event chat.
- Do not delete the database to "clean up" before exporting the audit.
- Do not rotate `FLAG_SECRET` mid-event; every team's flag changes and solved
  teams will see a different own-flag panel.

---

## 6. Limitations

These are deliberate, documented tradeoffs:

1. **No isolation.** All challenge code runs in the organizer's Python process
   space on the organizer's laptop. The challenges expose only HTTP endpoints,
   but do not add file upload, command execution, or arbitrary URL fetching to
   them without a sandbox.
2. **A launch URL is a password.** Signed tokens prevent tampering, not
   sharing. The 12-hour lifetime limits the damage; it does not eliminate it.
3. **Per-team flags detect copying, not collaboration.** A team can still solve
   together and each team must run the exploit on its own session. That is the
   intended learning outcome.
4. **In-memory rate limits** reset on restart and are per process. Do not run
   multiple Waitress processes behind a load balancer and expect shared limits.
   The Chronos signing limit is per source IP, so many teams behind one campus
   NAT can share the same 30/minute budget. For a small event this is fine; if
   you expect a large NATed audience, raise `SIGN_LIMIT` in the challenge app or
   place the event behind a proxy that preserves client IPs.
5. **IP evidence is weak** behind NAT, VPNs, and tunnels. Use `TRUST_PROXY=1`
   only when every request arrives through the trusted tunnel, otherwise clients
   can spoof `X-Forwarded-For`.
6. **The scoreboard is not internet-hardened.** SQLite, Flask's development
   defaults, and HTTP Basic are appropriate for a laptop event, not a public
   service. Keep it on the LAN or behind an invite code.
7. **Secret compromise is total compromise.** Anyone with
   `instance/secrets.json` and `FLAG_SECRET` can derive every flag and every
   Chronos key. Protect the file; do not commit it; do not show it on a
   projector.
8. **No replay protection on vault submissions.** ECDSA signatures are verified
   mathematically; a valid signature can be posted more than once. It only
   returns the same team's flag, so this does not create a scoring advantage.
9. **Ban is manual.** The platform does not auto-ban on a share attempt, because
   false positives and innocent mistakes are real. The organizer decides.

---

## 7. Pre-event checklist

- [ ] `instance/secrets.json` exists and is readable only by the organizer.
- [ ] `instance/` is not in version control (`git status`).
- [ ] The organizer password works at `/admin`.
- [ ] `REGISTRATION_CODE` is set if the event is public or remote.
- [ ] `COOKIE_SECURE=1` and `TRUST_PROXY=1` are set for HTTPS tunnels; both are
      unset for plain HTTP LAN play.
- [ ] You tested a copied flag and saw `flag_share_attempt` in `/admin`.
- [ ] You tested the ban button on a throwaway team.
- [ ] The laptop will not sleep, and the DB/secrets are backed up.
- [ ] The projector shows `/scoreboard`, not `/admin`.

## 8. Post-event checklist

- [ ] Export `/admin/audit.csv`.
- [ ] Back up `instance/ctf.db` and `instance/secrets.json` together.
- [ ] Screenshot or save the final scoreboard.
- [ ] Record any warnings or bans in a private organizer note.
- [ ] For the next event, delete the DB and rotate `instance/secrets.json`.
