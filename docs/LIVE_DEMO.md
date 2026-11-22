# Live demo runbook (15 minutes)

Use this for an organizer, interviewer, or community demo. It is not
player-facing.

The goal is not to show polished slides. The goal is to show that the challenge
runs, that you understand the solve path, and that you can explain the security
decisions behind it.

---

## Before the call

### Book and join

- Book the earliest slot you can. Slots are usually first come, first served.
- Join the Discord server and claim the **Core Team Applicant** role. Without
  it you may not be able to speak in the meeting room.
- Join the waiting-room voice channel at the start of your slot.
- Test Discord screen sharing and your microphone **before** the call.

### 20 minutes before

- [ ] Laptop is plugged in and awake.
- [ ] Phone hotspot is ready as a backup.
- [ ] Notifications are off (Windows Focus Assist / Do Not Disturb).
- [ ] Email, chat, and personal tabs are closed.
- [ ] `/admin`, `instance/secrets.json`, `docs/FLAGS.md`, and the writeups are
      closed.
- [ ] Start the event with `START_GDG_CTF.bat`.
- [ ] Confirm all three services are healthy:
      `http://127.0.0.1:8000/healthz`, `:8081/healthz`, `:8082/healthz`.
- [ ] Open the scoreboard in one tab.
- [ ] Register a demo team, for example `DEMO` / `gdg-demo-2026`.
- [ ] Launch **The Intern's Secret** and leave the browser on Maya's login page.
- [ ] Browser zoom is 110–125% and the terminal font is large enough to read.
- [ ] Screen share a **window**, not the entire desktop.

If you want a completely clean event for the demo, run this before registering
the demo team:

```bat
START_GDG_CTF.bat reset
```

This clears test teams and scores but keeps the organizer password and flag
secrets.

---

## The 15-minute flow

| Time | Segment |
|---|---|
| 0:00–1:00 | What you built and why |
| 1:00–2:00 | Architecture in one minute |
| 2:00–7:00 | Beginner IDOR live solve |
| 7:00–9:00 | Explain the vulnerability and fix |
| 9:00–12:00 | Anti-cheat and platform design |
| 12:00–15:00 | Questions and close |

If you also want to show Chronos Engine, keep it to three minutes and run it
while you talk. Do not let it eat the whole slot.

---

## Opening (about one minute)

Say something close to this, in your own words:

> I built a small CTF package that runs from one laptop. It has a Flask
> scoreboard and two challenges: a beginner IDOR challenge and an advanced
> ECDSA nonce-reuse challenge. There is no Docker, no VPS, and no per-team
> containers. Players only need a browser.
>
> I wanted to show that a security event can be run by a student team without
> paid infrastructure, while still having per-team flags and an organizer audit
> trail.

Then show the scoreboard.

---

## Architecture in one minute

Show the terminal output and say:

> Three Flask apps run under Waitress: the scoreboard on 8000, the beginner
> challenge on 8081, and Chronos on 8082. The scoreboard signs a short-lived
> team token into each launch URL. The challenge stores the team in its own
> session and removes the token from the address bar.
>
> Flags are derived per team with HMAC, so the database does not need a table of
> plaintext flags. Chronos also derives a different ECDSA key per team, so one
> team's forged signature does not work on another team's instance.

Do not read code yet. Keep this high level.

---

## Beginner live solve

### 1. Launch

From the scoreboard challenge page, click **Launch**. You should land on:

```text
GDG Labs · Onboarding Portal
```

### 2. Sign in as Maya

The page shows the demo credentials:

```text
maya.intern
coffee-first
```

Say:

> Maya is an intern. The portal is meant to show her own onboarding notes.

### 3. Open note 101

Click **Open note 101**. The browser shows JSON:

```text
http://127.0.0.1:8081/api/notes/101
```

Say:

> The legacy API opens notes by numeric ID. The request is authenticated, but
> the number is supplied by the browser.

### 4. Change the ID

In the address bar, change `101` to `1`:

```text
http://127.0.0.1:8081/api/notes/1
```

Press Enter. The response is the Head of Platform's private note. The `body`
field contains:

```text
GDG{intern_<20 hex>}
```

Say:

> I did not log in as the platform lead. I just changed an object ID. This is an
> IDOR: Insecure Direct Object Reference.

### 5. Submit

Copy the complete flag, return to the scoreboard challenge page, paste it, and
submit. The team should gain 100 points and the challenge should show as solved.

### If you have time: show DevTools

Open `F12` → **Network**, click a note, and show the request to
`/api/notes/101`. Explain that the browser is just sending an HTTP request and
there is no hidden client-side protection.

---

## Explain the vulnerability (two minutes)

Keep it simple:

1. **Authentication** asks: "Are you logged in?"
2. **Authorization** asks: "Are you allowed to access this object?"
3. The endpoint does the first check but not the second.

The vulnerable code is roughly:

```python
note = NOTES.get(note_id)
if note is None:
    return jsonify({"error": "note not found"}), 404
```

There is no `owner_id` check.

The fix:

```python
if note["owner_id"] != user["id"] and user["role"] != "Admin":
    return jsonify({"error": "note not found"}), 404
```

Or scope the database query:

```sql
SELECT * FROM notes WHERE id = ? AND owner_id = ?
```

Return `404`, not `403`, so the endpoint does not confirm that a private note
exists.

Real-world framing:

> A bank uses `/account/12345`. If changing it to `/account/12346` shows another
> customer's account, that is the same class of bug.

---

## Anti-cheat and platform design (three minutes)

Say:

> The obvious problem with a local CTF is flag sharing. I made three design
> choices.

1. **Per-team flags.** The flag is
   `HMAC(FLAG_SECRET, team_id + ":" + challenge)`. A copied flag is another
   team's HMAC output, so it never matches. The scoreboard records a
   `flag_share_attempt` for organizer review.
2. **Signed launch tokens.** The scoreboard signs the team ID and name into the
   launch URL. Tampering is rejected, and tokens expire after 12 hours.
3. **Per-team Chronos keys.** Each team gets a different ECDSA private key and
   nonce seed. A signature forged for one team's vault is invalid on another
   team's timeline.

Then show or mention:

- The organizer `/admin` page has teams, submissions, audit rows, and a CSV
  export.
- Registration, login, submissions, and signing are rate-limited.
- The platform uses CSRF tokens, parameterized SQL, and security headers.

Be honest about limits:

> This is not a hardened internet service. It is designed for a trusted laptop
> on a LAN. There is no container isolation, launch URLs are bearer credentials,
> and rate limits are in process memory. For a public event I would add
> isolation, a shared rate-limit store, and a stricter registration flow.

That honesty is usually more impressive than claiming it is production-grade.

---

## Optional: Chronos Engine (three minutes maximum)

Only do this if the beginner demo finished early.

1. Launch **Chronos Engine** from the scoreboard.
2. Copy the launch URL from the challenge page.
3. In a terminal, run:

```powershell
.\.venv\Scripts\python.exe challenges\02-chronos-engine\solve.py --launch "<launch-url>"
```

4. Explain while it runs:

> The service derives its ECDSA nonce from a 60-second epoch. Two signatures in
> the same epoch reuse the same `k`. From two signatures:

```text
s1 = k^-1 (z1 + r d)
s2 = k^-1 (z2 + r d)
```

> Subtract them, recover `k`, then recover the private key `d`. Finally, sign
> the exact message `vault:admin` and open the vault.

The solver retries across an epoch boundary automatically. If it takes longer
than about 60 seconds, stop it and explain the math instead. Do not let it
consume the interview.

### Chronos in 60 seconds

If they ask "what is the second challenge?", say:

> Chronos is a fictional audit signer. It signs public `timeline:*` messages with
> ECDSA, but it derives the nonce from a 60-second epoch. Two different messages
> signed in the same epoch reuse the same nonce. That leaks the private key.
> Once I have the key, I can sign the privileged `vault:admin` message that the
> public oracle refuses to sign, and the vault returns the flag.

Then show `/api/meta`:

- curve: secp256k1
- hash: SHA-256
- nonce scheme: deterministic, epoch-derived
- required attestation: `vault:admin`
- vault endpoint: `/api/vault/open`

### The math, in the simplest form

ECDSA signing:

```text
s = k^-1 (z + r d) mod n
```

Two messages, same nonce `k`:

```text
s1 = k^-1 (z1 + r d)
s2 = k^-1 (z2 + r d)
```

Subtract:

```text
s1 - s2 = k^-1 (z1 - z2)
k       = (z1 - z2) / (s1 - s2) mod n
```

Substitute back:

```text
d = (s1 k - z1) / r mod n
```

`n` is the secp256k1 group order. `r` is the x-coordinate of `kG` modulo `n`.
Same `k` means the same `r`, which is why two signatures with the same `r` are
the giveaway.

### Where it lives in the code

- `challenges/02-chronos-engine/app.py` → `_nonce_for_epoch()`:
  `SHA256(nonce_seed + ":" + epoch)`, then reduce into the scalar range.
- `app.py` → `/api/sign`: rejects anything that does not start with `timeline:`,
  then signs with the epoch nonce.
- `app.py` → `/api/vault/open`: accepts only `vault:admin`, parses hex `r`/`s`,
  and verifies with the team's public key.
- `challenges/02-chronos-engine/solve.py` → `recover_private_key()`: the two
  formulas above, followed by a public-key sanity check.

If they ask to see code, show `_nonce_for_epoch()` and `recover_private_key()`.
Do not open the whole curve implementation unless they specifically ask.

### Chronos-specific questions

**Why does reusing `k` leak the key?**
Two linear equations share the unknown `k` and `d`. Subtract them and `d`
cancels out, so `k` becomes solvable. Substitute `k` back and `d` falls out.

**Why is `r` the same?**
`r` is the x-coordinate of `kG`. Same nonce means the same point and the same
`r`. A repeated `r` across different messages is a critical red flag.

**Why did the developer use an epoch nonce?**
The fictional story is "reproducible audit signatures." It is a plausible but
fatal design choice. In real crypto, nonces must never be derived from public,
predictable, or repeated input.

**Why doesn't the `timeline:` restriction save the service?**
The restriction only applies to the oracle. After recovering `d`, the attacker
signs `vault:admin` locally. The key, not the endpoint, is the trust boundary.

**How does the solver know it recovered the right key?**
It derives the public key from the recovered `d` and compares it with
`/api/meta`. If they differ, it aborts instead of submitting a bad forgery.

**How do you get two signatures in the same epoch?**
Request two different `timeline:*` messages back to back. If the `r` values
differ, the calls crossed an epoch boundary; wait for the next epoch and retry.
The solver does this automatically up to three times.

**What is hashed for `vault:admin`?**
The exact ASCII string `vault:admin`, with SHA-256, reduced modulo `n`. No JSON
wrapper and no newline.

**Why hex `r` and `s`?**
The vault expects hexadecimal integers. The solver formats them with `0x` and
zero-padding.

**What if the signature is shared with another team?**
Each team has a different private key and nonce seed derived from
`FLAG_SECRET` and the team ID. A signature that opens team A's vault is invalid
on team B's public key.

**How would you fix it?**
Use a CSPRNG nonce or RFC 6979 deterministic nonces, which bind the nonce to the
message and private key rather than to a timestamp. Never derive a nonce from
an epoch, counter, or other public value. Use a maintained constant-time crypto
library. Do not expose a signing oracle for a key that protects a higher-value
action, and monitor for repeated `r` values.

**Is the custom curve code production-ready?**
No. It is deliberately small and not constant-time, written only to model the
flaw. Production code should use a maintained library.

**What is the flag?**
Platform mode: `GDG{chronos_<20 hex>}`, unique per team. Standalone mode:
`GDG{n0nc3_r3us3_1s_f4t4l}`.

**What if the live solver stalls?**
Wait up to 60 seconds while explaining the math. If it still has not finished,
stop it and say: "The solver is waiting for two signatures in the same epoch.
The attack itself is two requests; the wait is just the epoch boundary." Then
move on.

---

## Questions they may ask

**Why these two challenges?**
One teaches authentication versus authorization; the other teaches a classic
crypto failure. Together they cover beginner and experienced players.

**Why Flask, SQLite, and Waitress?**
They are free, available on any student laptop, and easy to audit. SQLite is
enough for a small event, and Waitress avoids shipping the Flask development
server. No Docker means no per-team container overhead.

**How do you prevent flag sharing?**
Per-team HMAC flags, signed launch tokens, per-team Chronos keys, and an audit
trail. A copied flag is rejected and logged. It does not stop deliberate account
sharing, so the organizer still reviews the logs.

**What are the limitations?**
No isolation, launch URLs act like passwords, in-memory rate limits reset on
restart, IP evidence is weak behind NAT, and the admin is manual.

**How would you scale it?**
For a small event, one laptop is enough. For a larger event I would move to
Postgres, a shared rate-limit store, multiple workers, and isolated challenge
containers. I would keep the per-team flag derivation because it is independent
of the deployment model.

**What was the hardest part?**
Making the crypto challenge reproducible: a small secp256k1 implementation,
per-team keys, an epoch-based nonce, and a solver that verifies the recovered
key before submitting. The deployment constraint was also deliberate: three
services, one command, no Docker.

**How would you teach this to beginners?**
Start with the request in DevTools, explain authentication versus authorization,
then let them change the ID themselves. Use the hints as a ladder, not as a
walkthrough. Finish with the fix and a real-world example.

**How do you handle a cheating incident?**
Export the audit CSV, review the submission and IP history, talk to the team,
and use the ban control only for a clear pattern. Do not publish personal data
or flags in the event chat.

**What would you improve next?**
Persistent rate limiting, optional container isolation, a team-facing incident
report form, automated anomaly alerts, and a post-event feedback loop.

---

## Close

> The project is deliberately small: one laptop, three services, two challenges,
> and a scoreboard that can detect the most common form of flag sharing. I
> tested it end to end, including registration, both solves, submissions,
> hints, audit, and ban. I would be glad to walk through any part in more detail.

Then stop talking and let them ask questions.

---

## If something breaks

- **Port already in use:** stop the old Python process, then start again.
- **Challenge says "launch from the scoreboard":** you opened 8081 or 8082
  directly. Use the Launch button.
- **Chronos solver waits:** it is waiting for two signatures in one epoch. Wait
  up to 60 seconds, or skip the live solve and explain the math.
- **Internet drops:** the local demo does not need internet. Keep the stack
  running and switch to your phone hotspot only if Discord disconnects.
- **Screen share shows the wrong window:** stop sharing and share only the
  browser window again.

Do not debug for more than 30 seconds in the interview. Say what you expected,
show the fallback, and keep moving.
