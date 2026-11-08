# GDG CTF Lite

Two fictional CTF challenges and a self-contained scoreboard that run from **one
student laptop**. No VPS, no cloud account, no Docker, no per-team containers.

- **The Intern's Secret** — beginner web challenge (IDOR), 100 points.
- **Chronos Engine** — experienced crypto/web challenge (ECDSA nonce reuse), 300 points.
- **GDG CTF Lite** — Flask + SQLite + Waitress scoreboard with per-team flags,
  three-step hint ladders, and an organizer audit page.

Everything is free and open source (MIT). All targets, companies, and people in
the challenges are fictional.

> **This repository contains spoilers.** It includes full writeups, hint
> ladders, reference exploits, and the static fallback flags. Publish it as an
> organizer resource, not as a player handout. Participants only need the
> scoreboard URL (see [What to give participants](#what-to-give-participants)).

---

## Quick start

Requirements: Python **3.10+**, pip, and a laptop on the same Wi-Fi as the players.

### Windows (PowerShell)

```powershell
cd "C:\path\to\gdg ctf"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run_all.py
```

If PowerShell blocks activation, run this once for the current window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### macOS / Linux

```bash
cd /path/to/gdg-ctf
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run_all.py
```

`run_all.py` prints the LAN address to share with players, for example:

```
Scoreboard:      http://192.168.1.20:8000
Interns Secret:  http://192.168.1.20:8081  (launch from the scoreboard)
Chronos Engine:  http://192.168.1.20:8082  (launch from the scoreboard)
Organizer audit: http://192.168.1.20:8000/admin  (user: organizer)
```

Players open **only the scoreboard URL**, register a team, and use the launch
buttons. They never clone the repository, install anything, or connect to a
challenge port directly.

On first start the app creates `instance/secrets.json` (shared HMAC secrets and
the organizer password) and `instance/ctf.db`. **Keep `instance/` private.** It
is already in `.gitignore`.

> If Windows Firewall asks, allow Python on **Private networks**. For a manual
> rule and macOS/Linux instructions, see [`docs/HOSTING.md`](docs/HOSTING.md).

---

## What to give participants

**Give them one thing: the scoreboard URL.**

```text
http://<LAN-IP>:8000
```

Do **not** give them this repository, a ZIP of it, the challenge folders, or the
challenge ports. The scoreboard serves everything a player needs:

- team registration and login
- the rules page
- challenge briefs and launch buttons (with signed team sessions)
- three-step hint ladders
- flag submission
- the live scoreboard
- the optional `chronos_client.py` download on the Chronos page

Players do not need Python, Git, Docker, or any install. They only need a
browser. Use one team per browser profile.

### Copy-paste participant message

Replace `<LAN-IP>` with the address printed by `run_all.py`.

> **GDG CTF — [date/time]**
>
> Bring a laptop and open:
> **http://<LAN-IP>:8000**
>
> Register your team on that page. Both challenges launch from the scoreboard —
> don't open the challenge ports directly.
>
> - One team per browser profile. If you share a laptop, use separate profiles
>   or private windows.
> - No installs needed. Everything runs in the browser.
> - Three sequential hints per challenge; each hint deducts points.
> - Flags look like `GDG{...}`. Submit them on the challenge page.
> - Shared flags don't work: each team gets its own flag.
>
> Rules are on the scoreboard. Good luck!

### Keep private (organizer only)

Never send or publish these during an event:

| Path | Why |
|---|---|
| `challenges/*/WRITEUP.md` | full solution |
| `challenges/*/HINTS.md` | exact hint ladder |
| `challenges/*/solve.py` | working exploit |
| `challenges/*/README.md` | organizer notes, flags, API details |
| `docs/FLAGS.md` | every static flag |
| `docs/ANTI_CHEAT.md` | detection and response playbook |
| `instance/secrets.json` | derives every team flag and the organizer password |
| `instance/ctf.db` | live teams, submissions, and audit log |
| `/admin` | organizer audit page |

The scoreboard pages and `docs/HOSTING.md` are safe to share. Avoid sharing this
README during the event: it names both bugs and lists the standalone fallback
flags.

### If someone asks for the challenge files

The challenges are browser-based; players do not need the source. If you are
running a source-review workshop, build a **sanitized player copy** containing
only the files needed to read the app, and omit the writeups, hints, `solve.py`,
challenge `README.md`, `instance/`, and `docs/FLAGS.md`.

Do not hand out the repository "just in case". It leaks the solutions, the
static fallback flags, and the organizer playbook, and it weakens the per-team
scoring model.

---

## Event flow

1. Organizer starts `run_all.py` and shares the `http://LAN-IP:8000` link.
2. Players register a team (optionally protected by `REGISTRATION_CODE`).
3. The scoreboard signs a team token into each challenge launch URL. The
   challenge service stores the team in its own session and removes the token
   from the address bar.
4. Players solve the challenge and submit the flag on the scoreboard.
5. Hints unlock sequentially and subtract their cost from the team score.
6. The organizer reviews `/admin` (HTTP Basic) for submissions, audit events,
   and cross-team flag attempts.

### Ports

| Service | Port | Purpose |
|---|---:|---|
| Scoreboard | 8000 | Registration, challenges, hints, submissions, `/admin` |
| The Intern's Secret | 8081 | Challenge app (launch through the scoreboard) |
| Chronos Engine | 8082 | Challenge app (launch through the scoreboard) |

---

## Architecture

```
                       player browser
                             |
                 http://LAN-IP:8000  (scoreboard)
                             |
                  Flask + SQLite + Waitress
                             |
          signed team token in the launch URL (?t=...)
                 /                           \
    http://LAN-IP:8081                 http://LAN-IP:8082
    The Intern's Secret                Chronos Engine
    per-team note flag                 per-team ECDSA key + flag
```

The scoreboard does not provision a canonical flag table. It recomputes each
team's flag from
`HMAC(FLAG_SECRET, team_id:challenge)` on demand. Chronos derives a different
private key and nonce seed per team, so a signature forged for one team does not
work on another team's timeline.

Shared session cookie names keep the three Flask apps independent even on the
same host:

- `gdg_platform_session`
- `gdg_interns_session`
- `gdg_chronos_session`

---

## Challenges

| | The Intern's Secret | Chronos Engine |
|---|---|---|
| Level | Beginner | Experienced |
| Category | Web | Crypto / Web |
| Points | 100 | 300 |
| Bug | IDOR on `/api/notes/<id>` | ECDSA nonce reused per 60-second epoch |
| Flag (platform) | `GDG{intern_<20 hex>}` | `GDG{chronos_<20 hex>}` |
| Flag (standalone) | `GDG{1d0r_1s_n0t_4_d00r}` | `GDG{n0nc3_r3us3_1s_f4t4l}` |
| Hints | 3 (5 / 10 / 15 pts) | 3 (10 / 20 / 30 pts) |

Each challenge directory contains a `README.md` (organizer notes), `HINTS.md`
(the exact three-step ladder), and `WRITEUP.md` (full solution). These files
contain spoilers — do not publish them to players.

The flag in a running platform event is **not** the standalone reference flag;
it is derived per team. The reference flags only apply when a challenge app is
started by itself without `TEAM_TOKEN_SECRET`. The organizer spoiler sheet with
all reference flags is [`docs/FLAGS.md`](docs/FLAGS.md).

---

## Anti-cheat in one paragraph

Flag sharing is detected, not just discouraged: a copied flag is another team's
HMAC output, so it never matches and the scoreboard records a
`flag_share_attempt` for organizer review. Launch tokens are signed and expire
after 12 hours; tampered tokens are rejected. Chronos keys are per team, so a
valid forged signature from team A is invalid on team B's instance. Submission,
login, registration, and signing endpoints are rate-limited. The organizer page
and audit CSV sit behind HTTP Basic with a generated password. See
[`docs/ANTI_CHEAT.md`](docs/ANTI_CHEAT.md) for the threat model, limitations, and
response playbook.

---

## Project layout

```
run_all.py                     starts all three services, creates secrets
requirements.txt               runtime dependencies
requirements-dev.txt           pytest + requests for tests
.github/workflows/tests.yml    GitHub Actions unit-test workflow
scoreboard/                    GDG CTF Lite platform
  app.py                       auth, submissions, hints, audit, admin
  challenges.py                challenge catalog + hint text
  templates/                   platform pages
  static/files/chronos_client.py  optional helper for players
challenges/01-interns-secret/  beginner IDOR challenge
challenges/02-chronos-engine/  experienced ECDSA challenge
  solve.py                     reference exploit (organizer/writeup use)
shared/team_context.py         signed tokens, launch guard, HMAC flags
tests/e2e_check.py             live three-service end-to-end check
tests/test_challenges.py       unit tests for tokens, flags, and challenges
tests/test_scoreboard.py       unit tests for scoring and flag-share audit
tools/flag_lookup.py           organizer tool to recompute a team's flag
docs/HOSTING.md                laptop/LAN runbook + optional free tunnels
docs/ANTI_CHEAT.md             controls, limits, organizer playbook
docs/FLAGS.md                  organizer spoiler sheet
SECURITY.md                    deliberate-vulnerability and reporting policy
instance/                      generated secrets + SQLite DB (private)
```

---

## Testing

With `run_all.py` running, in a second terminal:

```bash
python -m pip install -r requirements-dev.txt
python tests/e2e_check.py
```

The E2E check registers throwaway teams, launches both challenges through
signed tokens, solves the beginner IDOR, runs the Chronos solver through the
launch URL, submits both flags, verifies the 400-point score, confirms that a
copied flag is rejected and audited, exercises the sequential hint ladder and
score deduction, then verifies the organizer audit page, CSV export, and ban
action.

Unit tests (no running server required):

```bash
python -m pytest -q
```

---

## Publishing to GitHub

The repository ships a `.gitignore`, `.gitattributes`, an MIT license, a
security policy, and a GitHub Actions test workflow, so it is ready to push.

The repository intentionally contains challenge spoilers. Keep it **private
while the event is live**, then make it public afterward if you want to share
the organizer material.

### Push this prepared repository

This folder is already a Git repository with an initial commit on `main`.
Create an **empty** repository on GitHub (no README, no `.gitignore`), then:

```bash
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

If you copied the files without the `.git` directory, initialize and commit
first:

```bash
git init -b main
git add .
git status                 # confirm instance/ and caches are absent
git commit -m "GDG CTF Lite: two challenges and a laptop scoreboard"
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

Before committing, confirm the event state is ignored:

```bash
git check-ignore -v instance instance/ctf.db instance/secrets.json
```

`instance/` must never appear in `git status` or on GitHub. It contains the
flag-derivation secret and the organizer password.

### Suggested repository settings

- **Private** during the event; public after the awards if you want to publish.
- Enable **secret scanning** and **push protection**.
- Protect `main` and require the **tests** workflow to pass.
- Add a short description: "Two beginner/experienced CTF challenges plus a
  laptop-hosted Flask scoreboard. Organizer package; contains spoilers."
- Never attach `instance/`, a live database, or event audit exports to a
  release.

The workflow in `.github/workflows/tests.yml` runs the unit tests on Python
3.10 and 3.12 for every push and pull request. The live three-service E2E check
is intentionally manual because it needs `run_all.py` running; run it before
tagging a release.

### Making a release

```bash
git tag -a v1.0.0 -m "GDG CTF Lite v1.0.0"
git push origin v1.0.0
```

GitHub's automatic source archives contain the writeups and spoilers. Do not
send players a repository link or a source archive; give them only the running
scoreboard URL.

---

## Operational notes

- **Reset a test event:** stop the server, delete `instance/ctf.db`, restart.
  Delete `instance/secrets.json` too if you want brand-new flags and organizer
  password. Never delete secrets during a live event.
- **Public / remote event:** set `REGISTRATION_CODE` before starting. LAN is the
  primary mode; free tunnel instructions and caveats are in
  [`docs/HOSTING.md`](docs/HOSTING.md).
- **Campus Wi-Fi:** many campus and guest networks block device-to-device
  traffic. Use a phone hotspot or a small router if players cannot reach the
  laptop. This is the most common student-event failure, and it is a network
  policy issue, not an app issue.
- **Keep the laptop awake and plugged in.** Closing the lid usually stops the
  event.
- **Projector:** show `/scoreboard`, never `/admin` or `instance/secrets.json`.

---

## Safety and scope

This repository is a training target. It contains deliberately vulnerable code
and must not be deployed as a real service. The challenges do not use real
companies, real people, real credentials, or real user data. Only run the
optional public tunnel against this application, and only for participants you
invite. See [`docs/HOSTING.md`](docs/HOSTING.md) for the safety checklist.

## License

MIT — see [`LICENSE`](LICENSE).
