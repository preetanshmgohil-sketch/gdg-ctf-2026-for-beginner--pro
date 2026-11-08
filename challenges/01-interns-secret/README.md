# The Intern's Secret — organizer README

**Level:** Beginner · **Category:** Web · **Points:** 100
**Bug:** Insecure Direct Object Reference (IDOR) on `GET /api/notes/<id>`

> Spoiler warning: this directory also contains `HINTS.md` and `WRITEUP.md`.
> Do not publish those files or this README to players.

## Story

Maya has just joined GDG Labs. Her onboarding portal has a demo account, three
ordinary notes, and a legacy API that opens notes by number. The company's
platform lead left one final handover note behind. Find it and recover the vault
key.

## Player-facing prompt

> The onboarding portal is a quiet place for new joiners to find their first-week
> notes. Maya's account works, but the legacy note API looks older than the rest
> of the app. The platform lead's handover note is still in the system. Can you
> read a note that was never meant for you?

## Access

| Item | Value |
|---|---|
| Username | `maya.intern` |
| Password | `coffee-first` |
| Portal | `http://LAN-IP:8081` after launching from the scoreboard |
| Intended endpoint | `GET /api/notes/1` |

In platform mode, launch the challenge from the scoreboard. The launch link
creates a team session and the note contains the team's derived flag:
`GDG{intern_<20 hex>}`.

In standalone mode (no `TEAM_TOKEN_SECRET`), the reference flag is
`GDG{1d0r_1s_n0t_4_d00r}`.

## Running it by itself

```bash
cd challenges/01-interns-secret
python -m pip install flask
python app.py
```

Open <http://127.0.0.1:8081>, sign in with Maya's credentials, and use the
portal. There is no scoreboard in this mode.

To exercise the per-team code path without the platform:

```bash
# macOS/Linux
DEV_TEAM_ID=7 python app.py

# Windows PowerShell
$env:DEV_TEAM_ID = "7"
python app.py
```

This derives `GDG{intern_<hash>}` for team 7 using the development flag secret.

## Intended vulnerability

`get_note()` checks that a user is signed in but never checks that the requested
note belongs to that user:

```python
note = NOTES.get(note_id)
if note is None:
    return jsonify({"error": "note not found"}), 404
```

Maya owns notes 101–103. Note 1 belongs to the Head of Platform and contains the
flag. Changing the numeric ID is the entire challenge.

The session also stores the platform team binding. The login handler preserves
`team_id`/`team_name` when it clears the session, so the note flag remains the
team's derived flag after Maya signs in.

## Files

```
app.py                     Flask app, users, notes, IDOR endpoint
templates/login.html       sign-in page
templates/dashboard.html   Maya's notes
templates/404.html         not-found page
templates/launch_required.html  shown when a platform token is missing
static/style.css           portal styling
HINTS.md                   exact three-step hint ladder
WRITEUP.md                 full solution and remediation
```

## Verification

```bash
# Static mode
curl -c /tmp/c.txt -d "username=maya.intern&password=coffee-first" \
  http://127.0.0.1:8081/login
curl -b /tmp/c.txt http://127.0.0.1:8081/api/notes/1
```

Expected: JSON containing `GDG{1d0r_1s_n0t_4_d00r}` in the `body` field.

## Remediation (for the debrief)

Add an ownership or role check before returning a note:

```python
user = current_user()
note = NOTES.get(note_id)
if note is None or (note["owner_id"] != user["id"] and user["role"] != "Admin"):
    return jsonify({"error": "note not found"}), 404
```

Return `404` rather than `403` so the endpoint does not confirm that a private
note exists.

## Safety

The company, people, notes, and credentials are fictional. This app is
deliberately vulnerable and must not be reused as a real service.
