"""
GDG CTF Lite — a small, dependency-light scoreboard for a laptop-hosted event.

This is intentionally a small application, not a replacement for CTFd. It is
designed for a single trusted host, a few dozen teams, and a short event:

* SQLite instead of a database server
* signed team tokens instead of per-team containers
* per-team HMAC-derived flags and per-team Chronos keys
* submission auditing for accidental or deliberate flag sharing

Run it through run_all.py so the shared secrets and service URLs are wired up.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:  # one trusted reverse proxy in front of the app (optional)
    from werkzeug.middleware.proxy_fix import ProxyFix
except ImportError:  # pragma: no cover
    ProxyFix = None  # type: ignore[assignment]

from .challenges import CHALLENGE_BY_SLUG, CHALLENGES
from shared.team_context import make_team_token

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE_DIR / "instance" / "ctf.db"
DB_PATH = Path(os.environ.get("DB_PATH", str(DEFAULT_DB)))
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "").strip()
ORGANIZER_KEY = os.environ.get("ORGANIZER_KEY", "").strip()
TEAM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{2,31}$")
SUBMISSION_LIMIT = 12
SUBMISSION_WINDOW = 60
LOGIN_LIMIT = 10
LOGIN_WINDOW = 300

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-only-change-me"),
    SESSION_COOKIE_NAME="gdg_platform_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=32 * 1024,
    PERMANENT_SESSION_LIFETIME=43200,
)

if os.environ.get("TRUST_PROXY", "0") == "1" and ProxyFix is not None:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_ip TEXT NOT NULL,
            banned INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS solves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip TEXT NOT NULL,
            UNIQUE(team_id, challenge_id)
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL,
            provided TEXT NOT NULL,
            correct INTEGER NOT NULL,
            kind TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hint_unlocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL,
            hint_level INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(team_id, challenge_id, hint_level)
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            team_id INTEGER,
            detail TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_solves_team ON solves(team_id);
        CREATE INDEX IF NOT EXISTS idx_submissions_team ON submissions(team_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
        """
    )
    conn.commit()
    conn.close()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def client_ip() -> str:
    return request.remote_addr or "unknown"


def rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False


def csrf_token() -> str:
    token = session.get("_csrf")
    if not isinstance(token, str) or len(token) < 20:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def verify_csrf() -> None:
    expected = session.get("_csrf", "")
    provided = request.form.get("_csrf", "")
    if (
        not isinstance(expected, str)
        or len(expected) < 20
        or not isinstance(provided, str)
        or not hmac.compare_digest(expected, provided)
    ):
        abort(400, description="CSRF token mismatch")


def current_team() -> sqlite3.Row | None:
    team_id = session.get("team_id")
    if not isinstance(team_id, int):
        return None
    row = get_db().execute("SELECT * FROM teams WHERE id = ?", (team_id,)).fetchone()
    if row is None or row["banned"]:
        session.clear()
        return None
    return row


def login_required(view: Any) -> Any:
    from functools import wraps

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_team() is None:
            flash("Sign in to open the challenge board.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def flag_for(team_id: int, challenge_slug: str) -> str:
    challenge = CHALLENGE_BY_SLUG[challenge_slug]
    digest = hmac.new(
        os.environ.get("FLAG_SECRET", "local-dev-only-flag-secret").encode("utf-8"),
        f"{team_id}:{challenge_slug}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    return f"GDG{{{challenge['flag_prefix']}_{digest}}}"


def audit(kind: str, team_id: int | None, detail: str) -> None:
    get_db().execute(
        "INSERT INTO audit(kind, team_id, detail, ip, created_at) VALUES (?,?,?,?,?)",
        (kind, team_id, detail[:1000], client_ip(), utcnow()),
    )
    get_db().commit()


def team_solved(team_id: int) -> set[str]:
    rows = get_db().execute("SELECT challenge_id FROM solves WHERE team_id = ?", (team_id,)).fetchall()
    return {row["challenge_id"] for row in rows}


def team_hints(team_id: int) -> set[tuple[str, int]]:
    rows = get_db().execute(
        "SELECT challenge_id, hint_level FROM hint_unlocks WHERE team_id = ?", (team_id,)
    ).fetchall()
    return {(row["challenge_id"], row["hint_level"]) for row in rows}


def team_score(team_id: int) -> int:
    solved = team_solved(team_id)
    score = sum(CHALLENGE_BY_SLUG[slug]["points"] for slug in solved if slug in CHALLENGE_BY_SLUG)
    hints = team_hints(team_id)
    for slug, level in hints:
        challenge = CHALLENGE_BY_SLUG.get(slug)
        if challenge and 1 <= level <= len(challenge["hints"]):
            score -= challenge["hints"][level - 1]["cost"]
    return max(0, score)


def challenge_url(slug: str) -> str:
    challenge = CHALLENGE_BY_SLUG[slug]
    return os.environ.get(challenge["url_env"], challenge["default_url"]).rstrip("/")


def launch_url(slug: str) -> str:
    team = current_team()
    if team is None:
        raise RuntimeError("launch_url requires a signed-in team")
    token = make_team_token(team["id"], team["name"])
    return f"{challenge_url(slug)}/?t={quote(token)}"


def scoreboard_rows() -> list[dict[str, Any]]:
    teams = get_db().execute(
        "SELECT id, name, created_at FROM teams WHERE banned = 0 ORDER BY id"
    ).fetchall()
    rows: list[dict[str, Any]] = []
    for team in teams:
        solve_rows = get_db().execute(
            "SELECT challenge_id, created_at FROM solves WHERE team_id = ? ORDER BY created_at",
            (team["id"],),
        ).fetchall()
        last_solve = solve_rows[-1]["created_at"] if solve_rows else None
        rows.append(
            {
                "id": team["id"],
                "name": team["name"],
                "score": team_score(team["id"]),
                "solves": [r["challenge_id"] for r in solve_rows],
                "last_solve": last_solve,
            }
        )
    rows.sort(key=lambda row: (-row["score"], row["last_solve"] or "9999"))
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
    return rows


@app.before_request
def before_request() -> None:
    get_db()


@app.context_processor
def inject_globals() -> dict[str, Any]:
    team = current_team()
    return {
        "current_team": team,
        "csrf_token": csrf_token(),
        "challenges": CHALLENGES,
        "challenge_by_slug": CHALLENGE_BY_SLUG,
        "event_name": os.environ.get("EVENT_NAME", "GDG CTF"),
        "now": utcnow,
    }


@app.get("/")
def index() -> Any:
    if current_team() is not None:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register() -> Any:
    if request.method == "GET":
        if current_team() is not None:
            return redirect(url_for("dashboard"))
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE))

    verify_csrf()
    if rate_limited(f"register:{client_ip()}", 5, 600):
        flash("Too many registration attempts. Wait a few minutes.", "error")
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE)), 429

    name = (request.form.get("name") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    invite = (request.form.get("invite") or "").strip()

    if REGISTRATION_CODE and not hmac.compare_digest(invite, REGISTRATION_CODE):
        flash("That event invite code is not valid.", "error")
        return render_template("register.html", needs_code=True), 403
    if not TEAM_NAME_RE.match(name):
        flash("Team name must be 3–32 characters: letters, numbers, spaces, dot, dash, underscore.", "error")
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE)), 400
    if len(password) < 8:
        flash("Use at least 8 characters for the team password.", "error")
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE)), 400
    if password != confirm:
        flash("The two password fields do not match.", "error")
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE)), 400

    try:
        db = get_db()
        cur = db.execute(
            "INSERT INTO teams(name, password_hash, created_at, created_ip) VALUES (?,?,?,?)",
            (name, generate_password_hash(password), utcnow(), client_ip()),
        )
        team_id = int(cur.lastrowid)
        db.commit()
    except sqlite3.IntegrityError:
        flash("That team name is already registered.", "error")
        return render_template("register.html", needs_code=bool(REGISTRATION_CODE)), 409

    session.clear()
    session.permanent = True
    session["team_id"] = team_id
    audit("team_registered", team_id, f"team={name}")
    flash("Team created. Read the rules, then open your first challenge.", "success")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if request.method == "GET":
        if current_team() is not None:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    verify_csrf()
    if rate_limited(f"login:{client_ip()}", LOGIN_LIMIT, LOGIN_WINDOW):
        flash("Too many sign-in attempts. Wait a few minutes.", "error")
        return render_template("login.html"), 429

    name = (request.form.get("name") or "").strip()
    password = request.form.get("password") or ""
    row = get_db().execute("SELECT * FROM teams WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if row is None or row["banned"] or not check_password_hash(row["password_hash"], password):
        audit("failed_login", row["id"] if row else None, f"name={name[:64]}")
        flash("Team name or password is incorrect.", "error")
        return render_template("login.html"), 401

    next_path = request.args.get("next") or request.form.get("next") or ""
    session.clear()
    session.permanent = True
    session["team_id"] = row["id"]
    audit("login", row["id"], f"team={row['name']}")
    flash(f"Welcome back, {row['name']}.", "success")
    if next_path.startswith("/") and not next_path.startswith("//"):
        return redirect(next_path)
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout() -> Any:
    verify_csrf()
    team = current_team()
    if team:
        audit("logout", team["id"], f"team={team['name']}")
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("index"))


@app.get("/dashboard")
@login_required
def dashboard() -> Any:
    team = current_team()
    assert team is not None
    solved = team_solved(team["id"])
    hints = team_hints(team["id"])
    submissions = get_db().execute(
        "SELECT * FROM submissions WHERE team_id = ? ORDER BY id DESC LIMIT 25",
        (team["id"],),
    ).fetchall()
    return render_template(
        "dashboard.html",
        team=team,
        solved=solved,
        hints=hints,
        submissions=submissions,
        score=team_score(team["id"]),
    )


@app.get("/challenges")
@login_required
def challenges() -> Any:
    team = current_team()
    assert team is not None
    solved = team_solved(team["id"])
    hints = team_hints(team["id"])
    return render_template("challenges.html", solved=solved, hints=hints, score=team_score(team["id"]))


@app.get("/challenge/<slug>")
@login_required
def challenge_detail(slug: str) -> Any:
    challenge = CHALLENGE_BY_SLUG.get(slug)
    if challenge is None:
        abort(404)
    team = current_team()
    assert team is not None
    solved = slug in team_solved(team["id"])
    unlocked = {level for slug2, level in team_hints(team["id"]) if slug2 == slug}
    return render_template(
        "challenge.html",
        challenge=challenge,
        solved=solved,
        unlocked=unlocked,
        launch=launch_url(slug),
        own_flag=flag_for(team["id"], slug) if solved else None,
        score=team_score(team["id"]),
    )


@app.post("/challenge/<slug>/hint")
@login_required
def unlock_hint(slug: str) -> Any:
    verify_csrf()
    challenge = CHALLENGE_BY_SLUG.get(slug)
    if challenge is None:
        abort(404)
    team = current_team()
    assert team is not None
    try:
        level = int(request.form.get("level", "0"))
    except ValueError:
        abort(400)
    if not 1 <= level <= len(challenge["hints"]):
        abort(400)
    unlocked_levels = {lvl for slug2, lvl in team_hints(team["id"]) if slug2 == slug}
    if level > 1 and level - 1 not in unlocked_levels:
        flash(f"Unlock hint {level - 1} first.", "error")
        return redirect(url_for("challenge_detail", slug=slug))
    try:
        get_db().execute(
            "INSERT INTO hint_unlocks(team_id, challenge_id, hint_level, created_at) VALUES (?,?,?,?)",
            (team["id"], slug, level, utcnow()),
        )
        get_db().commit()
        flash(f"Hint {level} unlocked for {challenge['title']}.", "success")
    except sqlite3.IntegrityError:
        flash("That hint is already unlocked.", "info")
    return redirect(url_for("challenge_detail", slug=slug))


@app.post("/challenge/<slug>/submit")
@login_required
def submit_flag(slug: str) -> Any:
    verify_csrf()
    challenge = CHALLENGE_BY_SLUG.get(slug)
    if challenge is None:
        abort(404)
    team = current_team()
    assert team is not None

    if rate_limited(f"submit:{team['id']}", SUBMISSION_LIMIT, SUBMISSION_WINDOW):
        flash("Too many submissions. Take a breath and try again in a minute.", "error")
        return redirect(url_for("challenge_detail", slug=slug))

    provided = (request.form.get("flag") or "").strip()
    expected = flag_for(team["id"], slug)
    correct = bool(provided) and hmac.compare_digest(provided, expected)

    if correct:
        try:
            get_db().execute(
                "INSERT INTO solves(team_id, challenge_id, created_at, ip) VALUES (?,?,?,?)",
                (team["id"], slug, utcnow(), client_ip()),
            )
            get_db().commit()
            get_db().execute(
                "INSERT INTO submissions(team_id, challenge_id, provided, correct, kind, ip, created_at) VALUES (?,?,?,?,?,?,?)",
                (team["id"], slug, provided[:200], 1, "correct", client_ip(), utcnow()),
            )
            get_db().commit()
            flash(f"Correct. {challenge['title']} solved.", "success")
        except sqlite3.IntegrityError:
            flash("Your team has already solved this challenge.", "info")
        return redirect(url_for("challenge_detail", slug=slug))

    # Incorrect. Check whether this is another team's flag; if so, log it but
    # return the same generic response so the submitter does not learn that we
    # recognized it.
    shared_from: str | None = None
    for other in get_db().execute("SELECT id, name FROM teams WHERE id != ? AND banned = 0", (team["id"],)):
        if hmac.compare_digest(provided, flag_for(other["id"], slug)):
            shared_from = other["name"]
            break

    kind = "wrong"
    if shared_from:
        kind = "flag_share_attempt"
        audit(
            "flag_share_attempt",
            team["id"],
            f"challenge={slug} submitted_flag_from_team={shared_from}",
        )
    get_db().execute(
        "INSERT INTO submissions(team_id, challenge_id, provided, correct, kind, ip, created_at) VALUES (?,?,?,?,?,?,?)",
        (team["id"], slug, provided[:200], 0, kind, client_ip(), utcnow()),
    )
    get_db().commit()
    flash("Incorrect flag.", "error")
    return redirect(url_for("challenge_detail", slug=slug))


@app.get("/scoreboard")
def scoreboard() -> Any:
    return render_template("scoreboard.html", rows=scoreboard_rows())


def organizer_authorized() -> bool:
    if not ORGANIZER_KEY:
        return False
    auth = request.authorization
    if not auth or auth.type != "basic" or auth.username != "organizer":
        return False
    return hmac.compare_digest(auth.password or "", ORGANIZER_KEY)


def organizer_gate() -> Any:
    if not organizer_authorized():
        return (
            "Organizer access required.",
            401,
            {"WWW-Authenticate": 'Basic realm="GDG CTF organizer", charset="UTF-8"'},
        )
    return None


@app.get("/admin")
def admin() -> Any:
    gate = organizer_gate()
    if gate is not None:
        return gate

    db = get_db()
    teams = db.execute(
        "SELECT id, name, created_at, created_ip, banned FROM teams ORDER BY id"
    ).fetchall()
    team_rows = []
    for team in teams:
        team_rows.append(
            {
                "id": team["id"],
                "name": team["name"],
                "created_at": team["created_at"],
                "created_ip": team["created_ip"],
                "banned": team["banned"],
                "score": team_score(team["id"]),
                "solves": sorted(team_solved(team["id"])),
            }
        )

    submissions = db.execute(
        """
        SELECT s.id, s.challenge_id, s.provided, s.correct, s.kind, s.ip, s.created_at,
               t.name AS team_name
        FROM submissions s JOIN teams t ON t.id = s.team_id
        ORDER BY s.id DESC LIMIT 200
        """
    ).fetchall()
    audit_rows = db.execute(
        """
        SELECT a.id, a.kind, a.team_id, a.detail, a.ip, a.created_at,
               t.name AS team_name
        FROM audit a LEFT JOIN teams t ON t.id = a.team_id
        ORDER BY a.id DESC LIMIT 200
        """
    ).fetchall()

    share_attempts = db.execute(
        "SELECT COUNT(*) AS n FROM submissions WHERE kind = 'flag_share_attempt'"
    ).fetchone()["n"]

    return render_template(
        "admin.html",
        teams=team_rows,
        submissions=submissions,
        audit_rows=audit_rows,
        share_attempts=share_attempts,
    )


@app.post("/admin/team/<int:team_id>/ban")
def admin_ban(team_id: int) -> Any:
    gate = organizer_gate()
    if gate is not None:
        return gate
    verify_csrf()

    action = request.form.get("action", "ban")
    banned = 1 if action == "ban" else 0
    team = get_db().execute("SELECT id, name FROM teams WHERE id = ?", (team_id,)).fetchone()
    if team is None:
        abort(404)
    get_db().execute("UPDATE teams SET banned = ? WHERE id = ?", (banned, team_id))
    get_db().commit()
    audit(
        "team_banned" if banned else "team_unbanned",
        team_id,
        f"team={team['name']}",
    )
    flash(f"{team['name']} {'banned' if banned else 'unbanned'}.", "success")
    return redirect(url_for("admin"))


@app.get("/admin/audit.csv")
def admin_audit_csv() -> Any:
    gate = organizer_gate()
    if gate is not None:
        return gate

    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "kind", "team_id", "team_name", "detail", "ip", "created_at"])
    rows = get_db().execute(
        """
        SELECT a.id, a.kind, a.team_id, t.name AS team_name, a.detail, a.ip, a.created_at
        FROM audit a LEFT JOIN teams t ON t.id = a.team_id
        ORDER BY a.id
        """
    ).fetchall()
    for row in rows:
        writer.writerow(
            [row["id"], row["kind"], row["team_id"], row["team_name"], row["detail"], row["ip"], row["created_at"]]
        )
    return (
        output.getvalue(),
        200,
        {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": "attachment; filename=gdg-ctf-audit.csv",
        },
    )


@app.get("/rules")
def rules() -> Any:
    return render_template("rules.html")


@app.get("/healthz")
def healthz() -> Any:
    return jsonify({"status": "ok", "service": "gdg-ctf-lite"})


@app.get("/static/files/<path:filename>")
def files(filename: str) -> Any:
    return send_from_directory(Path(app.static_folder) / "files", filename, as_attachment=False)


@app.get("/robots.txt")
def robots() -> Any:
    return "User-agent: *\nDisallow: /admin\nDisallow: /static/files\n", 200, {"Content-Type": "text/plain"}


@app.errorhandler(404)
def not_found(_: Any) -> Any:
    return render_template("error.html", code=404, message="That page is not on the board."), 404


@app.errorhandler(400)
def bad_request(error: Any) -> Any:
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request.")), 400


@app.after_request
def security_headers(response: Any) -> Any:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    )
    if request.path.startswith("/challenge/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), debug=False)
