"""
The Intern's Secret — beginner web challenge.

Intentionally vulnerable: the note API checks that a user is logged in but does
not check that the requested note belongs to that user. This is a deliberately
small IDOR (Insecure Direct Object Reference) challenge for a beginner CTF.

Do not deploy this as a real application.
"""

from __future__ import annotations

import hmac
import os
import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

# Support both the repository layout and the Docker image layout.
_HERE = Path(__file__).resolve().parent
for _base in (_HERE, _HERE.parent, _HERE.parent.parent):
    if (_base / "shared" / "team_context.py").is_file():
        sys.path.insert(0, str(_base))
        break

from shared.team_context import init_team_context, team_flag  # noqa: E402

DEFAULT_FLAG = "GDG{1d0r_1s_n0t_4_d00r}"
INSTANCE_ID = os.environ.get("INSTANCE_ID", "local")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-only-change-me"),
    SESSION_COOKIE_NAME="gdg_interns_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
    PERMANENT_SESSION_LIFETIME=43200,
)
app.config["JSON_SORT_KEYS"] = False

init_team_context(app, "interns-secret", "intern", DEFAULT_FLAG)

USERS: dict[int, dict[str, Any]] = {
    42: {
        "id": 42,
        "username": "maya.intern",
        "password": "coffee-first",
        "name": "Maya Chen",
        "role": "Intern",
    },
    1: {
        "id": 1,
        "username": "admin",
        "password": "not-a-real-password",
        "name": "Priya Raman",
        "role": "Head of Platform",
    },
}

NOTES: dict[int, dict[str, Any]] = {
    1: {
        "id": 1,
        "owner_id": 1,
        "title": "Executive onboarding note",
        "visibility": "private",
        "body": (
            "Welcome aboard.\n\n"
            "The final piece of the platform handover is the vault key. "
            "Keep it out of public channels: {flag}\n\n"
            "Do not forward this note."
        ),
    },
    101: {
        "id": 101,
        "owner_id": 42,
        "title": "Day 1 checklist",
        "visibility": "private",
        "body": (
            "1. Collect laptop.\n"
            "2. Read the platform glossary.\n"
            "3. Ask @ops for staging access.\n"
            "4. Do not touch the legacy admin notes."
        ),
    },
    102: {
        "id": 102,
        "owner_id": 42,
        "title": "Coffee machine cheat sheet",
        "visibility": "private",
        "body": "The machine on floor 3 makes a very respectable flat white. That is all.",
    },
    103: {
        "id": 103,
        "owner_id": 42,
        "title": "Glossary",
        "visibility": "private",
        "body": "Temporal: anything the platform team has not finished migrating yet.",
    },
}


def current_user() -> dict[str, Any] | None:
    uid = session.get("uid")
    if isinstance(uid, int):
        return USERS.get(uid)
    return None


def note_body(note: dict[str, Any]) -> str:
    if note["id"] == 1:
        return note["body"].format(flag=team_flag("interns-secret", "intern", DEFAULT_FLAG))
    return note["body"]


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.get("/")
def index() -> Any:
    if current_user() is not None:
        return redirect(url_for("dashboard"))
    return render_template("login.html", instance_id=INSTANCE_ID)


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if request.method == "GET":
        if current_user() is not None:
            return redirect(url_for("dashboard"))
        return render_template("login.html", instance_id=INSTANCE_ID)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    for user in USERS.values():
        if user["username"] == username and hmac.compare_digest(user["password"], password):
            # Keep the platform team binding: the note flag is derived from it.
            team_id = session.get("team_id")
            team_name = session.get("team_name")
            session.clear()
            if isinstance(team_id, int) and isinstance(team_name, str):
                session["team_id"] = team_id
                session["team_name"] = team_name[:64]
            session["uid"] = user["id"]
            return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Those credentials did not match the onboarding invite.",
        instance_id=INSTANCE_ID,
    ), 401


@app.post("/logout")
def logout() -> Any:
    session.clear()
    return redirect(url_for("index"))


@app.get("/dashboard")
@login_required
def dashboard() -> Any:
    user = current_user()
    assert user is not None
    owned_notes = [n for n in NOTES.values() if n["owner_id"] == user["id"]]
    return render_template("dashboard.html", user=user, notes=owned_notes, instance_id=INSTANCE_ID)


@app.get("/api/notes/<int:note_id>")
@login_required
def get_note(note_id: int) -> Any:
    """
    Intended beginner bug: authentication is checked, authorization is not.
    Any signed-in user can read any note by changing the numeric id.
    """
    note = NOTES.get(note_id)
    if note is None:
        return jsonify({"error": "note not found"}), 404

    return jsonify(
        {
            "id": note["id"],
            "title": note["title"],
            "body": note_body(note),
            "owner_id": note["owner_id"],
        }
    )


@app.get("/healthz")
def healthz() -> Any:
    return jsonify({"status": "ok", "service": "interns-secret"})


@app.get("/robots.txt")
def robots() -> Any:
    return "User-agent: *\nDisallow: /api/\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.after_request
def security_headers(response: Any) -> Any:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    )
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(404)
def not_found(_: Any) -> Any:
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found"}), 404
    return render_template("404.html"), 404


if __name__ == "__main__":
    # Local development only. Production uses gunicorn from the Dockerfile.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8081")), debug=False)
