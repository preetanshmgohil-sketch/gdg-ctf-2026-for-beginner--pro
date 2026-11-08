"""
Team context shared by the challenge services and the laptop scoreboard.

The scoreboard signs a short-lived team token and puts it in the launch URL.
A challenge service validates the token, stores the team in its own Flask
session, and removes the token from the browser address bar with a redirect.

The flag and the Chronos private key are derived from the team id with an
HMAC secret. No flags are stored in a database or in the challenge image.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from flask import Flask, Response, g, jsonify, render_template, request, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

TOKEN_SALT = "gdg-team-token-v1"
DEV_TEAM_NAME = os.environ.get("DEV_TEAM_NAME", "Local Demo Team")


def _secret(name: str, default: str) -> str:
    return os.environ.get(name, default)


def team_token_secret() -> str:
    return _secret("TEAM_TOKEN_SECRET", "")


def flag_secret() -> str:
    return _secret("FLAG_SECRET", "local-dev-only-flag-secret")


def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt=TOKEN_SALT)


def make_team_token(team_id: int, team_name: str, secret: str | None = None) -> str:
    secret = secret or team_token_secret()
    if not secret:
        raise RuntimeError("TEAM_TOKEN_SECRET is not configured")
    return _serializer(secret).dumps({"team_id": int(team_id), "team_name": str(team_name)})


def parse_team_token(token: str, secret: str | None = None, max_age: int = 43200) -> dict[str, Any] | None:
    secret = secret or team_token_secret()
    if not secret or not token:
        return None
    try:
        data = _serializer(secret).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired, TypeError, ValueError):
        return None
    try:
        team_id = int(data["team_id"])
        team_name = str(data["team_name"])[:64]
    except (KeyError, TypeError, ValueError):
        return None
    if team_id <= 0:
        return None
    return {"id": team_id, "name": team_name}


def get_team() -> dict[str, Any] | None:
    """Return the current team from the Flask request context."""
    team = getattr(g, "team", None)
    if team:
        return team
    # Optional standalone demo mode: no platform secret, but an explicit team
    # id lets a developer exercise the per-team code path without the platform.
    if not team_token_secret():
        raw = os.environ.get("DEV_TEAM_ID", "").strip()
        if raw:
            try:
                team_id = int(raw)
            except ValueError:
                team_id = 0
            if team_id > 0:
                return {"id": team_id, "name": DEV_TEAM_NAME}
    return None


def derive_flag(team_id: int, challenge_slug: str, prefix: str) -> str:
    digest = hmac.new(
        flag_secret().encode("utf-8"),
        f"{team_id}:{challenge_slug}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    return f"GDG{{{prefix}_{digest}}}"


def team_flag(challenge_slug: str, prefix: str, default_flag: str) -> str:
    team = get_team()
    if team is None:
        return default_flag
    return derive_flag(team["id"], challenge_slug, prefix)


def _strip_token_from_url() -> str:
    pairs = [(k, v) for k, v in request.args.items(multi=True) if k != "t"]
    target = request.path
    if pairs:
        target = f"{target}?{urlencode(pairs)}"
    return target


def init_team_context(app: Flask, challenge_slug: str, prefix: str, default_flag: str) -> None:
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(hours=12))

    @app.before_request
    def load_team() -> Response | None:
        g.team = None

        token = request.args.get("t")
        if request.method == "GET" and token:
            parsed = parse_team_token(token)
            if parsed:
                session.permanent = True
                session["team_id"] = parsed["id"]
                session["team_name"] = parsed["name"]
                return _redirect(_strip_token_from_url())

        team_id = session.get("team_id")
        team_name = session.get("team_name")
        if isinstance(team_id, int) and team_id > 0 and isinstance(team_name, str):
            g.team = {"id": team_id, "name": team_name[:64]}

        # In platform mode a team token is mandatory. In static standalone mode
        # (no TEAM_TOKEN_SECRET) the challenge uses its reference flag.
        if g.team is None and team_token_secret():
            if request.endpoint in {"healthz", "static", "robots"}:
                return None
            if request.path.startswith("/api/"):
                return jsonify({"error": "launch this challenge from the scoreboard"}), 401
            return render_template("launch_required.html"), 401
        return None

    @app.context_processor
    def inject_team() -> dict[str, Any]:
        return {
            "team": get_team(),
            "challenge_slug": challenge_slug,
            "current_flag": team_flag(challenge_slug, prefix, default_flag),
        }


def _redirect(target: str) -> Response:
    from flask import redirect

    return redirect(target, code=302)
