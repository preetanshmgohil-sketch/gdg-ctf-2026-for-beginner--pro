#!/usr/bin/env python3
"""End-to-end smoke test for the running three-service stack.

It registers a throwaway team, launches both challenges through signed team
tokens, solves them exactly as a player would, submits both flags, and checks
the scoreboard. Run while `python run_all.py` is active:

    python tests/e2e_check.py
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests

BASE = Path(__file__).resolve().parent.parent
PLATFORM = os.environ.get("PLATFORM_URL", "http://127.0.0.1:8000")
CSRF_RE = re.compile(r'name="_csrf" value="([^"]+)"')
LAUNCH_RE = re.compile(r'href="(http://[^"]+\?t=[^"]+)"')
FLAG_RE = re.compile(r"GDG\{[a-z0-9_]+\}")
NOTE_FLAG_RE = re.compile(r"GDG\{intern_[0-9a-f]{20}\}")


def wait_for(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"{url} did not become ready")


def csrf(page: str) -> str:
    match = CSRF_RE.search(page)
    if not match:
        raise RuntimeError("CSRF token not found in page")
    return match.group(1)


def register(team_name: str, password: str) -> requests.Session:
    session = requests.Session()
    page = session.get(f"{PLATFORM}/register", timeout=10).text
    response = session.post(
        f"{PLATFORM}/register",
        data={
            "_csrf": csrf(page),
            "name": team_name,
            "password": password,
            "confirm": password,
        },
        timeout=10,
        allow_redirects=True,
    )
    response.raise_for_status()
    assert "Team created" in response.text, "registration did not complete"
    return session


def launch_url(session: requests.Session, slug: str) -> str:
    page = session.get(f"{PLATFORM}/challenge/{slug}", timeout=10).text
    match = LAUNCH_RE.search(page)
    if not match:
        raise RuntimeError(f"launch link missing for {slug}")
    return html.unescape(match.group(1))


def solve_beginner(launch: str) -> str:
    base = re.sub(r"/$", "", launch.split("?", 1)[0])

    session = requests.Session()
    response = session.get(launch, timeout=10)
    assert response.status_code == 200
    assert "gdg_interns_session" in session.cookies, "team token did not create a session"
    assert "?t=" not in response.url, "token was not stripped from the URL"

    login = session.post(
        f"{base}/login",
        data={"username": "maya.intern", "password": "coffee-first"},
        timeout=10,
    )
    login.raise_for_status()
    note = session.get(f"{base}/api/notes/1", timeout=10)
    note.raise_for_status()
    body = note.json()["body"]
    match = NOTE_FLAG_RE.search(body)
    if not match:
        raise RuntimeError(f"per-team flag missing from note body: {body!r}")
    return match.group(0)


def solve_chronos(launch: str) -> str:
    process = subprocess.run(
        [sys.executable, str(BASE / "challenges" / "02-chronos-engine" / "solve.py"), "--launch", launch],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if process.returncode != 0:
        raise RuntimeError(f"solver failed:\n{process.stdout}\n{process.stderr}")
    match = FLAG_RE.search(process.stdout)
    if not match:
        raise RuntimeError(f"flag missing from solver output:\n{process.stdout}")
    return match.group(0)


def submit(session: requests.Session, slug: str, flag: str) -> requests.Response:
    page = session.get(f"{PLATFORM}/challenge/{slug}", timeout=10).text
    return session.post(
        f"{PLATFORM}/challenge/{slug}/submit",
        data={"_csrf": csrf(page), "flag": flag},
        timeout=10,
        allow_redirects=True,
    )


def organizer_key() -> str:
    key = os.environ.get("ORGANIZER_KEY", "").strip()
    if key:
        return key
    secrets_file = BASE / "instance" / "secrets.json"
    return json.loads(secrets_file.read_text(encoding="utf-8"))["ORGANIZER_KEY"]


def main() -> int:
    for port in (8000, 8081, 8082):
        wait_for(f"http://127.0.0.1:{port}/healthz")

    suffix = secrets.token_hex(3)
    password = "e2e-test-password"

    print("[1] register team")
    team_name = f"E2E Squad {suffix}"
    team = register(team_name, password)

    print("[2] launch and solve beginner IDOR")
    beginner_flag = solve_beginner(launch_url(team, "interns-secret"))
    print(f"    flag: {beginner_flag}")

    print("[3] launch and solve Chronos via signed launch link")
    chronos_flag = solve_chronos(launch_url(team, "chronos-engine"))
    print(f"    flag: {chronos_flag}")

    print("[4] submit both flags")
    first = submit(team, "interns-secret", beginner_flag)
    assert first.status_code == 200 and "Correct." in first.text, "beginner submission failed"
    second = submit(team, "chronos-engine", chronos_flag)
    assert second.status_code == 200 and "Correct." in second.text, "chronos submission failed"

    print("[5] verify dashboard, scoreboard, and per-team flags")
    dashboard = team.get(f"{PLATFORM}/dashboard", timeout=10).text
    assert team_name in dashboard
    assert "400" in dashboard, "expected 400-point score"

    board = team.get(f"{PLATFORM}/scoreboard", timeout=10).text
    assert team_name in board

    for slug, flag in (("interns-secret", beginner_flag), ("chronos-engine", chronos_flag)):
        page = team.get(f"{PLATFORM}/challenge/{slug}", timeout=10).text
        assert flag in page, f"{slug} own-flag panel missing"

    print("[6] verify a copied flag is rejected")
    copy_name = f"Copy Cat {suffix}"
    other = register(copy_name, password)
    copied = submit(other, "interns-secret", beginner_flag)
    assert "Incorrect flag." in copied.text, "copied flag was accepted"

    print("[7] verify the sequential hint ladder and score deduction")
    hint_page = team.get(f"{PLATFORM}/challenge/chronos-engine", timeout=10).text
    hinted = team.post(
        f"{PLATFORM}/challenge/chronos-engine/hint",
        data={"_csrf": csrf(hint_page), "level": "1"},
        timeout=10,
        allow_redirects=True,
    )
    assert "Hint 1 unlocked" in hinted.text
    assert "Your score: 390" in hinted.text, "hint cost was not deducted"
    skipped = team.post(
        f"{PLATFORM}/challenge/chronos-engine/hint",
        data={"_csrf": csrf(hinted.text), "level": "3"},
        timeout=10,
        allow_redirects=True,
    )
    assert "Unlock hint 2 first." in skipped.text, "hint skipping was allowed"

    print("[8] verify organizer audit and flag-share detection")
    assert requests.get(f"{PLATFORM}/admin", timeout=10).status_code == 401
    admin = requests.Session()
    admin.auth = ("organizer", organizer_key())
    admin_page = admin.get(f"{PLATFORM}/admin", timeout=10)
    assert admin_page.status_code == 200
    assert team_name in admin_page.text
    assert "flag_share_attempt" in admin_page.text, "cross-team attempt was not audited"
    csv_response = admin.get(f"{PLATFORM}/admin/audit.csv", timeout=10)
    assert csv_response.status_code == 200 and "flag_share_attempt" in csv_response.text

    print("[9] verify organizer ban action")
    db = sqlite3.connect(BASE / "instance" / "ctf.db")
    copy_id = db.execute("SELECT id FROM teams WHERE name = ?", (copy_name,)).fetchone()[0]
    db.close()
    banned = admin.post(
        f"{PLATFORM}/admin/team/{copy_id}/ban",
        data={"_csrf": csrf(admin_page.text), "action": "ban"},
        timeout=10,
        allow_redirects=True,
    )
    assert "banned." in banned.text, "ban action failed"
    fresh = requests.Session()
    login_page = fresh.get(f"{PLATFORM}/login", timeout=10).text
    blocked = fresh.post(
        f"{PLATFORM}/login",
        data={"_csrf": csrf(login_page), "name": copy_name, "password": password},
        timeout=10,
    )
    assert blocked.status_code == 401, "banned team could still sign in"

    print()
    print("E2E OK")
    print(f"  team:     {team_name}")
    print(f"  beginner: {beginner_flag}")
    print(f"  chronos:  {chronos_flag}")
    print("  copied flag rejected")
    print("  hint ladder + organizer audit OK")
    print("  organizer ban action OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
