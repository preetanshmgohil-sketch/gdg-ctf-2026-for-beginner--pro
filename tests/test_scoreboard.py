from __future__ import annotations

import importlib
import re
import sqlite3
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

CSRF_RE = re.compile(r'name="_csrf" value="([^"]+)"')


def test_flag_share_is_rejected_and_audited(monkeypatch, tmp_path):
    db_path = tmp_path / "ctf.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("SECRET_KEY", "unit-scoreboard-session")
    monkeypatch.setenv("TEAM_TOKEN_SECRET", "unit-token-secret")
    monkeypatch.setenv("FLAG_SECRET", "unit-flag-secret")
    monkeypatch.setenv("ORGANIZER_KEY", "unit-organizer-key")

    sys.modules.pop("scoreboard.app", None)
    importlib.invalidate_caches()
    platform = importlib.import_module("scoreboard.app")
    platform.init_db()

    db = sqlite3.connect(db_path)
    db.execute(
        "INSERT INTO teams(id, name, password_hash, created_at, created_ip) VALUES (1, 'Alpha', 'x', '2026-01-01T00:00:00+00:00', '127.0.0.1')"
    )
    db.execute(
        "INSERT INTO teams(id, name, password_hash, created_at, created_ip) VALUES (2, 'Beta', 'x', '2026-01-01T00:00:00+00:00', '127.0.0.1')"
    )
    db.execute(
        "INSERT INTO solves(team_id, challenge_id, created_at, ip) VALUES (1, 'interns-secret', '2026-01-01T00:01:00+00:00', '127.0.0.1')"
    )
    db.execute(
        "INSERT INTO hint_unlocks(team_id, challenge_id, hint_level, created_at) VALUES (1, 'chronos-engine', 1, '2026-01-01T00:02:00+00:00')"
    )
    db.commit()
    db.close()

    alpha_flag = platform.flag_for(1, "interns-secret")
    beta_flag = platform.flag_for(2, "interns-secret")
    assert alpha_flag != beta_flag

    with platform.app.app_context():
        assert platform.team_score(1) == 90  # 100 solve - 10 hint

    client = platform.app.test_client()
    with client.session_transaction() as session:
        session["team_id"] = 1
        session["team_name"] = "Alpha"

    page = client.get("/challenge/interns-secret")
    assert page.status_code == 200
    csrf = CSRF_RE.search(page.get_data(as_text=True))
    assert csrf

    response = client.post(
        "/challenge/interns-secret/submit",
        data={"_csrf": csrf.group(1), "flag": beta_flag},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Incorrect flag." in response.get_data(as_text=True)

    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    submission = db.execute(
        "SELECT correct, kind FROM submissions WHERE team_id = 1 ORDER BY id DESC LIMIT 1"
    ).fetchone()
    audit = db.execute(
        "SELECT kind, detail FROM audit WHERE kind = 'flag_share_attempt' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()

    assert submission is not None
    assert submission["correct"] == 0
    assert submission["kind"] == "flag_share_attempt"
    assert audit is not None
    assert "Beta" in audit["detail"]

    # An empty/missing CSRF token must not match an empty session token.
    no_csrf = client.post("/logout", data={}, follow_redirects=False)
    assert no_csrf.status_code == 400
