from __future__ import annotations

import importlib.util
import os
import re
import secrets
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "challenges" / "02-chronos-engine"))

import ecdsa_secp256k1 as curve  # noqa: E402
from shared.team_context import derive_flag, make_team_token, parse_team_token  # noqa: E402

CSRF_RE = re.compile(r'name="_csrf" value="([^"]+)"')


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def team_client(app, team_id: int):
    client = app.test_client()
    with client.session_transaction() as session:
        session["team_id"] = team_id
        session["team_name"] = f"Unit Team {team_id}"
    return client


def forge(private_key: int, message: str) -> tuple[int, int]:
    while True:
        nonce = secrets.randbelow(curve.N - 1) + 1
        try:
            r, s, _ = curve.sign(private_key, message, nonce)
            return r, s
        except ValueError:
            continue


# --------------------------------------------------------------------------
# Shared tokens
# --------------------------------------------------------------------------


def test_team_token_roundtrip_and_tamper(monkeypatch):
    monkeypatch.setenv("TEAM_TOKEN_SECRET", "unit-token-secret")
    token = make_team_token(7, "Temporal Turtles")
    assert parse_team_token(token) == {"id": 7, "name": "Temporal Turtles"}

    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert parse_team_token(tampered) is None
    assert parse_team_token(token, secret="wrong-secret") is None
    assert parse_team_token(token, max_age=-1) is None


def test_flags_are_team_specific(monkeypatch):
    monkeypatch.setenv("FLAG_SECRET", "unit-flag-secret")
    first = derive_flag(7, "interns-secret", "intern")
    second = derive_flag(8, "interns-secret", "intern")
    assert first != second
    assert re.fullmatch(r"GDG\{intern_[0-9a-f]{20}\}", first)
    assert derive_flag(7, "interns-secret", "intern") == first


# --------------------------------------------------------------------------
# Beginner: IDOR and per-team flag
# --------------------------------------------------------------------------


def test_beginner_idor_returns_the_team_flag(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "unit-interns-session")
    monkeypatch.setenv("TEAM_TOKEN_SECRET", "unit-token-secret")
    monkeypatch.setenv("FLAG_SECRET", "unit-flag-secret")
    monkeypatch.delenv("DEV_TEAM_ID", raising=False)

    module = load_module(BASE / "challenges" / "01-interns-secret" / "app.py", "gdg_interns_unit")
    client = module.app.test_client()

    # Platform mode requires a launch token.
    assert client.get("/").status_code == 401
    assert client.get("/api/notes/1").status_code == 401

    token = make_team_token(11, "Alpha")
    launched = client.get(f"/?t={token}", follow_redirects=True)
    assert launched.status_code == 200
    assert b"t=" not in launched.request.query_string

    login = client.post(
        "/login",
        data={"username": "maya.intern", "password": "coffee-first"},
        follow_redirects=False,
    )
    assert login.status_code == 302

    note = client.get("/api/notes/1")
    assert note.status_code == 200
    expected = derive_flag(11, "interns-secret", "intern")
    assert expected in note.get_json()["body"]

    # The team binding survives the challenge's own login.
    with client.session_transaction() as session:
        assert session["team_id"] == 11


def test_beginner_static_flag_without_platform(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "unit-interns-session")
    monkeypatch.delenv("TEAM_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("DEV_TEAM_ID", raising=False)

    module = load_module(BASE / "challenges" / "01-interns-secret" / "app.py", "gdg_interns_static")
    client = module.app.test_client()
    assert client.get("/").status_code == 200
    client.post("/login", data={"username": "maya.intern", "password": "coffee-first"})
    body = client.get("/api/notes/1").get_json()["body"]
    assert "GDG{1d0r_1s_n0t_4_d00r}" in body


# --------------------------------------------------------------------------
# Experienced: nonce reuse and per-team key isolation
# --------------------------------------------------------------------------


def test_chronos_nonce_reuse_and_cross_team_rejection(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "unit-chronos-session")
    monkeypatch.setenv("TEAM_TOKEN_SECRET", "unit-token-secret")
    monkeypatch.setenv("FLAG_SECRET", "unit-flag-secret")

    module = load_module(BASE / "challenges" / "02-chronos-engine" / "app.py", "gdg_chronos_unit")
    module._rate_buckets.clear()
    monkeypatch.setattr(module, "_now", lambda: 1_700_000_000.0)

    first = team_client(module.app, 1)
    second = team_client(module.app, 2)

    meta_first = first.get("/api/meta").get_json()
    meta_second = second.get("/api/meta").get_json()
    assert meta_first["public_key"]["x"] != meta_second["public_key"]["x"]

    # The oracle refuses the vault message.
    assert first.post("/api/sign", json={"message": "vault:admin"}).status_code == 403

    sig_a = first.post("/api/sign", json={"message": "timeline:alpha"}).get_json()
    sig_b = first.post("/api/sign", json={"message": "timeline:beta"}).get_json()
    assert sig_a["r"] == sig_b["r"], "same epoch must reuse the nonce"
    assert sig_a["epoch"] == sig_b["epoch"]

    r = int(sig_a["r"], 16)
    s1, z1 = int(sig_a["s"], 16), int(sig_a["z"], 16)
    s2, z2 = int(sig_b["s"], 16), int(sig_b["z"], 16)
    k = ((z1 - z2) * pow(s1 - s2, -1, curve.N)) % curve.N
    d = ((s1 * k - z1) * pow(r, -1, curve.N)) % curve.N

    expected_pub = (int(meta_first["public_key"]["x"], 16), int(meta_first["public_key"]["y"], 16))
    assert curve.public_key(d) == expected_pub

    fr, fs = forge(d, "vault:admin")

    opened = first.post(
        "/api/vault/open",
        json={"message": "vault:admin", "r": f"0x{fr:064x}", "s": f"0x{fs:064x}"},
    )
    assert opened.status_code == 200
    assert opened.get_json()["flag"] == derive_flag(1, "chronos-engine", "chronos")

    # Team 1's valid forgery is invalid on team 2's timeline.
    rejected = second.post(
        "/api/vault/open",
        json={"message": "vault:admin", "r": f"0x{fr:064x}", "s": f"0x{fs:064x}"},
    )
    assert rejected.status_code == 403
