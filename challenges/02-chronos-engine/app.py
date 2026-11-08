"""
Chronos Engine — experienced web/crypto challenge.

The service is a fictional "temporal attestation" API. It signs public timeline
messages with ECDSA. The signing nonce is derived from a 60-second epoch, so
two signatures made in the same epoch reuse the same nonce. That is the
intentional flaw: recover the private key and forge the admin attestation.

This is a CTF service. Do not reuse this code for real cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

try:  # pragma: no cover - exercised by the production container
    from werkzeug.middleware.proxy_fix import ProxyFix
except ImportError:  # pragma: no cover
    ProxyFix = None  # type: ignore[assignment]

import ecdsa_secp256k1 as curve

# Support both the repository layout and the Docker image layout.
_HERE = Path(__file__).resolve().parent
for _base in (_HERE, _HERE.parent, _HERE.parent.parent):
    if (_base / "shared" / "team_context.py").is_file():
        sys.path.insert(0, str(_base))
        break

from shared.team_context import flag_secret, get_team, init_team_context, team_flag  # noqa: E402

DEFAULT_FLAG = "GDG{n0nc3_r3us3_1s_f4t4l}"
INSTANCE_ID = os.environ.get("INSTANCE_ID", "local")
EPOCH_SECONDS = 60
MAX_MESSAGE_LEN = 120
SIGN_LIMIT = 30
SIGN_WINDOW_SECONDS = 60

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024,
    JSON_SORT_KEYS=False,
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-only-change-me"),
    SESSION_COOKIE_NAME="gdg_chronos_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=43200,
)
init_team_context(app, "chronos-engine", "chronos", os.environ.get("FLAG", DEFAULT_FLAG))

if os.environ.get("TRUST_PROXY", "0") == "1" and ProxyFix is not None:
    # One trusted reverse proxy (Caddy/Traefik) is in front of the app.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]


@lru_cache(maxsize=512)
def _team_key_material(team_id: int) -> tuple[int, tuple[int, int], bytes]:
    secret = flag_secret().encode("utf-8")
    key_digest = hmac.new(secret, f"chronos-key:{team_id}".encode("ascii"), hashlib.sha256).digest()
    private_key = int.from_bytes(key_digest, "big") % (curve.N - 1) + 1
    nonce_seed = hmac.new(secret, f"chronos-nonce:{team_id}".encode("ascii"), hashlib.sha256).digest()
    return private_key, curve.public_key(private_key), nonce_seed


@lru_cache(maxsize=1)
def _static_key_material() -> tuple[int, tuple[int, int], bytes]:
    raw = os.environ.get("CHRONOS_PRIVATE_KEY", "").strip()
    if raw:
        try:
            key = int(raw, 16)
        except ValueError as exc:
            raise RuntimeError("CHRONOS_PRIVATE_KEY must be a hex integer") from exc
        if not 1 <= key < curve.N:
            raise RuntimeError("CHRONOS_PRIVATE_KEY out of range")
    else:
        key = secrets.randbelow(curve.N - 1) + 1
    nonce_seed = os.environ.get("CHRONOS_NONCE_SEED", secrets.token_hex(32)).encode("utf-8")
    return key, curve.public_key(key), nonce_seed


def _key_material() -> tuple[int, tuple[int, int], bytes]:
    team = get_team()
    if team is not None:
        return _team_key_material(team["id"])
    return _static_key_material()

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def _now() -> float:
    return time.time()


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _rate_limited() -> bool:
    now = _now()
    bucket = _rate_buckets[_client_ip()]
    with _rate_lock:
        while bucket and now - bucket[0] > SIGN_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= SIGN_LIMIT:
            return True
        bucket.append(now)
        return False


def _epoch() -> int:
    return int(_now()) // EPOCH_SECONDS


def _nonce_for_epoch(epoch: int, nonce_seed: bytes) -> int:
    digest = hashlib.sha256(nonce_seed + b":" + str(epoch).encode("ascii")).digest()
    return int.from_bytes(digest, "big") % (curve.N - 1) + 1


def _pubkey_json(public_key: tuple[int, int]) -> dict[str, str]:
    x, y = public_key
    return {
        "x": f"0x{x:064x}",
        "y": f"0x{y:064x}",
        "uncompressed": f"0x04{x:064x}{y:064x}",
    }


def _vault_flag() -> str:
    return team_flag("chronos-engine", "chronos", os.environ.get("FLAG", DEFAULT_FLAG))


def _json_error(message: str, status: int) -> tuple[Response, int]:
    return jsonify({"error": message}), status


@app.get("/")
def index() -> Any:
    _, public_key, _ = _key_material()
    return render_template(
        "index.html",
        instance_id=INSTANCE_ID,
        pubkey=_pubkey_json(public_key),
        epoch_seconds=EPOCH_SECONDS,
    )


@app.get("/api/meta")
def meta() -> Any:
    _, public_key, _ = _key_material()
    return jsonify(
        {
            "service": "chronos-engine",
            "version": "1.4.2-audit",
            "instance": INSTANCE_ID,
            "curve": "secp256k1",
            "hash": "sha256",
            "public_key": _pubkey_json(public_key),
            "signing_policy": {
                "allowed_prefix": "timeline:",
                "max_message_length": MAX_MESSAGE_LEN,
                "nonce_scheme": "deterministic, epoch-derived for reproducible audit signatures",
                "epoch_seconds": EPOCH_SECONDS,
                "rate_limit": f"{SIGN_LIMIT} signatures per {SIGN_WINDOW_SECONDS}s per source",
            },
            "required_attestation": {
                "message": "vault:admin",
                "encoding": "hex integers for r and s",
                "endpoint": "/api/vault/open",
            },
        }
    )


@app.post("/api/sign")
def sign() -> Any:
    if _rate_limited():
        return _json_error("signing rate limit exceeded", 429)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _json_error("expected a JSON object", 400)

    message = data.get("message")
    if not isinstance(message, str):
        return _json_error("message must be a string", 400)
    if not message.startswith("timeline:"):
        return _json_error("the public oracle only signs timeline:* messages", 403)
    if len(message) > MAX_MESSAGE_LEN:
        return _json_error(f"message must be at most {MAX_MESSAGE_LEN} characters", 400)

    private_key, _, nonce_seed = _key_material()
    epoch = _epoch()
    nonce = _nonce_for_epoch(epoch, nonce_seed)
    try:
        r, s, z = curve.sign(private_key, message, nonce)
    except ValueError:
        return _json_error("the engine could not produce a safe signature; retry", 503)

    return jsonify(
        {
            "message": message,
            "r": f"0x{r:064x}",
            "s": f"0x{s:064x}",
            "z": f"0x{z:064x}",
            "epoch": epoch,
            "issued_at": int(_now()),
        }
    )


@app.post("/api/vault/open")
def open_vault() -> Any:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _json_error("expected a JSON object", 400)
    if data.get("message") != "vault:admin":
        return _json_error("this endpoint only accepts the vault:admin attestation", 400)

    try:
        r = int(str(data.get("r", "")), 16)
        s = int(str(data.get("s", "")), 16)
    except (TypeError, ValueError):
        return _json_error("r and s must be hexadecimal integers", 400)

    _, public_key, _ = _key_material()
    if not curve.verify(public_key, "vault:admin", r, s):
        return _json_error("invalid attestation", 403)

    return jsonify(
        {
            "status": "open",
            "message": "The vault accepts the engine's signature. Take the archive.",
            "flag": _vault_flag(),
        }
    )


@app.get("/healthz")
def healthz() -> Any:
    return jsonify({"status": "ok", "service": "chronos-engine"})


@app.get("/robots.txt")
def robots() -> Any:
    return Response(
        "User-agent: *\nDisallow: /api/\n",
        mimetype="text/plain",
    )


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
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8082")), debug=False)
