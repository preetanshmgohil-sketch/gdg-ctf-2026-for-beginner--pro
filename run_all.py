#!/usr/bin/env python3
"""
Start the whole laptop-hosted event:

    python run_all.py

Services:
    scoreboard        0.0.0.0:8000
    interns-secret    0.0.0.0:8081
    chronos-engine    0.0.0.0:8082

The first run creates instance/secrets.json with the shared HMAC secrets.
Keep that file private. Use a LAN IP for an in-person event, or set
INTERNS_URL / CHRONOS_URL to free tunnel URLs before starting.
"""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import socket
import sys
import threading
from pathlib import Path

BASE = Path(__file__).resolve().parent
INSTANCE = BASE / "instance"
SECRETS_FILE = INSTANCE / "secrets.json"

if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))


def load_or_create_secrets() -> dict[str, str]:
    INSTANCE.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    if SECRETS_FILE.is_file():
        try:
            data = json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                existing = {str(k): str(v) for k, v in data.items()}
        except (OSError, ValueError):
            existing = {}

    required = [
        "TEAM_TOKEN_SECRET",
        "FLAG_SECRET",
        "PLATFORM_SECRET",
        "INTERNS_SECRET",
        "CHRONOS_SECRET",
        "ORGANIZER_KEY",
    ]
    changed = False
    for key in required:
        if not existing.get(key):
            existing[key] = secrets.token_urlsafe(40)
            changed = True

    if changed:
        SECRETS_FILE.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        try:
            SECRETS_FILE.chmod(0o600)
        except OSError:
            pass
    return existing


def lan_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def configure_env(secrets_data: dict[str, str]) -> tuple[str, str, str]:
    ip = os.environ.get("LAN_IP", "").strip() or lan_ip()
    os.environ.setdefault("SECRET_KEY", secrets_data["PLATFORM_SECRET"])
    os.environ.setdefault("TEAM_TOKEN_SECRET", secrets_data["TEAM_TOKEN_SECRET"])
    os.environ.setdefault("FLAG_SECRET", secrets_data["FLAG_SECRET"])
    os.environ.setdefault("DB_PATH", str(INSTANCE / "ctf.db"))
    os.environ.setdefault("EVENT_NAME", "GDG CTF")
    os.environ.setdefault("INTERNS_URL", f"http://{ip}:8081")
    os.environ.setdefault("CHRONOS_URL", f"http://{ip}:8082")
    os.environ.setdefault("INTERNS_SECRET", secrets_data["INTERNS_SECRET"])
    os.environ.setdefault("CHRONOS_SECRET", secrets_data["CHRONOS_SECRET"])
    os.environ.setdefault("ORGANIZER_KEY", secrets_data["ORGANIZER_KEY"])
    return ip, os.environ["INTERNS_URL"], os.environ["CHRONOS_URL"]


def load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    try:
        import waitress  # noqa: F401
    except ImportError:
        print("Missing dependency: waitress", file=sys.stderr)
        print("Run: python -m pip install -r requirements.txt", file=sys.stderr)
        return 1

    secrets_data = load_or_create_secrets()
    ip, interns_url, chronos_url = configure_env(secrets_data)

    # Add challenge directories for the local ecdsa module import.
    challenge_dirs = [
        BASE / "challenges" / "01-interns-secret",
        BASE / "challenges" / "02-chronos-engine",
    ]
    for challenge_dir in challenge_dirs:
        if str(challenge_dir) not in sys.path:
            sys.path.insert(0, str(challenge_dir))

    # Set per-app session keys before importing the Flask apps.
    os.environ["SECRET_KEY"] = secrets_data["INTERNS_SECRET"]
    interns = load_module(challenge_dirs[0] / "app.py", "gdg_interns_app")

    os.environ["SECRET_KEY"] = secrets_data["CHRONOS_SECRET"]
    chronos = load_module(challenge_dirs[1] / "app.py", "gdg_chronos_app")

    os.environ["SECRET_KEY"] = secrets_data["PLATFORM_SECRET"]
    from scoreboard.app import app as scoreboard_app, init_db

    init_db()

    from waitress import serve

    services = [
        ("scoreboard", scoreboard_app, 8000),
        ("interns-secret", interns.app, 8081),
        ("chronos-engine", chronos.app, 8082),
    ]

    threads: list[threading.Thread] = []
    for name, app, port in services:
        thread = threading.Thread(
            target=serve,
            kwargs={"app": app, "host": "0.0.0.0", "port": port, "threads": 12, "_quiet": True},
            name=f"serve-{name}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    print()
    print("  GDG CTF Lite is running")
    print("  ----------------------")
    print(f"  Scoreboard:      http://{ip}:8000")
    print(f"  Interns Secret:  {interns_url}  (launch from the scoreboard)")
    print(f"  Chronos Engine:  {chronos_url}  (launch from the scoreboard)")
    print(f"  Organizer audit: http://{ip}:8000/admin  (user: organizer)")
    print("                   password is ORGANIZER_KEY in instance/secrets.json")
    print()
    if not os.environ.get("REGISTRATION_CODE"):
        print("  Registration is open. Set REGISTRATION_CODE=... for a public tunnel.")
    print("  Keep this laptop awake and on the same network as the players.")
    print("  Press Ctrl+C to stop all services.")
    print()

    try:
        while any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n  Stopping event services.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
