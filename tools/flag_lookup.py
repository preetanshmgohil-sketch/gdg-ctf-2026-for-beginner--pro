#!/usr/bin/env python3
"""Recompute a team's flag from the organizer secret file.

This is an organizer support tool. It does not break anything; it simply runs
the same HMAC derivation the scoreboard and challenge services use.

Usage:
    python tools/flag_lookup.py 7 interns-secret
    python tools/flag_lookup.py 7 chronos-engine --secrets /path/to/secrets.json

The default secret file is instance/secrets.json next to this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path

PREFIXES = {
    "interns-secret": "intern",
    "chronos-engine": "chronos",
}
BASE = Path(__file__).resolve().parent.parent


def load_flag_secret(path: Path) -> str:
    env_secret = os.environ.get("FLAG_SECRET", "").strip()
    if env_secret:
        return env_secret
    if not path.is_file():
        raise SystemExit(f"secret file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    secret = str(data.get("FLAG_SECRET", "")).strip()
    if not secret:
        raise SystemExit(f"FLAG_SECRET missing from {path}")
    return secret


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute a GDG CTF team flag")
    parser.add_argument("team_id", type=int, help="numeric team id shown in /admin")
    parser.add_argument("slug", choices=sorted(PREFIXES), help="challenge slug")
    parser.add_argument(
        "--secrets",
        type=Path,
        default=BASE / "instance" / "secrets.json",
        help="path to secrets.json (default: instance/secrets.json)",
    )
    args = parser.parse_args()

    secret = load_flag_secret(args.secrets)
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{args.team_id}:{args.slug}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    print(f"GDG{{{PREFIXES[args.slug]}_{digest}}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
