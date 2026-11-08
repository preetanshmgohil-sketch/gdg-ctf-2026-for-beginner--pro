#!/usr/bin/env python3
"""
Reference solution for Chronos Engine.

The signing oracle derives its ECDSA nonce from a 60-second epoch. Two
different messages signed in the same epoch therefore share the same k:

    s1 = k^-1 (z1 + r*d) mod n
    s2 = k^-1 (z2 + r*d) mod n

Subtract, recover k, then recover the private key d and sign vault:admin.

Usage (standalone):
    python solve.py --url http://127.0.0.1:8082

Usage (platform-launched, copy the launch link):
    python solve.py --launch "http://192.168.1.20:8082/?t=..."

Usage (platform-launched, copy the session cookie from DevTools):
    python solve.py --url http://192.168.1.20:8082 \\
        --cookie "gdg_chronos_session=eyJ..."
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import ecdsa_secp256k1 as curve


class Api:
    def __init__(self, base_url: str, cookie: str | None = None, launch: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.headers = {"Accept": "application/json"}
        if cookie:
            self.headers["Cookie"] = cookie.strip()

        if launch:
            # Following the signed launch link stores the team session cookie
            # in the jar. The token is removed from the address bar by a 302.
            parsed = urllib.parse.urlparse(launch)
            if not parsed.scheme or not parsed.netloc:
                raise RuntimeError("--launch must be a full http(s) URL")
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            request = urllib.request.Request(launch, headers=self.headers, method="GET")
            with self.opener.open(request, timeout=15) as response:
                response.read()

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(req, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {body}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, payload)


def parse_hex(value: str) -> int:
    return int(value, 16)


def recover_private_key(first: dict[str, Any], second: dict[str, Any]) -> int:
    r1, s1, z1 = parse_hex(first["r"]), parse_hex(first["s"]), parse_hex(first["z"])
    r2, s2, z2 = parse_hex(second["r"]), parse_hex(second["s"]), parse_hex(second["z"])

    if r1 != r2:
        raise ValueError("signatures do not share a nonce")
    if s1 == s2:
        raise ValueError("signatures are identical or degenerate")

    k = ((z1 - z2) * pow(s1 - s2, -1, curve.N)) % curve.N
    d = ((s1 * k - z1) * pow(r1, -1, curve.N)) % curve.N
    if not (1 <= d < curve.N):
        raise ValueError("recovered private key out of range")
    return d


def forge(api: Api) -> str:
    meta = api.get("/api/meta")
    expected_x = parse_hex(meta["public_key"]["x"])
    expected_y = parse_hex(meta["public_key"]["y"])

    for attempt in range(3):
        first = api.post("/api/sign", {"message": "timeline:alpha"})
        second = api.post("/api/sign", {"message": "timeline:beta"})

        if first["r"] == second["r"]:
            break

        # We crossed an epoch boundary between the two calls. Wait for the
        # start of the next epoch plus a small margin and try again.
        now = time.time()
        time.sleep(curve_epoch_wait(now) + 1.1)
    else:
        raise RuntimeError("could not obtain two signatures from the same epoch")

    print(f"[+] two signatures share nonce: r={first['r']}")
    print(f"[+] epoch: {first['epoch']} / {second['epoch']}")

    d = recover_private_key(first, second)
    actual = curve.public_key(d)
    if actual != (expected_x, expected_y):
        raise RuntimeError("public key check failed; attack did not recover the key")

    print("[+] private key recovered and verified against /api/meta")

    while True:
        nonce = secrets.randbelow(curve.N - 1) + 1
        try:
            r, s, _ = curve.sign(d, "vault:admin", nonce)
            break
        except ValueError:
            continue

    print("[+] forged an attestation for vault:admin")
    result = api.post(
        "/api/vault/open",
        {"message": "vault:admin", "r": f"0x{r:064x}", "s": f"0x{s:064x}"},
    )
    if result.get("status") != "open" or not result.get("flag"):
        raise RuntimeError(f"vault rejected the forged signature: {result}")
    return result["flag"]


def curve_epoch_wait(now: float) -> float:
    return 60.0 - (now % 60.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Chronos Engine")
    parser.add_argument("--url", default="http://127.0.0.1:8082", help="challenge base URL")
    parser.add_argument("--launch", default="", help="full launch URL copied from the scoreboard")
    parser.add_argument("--cookie", default="", help="raw Cookie header for a launched team session")
    args = parser.parse_args()

    try:
        flag = forge(Api(args.url, cookie=args.cookie or None, launch=args.launch or None))
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"[+] flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
