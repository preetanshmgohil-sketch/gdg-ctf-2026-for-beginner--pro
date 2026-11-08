#!/usr/bin/env python3
"""
Small, non-exploit helper for the Chronos Engine challenge.

It only wraps the public API. The intended solution is not included.

Standalone:
    python chronos_client.py --url http://127.0.0.1:8082

Platform-launched (copy the launch link):
    python chronos_client.py --launch "http://192.168.1.20:8082/?t=..."

Platform-launched (copy the session cookie from DevTools):
    python chronos_client.py --url http://192.168.1.20:8082 \
        --cookie "gdg_chronos_session=eyJ..."
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request


class ChronosClient:
    def __init__(self, base_url: str, cookie: str | None = None, launch: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.headers = {"Accept": "application/json"}
        if cookie:
            self.headers["Cookie"] = cookie.strip()

        if launch:
            parsed = urllib.parse.urlparse(launch)
            if not parsed.scheme or not parsed.netloc:
                raise RuntimeError("--launch must be a full http(s) URL")
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            request = urllib.request.Request(launch, headers=self.headers, method="GET")
            with self.opener.open(request, timeout=15) as response:
                response.read()

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        body = None
        headers = dict(self.headers)
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc

    def meta(self) -> dict:
        return self._request("GET", "/api/meta")

    def sign(self, message: str) -> dict:
        return self._request("POST", "/api/sign", {"message": message})

    def open_vault(self, r: str, s: str) -> dict:
        return self._request("POST", "/api/vault/open", {"message": "vault:admin", "r": r, "s": s})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8082")
    parser.add_argument("--launch", default="", help="full launch URL copied from the scoreboard")
    parser.add_argument("--cookie", default="", help="raw Cookie header for a launched team session")
    parser.add_argument("--message", default="timeline:hello")
    args = parser.parse_args()

    client = ChronosClient(args.url, cookie=args.cookie or None, launch=args.launch or None)
    print(json.dumps(client.meta(), indent=2))
    print(json.dumps(client.sign(args.message), indent=2))


if __name__ == "__main__":
    main()
