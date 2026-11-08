"""Challenge catalog for the laptop scoreboard."""

from __future__ import annotations

CHALLENGES: list[dict] = [
    {
        "slug": "interns-secret",
        "title": "The Intern's Secret",
        "category": "Web",
        "difficulty": "Beginner",
        "points": 100,
        "flag_prefix": "intern",
        "url_env": "INTERNS_URL",
        "default_url": "http://127.0.0.1:8081",
        "summary": "A new intern's onboarding portal hides a note that was never meant for her.",
        "description": (
            "Maya has just joined GDG Labs. Her onboarding portal has a demo "
            "account, three ordinary notes, and a legacy API that opens notes by "
            "number. The company's platform lead left one final handover note "
            "behind. Find it and recover the vault key."
        ),
        "hints": [
            {
                "level": 1,
                "cost": 5,
                "text": "You are signed in as Maya (employee 42). The portal trusts the number in the note URL a little too much.",
            },
            {
                "level": 2,
                "cost": 10,
                "text": "Open DevTools → Network after clicking one of your notes. The request goes to /api/notes/<id>. Try a different, much smaller id.",
            },
            {
                "level": 3,
                "cost": 15,
                "text": "Request /api/notes/1 while signed in. The response is JSON and contains the executive note. Read the body field carefully.",
            },
        ],
    },
    {
        "slug": "chronos-engine",
        "title": "Chronos Engine",
        "category": "Crypto / Web",
        "difficulty": "Experienced",
        "points": 300,
        "flag_prefix": "chronos",
        "url_env": "CHRONOS_URL",
        "default_url": "http://127.0.0.1:8082",
        "summary": "A deterministic temporal signer reuses an ECDSA nonce. Forge the vault attestation.",
        "description": (
            "Chronos Engine is a fictional audit service that signs public "
            "timeline snapshots. Its operators made signatures reproducible by "
            "deriving the ECDSA nonce from a 60-second epoch. The archive vault "
            "will open only for a valid signature over vault:admin — a message "
            "the public oracle refuses to sign. Recover the engine key and forge "
            "the attestation."
        ),
        "hints": [
            {
                "level": 1,
                "cost": 10,
                "text": "The metadata says the nonce is deterministic and epoch-derived. Ask for two different timeline messages in the same epoch and compare their r values.",
            },
            {
                "level": 2,
                "cost": 20,
                "text": "Equal r means equal k. Write the two ECDSA equations, subtract them to eliminate the private key, and solve for k. Then substitute back to recover d.",
            },
            {
                "level": 3,
                "cost": 30,
                "text": "k = (z1 - z2) / (s1 - s2) mod n, then d = (s1*k - z1) / r mod n. Sign the exact message vault:admin with a fresh nonce and POST r and s to /api/vault/open.",
            },
        ],
    },
]

CHALLENGE_BY_SLUG = {challenge["slug"]: challenge for challenge in CHALLENGES}
