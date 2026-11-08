# Security policy

## This is a deliberately vulnerable training target

GDG CTF Lite contains intentional security flaws, including an IDOR and an
ECDSA nonce-reuse vulnerability. It must not be deployed as a real service and
must not handle real credentials, personal data, or production traffic.

The challenge apps are designed for a trusted organizer laptop on a local
network. The optional tunnel instructions in [`docs/HOSTING.md`](docs/HOSTING.md)
are for invite-based events only; set `REGISTRATION_CODE` before exposing any
tunnel.

## Reporting

If you find an **unintended** issue in the scoreboard or platform code — for
example, a way for a player to read another team's data, bypass a ban, or escape
the intended challenge boundary — please report it privately to the event
organizer or repository maintainer instead of opening a public issue during the
event.

Do not report the intended challenge vulnerabilities (the IDOR and the nonce
reuse) as bugs. They are the exercise.

## Supported versions

This is an event package, not a long-lived product. Security fixes are applied
to the current `main` branch only.

## Organizer responsibilities

- Keep `instance/secrets.json` and `instance/ctf.db` private.
- Do not commit the `instance/` directory; it is ignored by `.gitignore`.
- Rotate `instance/secrets.json` between events.
- Review `/admin` for `flag_share_attempt` rows during the event.
- Keep the repository private while an event is live; it contains writeups and
  reference exploits.
