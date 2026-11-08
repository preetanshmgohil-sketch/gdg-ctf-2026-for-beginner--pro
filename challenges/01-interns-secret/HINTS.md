# The Intern's Secret — hint ladder

These are the same three hints the scoreboard unlocks. They are sequential and
cost 5, 10, and 15 points.

## Hint 1 — 5 points

You are signed in as Maya (employee 42). The portal trusts the number in the
note URL a little too much.

## Hint 2 — 10 points

Open DevTools → Network after clicking one of your notes. The request goes to
`/api/notes/<id>`. Try a different, much smaller id.

## Hint 3 — 15 points

Request `/api/notes/1` while signed in. The response is JSON and contains the
executive note. Read the `body` field carefully.
