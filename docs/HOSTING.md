# Hosting GDG CTF Lite from a laptop

This guide is for a student organizer with **one laptop and no server**. The
primary mode is a LAN event: the laptop runs everything, players connect over
the same Wi-Fi, and nothing is exposed to the public internet.

- [1. What you need](#1-what-you-need)
- [2. First run](#2-first-run)
- [3. Let players reach the laptop](#3-let-players-reach-the-laptop)
- [4. Event-day runbook](#4-event-day-runbook)
- [5. Registration control](#5-registration-control)
- [6. Reset, backup, and restore](#6-reset-backup-and-restore)
- [7. Optional free public tunnels](#7-optional-free-public-tunnels)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Safety checklist](#9-safety-checklist)

---

## 1. What you need

- A laptop with Python 3.10 or newer.
- The players and the laptop on the same network.
- No Docker, VPS, domain, TLS certificate, or paid service.
- Optional: a phone hotspot or small router if campus Wi-Fi blocks
  device-to-device traffic.

Check Python:

```powershell
py --version
```

```bash
python3 --version
```

---

## 2. First run

From the project directory:

### Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run_all.py
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run_all.py
```

On first start, `run_all.py`:

1. creates `instance/secrets.json` with random secrets and an organizer password;
2. creates `instance/ctf.db`;
3. detects the LAN IP;
4. starts the scoreboard on 8000 and the challenges on 8081 and 8082.

Leave the terminal open. `Ctrl+C` stops all three services.

Verify locally:

- Scoreboard: <http://127.0.0.1:8000/healthz>
- Beginner: <http://127.0.0.1:8081/healthz>
- Hard: <http://127.0.0.1:8082/healthz>

All three should return JSON with `"status": "ok"`.

---

## 3. Let players reach the laptop

### 3.1 Find the LAN IP

`run_all.py` prints it. To confirm manually:

```powershell
ipconfig
```

Use the **IPv4 Address** of the Wi-Fi adapter, for example `192.168.1.20`.
If the laptop has several adapters (VPN, Docker, virtual machines) and the
detected address is wrong, override it:

```powershell
$env:LAN_IP = "192.168.1.20"
python run_all.py
```

```bash
LAN_IP=192.168.1.20 python run_all.py
```

```bash
# macOS (Wi-Fi)
ipconfig getifaddr en0

# Linux
hostname -I
```

Players open:

```
http://192.168.1.20:8000
```

not `127.0.0.1`, which only works on the host laptop.

### 3.2 Allow the ports through the firewall

**Windows** — allow Python on Private networks when prompted. For a permanent
rule, open PowerShell **as Administrator**:

```powershell
New-NetFirewallRule `
  -DisplayName "GDG CTF Lite" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8000,8081,8082 `
  -Action Allow `
  -Profile Private
```

**macOS** — allow incoming connections for Python/Terminal in
System Settings → Network → Firewall → Options. Or, if you use the application
firewall from a terminal:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$(which python3)"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "$(which python3)"
```

**Ubuntu/Debian with ufw:**

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 8081/tcp
sudo ufw allow 8082/tcp
```

**firewalld:**

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --permanent --add-port=8082/tcp
sudo firewall-cmd --reload
```

### 3.3 Verify from a second device

Before the event, open `http://LAN-IP:8000/healthz` from a phone or another
laptop. If it does not load:

- confirm both devices are on the same SSID/VLAN;
- disable the phone's VPN;
- check the firewall rule;
- try a phone hotspot with the laptop and a test phone connected to it.

**Campus/guest Wi-Fi often enables client isolation.** In that case devices
cannot talk to each other even though they all have internet access. Use a phone
hotspot or a small travel router. This is the most common failure mode for a
laptop-hosted student event. Test it before the event, not at the start.

### 3.4 Keep the laptop awake

**Windows:**

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 15
```

**macOS:**

```bash
caffeinate -d
```

Keep the laptop plugged in.

---

## 4. Event-day runbook

### Before players arrive

- [ ] Run the health checks from a second device.
- [ ] Register a test team, launch both challenges, and submit a wrong flag.
- [ ] Confirm `/scoreboard` loads on the projector.
- [ ] Bookmark `/admin` and confirm the organizer password from
      `instance/secrets.json`.
- [ ] If the event is public or remote, set `REGISTRATION_CODE` (see below).
- [ ] Disable sleep and connect power.
- [ ] Keep the terminal visible so you notice crashes.

### During the event

- Share only `http://LAN-IP:8000`.
- Show `/scoreboard` on the projector, **never** `/admin`.
- Watch the terminal for repeated 500s.
- Review `/admin` every 20–30 minutes for `flag_share_attempt` rows.
- Do not open `instance/ctf.db` in a tool that writes to it while the event is
  live. Read-only access is fine.

### One team per browser profile

The three services use separate cookie names, but two teams sharing one browser
profile will share the scoreboard login and launch sessions. If several people
must use one laptop, use separate browser profiles or private windows.

### After the event

- Stop the server with `Ctrl+C`.
- Export the audit CSV from `/admin/audit.csv`.
- Back up `instance/ctf.db` and `instance/secrets.json` (see below).
- Save the final scoreboard page or screenshot.

---

## 5. Registration control

Open registration is convenient on a trusted LAN. For a public tunnel or a
larger event, require an invite code.

**Windows PowerShell:**

```powershell
$env:REGISTRATION_CODE = "gdg-2026-<something-random>"
python run_all.py
```

**macOS/Linux:**

```bash
REGISTRATION_CODE="gdg-2026-<something-random>" python run_all.py
```

The code is checked on the registration form. It is not stored in the database.
Changing it requires restarting the scoreboard.

Rate limits already apply: 5 registration attempts per IP per 10 minutes, 10
login attempts per IP per 5 minutes, 12 submissions per team per minute, and 30
signatures per IP per minute on Chronos.

---

## 6. Reset, backup, and restore

### Back up during the event

Copy these two files somewhere safe:

```
instance/ctf.db
instance/secrets.json
```

`secrets.json` contains the HMAC keys used to derive every team's flag. Without
it, you cannot recompute a team's flag after the fact. Do not publish it.

### Reset a test event

```powershell
# Windows
Remove-Item instance\ctf.db, instance\ctf.db-wal, instance\ctf.db-shm -ErrorAction SilentlyContinue
python run_all.py
```

```bash
# macOS/Linux
rm -f instance/ctf.db instance/ctf.db-wal instance/ctf.db-shm
python run_all.py
```

This clears teams, solves, submissions, hints, and audit rows. Existing
`secrets.json` is reused, so the organizer password stays the same.

To rotate all secrets as well (new flags for reused team IDs, new organizer
password), delete `instance/secrets.json` too **before** a fresh event. Never do
this mid-event.

### Restore

Stop the server, replace `instance/ctf.db` and `instance/secrets.json` with the
backup, and start again. Keep the pair together: a DB restored with a different
secret file will derive different flags and invalidate solves.

---

## 7. Optional free public tunnels

**LAN is the primary and recommended mode.** Public tunnels are optional, free,
and have real caveats. If you use one:

- set a `REGISTRATION_CODE`;
- understand that the challenge URLs become public to anyone who learns them;
- expect free-tier downtime, random URLs, and rate limits;
- never port-forward your router or expose the laptop directly.

### Option A — Tailscale Funnel (recommended if you accept a free account)

Tailscale Funnel publishes three HTTPS ports from your machine. It requires a
free Tailscale account on the **host laptop only**; players use normal browser
URLs.

1. Install Tailscale and sign in: <https://tailscale.com/download>
2. Enable MagicDNS and HTTPS certificates in the Tailscale admin console, and
   make sure Funnel is allowed for your device (the default tailnet policy
   usually includes the `funnel` node attribute).
3. Publish the three local ports (Tailscale allows 443, 8443, and 10000):

   ```bash
   tailscale funnel --bg --https=443  127.0.0.1:8000
   tailscale funnel --bg --https=8443 127.0.0.1:8081
   tailscale funnel --bg --https=10000 127.0.0.1:8082
   tailscale funnel status
   ```

4. Note your public hostname, for example `gdg-laptop.tailnet-abc.ts.net`.
   The URLs are:

   ```
   https://gdg-laptop.tailnet-abc.ts.net          (scoreboard)
   https://gdg-laptop.tailnet-abc.ts.net:8443     (beginner)
   https://gdg-laptop.tailnet-abc.ts.net:10000    (hard)
   ```

5. Start the event with matching URLs and secure cookies:

   **macOS/Linux:**

   ```bash
   export INTERNS_URL="https://gdg-laptop.tailnet-abc.ts.net:8443"
   export CHRONOS_URL="https://gdg-laptop.tailnet-abc.ts.net:10000"
   export REGISTRATION_CODE="gdg-2026-<random>"
   export COOKIE_SECURE=1
   export TRUST_PROXY=1
   python run_all.py
   ```

   **Windows PowerShell:**

   ```powershell
   $env:INTERNS_URL = "https://gdg-laptop.tailnet-abc.ts.net:8443"
   $env:CHRONOS_URL = "https://gdg-laptop.tailnet-abc.ts.net:10000"
   $env:REGISTRATION_CODE = "gdg-2026-<random>"
   $env:COOKIE_SECURE = "1"
   $env:TRUST_PROXY = "1"
   python run_all.py
   ```

6. Share only the scoreboard URL. The scoreboard embeds the two challenge URLs
   into the launch links.

> Funnel caveats: macOS requires the open-source Tailscale variant (the App
> Store build cannot serve Funnel). Free plans have bandwidth limits. Funnel is
> public internet, so keep the invite code on. If `/admin` shows `127.0.0.1`
> for every player, the proxy is not forwarding client addresses; rate limits
> then apply to the tunnel as a single client.

`COOKIE_SECURE=1` makes session cookies HTTPS-only. Use it for every HTTPS
tunnel. Clear it for plain HTTP LAN events, or browsers will refuse the cookie.
`TRUST_PROXY=1` makes Flask use the proxy's `X-Forwarded-For` for rate limits
and audit IPs. Use it only when all traffic goes through the tunnel; do not set
it on a direct LAN deployment.

To stop publishing:

```bash
tailscale funnel reset
```

### Option B — Cloudflare Quick Tunnel (no account)

Quick Tunnels are free and ephemeral. You need three tunnels because the three
services listen on different ports, and the scoreboard must be started with the
two challenge tunnel URLs.

1. Install `cloudflared`:

   ```powershell
   winget install --id Cloudflare.cloudflared
   ```

   ```bash
   brew install cloudflared
   ```

   Linux: download the binary from the Cloudflare releases page.

2. Start the stack once so the local services are alive:

   ```bash
   python run_all.py
   ```

3. In three more terminals, start three tunnels:

   ```bash
   cloudflared tunnel --url http://localhost:8000
   cloudflared tunnel --url http://localhost:8081
   cloudflared tunnel --url http://localhost:8082
   ```

   Each prints a random `https://....trycloudflare.com` URL.

4. Stop the stack (`Ctrl+C` in the first terminal). Keep the three tunnel
   terminals running; they will reconnect to the local ports.

5. Restart with the two challenge URLs and an invite code:

   ```bash
   export INTERNS_URL="https://<beginner-tunnel>.trycloudflare.com"
   export CHRONOS_URL="https://<hard-tunnel>.trycloudflare.com"
   export REGISTRATION_CODE="gdg-2026-<random>"
   export COOKIE_SECURE=1
   export TRUST_PROXY=1
   python run_all.py
   ```

   Windows equivalent uses `$env:NAME = "value"` before `python run_all.py`.

6. Share the scoreboard tunnel URL only.

Caveats: random URL on every restart, no uptime guarantee, 200 in-flight
requests per tunnel, no Server-Sent Events, possible network blocks, and
Cloudflare may rate-limit or interrupt long-lived connections. Do not run a
graded or high-stakes event on a quick tunnel.

### Why not port forwarding?

Forwarding 8000/8081/8082 on a home router exposes the deliberately vulnerable
apps to the internet and usually violates the ISP/campus network policy. Do not
do it. Use LAN or a tunnel with an invite code.

---

## 8. Troubleshooting

**`ModuleNotFoundError: No module named 'flask'` or `'waitress'`**

The virtual environment is not active, or dependencies were installed into a
different Python. Activate `.venv` and run:

```bash
python -m pip install -r requirements.txt
```

**Port already in use**

```powershell
netstat -ano | findstr :8000
```

```bash
lsof -i :8000
```

Stop the other process, or edit the ports in `run_all.py` and the
`default_url` values in `scoreboard/challenges.py`. All three must stay in sync.

**Players get "launch this challenge from the scoreboard"**

They opened `http://LAN-IP:8081` directly. Challenge sessions are created by the
signed launch link. Use the launch button on the scoreboard challenge page.

**"That launch link may have expired"**

Team tokens are valid for 12 hours. Sign in and launch the challenge again.

**Login works, then the challenge asks for a launch again**

Clear the site cookies for the challenge host and relaunch from the dashboard.
Switching between `127.0.0.1`, `localhost`, and the LAN IP creates separate
cookie scopes.

**A player cannot connect but the host can**

Firewall, VPN, guest Wi-Fi client isolation, or a different VLAN. Test with a
phone hotspot. See section 3.3.

**Scoreboard shows a 500 after a manual database edit**

Stop the server, restore `instance/ctf.db` from backup, and restart. Avoid
writing to the DB while the server is live.

**Chronos solver fails with "could not obtain two signatures from the same epoch"**

The signing endpoint is rate-limited to 30 requests per minute per IP, and the
solver needs two signatures in one 60-second epoch. Wait a minute and retry.
Make sure the host clock is roughly correct (NTP).

**Flags changed after a restart**

You replaced or deleted `instance/secrets.json`. Restore the original file. The
secret is the only input that turns a team ID into a flag.

---

## 9. Safety checklist

- [ ] This is a fictional training target; do not reuse the challenge code in
      production.
- [ ] Only invite known participants. Set `REGISTRATION_CODE` for anything
      public.
- [ ] Do not put real credentials, real personal data, or real company names in
      the challenges.
- [ ] Keep `instance/secrets.json` and `instance/ctf.db` off GitHub and off the
      projector.
- [ ] Do not expose the laptop on public Wi-Fi without a firewall and an invite
      code.
- [ ] Do not run players' binaries on the host laptop. The challenges are
      browser/HTTP only; players use their own devices.
- [ ] Back up the DB and secrets before the award ceremony.
