# Nightly sweep — 2026-05-26

Generated at 2026-05-26T09:44:07+01:00 on MasterPi.
Uptime: up 12 hours, 40 minutes. Load: 0.00, 0.02, 0.00.

## System

- ✓ Memory free: 2984MB / 3796MB
- ✓ Root disk 69% full (8.7G avail)
- ✓ No OOM kills in last 24h
- ✓ No pending reboot

## Cloudflare tunnel

- ✓ Tunnel /ready → 200 (at sweep time)
- ✓ No all-4-down events in last 24h
- ✓ Cloudflared watchdog: no restarts needed in last 24h

## Project services (port reachability)

- ✓ splendor (port 3000): HTTP 200
- ✓ cluedo (port 4000): HTTP 200
- ✓ cah (port 5000): HTTP 200
- ✓ flamecraft (port 6000): HTTP 200
- ✓ 30seconds (port 3030): HTTP 200
- ✓ unicorns (port 5555): HTTP 200
- ✓ catan (port 3003): HTTP 200
- ✓ monopoly (port 3002): HTTP 200
- ✓ games-table (port 1000): HTTP 200
- ✓ games-registry (port 8001): HTTP 200
- ✓ mrt-classroom-clash (port 8700): HTTP 200
- ✓ quizplatform (port 7010): HTTP 200
- ✓ voice-log (port 5700): HTTP 200
- ✓ voice-log-site (port 5710): HTTP 200

## Service crashes (unexpected restarts in last 24h)

- ⚠️  wm8960-soundcard.service — 1 crash(es) in last 24h (see: journalctl -u wm8960-soundcard.service --since '24 hours ago')

## Errors in service logs (last 24h)

- ✓ No matching error patterns in any service log

## CHANGELOG drift (code touched but no fresh entry)

- ✓ flamecraft: changelog present but couldn't parse a date (skipping drift check)
- ✓ All projects' CHANGELOGs look reasonably fresh

## Public games hub (games.teunkey.com)

- ✓ https://games.teunkey.com/ → 200 (public hub is up)
- ✓ Registry reports 8 game entries

---

## ⚠️  1 issue(s) flagged across 1 section(s)

- Service crashes (unexpected restarts in last 24h) (1)
