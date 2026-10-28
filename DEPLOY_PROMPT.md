Deploy the `scam-check` bot as a new Docker Compose stack on this server (Linux with Docker Compose and Tailscale). It has two front ends: a Telegram bot, and an iMessage bridge that my iPhone's Shortcuts automation calls over Tailscale.

Source: the `scam-check/` folder I've placed at <PATH WHERE YOU COPIED IT>. Target: `<YOUR STACKS DIR>/scam-check/` (e.g. `~/docker/scam-check/`).

Steps:
1. If the target exists, back it up first (e.g. `scam-check.bak-YYYYMMDDHHMMSS-predeploy`). Then copy the source contents to the target. Keep an existing `data/` and `.env` if present, and never copy `data/` from the source.
2. Run `id -u` and `id -g` for the user that owns the stack. If they aren't 1000/1000, set the `UID`/`GID` build args in `compose.yaml` to match.
3. Create `.env` from `.env.example` with `chmod 600` (or keep an existing one and add any new keys from `.env.example`).
   - Generate `BRIDGE_TOKEN` with `openssl rand -hex 24` and write it in. Show me the token ONCE at the end so I can paste it into the iPhone Shortcut.
   - Set `BRIDGE_PUBLIC_URL=https://<host>.<tailnet>.ts.net:8787`. Confirm the hostname with `tailscale status --self` / `tailscale cert` naming and adjust if needed.
   - STOP and ask me for TELEGRAM_BOT_TOKEN, ANTHROPIC_API_KEY, OWNER_NAME, IMESSAGE_CONTACTS (phone numbers + contact names), and optionally GOOGLE_SAFE_BROWSING_KEY / VIRUSTOTAL_API_KEY. Don't invent values, and don't echo the API secrets back.
   - If I don't know ADMIN_CHAT_ID yet, set it to `0` for now.
4. Check that host port 18787 is free (`ss -ltnp | grep 18787`). Then run `mkdir -p data && docker compose up -d --build` followed by `docker compose logs --tail=50 scam-check`.
   - Expected log lines: `imessage_bridge=True` and `iMessage bridge listening on :8787`.
   - `docker port scam-check` must show ONLY `127.0.0.1:18787`.
5. Expose the bridge to the tailnet only:
   - First run `tailscale serve status` to see the existing Serve config. Don't modify existing entries, and pick another port if 8787 is taken.
   - Run `sudo tailscale serve --bg --https=8787 http://127.0.0.1:18787`.
   - Verify with `curl -s https://<host>.<tailnet>.ts.net:8787/healthz` → `{"ok": true, ...}`.
   - Run `curl -s -o /dev/null -w '%{http_code}' -X POST https://<host>.<tailnet>.ts.net:8787/ingest -d token=wrong` → `401`.
   - Do NOT use `tailscale funnel`. This must not be public.
6. Check outbound reachability from inside the container:
   `docker compose exec scam-check python -c "import httpx;[print(u, httpx.get(u,timeout=10).status_code) for u in ['https://api.telegram.org','https://api.anthropic.com','https://rdap.org/domain/google.com']]"`
   Any HTTP status code means it's reachable. A DNS or connect error means investigate DNS filtering (Pi-hole/AdGuard etc.) for those hosts.
7. If ADMIN_CHAT_ID was 0, tell me to message the bot `/myid`, wait for the number, write it to `.env`, then run `docker compose up -d`.
8. Run an end-to-end bridge test using a configured contact's phone number from IMESSAGE_CONTACTS:
   ```
   T=$(grep ^BRIDGE_TOKEN .env | cut -d= -f2)
   TK=$(curl -s -X POST https://<host>.<tailnet>.ts.net:8787/ingest -F token=$T -F sender=Test -F phone=<CONTACT_NUMBER> -F "text=is this real? USPS: pay redelivery fee at usps-redeliver.top/abc" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ticket"])')
   curl -s -H "X-Token: $T" "https://<host>.<tailnet>.ts.net:8787/result?ticket=$TK&wait=50"
   ```
   With the default `AUTO_SEND_ENABLED=false`, expect `{"status": "done", "action": "none", "draft": "Scam check: This is a scam. ...", ...}` (no `text` field) and a Telegram card to me. Nothing is texted to anyone; this only exercises the server.
9. If I keep a server reference doc, add a "scam-check" section covering the path, purpose, the Telegram long-polling (outbound-only) front end, the iMessage bridge (container 8787 → host 127.0.0.1:18787 → tailscale serve https :8787), the data dir, how to view logs, and env var names (no secrets).
10. Remind me to:
    (a) build the iPhone Shortcut automation from the README's "Build the Shortcut" section,
    (b) turn on VPN On Demand in the Tailscale iOS app,
    (c) add uptime monitoring for `scam-check` (a Docker container monitor, or a push monitor fed by a cron curl of `http://127.0.0.1:18787/healthz`).

Constraints: no WAN exposure, no Funnel, don't change other stacks or existing Serve entries, and don't print API secrets.
