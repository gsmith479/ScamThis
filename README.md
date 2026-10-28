# scam-check — "Is this real or fake?" bot for the people you look out for

Someone you look out for sends a screenshot, pasted text, link, or a description of a call to a private
Telegram bot. The bot runs URL threat intel, asks Claude (vision + optional web search) for a
verdict, and either replies on its own or waits for you to approve. You get a copy of every case.

```
Their phone ──Telegram──▶ scam-check container (home server, outbound-only)
                              │ 1. batch messages (6 s debounce, so 3 screenshots = 1 case)
                              │ 2. pull links incl. hidden "text_link" targets
                              │ 3. redact card/SSN/account numbers from text
                              │ 4. URL intel: Safe Browsing · VirusTotal (lookup only) · RDAP age · look-alike heuristics
                              │ 5. Claude: images + text + intel, web_search, check_url (for links read from screenshots)
                              │ 6. route: auto-reply  ─or─  hold for you  
                              ▼
          Your Telegram:      original messages + review card [Send] [Edit] [Send 'scam'] [Discard]
```

## iMessage mode: they keep texting you like they always do

An iOS Shortcuts automation on **your** iPhone runs on every text from the contacts you list and
hands it to the same pipeline. Their side doesn't change at all.

```
A listed contact texts you (iMessage/SMS)
   │
   ▼  iOS "Message" automation on YOUR iPhone (Run Immediately, Sender = your listed contacts)
POST https://<host>.<tailnet>.ts.net:8787/ingest   (tailnet only, token-protected)
   │      ├─ not from a configured contact ............ ignored
   │      ├─ 10 s debounce: "is this real?" + the forwarded text = one case
   │      ├─ prefilter: no link / image / scam-ish words .. ignored, never leaves your server
   │      └─ Claude: verdict "not_a_check" (normal chat) ... ignored, no reply
   ▼
GET /result?ticket=…&wait=25   (same shortcut run long-polls; first run to ask claims the reply)
   │
   ├─ action=reply → shortcut "Send Message" back:  "Scam check: This is a scam…"
   ├─ action=hold  → "Scam check: I want <OWNER_NAME> to double-check this one…"
   │                 + Telegram card for you with [📲 Send draft via Messages] [📲 Send 'it's a scam']
   │                   [✏️ Write my own] [🗑 Done]  → buttons open Messages pre-filled to them
   └─ nothing picked up within 180 s (iOS killed the run, phone offline) → Telegram alert + send button
```

What it can and can't see:
- **Text and links** in their message are fully supported, and that covers most "is this real?" texts.
- **Pictures:** the shortcut tries to attach the image. If your iOS version doesn't pass message
  attachments to automations, the server sees only iMessage's attachment placeholder. A picture
  with no question gets no auto-reply (it might just be a photo) and you get a Telegram nudge
  instead. A picture *with* a question ("is this real?") is held for you. For those, long-press the
  image in Messages → Share → Telegram → your bot. The result card then has a **📲 Send to <name>** button.
- **Follow-ups** like "so should I call them?" within 30 minutes get the earlier answer as context.

### Server side
```bash
# 1. in .env
BRIDGE_TOKEN=$(openssl rand -hex 24)        # paste the value, not the command
BRIDGE_PUBLIC_URL=https://<host>.<tailnet>.ts.net:8787
IMESSAGE_CONTACTS=+15555550123:Pat,Pat:Pat,+15555550199:Chris Lee,Chris Lee:Chris Lee
docker compose up -d --build

# 2. expose loopback:18787 to the tailnet only (HTTPS with your ts.net cert)
sudo tailscale serve --bg --https=8787 http://127.0.0.1:18787
tailscale serve status

# 3. from your phone or PC on the tailnet
curl https://<host>.<tailnet>.ts.net:8787/healthz        # {"ok": true, ...}
```
Use contact names exactly as they appear in your iPhone Contacts. The Shortcut's "Sender" is a
contact, and depending on iOS it reaches the server as the name or the number, so listing both
makes matching reliable.

### Build the Shortcut on your iPhone (one time, ~5 min)
Shortcuts app → **Automation** → **+** → **Message**
- **Sender:** Choose → the same contacts you listed in `IMESSAGE_CONTACTS`. Leave *Message Contains* empty.
- **Run Immediately**, and turn **Notify When Run** off → Next → **New Blank Automation**.

Add these actions in order. "Shortcut Input" is the message; tap the variable to pick its *Sender* or *Content*.

1. **Get Details of Contacts** → *Phone Number* of **Shortcut Input › Sender**
2. **Get Contents of URL**
   - URL `https://<host>.<tailnet>.ts.net:8787/ingest`, Method **POST**, Request Body **Form**
   - `token` (Text) = your BRIDGE_TOKEN
   - `sender` (Text) = **Shortcut Input › Sender**
   - `phone` (Text) = **Phone Number** (from step 1)
   - `text` (Text) = **Shortcut Input › Content**
   - *Optional, add later:* `image` (File) = **Shortcut Input**. Get the text-only version working
     first. Then add this field and test with both a picture and a plain text. If plain texts stop
     getting answers, or the run errors, remove it; your iOS isn't passing attachments to the automation.
3. **Get Dictionary Value** → key `ticket` in **Contents of URL** → **Set Variable** `Ticket`
4. **If** `Ticket` **has any value**
5. **Repeat 6 times**
   1. **Get Contents of URL** → `https://<host>.<tailnet>.ts.net:8787/result?ticket=[Ticket]&wait=25`,
      Method **GET**, Header `X-Token` = your BRIDGE_TOKEN
   2. **Get Dictionary Value** → key `status` → **If** *is* `done`
      1. **Get Dictionary Value** → key `text` in the step-5.1 **Contents of URL**
      2. **If** Dictionary Value **has any value** → **Send Message** *Dictionary Value*. For
         Recipients, long-press, clear the field, and pick **Shortcut Input**, so it replies to
         whoever texted.
      3. **Stop This Shortcut**
6. End Repeat / End If

The longest wait is about 6 × 25 s. A typical answer comes back in 15–45 s after the 10 s
debounce. Shortcuts automations work while the phone is locked.

### Things that make or break iMessage mode
- **Tailscale must be on** on your iPhone, or the request never reaches the server and nothing
  happens. In the Tailscale iOS app, turn on **VPN On Demand**.
- **The phone has to be on.** If it's dead or in Airplane Mode, nothing runs.
- **Replies come from your number**, which is why they carry the `Scam check:` prefix (`IMESSAGE_REPLY_PREFIX`). They
  show in your thread, so you see exactly what they were told.
- **Privacy:** every text from them hits *your* server. Texts that fail the prefilter are dropped
  in memory and aren't logged or sent anywhere. Only texts that might be a check go to Anthropic.
- **Testing:** have someone in `IMESSAGE_CONTACTS` text you "is this real? usps-redeliver.top/abc".

## Why a separate bot, not your general-purpose assistant

Scam messages are adversarial input written to manipulate whoever reads them. An agent with tools
on your server is the wrong reader: feeding it attacker-written text is a prompt-injection path to a shell. This bot's
model has exactly three tools (web search, URL lookups, submit verdict), none of which can touch
your network, and the system prompt treats the submission as untrusted evidence.

## Auto-send master switch (`AUTO_SEND_ENABLED`)

`AUTO_SEND_ENABLED=false` (the default) runs the entire pipeline — batching, prefilter, URL intel,
Claude, verdict, audit log, Telegram card — and then **sends nothing to anyone**. On iMessage the
bridge returns `action: none`, so the Shortcut's "Send Message" step never fires; on Telegram the
contact gets no reply at all, not even the "<OWNER_NAME> will double-check" holding text. Every
case lands on your Telegram card as `NEEDS REVIEW`, marked `🔒 auto-send is OFF`, with the
**📲 Send draft via Messages** / **📲 Send 'it's a scam'** / **✏️ Write my own** buttons. Nothing
reaches anyone until you tap.

This is the switch to leave off while you're tuning verdicts. The review-policy table below only
applies once you set it to `true`. Your own admin self-tests are unaffected: anything *you* send
the bot is still analyzed and answered in your own chat, so you can keep testing.

Confirm which mode you're in from the logs:

```
docker compose logs scam-check | grep AUTO_SEND_ENABLED
# AUTO_SEND_ENABLED=False -- REVIEW ONLY: nothing is sent to anyone unless you tap a button
```

## Review policy (applies when `AUTO_SEND_ENABLED=true`; default `REVIEW_MODE=uncertain`)

The two mistakes don't cost the same. "It's real" when it's a scam can drain an account, while
"it's suspicious" when it's real costs them one phone call. So:

| Verdict | What happens |
|---|---|
| scam / likely_scam, confidence ≥ 80 **or** a link flagged by Safe Browsing/VirusTotal | Auto-reply, you get an FYI card |
| They say they already clicked/paid/called (`already_engaged`) and verdict isn't "legit" | Auto-reply with damage-control steps + 🚨 card to you |
| unsure / likely_legit / legit / low-confidence scam | They get "<OWNER_NAME> will double-check; don't click/call/pay meanwhile." You get buttons. |
| Chit-chat | Auto-reply |
| API error | Safe holding message + card to you |

On a card you can tap **Send draft**, **Edit** (prompts you for text), **Send 'it's a scam'**, or
**Discard**. You can also *reply* to any card with your own text, which goes to them as
"From <OWNER_NAME>: …". `/pending` lists open cases.

Auto-replies never repeat the scam's link, phone number, or email, so they can't accidentally tap it.

## Setup (about 15 minutes)

1. **Create the bot**: In Telegram, message **@BotFather**, send `/newbot`, and give it a name like
   "Alex's Scam Checker". Copy the token. Optional: `/setuserpic`, and `/setjoingroups` → Disable.
2. **Anthropic key**: Create it at console.anthropic.com → API Keys. **Set a monthly spend limit** on the workspace.
3. **Optional free intel keys**:
   - Google Safe Browsing: Google Cloud console → enable *Safe Browsing API* → create an API key
     (restrict it to that API). The terms are non-commercial.
   - VirusTotal: free account → API key. Public tier allows 4 lookups/min, non-commercial. The bot
     only *looks up* URLs and never submits them, because submissions are public and smishing links
     often contain a per-victim token.
4. **Deploy** on the server (or hand `DEPLOY_PROMPT.md` to Claude Code):
   ```bash
   git clone <this repo> scam-check && cd scam-check
   cp .env.example .env && chmod 600 .env && nano .env   # token, API key, OWNER_NAME; ADMIN_CHAT_ID=0 for now
   mkdir -p data && docker compose up -d --build
   ```
   `AUTO_SEND_ENABLED=false` ships as the default, so the bot answers nobody until you flip it.
5. **Get the IDs**: Message your bot `/myid`, put the number in `ADMIN_CHAT_ID`, and run
   `docker compose up -d`. When your contacts tap Start, you get an **"Allow"** button for each.
   Tap it and they're in. To give them fixed names, add them to `ALLOWED_USERS=123:Pat,456:Chris Lee`.
6. **Test it yourself**: Anything you (the admin) send is analyzed and answered directly with the
   full card, so it's handy for tuning. Try a real smishing screenshot and a real pharmacy reminder.

## Message for your contacts (paste-ready)

> I set up a scam checker for you! 📱 Install the **Telegram** app, then open this link: t.me/YOUR_BOT_NAME and tap **Start**.
>
> Any time you get a text, email, call, or pop-up that seems off:
> 1. Take a screenshot (side button + volume up), tap the little preview, tap the **Share** arrow, pick **Telegram**, then the scam checker.
> 2. Or press and hold the message → **Copy**, then paste it into the scam checker chat.
> 3. Or just type what happened ("someone called saying they're from Medicare…").
>
> It answers in a minute or two. If it isn't sure, it sends it to me and I'll answer. Until you hear back, don't click links, call numbers in the message, or send money, gift cards, or codes. 💛

## Cost

Rates verified on the Anthropic pricing/models docs (Oct 2026): Sonnet 5.5 costs $2 per million
input tokens and $10 per million output tokens. Web search costs $10 per 1,000 searches plus the
tokens of the results. A text-only check is roughly 3–5k input and 400–800 output tokens. Each
screenshot adds about 1–1.6k tokens. Each search adds one search fee plus result tokens, which can
be several thousand. Every card shows the exact token and search counts, and
`data/cases.jsonl` keeps them per case, so you can compute real spend instead of guessing. Cost
control knobs are `CLAUDE_MODEL`, `ENABLE_WEB_SEARCH`, `WEB_SEARCH_MAX_USES`, and
`MAX_CHECKS_PER_USER_PER_DAY`, plus the console spend limit.

## Privacy notes / limitations

- Redaction (cards that pass Luhn, SSNs, 9+ digit account numbers; US phone numbers are kept) only
  applies to **text**. Screenshots go to Anthropic as-is. Commercial API inputs aren't used for
  training by default, but if a screenshot shows a full card number, Claude will see it.
- `data/cases.jsonl` is an audit log with redacted text, verdicts, routing, and tokens. It never
  stores images. `data/state.json` holds pending cases, so buttons still work after a restart.
- Voice notes aren't analyzed; the bot asks them to type it or send a screenshot.
- The bot can't see iMessage/SMS directly. They share into Telegram.
- Absence of Safe Browsing or VirusTotal hits means nothing for brand-new smishing domains. The RDAP
  "registered 3 days ago" signal and the look-alike heuristics carry more weight there.

## Ops

```bash
docker compose logs -f scam-check      # live logs
docker compose up -d --build           # after editing code or .env
tail -n 5 data/cases.jsonl | jq .      # recent cases
```
Monitoring: `GET http://127.0.0.1:18787/healthz` returns `{"ok": true, ...}`. If your uptime
monitor can't see the Docker socket, run a small cron script that curls it every minute and
reports to a push monitor (e.g. an Uptime Kuma *Push* monitor).
To run the tests locally: `pip install -r requirements.txt pytest && pytest -q`.

## Files

```
bot/main.py       Telegram handlers, batching, routing, admin buttons
bot/analyzer.py   Claude tool loop + system prompt (edit tone/rules here)
bot/urlcheck.py   URL extraction, heuristics, Safe Browsing / VirusTotal / RDAP
bot/policy.py     auto-send vs review decision
bot/redact.py     text redaction
bot/store.py      JSON state + audit log
```
