"""iMessage bridge: lets contacts keep texting the admin normally.

Flow
  1. iOS "Message" automation on the admin's iPhone fires for every text from a listed contact.
  2. Its shortcut POSTs the message (and any image it can see) to /ingest  -> {"ticket": ...}
  3. It long-polls /result?ticket=...  until the batch is done.
  4. If the result is {"action": "reply", "text": ...} it sends that text back with "Send Message".
  5. The admin gets the usual Telegram card. Cases that need review come with
     "📲 Send via Messages" buttons that open Messages pre-filled (via /open/...).

Ordinary chat is filtered out by a keyword/link/image prefilter and then by Claude's
"not_a_check" verdict, and never gets an automatic reply.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

from aiohttp import web

from .policy import looks_like_check
from .urlcheck import extract_urls

if TYPE_CHECKING:
    from .main import ScamBot

log = logging.getLogger("scamcheck.bridge")

OBJ = "￼"  # iMessage puts this placeholder where an attachment sits in the text


def digits(s: str) -> str:
    d = re.sub(r"\D", "", s or "")
    return d[-10:] if len(d) >= 10 else d


def name_key(s: str) -> str:
    """Contact names as matching keys: case, emoji and punctuation don't matter, so
    "Chris Lee-Jones \u2764\ufe0f" and "chris lee jones" are the same contact."""
    return " ".join(re.sub(r"[^\w\s]|_", " ", (s or "").lower()).split())


def parse_contacts(raw: str) -> dict[str, str]:
    """IMESSAGE_CONTACTS="+15555550123:Pat,+15555550199:Chris Lee" -> {"5555550123": "Pat", ...}.
    A non-numeric key (e.g. "Pat:Pat") matches on the contact name the shortcut sends."""
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        if ":" not in part:
            continue
        key, name = (x.strip() for x in part.split(":", 1))
        k = digits(key) or name_key(key)
        if k and name:
            out[k] = name
    return out


@dataclass
class IBatch:
    key: str                     # contact key (digits or lowercased name)
    name: str
    phone: str
    texts: list[str] = field(default_factory=list)
    images: list[tuple[str, str]] = field(default_factory=list)
    tickets: list[str] = field(default_factory=list)
    task: asyncio.Task | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    result: dict[str, Any] | None = None
    claimed: bool = False
    created: float = field(default_factory=time.time)
    case_id: str | None = None


class Bridge:
    def __init__(self, bot: "ScamBot", tg_bot: Any):
        self.sb = bot
        self.cfg = bot.cfg
        self.tg = tg_bot
        self.contacts = parse_contacts(self.cfg.imessage_contacts)
        self.open_batches: dict[str, IBatch] = {}   # contact key -> collecting batch
        self.tickets: dict[str, IBatch] = {}        # ticket -> batch
        self._runner: web.AppRunner | None = None
        self._janitor: asyncio.Task | None = None

    # ------------------------------------------------------------------ helpers
    def _authorized(self, request: web.Request, body_token: str | None = None) -> bool:
        tok = request.headers.get("X-Token") or request.query.get("token") or body_token or ""
        return bool(self.cfg.bridge_token) and hmac.compare_digest(tok, self.cfg.bridge_token)

    def sign(self, *parts: str) -> str:
        msg = ":".join(parts).encode()
        return hmac.new(self.cfg.bridge_token.encode(), msg, hashlib.sha256).hexdigest()[:20]

    def open_url(self, case_id: str, variant: str, to: str | None = None) -> str:
        """Link for a Telegram URL button -> page that opens Messages pre-filled."""
        q = {"v": variant, "sig": self.sign(case_id, variant, to or "")}
        if to:
            q["to"] = to
        return f"{self.cfg.bridge_public_url.rstrip('/')}/open/{case_id}?{urlencode(q)}"

    def resolve(self, sender: str, phone: str) -> tuple[str, str] | None:
        d = digits(phone)
        if d and d in self.contacts:
            return d, self.contacts[d]
        s = name_key(sender)
        if s in self.contacts:
            return s, self.contacts[s]
        # Shortcut "Sender" sometimes renders as the phone number itself
        d2 = digits(sender)
        if d2 and d2 in self.contacts:
            return d2, self.contacts[d2]
        return None

    def phone_for(self, key: str) -> str:
        return key if key.isdigit() else ""

    # ------------------------------------------------------------------ HTTP handlers
    async def ingest(self, request: web.Request) -> web.Response:
        fields: dict[str, str] = {}
        images: list[bytes] = []
        ctype = request.content_type
        if ctype.startswith("multipart/"):
            reader = await request.multipart()
            async for part in reader:
                if part.filename or (part.headers.get("Content-Type", "").startswith("image/")):
                    data = await part.read(decode=False)
                    if data:
                        images.append(bytes(data))
                else:
                    fields[part.name or ""] = await part.text()
        elif ctype == "application/json":
            body = await request.json()
            fields = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in body.items() if k != "images"}
            for b64 in body.get("images") or []:
                try:
                    images.append(base64.b64decode(b64))
                except (ValueError, TypeError):
                    pass
        else:
            fields = {k: v for k, v in (await request.post()).items() if isinstance(v, str)}

        if not self._authorized(request, fields.get("token")):
            return web.json_response({"error": "unauthorized"}, status=401)

        who = self.resolve(fields.get("sender", ""), fields.get("phone", ""))
        if who is None:
            log.info("ignoring iMessage from unconfigured sender %r", fields.get("sender"))
            return web.json_response({"ticket": None, "status": "done", "action": "none"})
        key, name = who

        batch = self.open_batches.get(key)
        if batch is None:
            batch = self.open_batches[key] = IBatch(key=key, name=name, phone=self.phone_for(key))
        text = (fields.get("text") or "").strip()
        if text:
            batch.texts.append(text)
        for raw in images[: max(0, 5 - len(batch.images))]:
            try:
                from .main import _shrink
                batch.images.append(await asyncio.to_thread(_shrink, raw))
            except Exception:  # noqa: BLE001
                log.warning("could not decode image from shortcut")
        ticket = secrets.token_urlsafe(9)
        batch.tickets.append(ticket)
        self.tickets[ticket] = batch
        if batch.task:
            batch.task.cancel()
        batch.task = asyncio.create_task(self._fire(batch))
        return web.json_response({"ticket": ticket, "status": "pending"})

    async def result(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        batch = self.tickets.get(request.query.get("ticket", ""))
        if batch is None:
            return web.json_response({"status": "done", "action": "none"})
        try:
            wait = max(0.0, min(float(request.query.get("wait", "25")), 50.0))
        except ValueError:
            wait = 25.0
        if not batch.done.is_set():
            try:
                await asyncio.wait_for(batch.done.wait(), timeout=wait)
            except asyncio.TimeoutError:
                return web.json_response({"status": "pending"})
        res = batch.result or {"action": "none"}
        if res.get("action") in ("reply", "hold") and not batch.claimed:
            batch.claimed = True  # first poller delivers; any other shortcut run gets "none"
            if batch.case_id:
                self.sb.store.update_case(batch.case_id, imessage_delivered=True)
            return web.json_response({"status": "done", "action": res["action"], "text": res["text"]})
        out: dict[str, Any] = {"status": "done", "action": "none"}
        # Review-only mode: hand back the generated draft for inspection. There is no
        # "text" key, so the Shortcut has nothing to send.
        for k in ("draft", "verdict", "confidence", "case"):
            if k in res:
                out[k] = res[k]
        return web.json_response(out)

    async def open_page(self, request: web.Request) -> web.Response:
        case_id = request.match_info["case_id"]
        variant = request.query.get("v", "draft")
        to = request.query.get("to", "")
        if not hmac.compare_digest(request.query.get("sig", ""), self.sign(case_id, variant, to)):
            return web.Response(status=403, text="bad signature")
        case = self.sb.store.get_case(case_id)
        if not case:
            return web.Response(status=404, text="case expired")
        text = {"draft": case.get("reply"), "scam": case.get("scam_text"),
                "custom": case.get("custom")}.get(variant) or ""
        if to:  # self-test case being sent to a chosen contact
            phone = to if to.isdigit() else ""
        else:
            phone = case.get("phone", "")
        text = self.cfg.imessage_reply_prefix + text
        sms = f"sms:{'+1' + phone if len(phone) == 10 else phone}&body={quote(text)}"
        self.sb.store.update_case(case_id, status=f"opened_{variant}")
        page = f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Send reply</title>
<body style="font:17px -apple-system,system-ui;margin:24px;max-width:560px">
<p><a href="{html.escape(sms)}" style="display:block;padding:16px;background:#0a84ff;color:#fff;
border-radius:12px;text-align:center;text-decoration:none;font-weight:600">Open in Messages</a></p>
<pre style="white-space:pre-wrap;background:#f2f2f7;padding:12px;border-radius:10px">{html.escape(text)}</pre>
<script>location.href={json.dumps(sms)};</script></body>"""
        return web.Response(text=page, content_type="text/html")

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "open_batches": len(self.open_batches)})

    # ------------------------------------------------------------------ batch processing
    async def _fire(self, batch: IBatch) -> None:
        try:
            await asyncio.sleep(self.cfg.imessage_debounce_seconds)
        except asyncio.CancelledError:
            return
        if self.open_batches.get(batch.key) is batch:
            del self.open_batches[batch.key]
        try:
            batch.result = await self._process(batch)
        except Exception:  # noqa: BLE001
            log.exception("iMessage batch failed")
            batch.result = {"action": "none"}
            await self._admin(f"❌ iMessage check for {batch.name} crashed; see logs.")
        finally:
            batch.done.set()
        if batch.result.get("action") == "reply":
            # (held cases already have Send buttons on the review card)
            asyncio.create_task(self._watch_delivery(batch))

    async def _watch_delivery(self, batch: IBatch) -> None:
        """If no shortcut run picks the reply up (iOS killed it, phone offline), tell the admin."""
        await asyncio.sleep(self.cfg.imessage_claim_timeout)
        if batch.claimed or not batch.case_id:
            return
        batch.claimed = True  # don't let a late poll send a stale reply
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup
        variant = "draft"
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(f"📲 Send to {batch.name} via Messages",
                                                         url=self.open_url(batch.case_id, variant))]])
        await self._admin(f"⚠️ Your iPhone didn't pick up the reply for {batch.name} (case {batch.case_id}). "
                          "Send it manually:", reply_markup=kb)

    async def _admin(self, text: str, **kw: Any) -> Any:
        try:
            return await self.tg.send_message(self.cfg.admin_chat_id, text, **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("admin notify failed: %s", e)

    async def _process(self, batch: IBatch) -> dict[str, Any]:
        raw_text = "\n".join(batch.texts)
        has_placeholder = OBJ in raw_text
        clean = raw_text.replace(OBJ, "").strip()
        urls = extract_urls(clean)
        unseen_attachment = has_placeholder and not batch.images

        if not looks_like_check(clean, bool(batch.images) or has_placeholder, bool(urls)):
            return {"action": "none"}

        if unseen_attachment and not clean:
            # A bare picture we can't see: could be just a photo. Don't auto-reply; nudge the admin.
            await self._admin(
                f"🖼 {batch.name} texted you a picture the iPhone automation can't read. If it looks like "
                "something to check, long-press it in Messages → Share → Telegram → this bot; the result "
                f"will include a button to send the answer to {batch.name}.")
            return {"action": "none"}

        if not self.sb.store.take_quota(f"im:{batch.key}", self.cfg.max_checks_per_user_per_day):
            await self._admin(f"⚠️ {batch.name} hit the daily check limit (iMessage). Last text:\n{clean[:500]}")
            return {"action": "none"}

        if unseen_attachment:
            clean += ("\n[They also sent a picture/attachment that this automation could not see. If the "
                      "verdict depends on it, choose 'unsure'.]")

        prev = self.sb.store.last_case(f"im:{batch.key}", within=1800)
        context = (f"About {int((time.time() - prev['ts']) / 60)} min ago in this thread you answered "
                   f"(verdict {prev['verdict']}): {prev['reply']}") if prev else None
        note = (f"Channel: iMessage thread on {self.cfg.owner_name}'s personal phone. MOST messages here are ordinary "
                "personal conversation — use verdict not_a_check unless they are clearly asking whether "
                "something is legitimate, or sharing a suspicious message/call/link. If they're following "
                "up on your earlier answer, answer the follow-up briefly.")

        case_id, v, decision = await self.sb.run_case(
            user_key=f"im:{batch.key}", name=batch.name, raw_text=clean, urls=urls, images=batch.images,
            channel="imessage", phone=batch.phone, context=context, channel_note=note,
            unseen_attachment=unseen_attachment)
        batch.case_id = case_id

        if v.verdict == "not_a_check":
            return {"action": "none"}
        if not self.cfg.auto_send_enabled:
            # AUTO_SEND_ENABLED=false: the reply IS generated, it just isn't delivered.
            # "draft" is informational only -- the Shortcut sends on "text", which stays
            # absent, so nothing can go out. The Telegram card carries the send buttons.
            return {"action": "none", "draft": self.cfg.imessage_reply_prefix + v.reply_text,
                    "verdict": v.verdict, "confidence": v.confidence, "case": case_id}
        if decision == "auto":
            return {"action": "reply", "text": self.cfg.imessage_reply_prefix + v.reply_text}
        if self.cfg.imessage_hold_message:
            return {"action": "hold", "text": self.cfg.imessage_reply_prefix + (
                f"I want {self.cfg.owner_name} to double-check this one — expect a text soon. "
                "Until then: don't click any links, don't call or text them back, and don't send money, "
                "gift cards, or codes.")}
        return {"action": "none"}

    # ------------------------------------------------------------------ lifecycle
    async def _janitor_loop(self) -> None:
        while True:
            await asyncio.sleep(300)
            cutoff = time.time() - 3600
            for t, b in list(self.tickets.items()):
                if b.created < cutoff:
                    del self.tickets[t]

    def app(self) -> web.Application:
        app = web.Application(client_max_size=25 * 1024 * 1024)
        app.add_routes([
            web.post("/ingest", self.ingest),
            web.get("/result", self.result),
            web.get("/open/{case_id}", self.open_page),
            web.get("/healthz", self.health),
        ])
        return app

    async def start(self) -> None:
        self._runner = web.AppRunner(self.app())
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.cfg.bridge_port)
        await site.start()
        self._janitor = asyncio.create_task(self._janitor_loop())
        log.info("iMessage bridge listening on :%d (%d contacts)", self.cfg.bridge_port, len(self.contacts))

    async def stop(self) -> None:
        if self._janitor:
            self._janitor.cancel()
        if self._runner:
            await self._runner.cleanup()
