"""Telegram front end: contacts send suspicious stuff, Claude judges it, admin reviews."""
from __future__ import annotations

import asyncio
import base64
import html
import io
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from PIL import Image
from telegram import (ForceReply, InlineKeyboardButton, InlineKeyboardMarkup, Message,
                      MessageEntity, Update)
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from .analyzer import Analyzer, Verdict
from .config import Config
from .policy import route
from .redact import redact, strip_emoji
from .store import Store
from .urlcheck import UrlChecker, UrlReport, extract_urls

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("scamcheck")

MAX_IMAGES = 5
MAX_IMAGE_EDGE = 1568
VERDICT_LABEL = {
    "scam": "🚩 SCAM", "likely_scam": "⚠️ LIKELY SCAM", "unsure": "🤔 UNSURE",
    "likely_legit": "🙂 LIKELY LEGIT", "legit": "✅ LEGIT", "not_a_check": "💬 CHAT",
}


@dataclass
class Batch:
    messages: list[Message] = field(default_factory=list)
    task: asyncio.Task | None = None


def _origin_label(msg: Message) -> str | None:
    o = getattr(msg, "forward_origin", None)
    if o is None:
        return None
    for attr in ("sender_user", "sender_chat", "chat"):
        obj = getattr(o, attr, None)
        if obj is not None:
            name = getattr(obj, "full_name", None) or getattr(obj, "title", None) or "?"
            uname = getattr(obj, "username", None)
            return f"{name}" + (f" (@{uname})" if uname else "")
    return getattr(o, "sender_user_name", None) or "unknown"


def _links_from_entities(msg: Message) -> list[str]:
    """Hidden links (text_link entities) never appear in the visible text — grab them."""
    out: list[str] = []
    types = [MessageEntity.URL, MessageEntity.TEXT_LINK]
    parsed = {}
    if msg.text:
        parsed = msg.parse_entities(types)
    elif msg.caption:
        parsed = msg.parse_caption_entities(types)
    for ent, txt in parsed.items():
        url = ent.url if ent.type == MessageEntity.TEXT_LINK else txt
        if url and url not in out:
            out.append(url)
    return out


def _shrink(raw: bytes) -> tuple[str, str]:
    img = Image.open(io.BytesIO(raw))
    img = img.convert("RGB")
    img.thumbnail((MAX_IMAGE_EDGE, MAX_IMAGE_EDGE))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return "image/jpeg", base64.b64encode(buf.getvalue()).decode()


class ScamBot:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(cfg.data_dir)
        self.checker = UrlChecker(cfg.safe_browsing_key, cfg.virustotal_key, cfg.enable_rdap,
                                  cfg.resolve_redirects)
        self.analyzer = Analyzer(cfg.anthropic_api_key, cfg.claude_model, self.checker,
                                 owner=cfg.owner_name, enable_web_search=cfg.enable_web_search,
                                 web_search_max_uses=cfg.web_search_max_uses)
        self.batches: dict[int, Batch] = {}
        self.tg_bot: Any = None
        self.bridge: Any = None

    # ------------------------------------------------------------------ helpers
    def users(self) -> dict[int, str]:
        u = dict(self.cfg.allowed_users)
        u.update(self.store.runtime_users())
        return u

    def is_admin_chat(self, chat_id: int) -> bool:
        return chat_id == self.cfg.admin_chat_id

    def name_for(self, uid: int) -> str | None:
        if uid == self.cfg.admin_chat_id:
            return self.users().get(uid, self.cfg.owner_name)
        return self.users().get(uid)

    # ------------------------------------------------------------------ commands
    async def cmd_start(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        name = self.name_for(user.id)
        if not name:
            await update.message.reply_text("Hi! This is a private bot. I've let the owner know you stopped by.")
            await self._notify_unknown(ctx, update)
            return
        await update.message.reply_text(
            f"Hi {name}! I'm {self.cfg.owner_name}'s scam checker.\n\n"
            "Got a text, email, call, or pop-up that seems off? Send it to me:\n"
            "• Take a screenshot and send it here, or\n"
            "• Copy and paste the message here, or\n"
            "• Just tell me what happened.\n\n"
            "I'll tell you if it's real or fake and what to do. "
            f"If I'm not sure, {self.cfg.owner_name} will check it personally.\n\n"
            "Until you hear back: don't click links, don't call numbers in the message, "
            "and never send money, gift cards, or codes."
        )

    async def cmd_myid(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(f"Your Telegram user ID is {update.effective_user.id}")

    async def cmd_help(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if self.is_admin_chat(update.effective_chat.id):
            await update.message.reply_text(
                "Admin commands:\n/pending – list cases waiting on you\n/users – list allowed users\n"
                "/removeuser <id> – revoke a runtime-approved user\n/myid – show your ID\n\n"
                "Reply to any review card with text to send that text to the person who asked.")
        else:
            await self.cmd_start(update, ctx)

    async def cmd_pending(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin_chat(update.effective_chat.id):
            return
        p = self.store.pending()
        if not p:
            await update.message.reply_text("Nothing pending. 👍")
            return
        lines = [f"• {cid} – {c['name']} – {VERDICT_LABEL.get(c['verdict'], c['verdict'])} "
                 f"({int((time.time() - c['created']) / 60)} min ago)" for cid, c in p.items()]
        await update.message.reply_text("Pending:\n" + "\n".join(lines))

    async def cmd_users(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin_chat(update.effective_chat.id):
            return
        runtime = self.store.runtime_users()
        lines = [f"• {n} ({uid}){' [runtime]' if uid in runtime else ' [env]'}" for uid, n in self.users().items()]
        await update.message.reply_text("Allowed users:\n" + ("\n".join(lines) or "(none)"))

    async def cmd_removeuser(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin_chat(update.effective_chat.id):
            return
        try:
            uid = int(ctx.args[0])
        except (IndexError, ValueError):
            await update.message.reply_text("Usage: /removeuser <telegram_id>")
            return
        ok = self.store.remove_user(uid)
        await update.message.reply_text("Removed." if ok else "Not a runtime user (env users must be removed from .env).")

    # ------------------------------------------------------------------ unknown users
    async def _notify_unknown(self, ctx: ContextTypes.DEFAULT_TYPE, update: Update) -> None:
        u = update.effective_user
        if not self.store.should_notify_unknown(u.id):
            return
        label = u.full_name + (f" (@{u.username})" if u.username else "")
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(f"✅ Allow {u.first_name}", callback_data=f"allow:{u.id}")]])
        try:
            await ctx.bot.send_message(
                self.cfg.admin_chat_id,
                f"👤 Unknown user messaged the bot: {label}\nID: {u.id}\n\nAllow them to use the scam checker?",
                reply_markup=kb)
        except Exception as e:  # noqa: BLE001  (e.g. ADMIN_CHAT_ID not set yet)
            log.warning("could not notify admin about user %s: %s", u.id, e)

    # ------------------------------------------------------------------ message intake
    async def on_message(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        msg = update.effective_message
        chat = update.effective_chat
        user = update.effective_user
        if msg is None or user is None or chat.type != "private":
            return

        # Admin replying to a review card / edit prompt => custom answer
        if self.is_admin_chat(chat.id) and msg.reply_to_message is not None:
            case_id = self.store.case_for_msg(msg.reply_to_message.message_id)
            if case_id and msg.text:
                await self._send_custom(ctx, case_id, msg.text, msg)
                return

        name = self.name_for(user.id)
        if not name:
            await msg.reply_text("Sorry, this is a private bot.")
            await self._notify_unknown(ctx, update)
            return

        if msg.voice or msg.audio or msg.video_note:
            await msg.reply_text(
                "I can't listen to voice messages yet. Please type out what they said, or send a "
                "screenshot. And don't call them back on the number they gave!")
            return

        batch = self.batches.get(user.id)
        if batch is None:
            batch = self.batches[user.id] = Batch()
            if self.cfg.auto_send_enabled or self.is_admin_chat(chat.id):
                await msg.reply_text("Got it — checking now. Give me a minute.")
        batch.messages.append(msg)
        if batch.task:
            batch.task.cancel()
        batch.task = asyncio.create_task(self._fire(user.id, chat.id, name, ctx))

    async def _fire(self, uid: int, chat_id: int, name: str, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            await asyncio.sleep(self.cfg.debounce_seconds)
        except asyncio.CancelledError:
            return
        batch = self.batches.pop(uid, None)
        if not batch:
            return
        try:
            await self._process(uid, chat_id, name, batch.messages, ctx)
        except Exception:  # noqa: BLE001
            log.exception("processing failed")
            if self.cfg.auto_send_enabled:
                await ctx.bot.send_message(
                    chat_id, f"Sorry {name}, something went wrong on my end. {self.cfg.owner_name} has been "
                    "told. Until then: don't click links, call numbers in it, or send money or codes.")
            await ctx.bot.send_message(self.cfg.admin_chat_id, f"❌ Processing crashed for {name}; see logs.")

    # ------------------------------------------------------------------ core pipeline
    async def _process(self, uid: int, chat_id: int, name: str, msgs: list[Message],
                       ctx: ContextTypes.DEFAULT_TYPE) -> None:
        is_admin = uid == self.cfg.admin_chat_id
        if not is_admin and not self.store.take_quota(uid, self.cfg.max_checks_per_user_per_day):
            if self.cfg.auto_send_enabled:
                await ctx.bot.send_message(chat_id, f"I've hit my limit for today, {name}. {self.cfg.owner_name} "
                                           "will look at this one personally.")
            await self._forward_originals(ctx, chat_id, msgs)
            await ctx.bot.send_message(self.cfg.admin_chat_id, f"⚠️ {name} hit the daily check limit; originals above.")
            return

        await ctx.bot.send_chat_action(chat_id, ChatAction.TYPING)

        parts: list[str] = []
        urls: list[str] = []
        images: list[tuple[str, str]] = []
        skipped_media = 0
        for m in msgs:
            origin = _origin_label(m)
            body = m.text or m.caption or ""
            if origin:
                parts.append(f"[Forwarded message, originally from: {origin}]")
            if body:
                parts.append(body)
            if m.contact:
                parts.append(f"[Shared contact card: {m.contact.first_name or ''} {m.contact.last_name or ''} "
                             f"{m.contact.phone_number or ''}]")
            for u in _links_from_entities(m) + extract_urls(body):
                if u not in urls:
                    urls.append(u)
            photo_file = None
            if m.photo:
                photo_file = m.photo[-1]
            elif m.document and (m.document.mime_type or "").startswith("image/"):
                photo_file = m.document
            if photo_file is not None:
                if len(images) >= MAX_IMAGES:
                    skipped_media += 1
                    continue
                f = await photo_file.get_file()
                raw = bytes(await f.download_as_bytearray())
                try:
                    images.append(await asyncio.to_thread(_shrink, raw))
                except Exception:  # noqa: BLE001
                    skipped_media += 1
            elif m.video or (m.document and not (m.document.mime_type or "").startswith("image/")):
                skipped_media += 1
        if skipped_media:
            parts.append(f"[{skipped_media} attachment(s) could not be analyzed (video/file/over limit)]")

        hidden = [u for u in urls if u not in "\n".join(parts)]
        if hidden:
            parts.append("[Hidden link targets behind clickable text: " + ", ".join(hidden) + "]")

        raw_text = "\n".join(parts)

        async def tell_sender(v: Verdict, decision: str) -> None:
            if is_admin:
                return
            if not self.cfg.auto_send_enabled:
                # AUTO_SEND_ENABLED=false: stay silent to them. The admin gets the card and sends.
                await self._forward_originals(ctx, chat_id, msgs)
                return
            if decision == "auto":
                await ctx.bot.send_message(chat_id, v.reply_text, disable_web_page_preview=True)
            else:
                await ctx.bot.send_message(
                    chat_id,
                    f"{name}, I want {self.cfg.owner_name} to double-check this one before I answer. "
                    "Until you hear back: don't click any links, don't call or text back, and don't send "
                    "money, gift cards, or codes.", disable_web_page_preview=True)
            await self._forward_originals(ctx, chat_id, msgs)

        await self.run_case(user_key=str(uid), name=name, raw_text=raw_text, urls=urls, images=images,
                            channel="telegram", chat_id=chat_id, is_admin=is_admin, before_card=tell_sender,
                            tg_bot=ctx.bot)

    # ------------------------------------------------------------------ channel-agnostic core
    async def run_case(self, *, user_key: str, name: str, raw_text: str, urls: list[str],
                       images: list[tuple[str, str]], channel: str, tg_bot: Any = None,
                       chat_id: int | None = None, phone: str = "", is_admin: bool = False,
                       context: str | None = None, channel_note: str | None = None,
                       unseen_attachment: bool = False, before_card: Any = None) -> tuple[str, Verdict, str]:
        """Redact → URL intel → Claude → route → log → admin card. Returns (case_id, verdict, decision)."""
        bot = tg_bot or self.tg_bot
        text = redact(raw_text)
        url_reports = await self.checker.check(urls)
        v = await self.analyzer.analyze(name, text, url_reports, images, context=context, channel_note=channel_note)
        v.reply_text = strip_emoji(v.reply_text)  # contact-facing: no emoji, whatever the model wrote
        all_reports = url_reports + v.extra_url_reports
        known_bad = any(r.is_known_bad for r in all_reports)

        decision = "auto" if is_admin else route(v, self.cfg.review_mode, self.cfg.auto_send_min_confidence,
                                                 known_bad, self.cfg.auto_send_enabled)
        case_id = secrets.token_hex(3)
        self.store.log_case({
            "ts": time.time(), "case": case_id, "channel": channel, "user": user_key, "name": name,
            "text": text, "urls": urls, "images": len(images), "verdict": v.verdict, "confidence": v.confidence,
            "engaged": v.already_engaged, "decision": decision, "model": self.cfg.claude_model,
            "tokens_in": v.input_tokens, "tokens_out": v.output_tokens, "searches": v.web_search_requests,
            "reply": v.reply_text, "admin_summary": v.admin_summary, "error": v.error,
        })
        if v.verdict != "not_a_check":
            self.store.set_last(user_key, v.verdict, v.reply_text)

        if channel == "imessage":
            scam_text = (f"I checked — this is a scam. Please delete it and don't click, reply, or call. "
                         "If you already did anything with it, call me right away.")
        else:
            scam_text = (f"{name}, {self.cfg.owner_name} checked — this is a scam. Please delete it and "
                         f"don't click, reply, or call. If you already did anything with it, call {self.cfg.owner_name} right away.")
        self.store.put_case(case_id, {
            "channel": channel, "chat_id": chat_id, "phone": phone, "name": name, "verdict": v.verdict,
            "reply": v.reply_text, "scam_text": scam_text, "created": time.time(),
            "status": "self-test" if is_admin else ("pending" if decision == "review" else "sent"),
        })

        if before_card is not None:
            await before_card(v, decision)

        # iMessage chit-chat: say nothing, bother nobody.
        if channel == "imessage" and v.verdict == "not_a_check" and not v.error:
            return case_id, v, decision

        bridge_links = self.cfg.bridge_enabled and bool(self.cfg.bridge_public_url)
        rows: list[list[InlineKeyboardButton]] = []
        if is_admin:
            status = "self-test"
            await bot.send_message(self.cfg.admin_chat_id, v.reply_text, disable_web_page_preview=True)
            if bridge_links and self.bridge is not None:
                rows = [[InlineKeyboardButton(f"📲 Send to {n}", url=self.bridge.open_url(case_id, "draft", key))]
                        for key, n in self.bridge.contacts.items() if key.isdigit()]
        elif decision == "auto":
            status = "AUTO-SENT" if channel == "telegram" else "AUTO-REPLIED VIA IMESSAGE"
            rows = [[InlineKeyboardButton("✏️ Send a follow-up", callback_data=f"edit:{case_id}")]]
        elif channel == "imessage":
            status = "NEEDS REVIEW"
            if bridge_links:
                rows.append([InlineKeyboardButton("📲 Send draft via Messages", url=self.bridge.open_url(case_id, "draft"))])
                rows.append([InlineKeyboardButton("📲 Send 'it's a scam'", url=self.bridge.open_url(case_id, "scam"))])
            rows.append([InlineKeyboardButton("✏️ Write my own", callback_data=f"edit:{case_id}"),
                         InlineKeyboardButton("🗑 Done / discard", callback_data=f"drop:{case_id}")])
        else:
            status = "NEEDS REVIEW"
            rows = [
                [InlineKeyboardButton("✅ Send draft", callback_data=f"send:{case_id}"),
                 InlineKeyboardButton("✏️ Edit", callback_data=f"edit:{case_id}")],
                [InlineKeyboardButton("🚩 Send 'it's a scam'", callback_data=f"scam:{case_id}"),
                 InlineKeyboardButton("🗑 Discard", callback_data=f"drop:{case_id}")],
            ]

        if channel == "imessage":
            for _, b64 in images[:3]:
                try:
                    await bot.send_photo(self.cfg.admin_chat_id, base64.b64decode(b64),
                                         caption=f"From {name} (iMessage)")
                except Exception:  # noqa: BLE001
                    log.warning("could not relay image to admin")

        head = "🚨 <b>THEY MAY HAVE ALREADY ENGAGED</b> 🚨\n" if v.already_engaged else ""
        if not self.cfg.auto_send_enabled and not is_admin:
            head += "🔒 <i>auto-send is OFF — nothing was sent to them. Use the buttons below.</i>\n"
        if channel == "imessage":
            head += f"📱 <b>iMessage from {html.escape(name)}</b>\n<blockquote>{html.escape(raw_text[:700])}</blockquote>\n"
            if unseen_attachment:
                head += "<i>(they also sent an attachment the automation couldn't read)</i>\n"
        sent = await bot.send_message(
            self.cfg.admin_chat_id, head + self._card_text(case_id, name, v, all_reports, status, channel),
            parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(rows) if rows else None,
            disable_web_page_preview=True)
        self.store.map_msg(sent.message_id, case_id)
        return case_id, v, decision

    async def _forward_originals(self, ctx: ContextTypes.DEFAULT_TYPE, chat_id: int, msgs: list[Message]) -> None:
        try:
            await ctx.bot.forward_messages(self.cfg.admin_chat_id, chat_id, [m.message_id for m in msgs])
        except Exception:  # noqa: BLE001
            for m in msgs:
                try:
                    await ctx.bot.copy_message(self.cfg.admin_chat_id, chat_id, m.message_id)
                except Exception:  # noqa: BLE001
                    log.warning("could not forward original %s", m.message_id)

    def _card_text(self, case_id: str, name: str, v: Verdict, reports: list[UrlReport], status: str,
                   channel: str = "telegram") -> str:
        e = html.escape
        lines = [
            f"<b>{e(VERDICT_LABEL.get(v.verdict, v.verdict))}</b> · {v.confidence}% · {e(name)} · "
            f"case <code>{case_id}</code> · <b>{e(status)}</b>",
        ]
        if v.red_flags:
            lines.append("\n<b>Red flags</b>\n" + "\n".join(f"• {e(f)}" for f in v.red_flags))
        if reports:
            lines.append("\n<b>URL intel</b>")
            for r in reports[:4]:
                bits = [f"SB: {r.safe_browsing}", f"VT: {r.virustotal}", f"Age: {r.domain_age}"]
                if r.heuristics:
                    bits.append("Flags: " + "; ".join(r.heuristics))
                lines.append(f"• <code>{e(r.url[:120])}</code>\n  " + e(" | ".join(bits)))
        if v.searches:
            lines.append("\n<b>Searched</b>: " + e("; ".join(v.searches)))
        lines.append("\n<b>Analysis</b>\n" + e(v.admin_summary))
        if channel == "imessage" and status == "NEEDS REVIEW":
            # <code> = tap-to-copy in Telegram, for pasting into Messages by hand
            lines.append("\n<b>Draft reply</b> (tap to copy)\n<code>" + e(v.reply_text) + "</code>")
        else:
            lines.append("\n<b>Draft reply</b>\n<blockquote>" + e(v.reply_text) + "</blockquote>")
        lines.append(f"\n<i>{v.input_tokens} in / {v.output_tokens} out tokens · {v.web_search_requests} searches"
                     + (" · reply to this card with text to send your own answer" if status == "NEEDS REVIEW" else "")
                     + "</i>")
        text = "\n".join(lines)
        return text if len(text) < 4000 else text[:3990] + "…"

    # ------------------------------------------------------------------ admin actions
    async def _send_custom(self, ctx: ContextTypes.DEFAULT_TYPE, case_id: str, text: str, admin_msg: Message) -> None:
        case = self.store.get_case(case_id)
        if not case:
            await admin_msg.reply_text("Case not found (expired?).")
            return
        if case.get("channel") == "imessage":
            # Can't send iMessage from the server: hand back a one-tap link that opens Messages pre-filled.
            self.store.update_case(case_id, custom=text)
            if self.bridge is not None and self.cfg.bridge_public_url:
                kb = InlineKeyboardMarkup([[InlineKeyboardButton(
                    f"📲 Send to {case['name']} via Messages", url=self.bridge.open_url(case_id, "custom"))]])
                await admin_msg.reply_text("Tap to send:", reply_markup=kb)
            else:
                await admin_msg.reply_text("Set BRIDGE_PUBLIC_URL to get a one-tap send link. Text it yourself.")
            return
        await ctx.bot.send_message(case["chat_id"], f"From {self.cfg.owner_name}:\n{text}")
        self.store.update_case(case_id, status="sent_custom")
        await admin_msg.reply_text(f"Sent to {case['name']}. ✅")

    async def on_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        q = update.callback_query
        if q.message is None or not self.is_admin_chat(q.message.chat.id):
            await q.answer("Not allowed.")
            return
        action, _, arg = (q.data or "").partition(":")

        if action == "allow":
            uid = int(arg)
            try:
                chat = await ctx.bot.get_chat(uid)
                name = chat.first_name or str(uid)
            except Exception:  # noqa: BLE001
                name = str(uid)
            self.store.add_user(uid, name)
            await q.answer("Allowed")
            await q.edit_message_text(f"✅ {name} ({uid}) can now use the bot. Rename by adding them to ALLOWED_USERS.")
            try:
                await ctx.bot.send_message(uid, f"You're all set, {name}! Send me anything that looks suspicious. /start shows how.")
            except Exception:  # noqa: BLE001
                pass
            return

        case = self.store.get_case(arg)
        if not case:
            await q.answer("Case expired.")
            return

        if action == "edit":
            await q.answer()
            prompt = await ctx.bot.send_message(
                self.cfg.admin_chat_id, f"Type the message to send to {case['name']} (case {arg}):",
                reply_markup=ForceReply(selective=True, input_field_placeholder=f"Reply to {case['name']}…"))
            self.store.map_msg(prompt.message_id, arg)
            return

        if case.get("status") != "pending" and not (action == "drop" and case.get("channel") == "imessage"):
            await q.answer(f"Already handled ({case.get('status')}).")
            return
        if case.get("channel") == "imessage" and action in ("send", "scam"):
            await q.answer("iMessage case: use the 📲 buttons.")
            return

        if action == "send":
            await ctx.bot.send_message(case["chat_id"], case["reply"], disable_web_page_preview=True)
            self.store.update_case(arg, status="sent_approved")
            done = "✅ Draft sent"
        elif action == "scam":
            await ctx.bot.send_message(
                case["chat_id"],
                f"{case['name']}, {self.cfg.owner_name} checked — this is a scam. Please delete it and don't "
                f"click, reply, or call. If you already did anything with it, call {self.cfg.owner_name} right away.")
            self.store.update_case(arg, status="sent_scam")
            done = "🚩 'Scam' reply sent"
        elif action == "drop":
            self.store.update_case(arg, status="discarded")
            done = "🗑 Discarded (nothing sent)"
        else:
            await q.answer("Unknown action")
            return
        await q.answer(done)
        try:
            await q.edit_message_reply_markup(InlineKeyboardMarkup(
                [[InlineKeyboardButton("✏️ Send a follow-up", callback_data=f"edit:{arg}")]]))
            await ctx.bot.send_message(self.cfg.admin_chat_id, f"{done} — case {arg} ({case['name']}).",
                                       reply_to_message_id=q.message.message_id)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ wiring
    async def _post_init(self, app: Application) -> None:
        self.tg_bot = app.bot
        if self.cfg.bridge_enabled:
            from .bridge import Bridge
            self.bridge = Bridge(self, app.bot)
            await self.bridge.start()

    async def _post_shutdown(self, app: Application) -> None:
        if self.bridge is not None:
            await self.bridge.stop()
        await self.checker.close()

    def build(self) -> Application:
        app = (Application.builder().token(self.cfg.telegram_token).concurrent_updates(True)
               .post_init(self._post_init).post_shutdown(self._post_shutdown).build())
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("help", self.cmd_help))
        app.add_handler(CommandHandler("myid", self.cmd_myid))
        app.add_handler(CommandHandler("pending", self.cmd_pending))
        app.add_handler(CommandHandler("users", self.cmd_users))
        app.add_handler(CommandHandler("removeuser", self.cmd_removeuser))
        app.add_handler(CallbackQueryHandler(self.on_callback))
        app.add_handler(MessageHandler(~filters.COMMAND & filters.ChatType.PRIVATE, self.on_message))
        return app


def main() -> None:
    cfg = Config.from_env()
    log.info("starting scam-check bot: model=%s review_mode=%s users=%d sb=%s vt=%s imessage_bridge=%s",
             cfg.claude_model, cfg.review_mode, len(cfg.allowed_users),
             bool(cfg.safe_browsing_key), bool(cfg.virustotal_key), cfg.bridge_enabled)
    log.info("AUTO_SEND_ENABLED=%s -- %s", cfg.auto_send_enabled,
             "replies go out automatically per review_mode" if cfg.auto_send_enabled
             else "REVIEW ONLY: nothing is sent to anyone unless you tap a button")
    ScamBot(cfg).build().run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)


if __name__ == "__main__":
    main()
