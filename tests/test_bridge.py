"""iMessage bridge: HTTP endpoints driven the way the iPhone Shortcut drives them."""
import asyncio
import io
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

import httpx
from aiohttp import FormData
from aiohttp.test_utils import TestClient, TestServer
from PIL import Image

from bot.analyzer import Verdict
from bot.bridge import Bridge, parse_contacts
from bot.config import Config
from bot.main import ScamBot
from bot.policy import looks_like_check

TOKEN = "s3cret-token"


class FakeTG:
    def __init__(self):
        self.sent = []
        self.mid = 0

    async def send_message(self, chat_id, text, **kw):
        self.mid += 1
        self.sent.append((chat_id, text, kw))
        return NS(message_id=self.mid)

    async def send_photo(self, chat_id, photo, **kw):
        self.sent.append((chat_id, "<photo>", kw))


def make(tmp_path, verdict_fn, **kw):
    kw.setdefault("auto_send_enabled", True)   # these tests exercise the auto-send path
    cfg = Config(telegram_token="t", anthropic_api_key="k", admin_chat_id=1, data_dir=str(tmp_path),
                 bridge_token=TOKEN, bridge_public_url="https://home.example.ts.net:8787",
                 imessage_contacts="+1 (555) 555-0123:Pat,Chris Lee:Chris Lee",
                 imessage_debounce_seconds=0, imessage_claim_timeout=1, enable_rdap=False, **kw)
    sb = ScamBot(cfg)
    sb.checker._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    calls = []

    async def fake_analyze(name, text, reports, images, **k):
        calls.append(dict(name=name, text=text, images=len(images), **k))
        return verdict_fn(text)
    sb.analyzer.analyze = fake_analyze
    tg = FakeTG()
    sb.tg_bot = tg
    sb.bridge = Bridge(sb, tg)
    return sb, tg, calls


def V(verdict, conf=95, reply="🚩 That's a scam, Pat."):
    return Verdict(verdict=verdict, confidence=conf, reply_text=reply, admin_summary="notes")


async def shortcut_run(client, text, phone="+15555550123", sender="Pat", image=None, token=TOKEN):
    """Exactly what the iPhone shortcut does: POST form, then long-poll until done."""
    form = FormData()
    form.add_field("token", token)
    form.add_field("sender", sender)
    form.add_field("phone", phone)
    form.add_field("text", text)
    if image is not None:
        form.add_field("image", image, filename="IMG_0001.jpeg", content_type="image/jpeg")
    r = await client.post("/ingest", data=form)
    if r.status != 200:
        return {"http": r.status}
    j = await r.json()
    if not j.get("ticket"):
        return j
    for _ in range(6):
        r = await client.get("/result", params={"ticket": j["ticket"], "wait": "5"}, headers={"X-Token": TOKEN})
        res = await r.json()
        if res["status"] == "done":
            return res
    return {"status": "timeout"}


def run(sb, coro_fn):
    async def go():
        async with TestClient(TestServer(sb.bridge.app())) as client:
            return await coro_fn(client)
    return asyncio.run(go())


# ---------------------------------------------------------------- unit bits
def test_contacts_and_prefilter():
    c = parse_contacts("+1 (555) 555-0123:Pat, Chris Lee:Chris Lee")
    assert c == {"5555550123": "Pat", "chris lee": "Chris Lee"}
    # emoji / punctuation in the iPhone contact name don't break matching
    c2 = parse_contacts("Chris Lee-Jones \u2764\ufe0f:Chris Lee")
    assert c2 == {"chris lee jones": "Chris Lee"}
    assert not looks_like_check("Love you! Dinner Sunday?", False, False)
    assert not looks_like_check("I won't be there till 6", False, False)
    assert looks_like_check("Is this real??", False, False)
    assert looks_like_check("got a text saying my package is held", False, False)
    assert looks_like_check("", True, False)


# ---------------------------------------------------------------- flows
def test_scam_auto_reply(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    res = run(sb, lambda c: shortcut_run(c, "Is this real? USPS: package held, pay at usps-redeliver.top/x"))
    assert res["action"] == "reply" and res["text"] == "Scam check: That's a scam, Pat."
    assert calls[0]["name"] == "Pat" and "not_a_check" in calls[0]["channel_note"]
    card = [s for s in tg.sent if "iMessage from Pat" in s[1]][0]
    assert "AUTO-REPLIED VIA IMESSAGE" in card[1]


def test_no_autosend_holds_everything(tmp_path):
    """AUTO_SEND_ENABLED=false: the full pipeline runs, the shortcut sends nothing."""
    sb, tg, calls = make(tmp_path, lambda t: V("scam"), auto_send_enabled=False)
    res = run(sb, lambda c: shortcut_run(c, "Is this real? USPS: package held, pay at usps-redeliver.top/x"))
    assert res["action"] == "none" and "text" not in res     # nothing for the iPhone to send
    assert res["draft"] == "Scam check: That's a scam, Pat."  # generated, emoji stripped
    assert res["verdict"] == "scam" and res["case"]
    assert len(calls) == 1                                   # and Claude did analyze it
    card = [s for s in tg.sent if "iMessage from Pat" in s[1]][0]
    assert "NEEDS REVIEW" in card[1] and "auto-send is OFF" in card[1]
    assert "Send draft via Messages" in str(card[2]["reply_markup"])
    assert sb.store.pending()                                # and it is queued for review


def test_no_autosend_suppresses_hold_message(tmp_path):
    """The 'owner will double-check' hold text is itself an auto-send, so it stays off too."""
    sb, tg, _ = make(tmp_path, lambda t: V("unsure", 40), auto_send_enabled=False,
                     imessage_hold_message=True)
    res = run(sb, lambda c: shortcut_run(c, "is this real? my account is locked"))
    assert res["action"] == "none" and "text" not in res
    assert res["draft"].startswith("Scam check: ")   # drafted, not delivered
    assert not any("expect a text soon" in s[1] for s in tg.sent)


def test_chitchat_never_reaches_claude(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    res = run(sb, lambda c: shortcut_run(c, "Love you! See you Sunday"))
    assert res == {"status": "done", "action": "none"} and calls == [] and tg.sent == []


def test_not_a_check_is_silent(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("not_a_check", reply="hi"))
    res = run(sb, lambda c: shortcut_run(c, "The package from Amazon came, thank you!"))
    assert res["action"] == "none" and len(calls) == 1 and tg.sent == []


def test_legit_holds_with_messages_links(tmp_path):
    sb, tg, _ = make(tmp_path, lambda t: V("likely_legit", 85, "✅ Looks real, Pat."))
    res = run(sb, lambda c: shortcut_run(c, "Is this real? Walgreens: your prescription is ready"))
    assert res["action"] == "hold" and "double-check" in res["text"]
    card = [s for s in tg.sent if "NEEDS REVIEW" in s[1]][0]
    buttons = [b for row in card[2]["reply_markup"].inline_keyboard for b in row]
    urls = [b.url for b in buttons if b.url]
    assert len(urls) == 2 and all(u.startswith("https://home.example.ts.net:8787/open/") for u in urls)
    assert "<code>Looks real, Pat.</code>" in card[1]   # draft shown exactly as it would be sent

    # Tapping the button: page opens Messages pre-filled to Pat's number
    path = urlsplit(urls[0])

    async def open_it(c):
        good = await c.get(path.path + "?" + path.query)
        bad = await c.get(path.path + "?v=draft&sig=nope")
        return good.status, await good.text(), bad.status
    status, page, bad = run(sb, open_it)
    assert status == 200 and bad == 403
    assert "sms:+15555550123&amp;body=" in page and "Looks%20real" in page


def test_batching_and_single_delivery(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    sb.cfg.imessage_debounce_seconds = 1

    async def two_messages(c):
        a = asyncio.create_task(shortcut_run(c, "USPS: pay redelivery fee at usps-fee.top"))
        await asyncio.sleep(0.3)
        b = asyncio.create_task(shortcut_run(c, "is this real?"))
        return await asyncio.gather(a, b)
    r1, r2 = run(sb, two_messages)
    assert len(calls) == 1 and "usps-fee.top" in calls[0]["text"] and "is this real" in calls[0]["text"]
    assert sorted([r1["action"], r2["action"]]) == ["none", "reply"]  # exactly one iMessage goes out


def test_auth_and_unknown_sender(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    assert run(sb, lambda c: shortcut_run(c, "is this real", token="wrong")) == {"http": 401}
    res = run(sb, lambda c: shortcut_run(c, "is this real", phone="+15550000000", sender="Bob"))
    assert res["action"] == "none" and calls == []
    # name-only match for a contact configured by name
    res = run(sb, lambda c: shortcut_run(c, "is this a scam?", phone="", sender="Chris Lee"))
    assert res["action"] == "reply"


def test_image_reaches_claude_and_admin(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    buf = io.BytesIO()
    Image.new("RGB", (2400, 1200), "white").save(buf, "JPEG")
    res = run(sb, lambda c: shortcut_run(c, "￼", image=buf.getvalue()))
    assert res["action"] == "reply" and calls[0]["images"] == 1
    assert any(s[1] == "<photo>" for s in tg.sent)


def test_unreadable_picture_pings_admin_only(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))
    res = run(sb, lambda c: shortcut_run(c, "￼"))
    assert res["action"] == "none" and calls == []
    assert "can't read" in tg.sent[0][1]


def test_followup_gets_context(tmp_path):
    sb, tg, calls = make(tmp_path, lambda t: V("scam"))

    async def both(c):
        await shortcut_run(c, "Is this real? Unpaid toll at ezdrive-pay.icu")
        return await shortcut_run(c, "so it's fake? should I call them?")
    res = run(sb, both)
    assert res["action"] == "reply" and "you answered" in calls[1]["context"]


def test_unclaimed_reply_alerts_admin(tmp_path):
    sb, tg, _ = make(tmp_path, lambda t: V("scam"))

    async def ingest_only(c):
        form = FormData()
        for k, v in {"token": TOKEN, "sender": "Pat", "phone": "5555550123", "text": "is this a scam"}.items():
            form.add_field(k, v)
        await c.post("/ingest", data=form)
        await asyncio.sleep(1.6)  # debounce 0 + claim timeout 1s; nobody polls
    run(sb, ingest_only)
    assert any("didn't pick up" in s[1] for s in tg.sent)
