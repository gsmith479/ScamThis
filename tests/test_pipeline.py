"""End-to-end pipeline test with Telegram and HTTP mocked out."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import httpx
from telegram import MessageEntity

from bot.analyzer import Verdict
from bot.config import Config
from bot.main import ScamBot


def rdap_handler(request: httpx.Request) -> httpx.Response:
    if "rdap.org" in str(request.url):
        created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": created}]})
    if "safebrowsing" in str(request.url):
        url = request.read().decode()
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING",
                                                      "threat": {"url": "https://ezdrive-pay.icu/x"}}]}
                              if "ezdrive" in url else {})
    return httpx.Response(404)


class FakeBot:
    def __init__(self):
        self.sent = []
        self.forwarded = []
        self._mid = 1000

    async def send_message(self, chat_id, text, **kw):
        self._mid += 1
        self.sent.append((chat_id, text, kw))
        return NS(message_id=self._mid)

    async def send_photo(self, chat_id, photo, **kw):
        self.sent.append((chat_id, "<photo>", kw))

    async def send_chat_action(self, *a, **k):
        pass

    async def forward_messages(self, to, frm, ids):
        self.forwarded.append((to, frm, ids))


class FakeMsg:
    def __init__(self, mid, text, hidden_link=None):
        self.message_id = mid
        self.text = text
        self.caption = None
        self.photo = []
        self.document = None
        self.video = None
        self.contact = None
        self.forward_origin = None
        self.hidden_link = hidden_link

    def parse_entities(self, types):
        if self.hidden_link:
            return {MessageEntity(MessageEntity.TEXT_LINK, 0, 8, url=self.hidden_link): "Pay here"}
        return {}

    def parse_caption_entities(self, types):
        return {}


def make_bot(tmp_path, verdict: Verdict, **cfg_kw):
    cfg_kw.setdefault("auto_send_enabled", True)   # most tests exercise the auto-send path
    cfg = Config(telegram_token="t", anthropic_api_key="k", admin_chat_id=1,
                 allowed_users={42: "Pat"}, data_dir=str(tmp_path), safe_browsing_key="sb", **cfg_kw)
    b = ScamBot(cfg)
    b.checker._client = httpx.AsyncClient(transport=httpx.MockTransport(rdap_handler))
    seen = {}

    async def fake_analyze(name, text, reports, images, **kw):
        seen.update(name=name, text=text, reports=reports, **kw)
        return verdict
    b.analyzer.analyze = fake_analyze
    return b, seen


def run(bot, msgs):
    fb = FakeBot()
    asyncio.run(bot._process(42, 42, "Pat", msgs, NS(bot=fb)))
    return fb


def test_scam_autosends_and_cards_admin(tmp_path):
    v = Verdict(verdict="likely_scam", confidence=60, reply_text="🚩 Scam, Pat. Delete it.",
                admin_summary="toll smish", red_flags=["unpaid toll"])
    bot, seen = make_bot(tmp_path, v)
    fb = run(bot, [FakeMsg(5, "Final notice: unpaid toll balance. Card 4111 1111 1111 1111",
                           hidden_link="https://ezdrive-pay.icu/x")])
    # hidden link extracted + checked, card number redacted before Claude
    assert "https://ezdrive-pay.icu/x" in seen["text"] and "4111" not in seen["text"]
    rep = seen["reports"][0]
    assert rep.safe_browsing.startswith("FLAGGED") and "VERY NEW" in rep.domain_age
    # confidence 60 < 80 but known-bad URL => auto-send
    to_mom = [s for s in fb.sent if s[0] == 42]
    assert to_mom[0][1] == "Scam, Pat. Delete it."   # emoji stripped before it reaches Pat
    card = [s for s in fb.sent if s[0] == 1][0]
    assert "AUTO-SENT" in card[1] and card[2]["parse_mode"] == "HTML"
    assert fb.forwarded == [(1, 42, [5])]


def test_no_autosend_telegram_stays_silent(tmp_path):
    """AUTO_SEND_ENABLED=false on Telegram: Pat gets nothing at all, the admin gets the card."""
    v = Verdict(verdict="scam", confidence=99, reply_text="\U0001f6a9 Scam, Pat. Delete it.",
                admin_summary="toll smish")
    bot, seen = make_bot(tmp_path, v, auto_send_enabled=False)
    fb = run(bot, [FakeMsg(7, "Final notice: unpaid toll. Pay at ezdrive-pay.icu/x")])
    assert seen["text"]                                       # analyzed as usual
    assert [s for s in fb.sent if s[0] == 42] == []            # nothing to Pat
    card = [s for s in fb.sent if s[0] == 1][0]
    assert "NEEDS REVIEW" in card[1] and "auto-send is OFF" in card[1]
    assert fb.forwarded == [(1, 42, [7])]                      # originals still relayed to the admin
    assert bot.store.pending()


def test_legit_waits_for_review_then_admin_approves(tmp_path):
    v = Verdict(verdict="likely_legit", confidence=85, reply_text="✅ Looks real.", admin_summary="pharmacy")
    bot, _ = make_bot(tmp_path, v)
    fb = run(bot, [FakeMsg(6, "Your prescription is ready for pickup at Walgreens.")])
    to_mom = [s[1] for s in fb.sent if s[0] == 42]
    assert len(to_mom) == 1 and "double-check" in to_mom[0]  # interim only, not the verdict
    case_id = next(iter(bot.store.pending()))

    # admin taps "Send draft"
    answered = []

    async def answer(t=None):
        answered.append(t)

    async def edit_markup(*a, **k):
        pass
    q = NS(message=NS(chat=NS(id=1), message_id=77), data=f"send:{case_id}", answer=answer,
           edit_message_reply_markup=edit_markup)
    fb2 = FakeBot()
    asyncio.run(bot.on_callback(NS(callback_query=q), NS(bot=fb2)))
    assert (42, "Looks real.") in [(s[0], s[1]) for s in fb2.sent]   # emoji stripped before sending
    assert bot.store.get_case(case_id)["status"] == "sent_approved"
    # second tap is a no-op
    asyncio.run(bot.on_callback(NS(callback_query=q), NS(bot=FakeBot())))
    assert "Already handled" in answered[-1]


def test_non_admin_cannot_press_buttons(tmp_path):
    bot, _ = make_bot(tmp_path, Verdict(verdict="unsure", confidence=10, reply_text="x", admin_summary="y"))
    out = []

    async def answer(t=None):
        out.append(t)
    q = NS(message=NS(chat=NS(id=42)), data="send:zzz", answer=answer)
    asyncio.run(bot.on_callback(NS(callback_query=q), NS(bot=FakeBot())))
    assert out == ["Not allowed."]
