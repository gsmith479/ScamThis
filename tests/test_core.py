import asyncio
from types import SimpleNamespace as NS

from bot.analyzer import Analyzer, Verdict
from bot.policy import route
from bot.redact import redact
from bot.store import Store
from bot.urlcheck import UrlChecker, extract_urls, heuristic_flags, registered_domain


# ---------------------------------------------------------------- URL extraction
def test_extract_urls():
    t = ("USPS: your package is held. Visit https://usps.com-track-redelivery.top/us?id=9 now. "
         "Or go to usps-help.xyz/abc. Hi Pat.How are you? e.g. 3.5 stars. Call 800-555-1212.")
    urls = extract_urls(t)
    assert "https://usps.com-track-redelivery.top/us?id=9" in urls
    assert "usps-help.xyz/abc" in urls
    assert not any("Pat.How" in u for u in urls)
    assert all("3.5" not in u for u in urls)


def test_registered_domain():
    assert registered_domain("https://usps.com-track-redelivery.top/x") == "com-track-redelivery.top"
    assert registered_domain("www.amazon.co.uk/foo") == "amazon.co.uk"
    assert registered_domain("http://192.168.1.10/login") == "192.168.1.10"


def test_heuristics_flag_lookalikes():
    f = " | ".join(heuristic_flags("https://usps.com-track-redelivery.top/us"))
    assert "usps" in f and ".top" in f
    f2 = " | ".join(heuristic_flags("https://ezdrive-toll-payment.icu/pay"))
    assert "toll" in f2
    assert heuristic_flags("https://www.usps.com/manage/package-intercept.htm") == []
    assert heuristic_flags("https://www.chase.com/") == []
    assert any("IP address" in x for x in heuristic_flags("http://45.12.1.9/paypal"))
    assert any("shortener" in x for x in heuristic_flags("https://bit.ly/3xYz"))
    assert any(".gov" in x for x in heuristic_flags("https://irs-gov-refund.com"))


# ---------------------------------------------------------------- redaction
def test_redaction():
    out = redact("card 4111 1111 1111 1111, ssn 123-45-6789, acct 0012345678901, call 5555550123")
    assert "4111" not in out and "123-45-6789" not in out and "0012345678901" not in out
    assert "5555550123" in out  # phone numbers are kept as evidence
    assert redact("order 1234 5678 9012 3456") == "order 1234 5678 9012 3456"  # not Luhn-valid


# ---------------------------------------------------------------- policy
def V(verdict, conf=90, engaged=False, error=None):
    return Verdict(verdict=verdict, confidence=conf, reply_text="x", admin_summary="y",
                   already_engaged=engaged, error=error)


def test_strip_emoji():
    from bot.redact import strip_emoji
    assert strip_emoji("\U0001f6a9 This is a scam, Pat.") == "This is a scam, Pat."
    assert strip_emoji("\u26a0\ufe0f Very likely a scam \U0001f44d.") == "Very likely a scam."
    assert strip_emoji("Hi Pat \u2764\ufe0f\nDon't click \u2014 just delete it.") == "Hi Pat\nDon't click \u2014 just delete it."
    assert strip_emoji("Call \u201cthe number\u201d on your card, $5 fee.") == "Call \u201cthe number\u201d on your card, $5 fee."


def test_policy():
    assert route(V("scam", 95), "uncertain", 80) == "auto"
    assert route(V("likely_scam", 60), "uncertain", 80) == "review"
    assert route(V("likely_scam", 60), "uncertain", 80, known_bad_url=True) == "auto"
    assert route(V("legit", 99), "uncertain", 80) == "review"
    assert route(V("likely_legit", 99), "uncertain", 80) == "review"
    assert route(V("unsure", 50), "uncertain", 80) == "review"
    assert route(V("unsure", 50, engaged=True), "uncertain", 80) == "auto"
    assert route(V("legit", 99, engaged=True), "uncertain", 80) == "review"
    assert route(V("not_a_check"), "always", 80) == "auto"
    assert route(V("scam", 99), "always", 80) == "review"
    assert route(V("legit", 99), "never", 80) == "auto"
    assert route(V("scam", 99, error="boom"), "never", 80) == "review"


def test_policy_auto_send_disabled_overrides_everything():
    """AUTO_SEND_ENABLED=false: nothing is ever auto-sent, whatever review_mode says."""
    for mode in ("uncertain", "always", "never"):
        assert route(V("scam", 99), mode, 80, auto_send_enabled=False) == "review"
        assert route(V("likely_scam", 99), mode, 80, known_bad_url=True, auto_send_enabled=False) == "review"
        assert route(V("unsure", 50, engaged=True), mode, 80, auto_send_enabled=False) == "review"
        assert route(V("legit", 99), mode, 80, auto_send_enabled=False) == "review"
        # chit-chat still resolves to "auto", which means "say nothing / raise no card"
        assert route(V("not_a_check"), mode, 80, auto_send_enabled=False) == "auto"


# ---------------------------------------------------------------- store
def test_store(tmp_path):
    s = Store(str(tmp_path))
    assert s.take_quota(1, 2) and s.take_quota(1, 2) and not s.take_quota(1, 2)
    s.put_case("abc", {"chat_id": 1, "name": "Pat", "status": "pending", "created": 0, "verdict": "unsure"})
    s.map_msg(55, "abc")
    s2 = Store(str(tmp_path))  # persistence round-trip
    assert s2.case_for_msg(55) == "abc" and "abc" in s2.pending()
    assert s2.should_notify_unknown(9) and not s2.should_notify_unknown(9)


# ---------------------------------------------------------------- analyzer tool loop
class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    async def create(self, **kw):
        self.calls.append(kw)
        return self.script.pop(0)


def usage(i=100, o=50, s=0):
    return NS(input_tokens=i, output_tokens=o, cache_read_input_tokens=0, cache_creation_input_tokens=0,
              server_tool_use=NS(web_search_requests=s))


VERDICT_INPUT = {"verdict": "scam", "confidence": 93, "reply_text": "🚩 This is a scam, Pat.",
                 "admin_summary": "toll smish", "red_flags": ["urgency"], "already_engaged": False,
                 "needs_more_info": False}


def test_analyzer_tool_loop(tmp_path):
    script = [
        NS(stop_reason="tool_use", usage=usage(s=1), content=[
            NS(type="server_tool_use", name="web_search", input={"query": "ezdrive toll text scam"}),
            NS(type="tool_use", id="t1", name="check_url", input={"urls": ["ezdrive-toll.icu"]}),
        ]),
        NS(stop_reason="tool_use", usage=usage(), content=[
            NS(type="tool_use", id="t2", name="submit_verdict", input=VERDICT_INPUT),
        ]),
    ]
    fake = FakeMessages(script)
    checker = UrlChecker(enable_rdap=False)
    a = Analyzer("k", "claude-sonnet-5-5", checker, client=NS(messages=fake))
    v = asyncio.run(a.analyze("Pat", "Unpaid toll! ezdrive-toll.icu", [], []))
    assert v.verdict == "scam" and v.confidence == 93 and v.error is None
    assert v.searches == ["ezdrive toll text scam"] and v.web_search_requests == 1
    assert v.extra_url_reports and "toll" in " ".join(v.extra_url_reports[0].heuristics)
    # second call must carry the tool_result for t1
    last_user = fake.calls[1]["messages"][-1]
    assert last_user["content"][0]["tool_use_id"] == "t1"
    tools = [t["name"] for t in fake.calls[0]["tools"]]
    assert tools == ["web_search", "check_url", "submit_verdict"]


def test_analyzer_forces_verdict_and_handles_pause():
    script = [
        NS(stop_reason="pause_turn", usage=usage(), content=[NS(type="text", text="searching")]),
        NS(stop_reason="end_turn", usage=usage(), content=[NS(type="text", text="I think it's a scam")]),
        NS(stop_reason="tool_use", usage=usage(), content=[
            NS(type="tool_use", id="t9", name="submit_verdict", input=VERDICT_INPUT)]),
    ]
    fake = FakeMessages(script)
    a = Analyzer("k", "m", UrlChecker(enable_rdap=False), client=NS(messages=fake), enable_web_search=False)
    v = asyncio.run(a.analyze("Chris", "hi", [], []))
    assert v.verdict == "scam"
    assert "tool_choice" not in fake.calls[1]
    assert fake.calls[2]["tool_choice"] == {"type": "tool", "name": "submit_verdict"}
    assert v.input_tokens == 300


def test_analyzer_failure_is_safe():
    class Boom:
        async def create(self, **kw):
            raise RuntimeError("api down")
    a = Analyzer("k", "m", UrlChecker(enable_rdap=False), client=NS(messages=Boom()))
    v = asyncio.run(a.analyze("Pat", "x", [], []))
    assert v.error and v.verdict == "unsure"
    assert "don't click" in v.reply_text
    assert route(v, "never", 80) == "review"


def test_user_content_shape():
    c = Analyzer.build_user_content("Pat", "hello", [], [("image/jpeg", "AAAA")])
    assert c[0]["type"] == "image" and c[-1]["type"] == "text"
    assert "<submission>" in c[-1]["text"]
