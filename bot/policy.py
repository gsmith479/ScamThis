"""Decides whether a verdict goes straight to the sender or waits for the admin."""
from __future__ import annotations

import re

from .analyzer import Verdict

# Cheap gate for the iMessage bridge so ordinary personal texts never reach Claude.
_CHECK_WORDS = re.compile(r"""(?ix)
    \b(real|fake|scam\w*|legit\w*|spam|phish\w*|fraud\w*|suspicious|sketchy|hack\w*|virus|
       is\s+this|is\s+that|should\s+i|did\s+you\s+send|safe\s+to|check\s+this|look\s+at\s+this|
       click\w*|link|verify|verification|code|password|account|locked|suspended|
       gift\s*cards?|bitcoin|crypto|wire|zelle|venmo|cash\s*app|paypal|refund|invoice|
       toll|package|deliver\w*|usps|fedex|ups|irs|medicare|social\s+security|warrant|jury|
       prize|won\s+(a|an|the|\$)|winner|lottery|sweepstakes|pop-?up|tech\s+support|microsoft|apple|amazon|
       bank|chase|wells|fraud\s+alert|someone\s+called|they\s+called|voicemail|texted\s+me|
       got\s+(a|this)\s+(text|email|call|message))\b""")


def looks_like_check(text: str, has_media: bool, has_urls: bool) -> bool:
    """True if a batch of iMessages might be a 'real or fake?' question.

    Deliberately generous: false positives cost one Claude call that comes back
    not_a_check (no reply sent); false negatives mean the sender gets no answer.
    """
    if has_urls or has_media:
        return True
    return bool(_CHECK_WORDS.search(text or ""))

SCAMMY = {"scam", "likely_scam"}


def route(v: Verdict, review_mode: str, min_conf: int, known_bad_url: bool = False,
          auto_send_enabled: bool = True) -> str:
    """Return "auto" or "review".

    Principle: auto-send only replies that push toward *caution*. Anything that
    could tell someone a message is safe waits for a human.

    auto_send_enabled=False is the hard override: every case becomes "review", so
    nothing reaches the sender without an explicit tap. The default here is
    True ("don't gate") because this is a pure function; the deployed default comes
    from Config.auto_send_enabled, which is False.
    """
    if v.error:
        return "review"
    if v.verdict == "not_a_check":
        return "auto"
    if not auto_send_enabled:
        return "review"
    if review_mode == "never":
        return "auto"
    if review_mode == "always":
        return "review"

    # "uncertain" mode
    if v.already_engaged and v.verdict in SCAMMY | {"unsure"}:
        return "auto"  # damage-control advice is time-sensitive and only ever cautious
    if v.verdict in SCAMMY and (v.confidence >= min_conf or known_bad_url):
        return "auto"
    return "review"
