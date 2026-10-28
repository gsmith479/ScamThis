"""Best-effort redaction of financial / identity numbers before text leaves the server.

Screenshots cannot be redacted this way; that limitation is documented in the README.
"""
from __future__ import annotations

import re

_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b")
# 13-19 digit runs, optionally separated by single spaces or dashes (card numbers)
_CARDLIKE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
# Long bare digit runs (bank/account numbers). 9+ digits, not part of a URL path we keep.
_LONGNUM = re.compile(r"(?<![\w/.:-])\d{9,}(?![\w/-])")


# Emoji / pictographs (incl. variation selector, ZWJ, keycap). Dashes and curly quotes are
# outside these ranges, so ordinary punctuation survives.
_EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2300-\u23FF\u2600-\u27BF\u2B00-\u2BFF"
                    "\uFE0F\u200D\u20E3]")


def strip_emoji(text: str) -> str:
    """Remove emoji from text that goes to a contact, tidying the spacing left behind."""
    if not text:
        return text
    lines = []
    for line in _EMOJI.sub("", text).split("\n"):
        line = re.sub(r"[ \t]{2,}", " ", line)
        line = re.sub(r" +([.,!?;:])", r"\1", line)
        lines.append(line.strip())
    return "\n".join(lines).strip()


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _is_phone(digits: str) -> bool:
    # Keep US phone numbers (10 digits, or 11 starting with 1) — they're useful evidence.
    return len(digits) == 10 or (len(digits) == 11 and digits.startswith("1"))


def redact(text: str) -> str:
    if not text:
        return text

    text = _SSN.sub("[REDACTED-SSN]", text)

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return "[REDACTED-CARD]"
        return m.group(0)

    text = _CARDLIKE.sub(card, text)

    def longnum(m: re.Match) -> str:
        digits = m.group(0)
        if _is_phone(digits):
            return digits
        return f"[REDACTED-{len(digits)}-DIGIT-NUMBER]"

    text = _LONGNUM.sub(longnum, text)
    return text
