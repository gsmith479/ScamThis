"""Configuration loaded from environment variables (.env via docker compose)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    v = os.getenv(name)
    try:
        return int(v) if v not in (None, "") else default
    except ValueError:
        return default


def _parse_users(raw: str) -> dict[int, str]:
    """ALLOWED_USERS format: "123456789:Pat,987654321:Chris Lee"."""
    users: dict[int, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            uid, name = part.split(":", 1)
        else:
            uid, name = part, part
        try:
            users[int(uid.strip())] = name.strip() or uid.strip()
        except ValueError:
            continue
    return users


@dataclass
class Config:
    telegram_token: str
    anthropic_api_key: str
    admin_chat_id: int
    allowed_users: dict[int, str] = field(default_factory=dict)

    claude_model: str = "claude-sonnet-5-5"
    enable_web_search: bool = True
    web_search_max_uses: int = 3

    # Review policy
    #   uncertain -> auto-send only confident SCAM verdicts; everything else waits for admin
    #   always    -> every reply waits for admin approval
    #   never     -> everything auto-sends (admin still gets a copy)
    review_mode: str = "uncertain"
    auto_send_min_confidence: int = 80
    # Master switch for every automatic outbound message to a contact, on both
    # channels. False = still analyze, log and card every case, but send them nothing
    # unless the admin taps a button. The review_mode knobs above only matter when True.
    # Defaults to False so a missing env var can never start texting people by itself.
    auto_send_enabled: bool = False

    # URL intelligence (all optional; empty = skipped)
    safe_browsing_key: str = ""
    virustotal_key: str = ""
    enable_rdap: bool = True
    # Following links tells the scammer someone clicked (many smishing links carry
    # a per-victim token). Off by default; known shorteners are only expanded if on.
    resolve_redirects: bool = False

    debounce_seconds: int = 6
    max_checks_per_user_per_day: int = 30
    data_dir: str = "/data"
    owner_name: str = "the admin"

    # iMessage bridge (iPhone Shortcuts automation -> HTTP). Off unless BRIDGE_TOKEN is set.
    bridge_token: str = ""
    bridge_port: int = 8787
    bridge_public_url: str = ""          # e.g. https://<host>.<tailnet>.ts.net:8787
    imessage_contacts: str = ""          # "+15555550123:Pat,+15555550199:Chris Lee"
    imessage_debounce_seconds: int = 10
    imessage_reply_prefix: str = "Scam check: "
    imessage_hold_message: bool = True
    imessage_claim_timeout: int = 180

    @property
    def bridge_enabled(self) -> bool:
        return bool(self.bridge_token)

    @classmethod
    def from_env(cls) -> "Config":
        missing = [k for k in ("TELEGRAM_BOT_TOKEN", "ANTHROPIC_API_KEY", "ADMIN_CHAT_ID", "OWNER_NAME") if not os.getenv(k)]
        if missing:
            raise SystemExit(f"Missing required env vars: {', '.join(missing)}")
        mode = os.getenv("REVIEW_MODE", "uncertain").strip().lower()
        if mode not in {"uncertain", "always", "never"}:
            mode = "uncertain"
        return cls(
            telegram_token=os.environ["TELEGRAM_BOT_TOKEN"].strip(),
            anthropic_api_key=os.environ["ANTHROPIC_API_KEY"].strip(),
            admin_chat_id=int(os.environ["ADMIN_CHAT_ID"]),
            allowed_users=_parse_users(os.getenv("ALLOWED_USERS", "")),
            claude_model=os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5").strip(),
            enable_web_search=_bool("ENABLE_WEB_SEARCH", True),
            web_search_max_uses=_int("WEB_SEARCH_MAX_USES", 3),
            review_mode=mode,
            auto_send_min_confidence=_int("AUTO_SEND_MIN_CONFIDENCE", 80),
            auto_send_enabled=_bool("AUTO_SEND_ENABLED", False),
            safe_browsing_key=os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip(),
            virustotal_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
            enable_rdap=_bool("ENABLE_RDAP", True),
            resolve_redirects=_bool("RESOLVE_REDIRECTS", False),
            debounce_seconds=_int("DEBOUNCE_SECONDS", 6),
            max_checks_per_user_per_day=_int("MAX_CHECKS_PER_USER_PER_DAY", 30),
            data_dir=os.getenv("DATA_DIR", "/data"),
            owner_name=os.environ["OWNER_NAME"].strip(),
            bridge_token=os.getenv("BRIDGE_TOKEN", "").strip(),
            bridge_port=_int("BRIDGE_PORT", 8787),
            bridge_public_url=os.getenv("BRIDGE_PUBLIC_URL", "").strip(),
            imessage_contacts=os.getenv("IMESSAGE_CONTACTS", ""),
            imessage_debounce_seconds=_int("IMESSAGE_DEBOUNCE_SECONDS", 10),
            imessage_reply_prefix=os.getenv("IMESSAGE_REPLY_PREFIX", "Scam check: "),
            imessage_hold_message=_bool("IMESSAGE_HOLD_MESSAGE", True),
            imessage_claim_timeout=_int("IMESSAGE_CLAIM_TIMEOUT", 180),
        )
