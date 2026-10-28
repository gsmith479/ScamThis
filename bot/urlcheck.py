"""Deterministic URL / domain intelligence.

Everything here is a *lookup about* a URL. Nothing visits the URL itself unless
RESOLVE_REDIRECTS is on, because many smishing links carry a per-victim token
and fetching them tells the scammer the number is live.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import tldextract

log = logging.getLogger(__name__)

# Bundled public-suffix snapshot; no network fetch at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=())

URL_RE = re.compile(
    r"""(?xi)
    \b(
      (?:https?://|www\.)[^\s<>"'`]+            # explicit scheme or www.
      |
      (?<![@\w.-])                               # bare domains like usps-track.top/abc
      (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
      (?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})
      (?:/[^\s<>"'`]*)?
    )
    """
)

_TRAILING = ".,;:!?)]}'\"…"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "s.id", "lnkd.in", "bl.ink",
    "short.io", "qrco.de", "urlz.fr", "v.gd", "y2u.be",
}

# Cheap TLDs heavily abused in smishing / phishing. A hit is a signal, not proof.
RISKY_TLDS = {
    "top", "xyz", "icu", "cc", "vip", "buzz", "club", "live", "shop", "online", "site",
    "click", "link", "work", "rest", "cyou", "sbs", "cfd", "bond", "lol", "mom", "life",
    "info", "win", "loan", "support", "help", "zip", "mov", "today", "world", "pw", "su",
    "tk", "ml", "ga", "cf", "gq", "ws", "best", "fun", "store", "asia", "cn",
}

# brand keyword -> registrable domains that legitimately use it
BRANDS: dict[str, set[str]] = {
    "usps": {"usps.com", "usps.gov"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dhl": {"dhl.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amzn.to", "a.co"},
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com", "apple.co"},
    "icloud": {"icloud.com", "apple.com"},
    "walmart": {"walmart.com"},
    "netflix": {"netflix.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "capitalone": {"capitalone.com"},
    "citi": {"citi.com", "citibank.com"},
    "arvest": {"arvest.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
    "cashapp": {"cash.app", "cash.me", "squareup.com"},
    "irs": {"irs.gov"},
    "ssa": {"ssa.gov"},
    "medicare": {"medicare.gov"},
    "ezpass": {"e-zpassny.com", "ezpassnj.com", "ezpassva.com", "ezpassmd.com", "e-zpassiag.com"},
    # "toll" outside a known agency is the classic toll-fee smishing lure
    "toll": {"thetollroads.com", "ntta.org", "sunpass.com", "txtag.org", "bancpass.com",
             "peachpass.com", "fastrak.org", "ipass.illinoistollway.com", "illinoistollway.com"},
    "geeksquad": {"bestbuy.com"},
    "norton": {"norton.com"},
    "mcafee": {"mcafee.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "meta.com"},
    "instagram": {"instagram.com"},
    "verizon": {"verizon.com", "vzw.com"},
    "att": {"att.com", "att.net"},
    "tmobile": {"t-mobile.com"},
    "costco": {"costco.com"},
    "target": {"target.com"},
    "coinbase": {"coinbase.com"},
}


def extract_urls(text: str) -> list[str]:
    """Pull URL-ish strings out of free text. Order preserved, de-duplicated."""
    if not text:
        return []
    out: list[str] = []
    for m in URL_RE.finditer(text):
        u = m.group(1).rstrip(_TRAILING)
        if not u or "." not in u:
            continue
        if not re.match(r"(?i)https?://|www\.", u):
            # Bare domain: skip mixed-case words like "Pat.How" (".how" is a real TLD).
            host_part = u.split("/", 1)[0]
            if host_part != host_part.lower() and host_part != host_part.upper():
                continue
        # Skip things that are obviously not hosts (e.g., "e.g.", "3.5", "a.m")
        host = registered_domain(u)
        if not host:
            continue
        if u not in out:
            out.append(u)
    return out


def _normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        url = "http://" + url
    return url


def hostname(url: str) -> str:
    try:
        return (urlsplit(_normalize(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registered_domain(url: str) -> str:
    host = hostname(url)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    ext = _extract(host)
    if not ext.suffix or not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}"


@dataclass
class UrlReport:
    url: str
    host: str = ""
    registered_domain: str = ""
    heuristics: list[str] = field(default_factory=list)
    safe_browsing: str = "not checked"
    virustotal: str = "not checked"
    domain_age: str = "not checked"
    redirects: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        lines = [
            f"URL: {self.url}",
            f"  host: {self.host}  | registered domain: {self.registered_domain or '?'}",
            f"  Google Safe Browsing: {self.safe_browsing}",
            f"  VirusTotal: {self.virustotal}",
            f"  Domain age (RDAP): {self.domain_age}",
        ]
        if self.redirects:
            lines.append("  Redirect chain: " + " -> ".join(self.redirects))
        if self.heuristics:
            lines.append("  Heuristic flags: " + "; ".join(self.heuristics))
        else:
            lines.append("  Heuristic flags: none")
        if self.errors:
            lines.append("  Lookup errors: " + "; ".join(self.errors))
        return "\n".join(lines)

    @property
    def is_known_bad(self) -> bool:
        return self.safe_browsing.startswith("FLAGGED") or self.virustotal.startswith("FLAGGED")


def heuristic_flags(url: str) -> list[str]:
    flags: list[str] = []
    norm = _normalize(url)
    host = hostname(url)
    reg = registered_domain(url)
    if not host:
        return ["could not parse host"]

    try:
        ipaddress.ip_address(host)
        flags.append("link points to a raw IP address instead of a domain name")
    except ValueError:
        pass

    if "xn--" in host:
        flags.append("punycode host (possible look-alike characters)")
    if "@" in (urlsplit(norm).netloc or ""):
        flags.append("'@' in the link (classic trick to hide the real destination)")

    ext = _extract(host)
    if ext.suffix and ext.suffix.split(".")[-1] in RISKY_TLDS:
        flags.append(f".{ext.suffix} is a cheap TLD heavily used by scam sites")

    if reg in SHORTENERS:
        flags.append("URL shortener hides the real destination")

    if host.count("-") >= 3 or len(host) > 45:
        flags.append("unusually long / hyphen-heavy host name")
    if ext.subdomain and ext.subdomain.count(".") >= 3:
        flags.append("deeply nested subdomains")

    lowered = (host + urlsplit(norm).path).lower().replace("-", "").replace(".", "")
    for brand, legit in BRANDS.items():
        if brand in {"att", "ups", "citi", "irs", "ssa"}:
            # short brands: only match as their own host label to avoid false hits
            labels = re.split(r"[.-]", host)
            hit = brand in labels
        else:
            hit = brand in lowered
        if hit and reg not in legit:
            if brand == "toll":
                flags.append("mentions 'toll' on a non-agency domain (toll-fee smishing pattern)")
            else:
                flags.append(f"mentions '{brand}' but the real domain is {reg}, not an official {brand} domain")
    if not reg.endswith(".gov") and re.search(r"(?i)\bgov\b|-gov|gov-", host):
        flags.append("pretends to be government but isn't a .gov domain")
    return flags


class UrlChecker:
    def __init__(self, safe_browsing_key: str = "", virustotal_key: str = "",
                 enable_rdap: bool = True, resolve_redirects: bool = False):
        self.sb_key = safe_browsing_key
        self.vt_key = virustotal_key
        self.enable_rdap = enable_rdap
        self.resolve_redirects = resolve_redirects
        self._vt_calls: list[float] = []
        self._vt_lock = asyncio.Lock()
        self._client = httpx.AsyncClient(timeout=10, headers={"User-Agent": "scam-check-bot/1.0"})

    async def close(self) -> None:
        await self._client.aclose()

    # --- individual lookups -------------------------------------------------
    async def _safe_browsing(self, urls: list[str]) -> dict[str, str]:
        if not self.sb_key:
            return {}
        body = {
            "client": {"clientId": "scam-check-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": _normalize(u)} for u in urls],
            },
        }
        try:
            r = await self._client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": self.sb_key}, json=body)
            r.raise_for_status()
            matches = r.json().get("matches", [])
        except Exception as e:  # noqa: BLE001
            log.warning("Safe Browsing lookup failed: %s", e)
            return {u: f"lookup failed ({type(e).__name__})" for u in urls}
        res = {u: "not on Google's threat lists" for u in urls}
        for m in matches:
            hit = m.get("threat", {}).get("url", "")
            for u in urls:
                if _normalize(u) == hit:
                    res[u] = f"FLAGGED as {m.get('threatType', 'threat')}"
        return res

    async def _vt_allowed(self) -> bool:
        # Public API: 4 requests/minute. Never block the user waiting for quota.
        async with self._vt_lock:
            now = time.monotonic()
            self._vt_calls = [t for t in self._vt_calls if now - t < 60]
            if len(self._vt_calls) >= 4:
                return False
            self._vt_calls.append(now)
            return True

    async def _virustotal(self, url: str) -> str:
        if not self.vt_key:
            return "not configured"
        if not await self._vt_allowed():
            return "skipped (rate limit)"
        headers = {"x-apikey": self.vt_key}
        # Lookup only (GET). We never POST/submit: submissions are public and can leak
        # per-victim tokens embedded in the link.
        url_id = base64.urlsafe_b64encode(_normalize(url).encode()).decode().strip("=")
        try:
            r = await self._client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            if r.status_code == 404:
                dom = registered_domain(url)
                if not dom or not await self._vt_allowed():
                    return "URL never seen by VirusTotal"
                r = await self._client.get(f"https://www.virustotal.com/api/v3/domains/{dom}", headers=headers)
                if r.status_code == 404:
                    return "neither URL nor domain known to VirusTotal"
                scope = f"domain {dom}"
            else:
                scope = "exact URL"
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            total = sum(v for v in stats.values() if isinstance(v, int))
            if mal or sus:
                return f"FLAGGED ({scope}): {mal} malicious / {sus} suspicious of {total} engines"
            return f"clean ({scope}): 0 of {total} engines flag it (absence of flags is NOT proof of safety)"
        except Exception as e:  # noqa: BLE001
            log.warning("VirusTotal lookup failed: %s", e)
            return f"lookup failed ({type(e).__name__})"

    async def _rdap_age(self, url: str) -> str:
        if not self.enable_rdap:
            return "disabled"
        dom = registered_domain(url)
        if not dom:
            return "n/a"
        try:
            ipaddress.ip_address(dom)
            return "n/a (IP address)"
        except ValueError:
            pass
        try:
            r = await self._client.get(f"https://rdap.org/domain/{dom}", follow_redirects=True,
                                       headers={"Accept": "application/rdap+json"})
            if r.status_code == 404:
                return "domain not found in RDAP (may be unregistered or a TLD without RDAP)"
            r.raise_for_status()
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                    created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    days = (datetime.now(timezone.utc) - created).days
                    tag = " — VERY NEW DOMAIN (strong scam signal)" if days < 60 else (
                        " — fairly new" if days < 365 else "")
                    return f"registered {created.date()} ({days} days old){tag}"
            return "registration date not published"
        except Exception as e:  # noqa: BLE001
            return f"lookup failed ({type(e).__name__})"

    async def _redirects(self, url: str) -> list[str]:
        if not self.resolve_redirects or registered_domain(url) not in SHORTENERS:
            return []
        chain = [url]
        try:
            cur = _normalize(url)
            for _ in range(5):
                r = await self._client.head(cur, follow_redirects=False)
                loc = r.headers.get("location")
                if not loc or r.status_code not in (301, 302, 303, 307, 308):
                    break
                cur = str(httpx.URL(cur).join(loc))
                chain.append(cur)
        except Exception as e:  # noqa: BLE001
            chain.append(f"(stopped: {type(e).__name__})")
        return chain if len(chain) > 1 else []

    # --- public API ---------------------------------------------------------
    async def check(self, urls: list[str], max_urls: int = 4) -> list[UrlReport]:
        urls = urls[:max_urls]
        if not urls:
            return []
        reports = {u: UrlReport(url=u, host=hostname(u), registered_domain=registered_domain(u),
                                heuristics=heuristic_flags(u)) for u in urls}

        # Expand shorteners first (only if enabled) so the final hop gets checked too.
        chains = await asyncio.gather(*(self._redirects(u) for u in urls))
        targets = list(urls)
        for u, chain in zip(urls, chains):
            if chain:
                reports[u].redirects = chain
                final = chain[-1]
                if not final.startswith("(") and final not in targets:
                    targets.append(final)
                    reports[u].heuristics += [f"[final destination] {f}" for f in heuristic_flags(final)]

        sb = await self._safe_browsing(targets)
        vt = await asyncio.gather(*(self._virustotal(u) for u in urls))
        ages = await asyncio.gather(*(self._rdap_age(u) for u in urls))

        for u, v, a in zip(urls, vt, ages):
            rep = reports[u]
            rep.virustotal = v
            rep.domain_age = a
            if self.sb_key:
                verdicts = [sb.get(t) for t in [u] + ([rep.redirects[-1]] if rep.redirects else []) if sb.get(t)]
                flagged = [x for x in verdicts if x.startswith("FLAGGED")]
                rep.safe_browsing = flagged[0] if flagged else (verdicts[0] if verdicts else "not checked")
            else:
                rep.safe_browsing = "not configured"
        return [reports[u] for u in urls]
