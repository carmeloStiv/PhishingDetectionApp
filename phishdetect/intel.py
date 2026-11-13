"""Threat-intelligence and registration-data providers.

Every provider returns a ProviderResult whose status is one of
    match          - the URL / host is listed (confirmed intelligence)
    clean          - the provider answered and has no listing (NOT proof of safety)
    error          - the provider could not be reached or answered unexpectedly
    not_configured - no API key / disabled by the operator
Results are cached in memory for a short time so repeated submissions do not
hammer third parties; "clean" answers expire quickly because feeds change.
"""
from __future__ import annotations

import base64
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from .config import Settings
from .indicators import REPUTATION, THREAT_INTEL, Indicator
from .reputation import is_established, user_content_platform
from .urltools import ParsedURL, URLParseError, parse_url

log = logging.getLogger(__name__)
# httpx logs full request URLs at INFO, which would put API keys (Safe Browsing ?key=) and
# submitted addresses into the server log.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

CLEAN_TTL = 15 * 60
MATCH_TTL = 6 * 3600


@dataclass
class ProviderResult:
    provider: str
    status: str
    detail: str = ""
    indicators: list[Indicator] = field(default_factory=list)


class TTLCache:
    def __init__(self, max_items: int = 5000) -> None:
        self._data: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            if item[0] < time.time():
                del self._data[key]
                return None
            return item[1]

    def set(self, key: str, value, ttl: float) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                now = time.time()
                for k in [k for k, v in self._data.items() if v[0] < now] or list(self._data)[: self._max // 10]:
                    self._data.pop(k, None)
            self._data[key] = (time.time() + ttl, value)


class Provider:
    name = "provider"
    label = "Provider"

    def __init__(self, settings: Settings, client: httpx.Client, cache: TTLCache | None = None) -> None:
        self.settings, self.client, self.cache = settings, client, cache or TTLCache()

    def configured(self) -> bool:
        return True

    def lookup(self, p: ParsedURL) -> ProviderResult:
        if not self.configured():
            return ProviderResult(self.label, "not_configured", "No API key configured by the operator.")
        key = f"{self.name}:{self._cache_key(p)}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            result = self._lookup(p)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            log.warning("%s lookup failed: %s", self.name, type(exc).__name__)
            return ProviderResult(self.label, "error", f"Lookup failed ({type(exc).__name__}).")
        if result.status in ("clean", "match"):
            self.cache.set(key, result, MATCH_TTL if result.status == "match" else CLEAN_TTL)
        return result

    def _cache_key(self, p: ParsedURL) -> str:
        return p.url

    def _lookup(self, p: ParsedURL) -> ProviderResult:  # pragma: no cover - interface
        raise NotImplementedError

    def _confirmed(self, id_: str, title: str, evidence: str) -> Indicator:
        return Indicator(
            id_, title, "critical", THREAT_INTEL, evidence,
            "This is a confirmed listing from an external threat-intelligence source, not a guess by this tool. "
            "Listings can occasionally be wrong or out of date, but they should be treated as dangerous.",
            group="intel_confirmed",
        )


class OpenPhishFeed(Provider):
    """OpenPhish community feed: a rolling list of currently active phishing URLs."""
    name, label = "openphish", "OpenPhish community feed"

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self._urls: set[str] = set()
        self._hosts: set[str] = set()
        self._loaded_at = 0.0
        self._last_attempt = 0.0
        self._lock = threading.Lock()

    def configured(self) -> bool:
        return self.settings.enable_openphish

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            now = time.time()
            fresh = now - self._loaded_at < self.settings.openphish_refresh_seconds
            if (fresh and not force) or (now - self._last_attempt < 60 and not force):
                return
            self._last_attempt = now
            resp = self.client.get(self.settings.openphish_feed_url, timeout=self.settings.intel_timeout * 2)
            resp.raise_for_status()
            urls, hosts = set(), set()
            for line in resp.text.splitlines()[:200_000]:
                try:
                    q = parse_url(line)
                except URLParseError:
                    continue
                urls.add(q.url.split("://", 1)[1].rstrip("/"))
                hosts.add(q.host_ascii)
            if not urls:
                raise ValueError("empty feed")
            self._urls, self._hosts, self._loaded_at = urls, hosts, now

    def lookup(self, p: ParsedURL) -> ProviderResult:   # local set lookup: no per-URL caching needed
        if not self.configured():
            return ProviderResult(self.label, "not_configured", "Disabled by the operator.")
        try:
            self.refresh()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("openphish refresh failed: %s", type(exc).__name__)
        if not self._urls:
            return ProviderResult(self.label, "error", "The feed could not be downloaded.")
        age_h = (time.time() - self._loaded_at) / 3600
        if age_h > 48:
            return ProviderResult(self.label, "error", f"The cached feed is {age_h:.0f} hours old and was not used.")
        note = f"{len(self._urls):,} active phishing URLs, feed fetched {age_h:.1f} h ago."
        if p.url.split("://", 1)[1].rstrip("/") in self._urls:
            return ProviderResult(self.label, "match", note, [self._confirmed(
                "openphish_url_match", "Listed as active phishing by OpenPhish", f"Exact URL match in the OpenPhish feed. {note}")])
        if p.host_ascii in self._hosts:
            if user_content_platform(p) or is_established(p):
                ind = Indicator("openphish_host_listed", "Another page on this shared host is listed by OpenPhish", "low", THREAT_INTEL,
                                f"{p.host} appears in the feed with a different path.",
                                "The host serves many unrelated pages, so a listing for a different page is only weak evidence here.")
                return ProviderResult(self.label, "clean", note + " Host listed with a different path.", [ind])
            return ProviderResult(self.label, "match", note, [self._confirmed(
                "openphish_host_match", "Host is serving active phishing according to OpenPhish",
                f"{p.host} is in the OpenPhish feed (different path). {note}")])
        return ProviderResult(self.label, "clean", "Not listed. " + note)


class GoogleSafeBrowsing(Provider):
    """Google Safe Browsing Lookup API v4 (threatMatches:find)."""
    name, label = "gsb", "Google Safe Browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def configured(self) -> bool:
        return bool(self.settings.google_safe_browsing_key)

    def _lookup(self, p: ParsedURL) -> ProviderResult:
        body = {
            "client": {"clientId": "phishing-detection-app", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": p.url}],
            },
        }
        resp = self.client.post(self.endpoint, params={"key": self.settings.google_safe_browsing_key}, json=body,
                                timeout=self.settings.intel_timeout)
        resp.raise_for_status()
        matches = resp.json().get("matches") or []
        if matches:
            kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return ProviderResult(self.label, "match", ", ".join(kinds), [self._confirmed(
                "gsb_match", "Flagged by Google Safe Browsing", "Threat type: " + ", ".join(k.replace("_", " ").lower() for k in kinds))])
        return ProviderResult(self.label, "clean", "Not listed.")


class VirusTotal(Provider):
    """VirusTotal API v3 URL report (existing analyses only; nothing is submitted for scanning)."""
    name, label = "virustotal", "VirusTotal"
    endpoint = "https://www.virustotal.com/api/v3/urls/"
    CONFIRM_AT = 3

    def configured(self) -> bool:
        return bool(self.settings.virustotal_key)

    def _lookup(self, p: ParsedURL) -> ProviderResult:
        url_id = base64.urlsafe_b64encode(p.url.encode()).decode().rstrip("=")
        resp = self.client.get(self.endpoint + url_id, headers={"x-apikey": self.settings.virustotal_key},
                               timeout=self.settings.intel_timeout)
        if resp.status_code == 404:
            return ProviderResult(self.label, "clean", "No existing report for this URL (never scanned, which is not the same as clean).")
        if resp.status_code == 429:
            return ProviderResult(self.label, "error", "API quota exceeded.")
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        bad, total = int(stats.get("malicious", 0)), sum(int(v) for v in stats.values())
        sus = int(stats.get("suspicious", 0))
        detail = f"{bad} of {total} engines flag it as malicious, {sus} as suspicious."
        if bad >= self.CONFIRM_AT:
            return ProviderResult(self.label, "match", detail, [self._confirmed("virustotal_match", "Flagged by multiple security vendors", detail)])
        if bad + sus >= 1:
            ind = Indicator("virustotal_few", "Flagged by one or two security vendors", "medium", THREAT_INTEL, detail,
                            "Single-vendor detections are frequently false positives, so this is treated as a warning "
                            "rather than a confirmed listing.", group="vt")
            return ProviderResult(self.label, "clean", detail, [ind])
        return ProviderResult(self.label, "clean", detail)


class URLhaus(Provider):
    """abuse.ch URLhaus (malware distribution URLs). Requires a free Auth-Key."""
    name, label = "urlhaus", "URLhaus (abuse.ch)"
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

    def configured(self) -> bool:
        return bool(self.settings.urlhaus_key)

    def _lookup(self, p: ParsedURL) -> ProviderResult:
        resp = self.client.post(self.endpoint, data={"url": p.url}, headers={"Auth-Key": self.settings.urlhaus_key},
                                timeout=self.settings.intel_timeout)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status == "ok":
            detail = f"Threat: {data.get('threat', 'unknown')}; status: {data.get('url_status', 'unknown')}."
            return ProviderResult(self.label, "match", detail, [self._confirmed("urlhaus_match", "Listed as malware distribution by URLhaus", detail)])
        if status == "no_results":
            return ProviderResult(self.label, "clean", "Not listed.")
        raise ValueError(f"unexpected query_status {status!r}")


class DomainAge(Provider):
    """Domain registration date via RDAP (the structured successor to WHOIS)."""
    name, label = "rdap", "Domain registration age (RDAP)"

    def configured(self) -> bool:
        return self.settings.enable_domain_age

    def _cache_key(self, p: ParsedURL) -> str:
        return p.registered_domain

    def lookup(self, p: ParsedURL) -> ProviderResult:
        if p.is_ip:
            return ProviderResult(self.label, "not_configured", "Not applicable to IP addresses.")
        return super().lookup(p)

    def _lookup(self, p: ParsedURL) -> ProviderResult:
        resp = self.client.get(self.settings.rdap_base_url + p.registered_domain, timeout=self.settings.intel_timeout,
                               follow_redirects=True, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            return ProviderResult(self.label, "error", "No registration record available for this domain ending.")
        resp.raise_for_status()
        created = None
        for ev in resp.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                break
        if created is None:
            return ProviderResult(self.label, "error", "The registry does not publish a registration date.")
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days = max((datetime.now(timezone.utc) - created).days, 0)
        detail = f"Registered {created.date().isoformat()} ({days} days ago)."
        inds: list[Indicator] = []
        if days < 30:
            inds.append(Indicator("domain_very_new", "Domain registered in the last 30 days", "medium", REPUTATION, detail,
                                  "Most phishing domains are used within days of registration and abandoned soon after. "
                                  "New legitimate sites exist too, so this needs supporting evidence.", group="age"))
        elif days < 180:
            inds.append(Indicator("domain_new", "Domain registered in the last six months", "low", REPUTATION, detail,
                                  "A young domain has had little time to build a track record.", group="age"))
        elif days >= 730:
            inds.append(Indicator("domain_aged", "Domain registered for more than two years", "positive", REPUTATION, detail,
                                  "Long-lived domains are less typical of phishing, although old sites can be hacked."))
        res = ProviderResult(self.label, "clean", detail, inds)
        res.age_days = days  # type: ignore[attr-defined]
        return res


def build_providers(settings: Settings, client: httpx.Client | None = None) -> tuple[list[Provider], DomainAge]:
    client = client or httpx.Client(headers={"User-Agent": "phishing-detection-app/2.0"}, follow_redirects=False)
    cache = TTLCache()
    providers: list[Provider] = [OpenPhishFeed(settings, client, cache), GoogleSafeBrowsing(settings, client, cache),
                                 VirusTotal(settings, client, cache), URLhaus(settings, client, cache)]
    return providers, DomainAge(settings, client, cache)
