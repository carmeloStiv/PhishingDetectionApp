"""Runtime configuration, read from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None or v == "" else v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    # --- network analysis ---
    enable_live_fetch: bool = field(default_factory=lambda: _bool("ENABLE_LIVE_FETCH", True))
    fetch_timeout: float = field(default_factory=lambda: float(_int("FETCH_TIMEOUT_SECONDS", 8)))
    fetch_max_bytes: int = field(default_factory=lambda: _int("FETCH_MAX_BYTES", 750_000))
    fetch_max_redirects: int = field(default_factory=lambda: _int("FETCH_MAX_REDIRECTS", 5))
    enable_domain_age: bool = field(default_factory=lambda: _bool("ENABLE_DOMAIN_AGE", True))
    rdap_base_url: str = field(default_factory=lambda: os.environ.get("RDAP_BASE_URL", "https://rdap.org/domain/"))
    intel_timeout: float = field(default_factory=lambda: float(_int("INTEL_TIMEOUT_SECONDS", 6)))
    # --- threat intelligence ---
    enable_openphish: bool = field(default_factory=lambda: _bool("ENABLE_OPENPHISH", True))
    openphish_feed_url: str = field(default_factory=lambda: os.environ.get(
        "OPENPHISH_FEED_URL", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"))
    openphish_refresh_seconds: int = field(default_factory=lambda: _int("OPENPHISH_REFRESH_SECONDS", 6 * 3600))
    google_safe_browsing_key: str = field(default_factory=lambda: os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", ""))
    virustotal_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))
    urlhaus_key: str = field(default_factory=lambda: os.environ.get("URLHAUS_AUTH_KEY", ""))
    # --- service ---
    rate_limit_per_minute: int = field(default_factory=lambda: _int("RATE_LIMIT_PER_MINUTE", 20))
    trust_proxy_headers: bool = field(default_factory=lambda: _bool("TRUST_PROXY_HEADERS", False))
    max_text_chars: int = field(default_factory=lambda: _int("MAX_TEXT_CHARS", 50_000))
    max_links_per_message: int = field(default_factory=lambda: _int("MAX_LINKS_PER_MESSAGE", 5))
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("DATA_DIR", "var")))
    feedback_retention_days: int = field(default_factory=lambda: _int("FEEDBACK_RETENTION_DAYS", 180))

    @classmethod
    def offline(cls) -> "Settings":
        """No outbound network at all: rules, ML and bundled reputation only."""
        s = cls()
        s.enable_live_fetch = s.enable_domain_age = s.enable_openphish = False
        s.google_safe_browsing_key = s.virustotal_key = s.urlhaus_key = ""
        return s
