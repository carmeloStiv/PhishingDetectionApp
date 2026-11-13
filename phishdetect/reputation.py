"""Popularity-based reputation from the bundled Chrome UX Report top-sites list.

Being popular is *supporting* evidence only. It is never applied to hosts on
platforms where anyone can publish content, and it never overrides a threat
intelligence match or page-content findings.
"""
from __future__ import annotations

import gzip
from functools import lru_cache

from .urltools import DATA_DIR, ParsedURL, reference_lists

# CrUX rank buckets. "Established" = listed at all; "well known" = top 100k.
ESTABLISHED_MAX_RANK = 1_000_000
WELL_KNOWN_MAX_RANK = 100_000


@lru_cache(maxsize=1)
def _top_domains() -> dict[str, int]:
    path = DATA_DIR / "top_domains.txt.gz"
    out: dict[str, int] = {}
    if not path.exists():
        return out
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            dom, _, rank = line.strip().partition(",")
            if dom:
                out[dom] = int(rank or 0)
    return out


def popularity_rank(site_domain: str) -> int | None:
    """CrUX rank bucket (1000, 5000, ... 1000000) or None when not listed.

    Keyed on the public-suffix-aware site domain, so `shop.ru.com` or
    `someone.github.io` never inherit the popularity of `ru.com` / `github.io`.
    """
    return _top_domains().get(site_domain)


def user_content_platform(parsed: ParsedURL) -> str | None:
    """Return the platform suffix if this host lets arbitrary users publish content."""
    if parsed.is_ip:
        return None
    platforms = reference_lists()["user_content_platforms"]
    host = parsed.host_ascii
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in platforms:
            # the bare marketing site of a platform (e.g. www.weebly.com) is not user content
            if i == 0 or (i == 1 and parts[0] == "www"):
                return cand if cand in _ALWAYS_USER_CONTENT else None
            return cand
    return None


_ALWAYS_USER_CONTENT = frozenset(
    "sites.google.com docs.google.com forms.gle forms.office.com sway.office.com sway.cloud.microsoft 1drv.ms "
    "storage.googleapis.com s3.amazonaws.com telegra.ph ipfs.io dweb.link t.me discord.gg page.link app.link "
    "medium.com airtable.com codesandbox.io".split()
)


def is_established(parsed: ParsedURL) -> bool:
    """Popular registered domain that is not a user-content platform."""
    if parsed.is_ip or user_content_platform(parsed):
        return False
    rank = popularity_rank(parsed.site_domain)
    return rank is not None and rank <= ESTABLISHED_MAX_RANK


def is_well_known(parsed: ParsedURL) -> bool:
    if parsed.is_ip or user_content_platform(parsed):
        return False
    rank = popularity_rank(parsed.site_domain)
    return rank is not None and rank <= WELL_KNOWN_MAX_RANK
