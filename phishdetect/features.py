"""Lexical feature extraction for the URL machine-learning model.

Deliberately excluded: the scheme (http/https), a leading "www." and any
popularity signal. Those correlate with *where the training data came from*
rather than with phishing, and reputation is handled by a separate, auditable
rule layer.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .brands import AUTH_WORDS, find_brand_matches, official_brand
from .reputation import user_content_platform
from .urltools import ParsedURL, reference_lists

FEATURE_NAMES = [
    "host_len", "path_len", "query_len", "n_subdomain_labels", "n_host_hyphens", "n_host_digits",
    "host_digit_ratio", "label_len", "label_entropy", "label_digit_ratio", "label_vowel_ratio",
    "label_max_consonant_run", "longest_sub_label", "is_ip", "has_port", "has_userinfo", "is_idn",
    "tld_len", "tld_suspicious", "tld_common", "n_path_segments", "max_path_seg_len", "path_entropy",
    "path_digit_ratio", "n_params", "n_pct", "n_special", "has_embedded_url", "has_email_in_url",
    "ext_php", "ext_html", "ext_exec", "ext_doc", "path_is_root", "n_auth_words_host",
    "n_auth_words_path", "brand_in_host", "brand_typo", "brand_in_path", "brand_embedded_domain",
    "is_official_brand", "is_user_content_platform", "is_shortener", "has_long_hex_token",
    "has_wp_path", "n_host_tokens", "double_slash_path", "has_tilde",
]

_COMMON_TLDS = frozenset(
    "com org net edu gov mil int uk de fr jp au ca nl it es se no fi dk ch at be ie nz br in mx kr pl cz pt gr".split()
)
_VOWELS = set("aeiou")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _max_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def extract_features(p: ParsedURL) -> list[float]:
    lists = reference_lists()
    host = p.host_ascii[4:] if p.host_ascii.startswith("www.") else p.host_ascii
    sub = p.subdomain[4:] if p.subdomain.startswith("www.") else ("" if p.subdomain == "www" else p.subdomain)
    label = p.domain_label or host
    path = p.path
    path_l = path.lower()
    full_tail = (path + "?" + p.query).lower()
    segs = [s for s in path.split("/") if s]
    last = segs[-1].lower() if segs else ""
    ext = last.rsplit(".", 1)[-1] if "." in last else ""
    tld = p.suffix.split(".")[-1] if p.suffix else ""
    host_toks = set(re.split(r"[^a-z]+", host))
    path_toks = set(re.split(r"[^a-z]+", full_tail))
    matches = find_brand_matches(p)
    kinds = {m.kind for m in matches}
    alpha = [c for c in label if c.isalpha()]

    f = {
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(p.query),
        "n_subdomain_labels": len([s for s in sub.split(".") if s]),
        "n_host_hyphens": host.count("-"),
        "n_host_digits": sum(c.isdigit() for c in host),
        "host_digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "label_len": len(label),
        "label_entropy": entropy(label),
        "label_digit_ratio": sum(c.isdigit() for c in label) / max(len(label), 1),
        "label_vowel_ratio": sum(c in _VOWELS for c in alpha) / max(len(alpha), 1),
        "label_max_consonant_run": _max_consonant_run(label),
        "longest_sub_label": max((len(s) for s in sub.split(".")), default=0),
        "is_ip": p.is_ip,
        "has_port": p.port is not None,
        "has_userinfo": bool(p.userinfo),
        "is_idn": "xn--" in p.host_ascii,
        "tld_len": len(tld),
        "tld_suspicious": tld in lists["suspicious_tlds"],
        "tld_common": tld in _COMMON_TLDS,
        "n_path_segments": len(segs),
        "max_path_seg_len": max((len(s) for s in segs), default=0),
        "path_entropy": entropy(path),
        "path_digit_ratio": sum(c.isdigit() for c in path) / max(len(path), 1),
        "n_params": len(p.params),
        "n_pct": full_tail.count("%"),
        "n_special": sum(full_tail.count(c) for c in "=&_~;,+"),
        "has_embedded_url": "http" in full_tail[1:] or "www." in full_tail,
        "has_email_in_url": bool(re.search(r"[\w.+-]+(@|%40)[\w-]+\.[a-z]{2,}", full_tail + "#" + p.fragment.lower())),
        "ext_php": ext in ("php", "asp", "aspx", "jsp", "cgi"),
        "ext_html": ext in ("html", "htm", "shtml"),
        "ext_exec": ext in ("exe", "scr", "apk", "msi", "bat", "vbs", "js", "jar", "iso", "lnk", "zip", "rar", "7z"),
        "ext_doc": ext in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "txt", "jpg", "png", "gif", "css"),
        "path_is_root": path in ("", "/") and not p.query,
        "n_auth_words_host": len(host_toks & AUTH_WORDS),
        "n_auth_words_path": len(path_toks & AUTH_WORDS),
        "brand_in_host": bool(kinds & {"token", "substring", "homoglyph", "other_tld"}),
        "brand_typo": "typo" in kinds,
        "brand_in_path": "path" in kinds,
        "brand_embedded_domain": "embedded_domain" in kinds,
        "is_official_brand": official_brand(p) is not None,
        "is_user_content_platform": user_content_platform(p) is not None,
        "is_shortener": p.registered_domain in lists["shorteners"] or p.host_ascii in lists["shorteners"],
        "has_long_hex_token": bool(re.search(r"[0-9a-f]{20,}", full_tail)),
        "has_wp_path": bool(re.search(r"/wp-(includes|content|admin)/|/\.well-known/", path_l)),
        "n_host_tokens": len([t for t in re.split(r"[.-]", host) if t]),
        "double_slash_path": "//" in path,
        "has_tilde": "~" in path,
    }
    return [float(f[name]) for name in FEATURE_NAMES]
