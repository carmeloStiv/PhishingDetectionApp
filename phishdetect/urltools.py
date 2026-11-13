"""URL extraction, parsing and normalisation.

Everything here is pure string processing: no network access.
"""
from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

DATA_DIR = Path(__file__).parent / "data"

# Use the public-suffix snapshot bundled with tldextract; never fetch at runtime.
_extract_private = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
_extract_icann = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False
)

MAX_URL_LENGTH = 4096

_URL_RE = re.compile(
    r"""(?ix)
    \b(?:https?://|hxxps?://|www\.)[^\s<>"'`\]\)]+        # explicit scheme or www.
    |
    \b(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+
      [a-z¡-￿][a-z0-9¡-￿-]{1,23}
      (?::\d{2,5})?(?:/[^\s<>"'`\]\)]*)?                 # bare domain with optional path
    """
)
_HREF_RE = re.compile(r"""(?is)<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)[^>]*>(.*?)</a>""")
_TRAILING_PUNCT = ".,;:!?)>]}'\""


@lru_cache(maxsize=1)
def reference_lists() -> dict:
    with open(DATA_DIR / "lists.json", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {k: frozenset(v) for k, v in raw.items()}


@dataclass
class ParsedURL:
    original: str
    url: str                 # normalised form used for lookups
    scheme: str
    host: str                # lower-case, unicode form
    host_ascii: str          # punycode / ASCII form
    port: int | None
    path: str
    query: str
    fragment: str
    userinfo: str
    is_ip: bool
    ip_obfuscated: bool
    registered_domain: str   # eTLD+1 using ICANN suffixes (e.g. blogspot.com)
    site_domain: str         # eTLD+1 including private suffixes (e.g. foo.blogspot.com)
    domain_label: str        # label left of the (private-aware) suffix
    subdomain: str
    suffix: str
    params: list[tuple[str, str]] = field(default_factory=list)

    @property
    def display(self) -> str:
        return defang(self.url)


class URLParseError(ValueError):
    pass


def defang(url: str) -> str:
    """Render a URL so that it cannot be clicked or auto-linked."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]") if url else url


def refang(text: str) -> str:
    return (
        text.replace("hxxp", "http").replace("hXXp", "http").replace("[.]", ".").replace("(.)", ".")
        .replace("[:]", ":")
    )


def _parse_obfuscated_ip(host: str) -> str | None:
    """Detect decimal / hex / octal encoded IPv4 hosts (e.g. 0x7f.1, 2130706433)."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        try:
            if re.fullmatch(r"0x[0-9a-f]+", p):
                nums.append(int(p, 16))
            elif re.fullmatch(r"0[0-7]+", p):
                nums.append(int(p, 8))
            elif re.fullmatch(r"\d+", p):
                nums.append(int(p))
            else:
                return None
        except ValueError:
            return None
    try:
        if len(nums) == 1:
            value = nums[0]
        else:
            if any(n > 255 for n in nums[:-1]):
                return None
            value = 0
            for n in nums[:-1]:
                value = (value << 8) | n
            tail_bits = 8 * (4 - (len(nums) - 1))
            if nums[-1] >= 1 << tail_bits:
                return None
            value = (value << tail_bits) | nums[-1]
        return str(ipaddress.IPv4Address(value))
    except (ValueError, ipaddress.AddressValueError):
        return None


def parse_url(raw: str) -> ParsedURL:
    """Parse a user-supplied URL (scheme optional). Raises URLParseError."""
    original = raw
    raw = refang(raw.strip())
    raw = "".join(ch for ch in raw if ch.isprintable() and not ch.isspace())
    if not raw:
        raise URLParseError("empty input")
    if len(raw) > MAX_URL_LENGTH:
        raise URLParseError("URL is too long")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        if re.match(r"^(javascript|data|vbscript|file|mailto|tel):", raw, re.I):
            raise URLParseError("only http and https URLs can be analysed")
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise URLParseError(f"not a valid URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise URLParseError("only http and https URLs can be analysed")
    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise URLParseError("URL has no host name")
    host = unicodedata.normalize("NFC", host)

    is_ip = False
    ip_obfuscated = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        decoded = _parse_obfuscated_ip(host)
        if decoded:
            is_ip, ip_obfuscated, host = True, True, decoded

    host_ascii = host
    if not is_ip:
        try:
            host_ascii = host.encode("idna").decode("ascii")
        except UnicodeError:
            try:
                import idna

                host_ascii = idna.encode(host, uts46=True).decode("ascii")
            except Exception as exc:  # noqa: BLE001
                raise URLParseError("host name is not valid") from exc
        if host_ascii.startswith("xn--") or ".xn--" in host_ascii:
            try:
                host = host_ascii.encode("ascii").decode("idna")
            except UnicodeError:
                host = host_ascii
        if not re.fullmatch(r"[a-z0-9_.-]+", host_ascii) or ".." in host_ascii:
            raise URLParseError("host name contains invalid characters")

    if is_ip:
        registered = site = host
        label = sub = suffix = ""
    else:
        icann = _extract_icann(host_ascii)
        priv = _extract_private(host_ascii)
        if not icann.suffix or not icann.domain:
            raise URLParseError("host name does not end in a recognised public suffix")
        registered = f"{icann.domain}.{icann.suffix}"
        if priv.domain and priv.suffix:
            # label / sub-domain are relative to the *site*: for foo.blogspot.com or
            # shop.ru.com the name the owner chose is "foo" / "shop".
            site, label, sub, suffix = f"{priv.domain}.{priv.suffix}", priv.domain, priv.subdomain, priv.suffix
        else:
            site, label, sub, suffix = registered, icann.domain, icann.subdomain, icann.suffix

    netloc = host_ascii if ":" not in host_ascii else f"[{host_ascii}]"
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        netloc += f":{port}"
    path = parts.path or "/"
    url = f"{scheme}://{netloc}{path}"
    if parts.query:
        url += "?" + parts.query
    return ParsedURL(
        original=original, url=url, scheme=scheme, host=host, host_ascii=host_ascii,
        port=port if port and port != default_port else None, path=path, query=parts.query,
        fragment=parts.fragment, userinfo=(parts.username or "") + (":" + parts.password if parts.password else ""),
        is_ip=is_ip, ip_obfuscated=ip_obfuscated, registered_domain=registered, site_domain=site,
        domain_label=label, subdomain=sub, suffix=suffix,
        params=parse_qsl(parts.query, keep_blank_values=True)[:50],
    )


def looks_like_single_url(text: str) -> bool:
    """True when the whole submission is one URL / domain rather than a message."""
    t = text.strip()
    if not t or len(t.split()) != 1:
        return False
    try:
        parse_url(t)
        return True
    except URLParseError:
        return False


def extract_urls(text: str, limit: int = 25) -> list[str]:
    """Extract candidate URLs from free text or HTML, in order, de-duplicated."""
    text = refang(text)
    found: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        candidate = candidate.strip().rstrip(_TRAILING_PUNCT)
        if not candidate or candidate.lower().startswith(("mailto:", "tel:", "#", "cid:")):
            return
        try:
            p = parse_url(candidate)
        except URLParseError:
            return
        if p.url not in seen:
            seen.add(p.url)
            found.append(candidate)

    for m in _HREF_RE.finditer(text):
        add(unquote(m.group(1)) if "%3A%2F" in m.group(1) else m.group(1))
    # Mask e-mail addresses so their domains are not mistaken for links.
    masked = re.sub(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", " ", text)
    for m in _URL_RE.finditer(masked):
        cand = m.group(0)
        if not re.match(r"(?i)^(https?://|www\.)", cand):
            # bare domain: require a real public suffix and avoid file names / abbreviations
            host = cand.split("/")[0].split(":")[0].lower()
            ext = _extract_icann(host)
            if not ext.suffix or not ext.domain:
                continue
            if "/" not in cand and ext.suffix in _FILE_LIKE_SUFFIXES:
                continue
            if "/" not in cand and len(ext.domain) < 3:
                continue
        add(cand)
        if len(found) >= limit:
            break
    return found[:limit]


# TLDs that collide with common file extensions or abbreviations in prose.
_FILE_LIKE_SUFFIXES = frozenset(
    "zip mov py sh pl rs md so ai app doc docx pdf txt name cab bat com.py id is it in to at no me my do be by or as us".split()
)


def extract_anchor_pairs(text: str) -> list[tuple[str, str]]:
    """(href, visible text) pairs from HTML anchors."""
    pairs = []
    for m in _HREF_RE.finditer(text):
        visible = re.sub(r"<[^>]+>", " ", m.group(2))
        pairs.append((m.group(1), re.sub(r"\s+", " ", visible).strip()))
    return pairs[:50]
