"""Brand impersonation helpers: official domains, look-alike and typo detection."""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

from .urltools import DATA_DIR, ParsedURL, reference_lists

# Characters from other scripts that render like Latin letters.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b",
    "н": "h", "г": "r", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ε": "e", "ι": "i",
    "κ": "k", "υ": "u", "χ": "x", "ɡ": "g", "ո": "n", "ս": "u", "օ": "o", "ı": "i", "ł": "l",
    "ø": "o", "đ": "d", "ħ": "h", "ɑ": "a", "ʏ": "y", "ǀ": "l", "ӏ": "l", "і": "i", "ѡ": "w", "ԍ": "g", "ѵ": "v",
    "ь": "b", "п": "n", "и": "u", "я": "r", "ш": "w", "ц": "u", "л": "n", "д": "a", "з": "3", "б": "6", "ё": "e", "ї": "i",
})
_LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "!": "i"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "!": "i"})


@dataclass(frozen=True)
class BrandMatch:
    brand: str
    kind: str      # official | embedded_domain | token | substring | typo | homoglyph | other_tld | path
    where: str     # domain | subdomain | path
    matched: str


@lru_cache(maxsize=1)
def _brand_db():
    with open(DATA_DIR / "brands.json", encoding="utf-8") as fh:
        raw = json.load(fh)["brands"]
    ambiguous = reference_lists()["ambiguous_brand_tokens"]
    token_to_brand: dict[str, str] = {}
    brand_domains: dict[str, frozenset[str]] = {}
    all_domains: dict[str, str] = {}
    strong: list[tuple[str, str]] = []   # (token, brand) usable for fuzzy / substring matching
    for b in raw:
        brand_domains[b["name"]] = frozenset(b["domains"])
        for d in b["domains"]:
            # a domain listed under several brands belongs to the one it is named after
            if d not in all_domains or d.split(".")[0].replace("-", "") == b["name"]:
                all_domains[d] = b["name"]
        for tok in [b["name"], *b["keywords"]]:
            token_to_brand.setdefault(tok, b["name"])
            if len(tok) >= 6 and tok not in ambiguous:
                strong.append((tok, b["name"]))
    return token_to_brand, brand_domains, all_domains, strong, ambiguous


def skeleton(text: str) -> str:
    """Map look-alike characters to plain ASCII Latin."""
    text = text.translate(_CONFUSABLES)
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def _leet_variants(token: str) -> set[str]:
    out = set()
    for table in (_LEET_L, _LEET_I):
        v = token.translate(table)
        out.add(v)
        out.add(v.replace("rn", "m"))
        out.add(v.replace("vv", "w"))
        out.add(v.replace("cl", "d"))
    out.discard(token)
    return out


def damerau_levenshtein(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def official_brand(parsed: ParsedURL) -> str | None:
    """Brand that officially owns this host's registered domain, if any."""
    if parsed.is_ip:
        return None
    _, _, all_domains, _, _ = _brand_db()
    host = parsed.host_ascii
    for cand in (parsed.site_domain, parsed.registered_domain):
        if cand in all_domains:
            return all_domains[cand]
    # multi-label official domains such as aws.amazon.com / tax.service.gov.uk
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in all_domains:
            return all_domains[cand]
    return None


def is_official_domain_for(brand: str, registered_domain: str) -> bool:
    _, brand_domains, _, _, _ = _brand_db()
    return registered_domain in brand_domains.get(brand, ())


def brand_for_token(token: str) -> str | None:
    return _brand_db()[0].get(token)


def host_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z]+", text.lower()) if t]


AUTH_WORDS = frozenset(
    "login log-in signin sign-in logon verify verification verified secure security account accounts update "
    "confirm confirmation auth authenticate authentication password passwd recover recovery unlock billing "
    "payment wallet banking support helpdesk service services customer alert suspend suspended limited restore "
    "validate validation webscr identity id signon sso myaccount credential invoice refund claim reward bonus "
    "airdrop connect dapp".split()
)


def has_auth_context(parsed: ParsedURL) -> bool:
    text = f"{parsed.host_ascii}{parsed.path}?{parsed.query}".lower()
    toks = set(re.split(r"[^a-z]+", text))
    return bool(toks & AUTH_WORDS) or any(w in text for w in ("login", "signin", "verify", "secure", "account", "wallet"))


def find_brand_matches(parsed: ParsedURL) -> list[BrandMatch]:
    """Brand references in a URL whose domain is NOT an official domain of that brand."""
    key = parsed.url
    hit = _MATCH_CACHE.get(key)
    if hit is None:
        if len(_MATCH_CACHE) > 2000:
            _MATCH_CACHE.clear()
        hit = _MATCH_CACHE[key] = _find_brand_matches(parsed)
    return list(hit)


_MATCH_CACHE: dict[str, list[BrandMatch]] = {}


def _find_brand_matches(parsed: ParsedURL) -> list[BrandMatch]:
    if parsed.is_ip:
        return _path_matches(parsed, None)
    token_to_brand, brand_domains, all_domains, strong, ambiguous = _brand_db()
    owner = official_brand(parsed)
    matches: list[BrandMatch] = []
    seen: set[str] = set()

    def add(brand: str, kind: str, where: str, matched: str) -> None:
        if brand == owner or brand in seen:
            return
        # sibling brands of the same owner (e.g. outlook on microsoft.com) are fine
        if owner and parsed.registered_domain in brand_domains.get(brand, ()):
            return
        seen.add(brand)
        matches.append(BrandMatch(brand, kind, where, matched))

    host_skel = skeleton(parsed.host)
    label_skel = skeleton(parsed.host.rsplit("." + parsed.suffix, 1)[0].split(".")[-1]) if parsed.suffix else host_skel
    sub_skel = host_skel[: -(len(label_skel) + len(parsed.suffix) + 2)] if parsed.subdomain else ""
    non_ascii = any(ord(c) > 127 for c in parsed.host)

    # 1. A full official domain embedded to the left of the real registered domain.
    if sub_skel:
        sub_dot = "." + sub_skel + "."
        for dom, brand in all_domains.items():
            if "." in dom and len(dom) >= 6 and ("." + dom + "." in sub_dot or sub_dot.startswith("." + dom.replace(".", "-") + ".")):
                add(brand, "embedded_domain", "subdomain", dom)

    # 2. Tokens in the registered-domain label and in the sub-domain.
    for where, text in (("domain", label_skel), ("subdomain", sub_skel)):
        if not text:
            continue
        toks = host_tokens(text)
        compact = re.sub(r"[^a-z0-9]", "", text)
        for tok in toks:
            brand = token_to_brand.get(tok)
            if brand:
                if where == "domain" and text == tok and not non_ascii:
                    add(brand, "other_tld", where, tok)
                else:
                    add(brand, "homoglyph" if non_ascii else "token", where, tok)
        for tok, brand in strong:
            if brand in seen:
                continue
            if tok in compact:
                add(brand, "homoglyph" if non_ascii else "substring", where, tok)
        # leet-speak / digit substitutions (paypa1, micr0soft, arnazon)
        raw_toks = [t for t in re.split(r"[^a-z0-9]+", text) if t]
        for rt in raw_toks:
            for variant in _leet_variants(rt):
                for tok, brand in strong:
                    if tok in variant and tok not in rt:
                        add(brand, "typo", where, rt)
                b = token_to_brand.get(variant)
                if b and len(variant) >= 4 and variant != rt:
                    add(b, "typo", where, rt)

    # 3. Edit-distance typosquats of the registered-domain label (and its hyphen parts).
    if not owner:
        cands = {label_skel, *[t for t in label_skel.split("-") if len(t) >= 6]}
        if sub_skel:
            cands |= {t for t in re.split(r"[.-]", sub_skel) if len(t) >= 8}
        for cand in cands:
            if len(cand) < 6 or cand in token_to_brand:
                continue
            variants = {cand, *_leet_variants(cand)}
            for tok, brand in strong:
                if brand in seen:
                    continue
                # longer names tolerate more edits before they stop being recognisable
                limit = 1 if len(tok) < 10 else 2 if len(tok) < 12 else 3
                if abs(len(tok) - len(cand)) <= limit:
                    tok_chars = set(tok)
                    if any(v != tok and len(tok_chars - set(v)) <= limit and damerau_levenshtein(v, tok, limit) <= limit
                           for v in variants):
                        add(brand, "typo", "domain", cand)
                elif len(tok) >= 8 and len(cand) > len(tok):
                    # long brand misspelt inside a longer label (mscrosoftonline, steamcomnunity-login)
                    tok_chars = set(tok)
                    for i in range(len(cand) - len(tok) + 1):
                        window = cand[i:i + len(tok)]
                        if len(tok_chars - set(window)) <= 1 and damerau_levenshtein(window, tok, 1) <= 1:
                            add(brand, "typo", "domain", cand)
                            break

    matches.extend(m for m in _path_matches(parsed, owner) if m.brand not in seen)
    return matches


def _path_matches(parsed: ParsedURL, owner: str | None) -> list[BrandMatch]:
    token_to_brand, brand_domains, _, strong, ambiguous = _brand_db()
    text = (parsed.path + " " + parsed.query).lower()
    if len(text) < 4:
        return []
    out, seen = [], set()
    toks = set(host_tokens(text))
    for tok in toks:
        brand = token_to_brand.get(tok)
        if not brand or brand == owner or brand in seen or tok in ambiguous or len(tok) < 5:
            continue
        if owner and parsed.registered_domain in brand_domains.get(brand, ()):
            continue
        seen.add(brand)
        out.append(BrandMatch(brand, "path", "path", tok))
    return out


_DISPLAY = {"paypal": "PayPal", "bankofamerica": "Bank of America", "wellsfargo": "Wells Fargo", "americanexpress": "American Express",
            "capitalone": "Capital One", "royalmail": "Royal Mail", "dhl": "DHL", "ups": "UPS", "usps": "USPS", "hsbc": "HSBC", "irs": "IRS",
            "hmrc": "HMRC", "linkedin": "LinkedIn", "whatsapp": "WhatsApp", "docusign": "DocuSign", "metamask": "MetaMask", "github": "GitHub",
            "icloud": "iCloud", "ebay": "eBay", "fedex": "FedEx", "tiktok": "TikTok", "openai": "OpenAI", "office365": "Office 365",
            "onedrive": "OneDrive", "sharepoint": "SharePoint", "westernunion": "Western Union", "geeksquad": "Geek Squad", "govuk": "GOV.UK",
            "att": "AT&T", "tmobile": "T-Mobile", "usbank": "U.S. Bank", "nhs": "NHS", "playstation": "PlayStation", "youtube": "YouTube"}


def display_name(brand: str | None) -> str:
    if not brand:
        return ""
    return _DISPLAY.get(brand, brand if len(brand) <= 3 and brand.isupper() else brand.capitalize())
