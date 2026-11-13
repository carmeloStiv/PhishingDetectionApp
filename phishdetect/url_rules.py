"""Deterministic URL / domain heuristics.

Each rule yields an Indicator with evidence and a plain-language explanation.
Rules look at URL *structure*, never at popularity alone, and never treat
HTTPS as a sign of legitimacy.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote

from .brands import AUTH_WORDS, display_name, find_brand_matches, has_auth_context, official_brand
from .indicators import HEURISTIC, REPUTATION, Indicator
from .reputation import is_established, is_well_known, popularity_rank, user_content_platform
from .urltools import ParsedURL, URLParseError, parse_url, reference_lists

_EXEC_EXT = ("exe", "scr", "msi", "bat", "cmd", "vbs", "jar", "apk", "iso", "lnk", "hta", "ps1", "dll")
_SCRIPTS = (
    ("Cyrillic", re.compile(r"[Ѐ-ԯ]")), ("Greek", re.compile(r"[Ͱ-Ͽ]")),
    ("Armenian", re.compile(r"[԰-֏]")), ("Latin", re.compile(r"[a-zÀ-ɏ]")),
)


def is_shortener(p: ParsedURL) -> bool:
    s = reference_lists()["shorteners"]
    return p.registered_domain in s or p.host_ascii in s


def analyse_url(p: ParsedURL) -> list[Indicator]:
    out: list[Indicator] = []
    lists = reference_lists()
    established = is_established(p)
    owner = official_brand(p)
    platform = user_content_platform(p)
    shortener = is_shortener(p)
    tail = (p.path + "?" + p.query).lower()

    def add(id_, title, severity, evidence, explanation, group="", weight=None):
        out.append(Indicator(id_, title, severity, HEURISTIC, evidence, explanation, weight, group))

    # ---- reputation context (supporting evidence, not a verdict) ----
    if owner and not platform:
        out.append(Indicator(
            "official_brand_domain", f"Official {display_name(owner)} domain", "positive", REPUTATION,
            f"{p.registered_domain} is on the curated list of domains operated by {display_name(owner)}.",
            "The registered domain belongs to the organisation itself. Phishing pages cannot be hosted on a "
            "brand's own domain unless that site has been compromised or allows user content.",
        ))
    elif established:
        rank = popularity_rank(p.site_domain)
        out.append(Indicator(
            "established_domain", "Long-established, widely visited domain", "positive", REPUTATION,
            f"{p.site_domain} is in the Chrome UX Report top {rank:,} most visited sites.",
            "Phishing domains are usually short-lived and receive little real traffic. A consistently popular "
            "domain is much less likely to be a throw-away phishing site, although legitimate sites can be compromised.",
        ))
    if platform:
        out.append(Indicator(
            "user_content_platform", "Hosted on a platform where anyone can publish", "info", HEURISTIC,
            f"{p.host} is served from {platform}.",
            "Free hosting, site builders, cloud storage and form services are legitimate, but attackers abuse them "
            "because the parent domain looks trustworthy. The reputation of the platform says nothing about this page.",
        ))

    # ---- hard structural tricks ----
    if p.userinfo:
        add("userinfo_in_url", "Deceptive '@' in the address", "high",
            f"The text before '@' ({p.userinfo[:60]}) is ignored by browsers; the real destination is {p.host}.",
            "Attackers put a trusted-looking name before an '@' so the address appears to go somewhere it does not.")
    if p.is_ip:
        try:
            private = not ipaddress.ip_address(p.host).is_global
        except ValueError:
            private = False
        if p.ip_obfuscated:
            add("obfuscated_ip", "Host is a disguised IP address", "high", f"The host decodes to {p.host}.",
                "Encoding an IP address as a hexadecimal, octal or single decimal number has no legitimate everyday "
                "use and is done to hide the destination from people and filters.", group="ip")
        add("ip_host", "Raw IP address instead of a domain name", "medium" if private else "high",
            f"The link goes to {p.host}" + (" (a private or reserved address)." if private else "."),
            "Legitimate public services use domain names. Links straight to an IP address are common in phishing "
            "and malware delivery because they need no domain registration.", group="ip")

    # ---- internationalised names / homographs ----
    if not p.is_ip and any(ord(c) > 127 for c in p.host):
        mixed = []
        for label in p.host.split("."):
            scripts = [name for name, rx in _SCRIPTS if rx.search(label)]
            if len(scripts) > 1:
                mixed.append(f"{label} ({' + '.join(scripts)})")
        if mixed:
            add("mixed_script", "Mixed alphabets inside one domain label", "high",
                "Mixed scripts: " + "; ".join(mixed) + f". Real (punycode) form: {p.host_ascii}",
                "Mixing Latin letters with look-alike Cyrillic or Greek letters is the classic homograph attack: "
                "the address looks identical to a known brand but is a different domain.", group="idn")
        else:
            add("idn_host", "Internationalised (non-ASCII) domain name", "info",
                f"Unicode form: {p.host}; real (punycode) form: {p.host_ascii}",
                "Non-ASCII domains are normal in many languages, but check the punycode form if the name resembles a brand.",
                group="idn")

    # ---- brand impersonation ----
    matches = find_brand_matches(p)
    auth_ctx = has_auth_context(p)
    ambiguous = lists["ambiguous_brand_tokens"]
    for m in matches:
        brand = display_name(m.brand)
        if m.kind == "embedded_domain":
            add("brand_domain_in_subdomain", f"Real {brand} domain used as a decoy sub-domain", "critical",
                f"'{m.matched}' appears on the left, but the registered domain is {p.registered_domain}.",
                "Only the registered domain (just before the first single '/') decides who you are talking to. "
                "Placing a genuine domain in front of it is a deliberate attempt to deceive.", group=f"brand:{brand}")
        elif m.kind == "homoglyph":
            add("brand_homoglyph", f"Look-alike characters imitate {brand}", "critical",
                f"{p.host} renders like '{m.matched}' but is really {p.host_ascii}.",
                "Characters from other alphabets were substituted for Latin letters so the name reads as a known brand.",
                group=f"brand:{brand}")
        elif m.kind == "typo":
            if established:
                continue
            add("brand_typosquat", f"Misspelling of {brand}", "high",
                f"'{m.matched}' in {p.host} closely imitates '{m.brand}', and {p.registered_domain} "
                f"is not an official {brand} domain.",
                "Typosquatted domains swap, drop or replace characters (for example 1 for l, rn for m) so a quick "
                "glance reads as the real brand.", group=f"brand:{brand}")
        elif m.kind in ("token", "substring"):
            if established and not platform:
                continue
            weak = m.matched in ambiguous or len(m.matched) < 5
            if weak and not (auth_ctx or platform):
                continue
            sev = "high" if (not weak or auth_ctx) else "medium"
            where = "sub-domain" if m.where == "subdomain" else "domain name"
            add("brand_in_host", f"{brand} name used on a domain it does not own", sev,
                f"'{m.matched}' appears in the {where} of {p.host}, but the registered domain is {p.registered_domain}"
                + (f" (user-published content on {platform})." if platform else "."),
                "Combining a brand name with other words (or placing it in a sub-domain) makes an unrelated domain "
                "look official. Organisations host sign-in pages on their own registered domains.",
                group=f"brand:{brand}")
        elif m.kind == "other_tld":
            if established:
                continue
            add("brand_other_tld", f"{brand} name under an unrecognised domain ending", "medium",
                f"{p.registered_domain} is not on the list of official {brand} domains.",
                "Brands do own many country domains, so this can be genuine, but exact brand names under unusual "
                "endings are also registered by impersonators.", group=f"brand:{brand}")
        elif m.kind == "path":
            if is_well_known(p) and not platform:
                continue
            # on a listed (but not top-tier) site this may be a hacked site hosting a kit, or just an article
            sev = "low" if (established and not platform) or not auth_ctx else "medium"
            add("brand_in_path", f"{brand} name in the path of an unrelated site", sev,
                f"'{m.matched}' appears in {p.path[:80]} on {p.registered_domain}.",
                "Phishing kits uploaded to hacked or throw-away sites are often stored in folders named after the "
                "brand they imitate.", group=f"brand:{brand}")

    # ---- hosting / destination hiding ----
    if shortener:
        add("url_shortener", "Link shortener hides the real destination", "low",
            f"{p.host} is a URL shortening service.",
            "Shorteners are widely used legitimately, but they prevent you from seeing where a link really goes, "
            "which is why they are popular in phishing messages. The verdict depends on the final destination.")
    host_toks = set(re.split(r"[^a-z]+", p.host_ascii)) - {"www"}
    auth_in_host = sorted(host_toks & AUTH_WORDS)
    if platform:
        path_auth = sorted(set(re.split(r"[^a-z]+", tail)) & AUTH_WORDS)
        if auth_in_host or path_auth:
            add("auth_words_on_free_hosting", "Sign-in / security wording on free hosting", "medium",
                f"Words {', '.join((auth_in_host + path_auth)[:5])} on {platform}.",
                "Banks, mail providers and shops do not host their sign-in pages on free site builders or shared "
                "cloud storage.", group="authwords")
    elif auth_in_host and not established and not owner and not p.is_ip:
        sev = "medium" if len(auth_in_host) >= 2 else "low"
        add("auth_words_in_host", "Security-sounding words in the domain name", sev,
            f"Host contains: {', '.join(auth_in_host[:5])}.",
            "Words such as 'secure', 'verify', 'login' or 'account' in a domain name are chosen to sound official. "
            "Real organisations rarely need them in the registered name.", group="authwords")

    # ---- weaker lexical signals (suppressed for established domains) ----
    if not established and not owner and not p.is_ip:
        tld = p.suffix.split(".")[-1]
        if tld in lists["suspicious_tlds"] and not platform:
            add("abused_tld", f"Domain ending .{tld} is heavily abused", "low",
                f"{p.registered_domain}",
                "Some domain endings are very cheap or free and account for a disproportionate share of phishing. "
                "Many legitimate sites use them too, so this is weak evidence on its own.")
        n_sub = len([s for s in p.subdomain.split(".") if s and s != "www"])
        if n_sub >= 3:
            add("many_subdomains", "Unusually deep sub-domain chain", "low",
                f"{n_sub} sub-domain levels in {p.host}",
                "Long chains of sub-domains push the real registered domain out of view, especially on phones.")
        if (p.domain_label.count("-") >= 3 and "xn--" not in p.domain_label) or len(p.host_ascii) > 60:
            add("long_or_hyphenated_host", "Very long or heavily hyphenated host name", "low",
                p.host_ascii[:100], "Stringing many words together with hyphens is a common way to build "
                "official-sounding throw-away domains.")
    if p.port is not None and not established:
        add("nonstandard_port", "Non-standard network port", "low", f"Port {p.port}",
            "Public websites almost always use the default ports. Unusual ports are typical of temporary servers.")

    # ---- path and query ----
    frag = p.fragment.lower()
    if re.search(r"[\w.+-]+(@|%40)[\w-]+\.[a-z]{2,}", tail + "#" + frag) and not established and not owner:
        add("email_in_url", "E-mail address embedded in the link", "medium",
            "The path, query or fragment contains an e-mail address.",
            "Phishing links are often personalised with the victim's address so the fake page can pre-fill it. "
            "Unsubscribe links from reputable senders also do this, so the surrounding evidence matters.")
    embedded = embedded_destination(p)
    if embedded and embedded.registered_domain != p.registered_domain:
        add("redirect_parameter", "Link carries another site's address", "low",
            f"A parameter points to {embedded.host}.",
            "Open redirects and tracking links can bounce you from a trusted-looking address to a different site. "
            "The real destination is the embedded address.")
    if re.search(r"/wp-(includes|content|admin)/|/\.well-known/", p.path.lower()) and re.search(
        r"\.(php|html?)$|/$", p.path.lower()
    ) and not established and (auth_ctx or matches):
        add("cms_internal_path", "Page hidden inside a site's system folders", "medium",
            p.path[:100], "Sign-in style pages stored under WordPress system folders are a hallmark of phishing "
            "kits uploaded to a hacked website.")
    ext = p.path.rsplit(".", 1)[-1].lower() if "." in p.path.rsplit("/", 1)[-1] else ""
    if ext in _EXEC_EXT and not owner:
        add("executable_download", "Link downloads an executable file", "medium", f".{ext} file",
            "Links that immediately download programs or scripts are a common malware delivery method.")
    if tail.count("%") >= 12 or len(p.url) > 300:
        if not established and not owner:
            add("obfuscated_url", "Very long or heavily encoded address", "low",
                f"{len(p.url)} characters, {tail.count('%')} encoded characters",
                "Excessive encoding or length can be used to hide the meaningful part of an address.")
    if p.scheme == "http" and auth_ctx and not p.is_ip:
        add("http_login", "Sign-in wording on an unencrypted (http) address", "low", p.url[:80],
            "Anything typed into an http page can be read in transit. Note that the reverse is not true: "
            "https only encrypts the connection and says nothing about who operates the site.")
    return out


def embedded_destination(p: ParsedURL) -> ParsedURL | None:
    for _, value in p.params:
        v = unquote(value).strip()
        if re.match(r"(?i)^(https?:)?//[^/\s]+\.[a-z]{2,}", v) or re.match(r"(?i)^www\.", v):
            try:
                return parse_url(v.lstrip("/") if v.startswith("//") else v)
            except URLParseError:
                continue
    m = re.search(r"/(https?:/{1,2}[^\s]+)", p.path)
    if m:
        try:
            return parse_url(re.sub(r"^(https?:)/+", r"\1//", m.group(1)))
        except URLParseError:
            return None
    return None
