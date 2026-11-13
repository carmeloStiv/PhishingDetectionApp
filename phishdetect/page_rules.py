"""Static analysis of retrieved page HTML. Nothing is rendered or executed."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from .brands import _brand_db, display_name, is_official_domain_for, official_brand
from .fetcher import FetchResult
from .indicators import PAGE, Indicator
from .reputation import is_established, user_content_platform
from .urltools import ParsedURL, URLParseError, parse_url

_EXFIL = re.compile(r"api\.telegram\.org/bot|discord(app)?\.com/api/webhooks|formspree\.io|formsubmit\.co|submit-form\.com|getform\.io|script\.google\.com/macros", re.I)
_SENSITIVE_FIELD = re.compile(r"(card.?num|cc.?num|cvv|cvc|ssn|social.?sec|seed|mnemonic|recovery.?phrase|private.?key|routing|iban|\bpin\b|otp|passcode|mother)", re.I)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self._in_script = False
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.links: list[str] = []
        self.resources: list[str] = []
        self.meta_refresh = ""
        self.scripts: list[str] = []
        self.text: list[str] = []
        self.iframes: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower()})
        elif tag == "input":
            self.inputs.append({"type": a.get("type", "text").lower(), "name": a.get("name", "") + " " + a.get("id", "") + " " + a.get("placeholder", "")})
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("img", "script", "link") and (a.get("src") or a.get("href")):
            self.resources.append(a.get("src") or a.get("href"))
            if tag == "script":
                self._in_script = True
        elif tag == "script":
            self._in_script = True
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script:
            if len(self.scripts) < 60:
                self.scripts.append(data[:20000])
        elif data.strip() and len(self.text) < 400:
            self.text.append(data.strip()[:300])


def _reg(base: str, ref: str) -> str | None:
    try:
        return parse_url(urljoin(base, ref)).registered_domain
    except (URLParseError, ValueError):
        return None


def analyse_page(submitted: ParsedURL, final: ParsedURL, fetch: FetchResult) -> list[Indicator]:
    out: list[Indicator] = []

    def add(id_, title, severity, evidence, explanation, group=""):
        out.append(Indicator(id_, title, severity, PAGE, evidence, explanation, None, group))

    trusted = (is_established(final) or official_brand(final) is not None) and not user_content_platform(final)

    hops = [parse_url(u) for u, _ in fetch.chain]
    domains = []
    for h in hops:
        if not domains or domains[-1] != h.registered_domain:
            domains.append(h.registered_domain)
    if len(domains) > 1:
        add("redirect_chain", "Redirects to a different site", "low" if len(domains) > 2 else "info",
            " -> ".join(domains[:6]),
            "The address you were given is not where you end up. Redirect chains are used legitimately for "
            "tracking, and maliciously to hide the final page from scanners.")
    if fetch.cert and fetch.cert.get("age_days") is not None and fetch.cert["age_days"] <= 7 and not trusted:
        add("fresh_certificate", "TLS certificate issued in the last week", "low",
            f"Issued {fetch.cert['age_days']} day(s) ago by {fetch.cert.get('issuer', 'unknown')}.",
            "A brand-new certificate on an unknown domain suggests the site was set up very recently. A valid "
            "certificate only proves the connection is encrypted - phishing sites have them too.")

    if not fetch.body:
        return out
    parser = _Parser()
    try:
        parser.feed(fetch.body[:750_000])
    except Exception:  # noqa: BLE001 - malformed HTML
        pass
    base = fetch.final_url or final.url
    has_password = any(i["type"] == "password" for i in parser.inputs)
    sensitive = sorted({m.group(1).lower() for i in parser.inputs for m in [_SENSITIVE_FIELD.search(i["name"])] if m})
    visible = " ".join(parser.text)[:20000]
    title = re.sub(r"\s+", " ", parser.title).strip()[:120]

    # where does submitted data go?
    for form in parser.forms:
        action = form["action"]
        if _EXFIL.search(action):
            add("form_exfiltration", "Form sends data to a messaging / form-relay service", "high",
                f"Form action: {action[:100]}",
                "Phishing kits forward stolen details to Telegram bots, Discord webhooks or free form relays "
                "because they need no server of their own.", group="form")
        elif action.lower().startswith("http") and has_password:
            dest = _reg(base, action)
            if dest and dest != final.registered_domain and not (official_brand(final) and dest and is_official_domain_for(official_brand(final), dest)):
                add("form_cross_domain", "Password form submits to a different domain", "high",
                    f"Page on {final.registered_domain}, form posts to {dest}.",
                    "A sign-in form normally submits to the site that shows it. Sending credentials elsewhere is a "
                    "strong sign of credential harvesting.", group="form")
    script_blob = "\n".join(parser.scripts)
    if _EXFIL.search(script_blob) and (has_password or sensitive):
        add("script_exfiltration", "Script forwards form data to a messaging / relay service", "high",
            _EXFIL.search(script_blob).group(0), "Collected details are sent to a third-party bot or webhook.", group="form")

    # brand impersonation in content
    token_to_brand, _, _, strong, ambiguous = _brand_db()
    title_brands = []
    for tok in set(re.findall(r"[a-z][a-z0-9]{2,}", (title + " " + visible[:600]).lower())):
        b = token_to_brand.get(tok)
        if b and tok not in ambiguous and len(tok) >= 5 and b not in title_brands:
            title_brands.append(b)
    owner = official_brand(final)
    foreign = [b for b in title_brands if b != owner and not is_official_domain_for(b, final.registered_domain)]
    collects = has_password or bool(sensitive)
    if foreign and collects and not trusted:
        add("page_brand_impersonation", f"Sign-in page presents itself as {display_name(foreign[0])}", "high",
            f'Page title "{title}" on {final.registered_domain}, which is not an official {display_name(foreign[0])} domain, '
            f"and the page asks for {'a password' if has_password else ', '.join(sensitive[:3])}.",
            "The page uses a brand's name while collecting credentials on a domain the brand does not own. This is "
            "the defining characteristic of a phishing page.", group="pagebrand")
    elif collects and not trusted:
        add("login_form_unverified", "Collects a password or sensitive data on an unverified domain", "medium" if sensitive else "low",
            ("Password field present. " if has_password else "") + (f"Sensitive fields: {', '.join(sensitive[:4])}." if sensitive else ""),
            "Many genuine small sites have sign-in forms, so this alone is weak evidence. Be sure you recognise the "
            "domain before typing anything.", group="pagebrand")
    if any(k in s for s in sensitive for k in ("seed", "mnemonic", "recovery", "private")):
        add("wallet_phrase_request", "Asks for a wallet recovery phrase or private key", "high",
            f"Fields: {', '.join(sensitive[:4])}", "No legitimate website ever needs your wallet recovery phrase.", group="wallet")

    # cloned page: most assets come from a brand's real site
    res_domains = [d for d in (_reg(base, r) for r in parser.resources[:150]) if d]
    if len(res_domains) >= 6 and not trusted:
        from collections import Counter
        top, n = Counter(res_domains).most_common(1)[0]
        _, _, all_domains, _, _ = _brand_db()
        if top != final.registered_domain and top in all_domains and n / len(res_domains) >= 0.5 and collects:
            add("cloned_assets", f"Page loads most of its images/scripts from {top}", "medium",
                f"{n} of {len(res_domains)} resources come from {top}.",
                "Copying a real site's HTML leaves its images and styles pointing at the original. A page that looks "
                "like a brand, lives elsewhere and asks for credentials is a clone.")

    # redirects and obfuscation in content
    m = re.search(r"url\s*=\s*['\"]?([^'\";>\s]+)", parser.meta_refresh, re.I)
    if m:
        dest = _reg(base, m.group(1))
        if dest and dest != final.registered_domain:
            add("meta_refresh", "Page immediately forwards to another site", "low", f"Meta refresh to {dest}",
                "Instant client-side redirects are used to bounce visitors through disposable pages.")
    if not trusted and (re.search(r"(document\.write|eval)\s*\(\s*(unescape|atob|decodeURIComponent)\s*\(", script_blob)
                        or re.search(r"atob\(\s*['\"][A-Za-z0-9+/=]{400,}", script_blob)):
        add("obfuscated_script", "Page content is assembled by obfuscated script", "medium" if collects else "low",
            "Script decodes and writes hidden content at load time.",
            "Legitimate sites minify code but rarely hide the page's own HTML inside encoded strings; phishing kits "
            "do it to evade scanners.")
    if not parser.text and not parser.forms and len(fetch.body) > 200 and not trusted:
        add("script_only_page", "Page has no readable content without running scripts", "info",
            "The HTML contains no visible text or forms.",
            "This analyser never executes scripts, so content that is built in the browser could not be inspected.")
    return out
