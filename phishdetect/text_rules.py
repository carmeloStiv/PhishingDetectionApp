"""Contextual analysis of e-mails and messages.

The rules look for *combinations* of social-engineering moves (who claims to be
writing, what they ask for, how much pressure they apply, and where the links
really go) rather than counting alarming keywords. A single phrase such as
"verify your account" carries little weight on its own; the same phrase next to
a link to an unrelated, unknown domain carries a lot.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr

from .brands import brand_for_token, display_name, is_official_domain_for, _brand_db
from .indicators import HEURISTIC, Indicator
from .urltools import URLParseError, extract_anchor_pairs, parse_url, reference_lists, _extract_icann

_F = re.I | re.S

PATTERNS: dict[str, list[re.Pattern]] = {
    "urgency": [re.compile(p, _F) for p in (
        r"\bwithin (the next )?\d+ ?(hours?|hrs?|days?|minutes?)\b", r"\b(immediately|urgent(ly)?|asap|right away|act now|without delay)\b",
        r"\bas soon as possible\b", r"\b(final|last|second|third) (notice|warning|reminder|attempt)\b",
        r"\bexpir(es?|ing|ed) (today|soon|in \d+)\b", r"\b(today|tonight) only\b", r"\btime[- ]sensitive\b",
        r"\bbefore (it'?s too late|midnight|the end of (the )?day)\b", r"\bimmediate (action|attention|response)\b",
        r"\b(24|48|72) ?(hours|hrs|h)\b", r"\bdeadline\b.{0,40}\b(today|tomorrow|hours)\b",
    )],
    "threat": [re.compile(p, _F) for p in (
        r"\b(account|access|mailbox|e-?mail|card|profile|service|subscription|membership|id|wallet)\b.{0,50}\b(suspend|lock|clos|disabl|deactivat|restrict|limit|terminat|block|delet|cancel|on hold)",
        r"\b(suspend|lock|clos|disabl|deactivat|restrict|terminat|block|delet)(ed|ing|e|ion)?\b.{0,40}\b(your|the) (account|access|mailbox|card|profile|service)",
        r"\b(unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed|irregular) (activity|sign[- ]?in|log[- ]?in|access|transaction|attempt|charge|device)",
        r"\b(legal action|law ?suit|arrest warrant|prosecut|court|penalt(y|ies)|fine of)\b",
        r"\bfailure to (comply|verify|respond|confirm|update|pay)\b", r"\b(permanent(ly)?|irreversibl[ey]) (lo(ss|se)|delet|clos|suspen|disabl)",
        r"\b(security|policy) (breach|violation|incident)\b", r"\bwe (were unable|could not|couldn'?t) (to )?(process|verify|validate|deliver)",
        r"\byour (password|mailbox|storage|quota).{0,30}(expire|full|exceeded|reached)",
    )],
    "credential_request": [re.compile(p, _F) for p in (
        r"\b(verify|confirm|update|validate|re-?enter|re-?confirm|provide|submit|restore|re-?activate|unlock|secure)\b.{0,25}\b(your |the )?(account|identity|password|log[- ]?in|credentials?|billing|payment (details|information|method)|card|bank(ing)?|personal (details|information)|security (details|information)|wallet|mailbox)\b",
        r"\b(enter|type|send|give|share|reply with)\b.{0,25}\b(your )?(password|passcode|pin\b|otp|one[- ]time (code|password|passcode)|verification code|security code|cvv|card number|ssn|social security|seed phrase|recovery phrase|private key|bank details|account number)",
        r"\b(log|sign) ?in\b.{0,30}\b(to|and) (verify|confirm|restore|secure|update|avoid|keep|continue|review)",
        r"\b(seed|recovery|secret) phrase\b", r"\bkeep (the )?same password\b", r"\bre-?validate\b",
    )],
    "payment_request": [re.compile(p, _F) for p in (
        r"\b(buy|purchase|get|grab|pick up|send|need)\b.{0,50}\bgift ?cards?\b", r"\bgift ?cards?\b.{0,60}\b(codes?|scratch|photos?|pictures?|numbers?)\b",
        r"\b(wire|bank) transfer\b", r"\b(bitcoin|btc|usdt|ethereum|crypto(currency)?)\b.{0,40}\b(send|pay|wallet|address|transfer|deposit)",
        r"\b(send|pay|transfer|deposit)\b.{0,40}\b(bitcoin|btc|usdt|ethereum|crypto(currency)?)\b",
        r"\b(processing|handling|clearance|customs|redelivery|shipping|release|activation) (fee|charge|duty)\b",
        r"\b(outstanding|overdue|unpaid|pending) (invoice|balance|payment|bill|toll)\b",
        r"\b(new|updated?|changed?) (bank|banking|account|payment) (details|information)\b",
        r"\b(bank|banking|account|payment) (details|information)\b.{0,30}\b(have |has |been |were |was )*(changed|updated|new)\b",
        r"\b(direct deposit|payroll)\b.{0,40}\b(change|update|new)\b", r"\bpay(ment)? (now|immediately|today)\b",
        r"\bwestern union|moneygram\b",
    )],
    "reward": [re.compile(p, _F) for p in (
        r"\byou('ve| have)? (been selected|won|are (a|the|our) (lucky )?winner)", r"\b(lottery|sweepstakes|jackpot|raffle)\b",
        r"\b(claim|collect|redeem) (your|the) (prize|reward|gift|refund|funds?|winnings|bonus|compensation|airdrop)",
        r"\b(inheritance|next of kin|beneficiary|unclaimed funds?)\b", r"\bfree (gift|iphone|voucher|reward)\b",
        r"\b(tax|payment) refund\b.{0,40}\b(pending|claim|eligible|owed|receive)", r"\b\d[\d,.]* ?(million|m) (usd|dollars|euros|pounds|gbp)\b",
        r"\beligible (for|to receive) (a|your) (refund|rebate|payment|reward)",
    )],
    "generic_greeting": [re.compile(p, _F) for p in (
        r"^\W*(dear|hello|hi|attention|greetings),? (valued |esteemed )?(customer|user|client|member|account ?holder|sir|madam|sir/madam|friend|beneficiary|subscriber|e-?mail user|winner|employee|colleague)s?\b",
        r"\bdear [\w.+-]+@[\w.-]+", r"^\W*dear (valued|esteemed)\b",
    )],
    "secrecy": [re.compile(p, _F) for p in (
        r"\bkeep (this|it) (confidential|private|between us|quiet|discreet)", r"\b(do not|don'?t) (tell|mention|share|discuss|call)\b",
        r"\bare you (available|at your desk|in the office|free)\b", r"\bi('m| am) (in|going into) a (meeting|conference)",
        r"\b(can'?t|cannot|unable to) (talk|take calls|call)\b", r"\bneed (you to do me )?a (quick |small |discreet )?(favou?r|task)\b",
        r"\bstrictly confidential\b", r"\bsend me your (cell|mobile|whatsapp|phone) number\b",
    )],
    "call_to_action": [re.compile(p, _F) for p in (
        r"\b(click|tap|press)\b.{0,20}\b(here|below|link|button)\b", r"\b(follow|use|visit|open) (the|this) (link|button|url|attachment|attached)",
        r"\b(log|sign) ?in (here|below|now)\b", r"\bsee (the )?attach(ed|ment)\b", r"\bscan (the|this) qr\b",
        r"\bcall (us )?(now|immediately)?.{0,20}\+?\d[\d\s().-]{7,}",
    )],
    "mailbox_lure": [re.compile(p, _F) for p in (
        r"\b(mail ?box|e-?mail account|web ?mail|mail quota|(your|mail) storage|your quota)\b.{0,60}\b(full|exceed|limit|suspen|shut ?down|deactivat|upgrad|re-?verif|re-?validat|expir|blocked|clos)",
        r"\b(pending|undelivered|held|quarantined|failed|blocked) (messages?|e-?mails?|mails?|deliveries)\b",
        r"\b(\(?\d+\)?|several|some|new) (messages?|e-?mails?) (are |were |have been )?(pending|held|quarantined|undelivered|blocked|not delivered)",
        r"\bpassword\b.{0,40}\b(expir|will expire|is due)", r"\bkeep (my |your |the )?(same |current )?password\b",
    )],
    "unexpected_charge": [re.compile(p, _F) for p in (
        r"\b(charged|debited|billed|deducted|auto[- ]?renew(ed|al)?|renewed)\b.{0,80}[$£€]\s?\d", r"[$£€]\s?\d[\d,.]*.{0,80}\b(charged|debited|billed|deducted|auto[- ]?renew(ed|al)?)\b",
        r"\b(will be|has been|was|were) (charged|debited|billed)\b",
    )],
    "delivery_lure": [re.compile(p, _F) for p in (
        r"\b(package|parcel|shipment|delivery|item)\b.{0,60}\b(could not|couldn'?t|unable|failed|fail|on hold|held|pending|undeliver|missed|reschedul|incomplete address|awaiting)",
    )],
}

LEAD_CHARS = 3000
_RISKY_ATTACH = re.compile(r"\b[\w .()-]{1,60}\.(html?|shtml|zip|rar|7z|exe|scr|iso|img|docm|xlsm|pptm|js|vbs|lnk|hta|bat|cmd|jar|ace|svg)\b", re.I)
_HEADER_RE = re.compile(r"(?im)^(from|reply-to|subject|to|return-path|date)\s*:")


@dataclass
class LinkFacts:
    """What the URL pipeline concluded about one link in the message."""
    host: str
    registered_domain: str
    official_brand: str | None
    trusted: bool        # official or established, and no risk findings
    risk_score: int


@dataclass
class ParsedMessage:
    body: str
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    has_headers: bool = False
    matches: dict[str, list[str]] = field(default_factory=dict)


def parse_message(text: str) -> ParsedMessage:
    head = text.lstrip()[:2000]
    if len(_HEADER_RE.findall(head.split("\n\n", 1)[0])) >= 2 or re.match(r"(?i)^(from|subject)\s*:", head):
        try:
            msg = message_from_string(text.lstrip())
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
            else:
                payload = msg.get_payload(decode=True)
                body_parts.append(payload.decode(msg.get_content_charset() or "utf-8", "replace") if payload else str(msg.get_payload()))
            def hdr(name: str) -> str:
                try:
                    return str(make_header(decode_header(msg.get(name, ""))))
                except Exception:  # noqa: BLE001 - malformed encoded-words
                    return str(msg.get(name, ""))

            name, addr = parseaddr(hdr("From"))
            reply = getaddresses([msg.get("Reply-To", "")])
            return ParsedMessage(
                body="\n".join(body_parts), subject=hdr("Subject"), from_name=name,
                from_addr=addr.lower(), reply_to=(reply[0][1].lower() if reply and reply[0][1] else ""), has_headers=True,
            )
        except Exception:  # noqa: BLE001 - fall back to treating everything as body
            pass
    return ParsedMessage(body=text)


def _plain(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"[ \t\r\f\v]+", " ", text)


def _email_domain(addr: str) -> str:
    dom = addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""
    ext = _extract_icann(dom)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else dom


def _brands_mentioned(text: str) -> list[str]:
    token_to_brand, _, _, strong, ambiguous = _brand_db()
    low = text.lower()
    found = []
    for tok in set(re.findall(r"[a-z][a-z0-9]{2,}", low)):
        b = token_to_brand.get(tok)
        if b and tok not in ambiguous and len(tok) >= 5 and b not in found:
            found.append(b)
    # multi-word brand names
    for phrase, brand in (("bank of america", "bankofamerica"), ("wells fargo", "wellsfargo"), ("american express", "americanexpress"),
                          ("royal mail", "royalmail"), ("capital one", "capitalone"), ("apple id", "apple"), ("office 365", "microsoft"),
                          ("microsoft 365", "microsoft"), ("western union", "westernunion"), ("geek squad", "geeksquad"),
                          ("canada post", "canadapost"), ("australia post", "auspost"), ("la poste", "laposte"), ("icloud", "apple")):
        if phrase in low and brand not in found:
            found.append(brand)
    return found


def analyse_message(msg: ParsedMessage, raw_text: str, links: list[LinkFacts]) -> list[Indicator]:
    out: list[Indicator] = []
    full_text = _plain((msg.subject + "\n" if msg.subject else "") + msg.body)
    # Lures are stated up front. Restricting the wording rules to the opening of the message
    # stops long newsletters and mail threads from tripping a rule somewhere on page three.
    text = full_text[:LEAD_CHARS]
    hits: dict[str, list[str]] = {}
    pos: dict[str, list[int]] = {}
    for name, patterns in PATTERNS.items():
        for rx in patterns:
            m = rx.search(text)
            if m:
                hits.setdefault(name, []).append(re.sub(r"\s+", " ", m.group(0))[:90])
                pos.setdefault(name, []).append(m.start())
    msg.matches = hits
    lists = reference_lists()

    def near(a: str, b: str, distance: int = 500) -> bool:
        return any(abs(x - y) <= distance for x in pos.get(a, []) for y in pos.get(b, []))

    def quote(name: str) -> str:
        return "; ".join(f'"{h}"' for h in hits.get(name, [])[:3])

    def add(id_, title, severity, evidence, explanation, group="", weight=None):
        out.append(Indicator(id_, title, severity, HEURISTIC, evidence, explanation, weight, group))

    unverified = [l for l in links if not l.trusted]
    all_links_trusted = bool(links) and not unverified
    lure = any(k in hits for k in ("credential_request", "threat", "payment_request", "delivery_lure", "mailbox_lure", "unexpected_charge"))
    # A lure needs a way to act on it: a link we cannot vouch for, an attachment, or a request to reply / call.
    vector = bool(unverified) or any(k in hits for k in ("call_to_action", "credential_request", "payment_request")) \
        or bool(_RISKY_ATTACH.search(text))
    pressure = vector and (near("urgency", "threat") or near("urgency", "delivery_lure") or near("urgency", "mailbox_lure"))

    # ---- who is writing ----
    from_dom = _email_domain(msg.from_addr)
    if from_dom:
        free = from_dom in lists["freemail"]
        claimed = _identity_brands(msg.from_name)
        sender_brand = next((b for b in claimed if not is_official_domain_for(b, from_dom)), None)
        shown_addr = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", msg.from_name)
        shown_dom = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", msg.from_name.lower())
        if sender_brand:
            add("sender_brand_mismatch", f"Sender name claims {display_name(sender_brand)}, address does not", "high",
                f'Display name "{msg.from_name[:60]}" but the address is @{from_dom}' + (" (a free mailbox provider)." if free else "."),
                "The display name is free text chosen by the sender. Organisations write from their own domains, "
                "never from free mailboxes or unrelated domains.", group="sender")
        elif shown_addr and _email_domain(shown_addr.group(0)) != from_dom and " via " not in msg.from_name.lower():
            add("sender_address_spoof", "Display name shows a different e-mail address", "high",
                f'Shown as "{msg.from_name[:60]}" but really sent from @{from_dom}.',
                "Putting a trusted address in the display name hides the real sender in most mail apps.", group="sender")
        elif shown_dom and _extract_icann(shown_dom.group(1)).suffix and _email_domain("x@" + shown_dom.group(1)) != from_dom \
                and ("mailbox_lure" in hits or "credential_request" in hits) and " via " not in msg.from_name.lower():
            add("sender_domain_claim", "Display name poses as another domain", "medium",
                f'Shown as "{msg.from_name[:60]}" but sent from @{from_dom}.',
                "Mail that pretends to come from your own mail system or another organisation's domain, while being "
                "sent from somewhere else, is a common mailbox-phishing trick.", group="sender")
        elif free and lure and re.search(r"(?i)\b(team|support|service|admin|administrator|help ?desk|security|billing|department|notification|customer|account)\b", msg.from_name):
            add("official_name_free_mailbox", "Official-sounding sender using a free mailbox", "medium",
                f'"{msg.from_name[:60]}" writes from @{from_dom}.',
                "Service desks and security teams do not write from personal webmail accounts.", group="sender")
        reply_dom = _email_domain(msg.reply_to)
        if reply_dom and reply_dom != from_dom:
            add("reply_to_mismatch", "Replies go to a different domain than the sender", "medium",
                f"From @{from_dom}, Reply-To @{reply_dom}.",
                "A different Reply-To lets an attacker spoof a trusted sender while still receiving the answers.")

    # ---- links that lie about their destination ----
    for href, visible in extract_anchor_pairs(raw_text):
        m = re.search(r"(?i)\b((?:https?://|www\.)[^\s]+|[a-z0-9-]+(?:\.[a-z0-9-]+)+)", visible)
        if not m:
            continue
        try:
            shown, real = parse_url(m.group(1)), parse_url(href)
        except URLParseError:
            continue
        if shown.registered_domain != real.registered_domain:
            add("link_text_mismatch", "Link text shows one site, link goes to another", "high",
                f"Displayed: {shown.host} / actual destination: {real.host}",
                "Showing a trusted address as the clickable text while pointing somewhere else is deliberate deception.",
                group="linkmismatch")
            break

    # ---- what is being asked, under what pressure, and where it leads ----
    if "credential_request" in hits:
        if all_links_trusted:
            add("credential_request", "Asks you to sign in or confirm account details", "info",
                quote("credential_request") + " - every link points to an established or official domain.",
                "Genuine services do send such notices. The links in this message go to well-established domains, "
                "which makes an impersonation unlikely. Navigating to the site yourself is still the safest habit.")
        elif unverified:
            backed = pressure or any(k in hits for k in ("threat", "urgency", "generic_greeting", "mailbox_lure"))
            add("credential_request_unverified_link", "Asks for account details and links to an unverified site",
                "medium" if backed else "low",
                quote("credential_request") + f" - links to {unverified[0].host}.",
                "The message wants you to sign in or confirm sensitive details through a link whose domain has no "
                "established reputation and is not an official domain of any known organisation.", group="credreq")
        else:
            add("credential_request", "Asks for passwords, codes or account details", "medium",
                quote("credential_request"),
                "Legitimate organisations do not ask you to send passwords, one-time codes, card numbers or recovery "
                "phrases by reply.", group="credreq")
    if pressure and not all_links_trusted:
        add("pressure_tactics", "Combines a threat with a deadline", "medium",
            quote("threat") or quote("delivery_lure") + " + " + quote("urgency"),
            "Threatening a loss (account closure, missed parcel, legal trouble) while imposing a short deadline is "
            "designed to make you act before you think. It is the most common phishing pattern.", group="pressure")
    elif ("threat" in hits or "urgency" in hits) and not all_links_trusted and "mailbox_lure" not in hits:
        which = "threat" if "threat" in hits else "urgency"
        add("pressure_language", "Uses alarming or urgent language", "low", quote(which),
            "Alarm or urgency on its own is common in ordinary mail too, so this is weak evidence unless combined "
            "with other findings.", group="pressure")
    if "payment_request" in hits:
        untraceable = any(re.search(r"gift ?card|bitcoin|btc|crypto|usdt|western union|moneygram", h, re.I) for h in hits["payment_request"])
        bank_change = any(re.search(r"payroll|direct deposit", h, re.I) or (re.search(r"bank|account|payment (details|information)", h, re.I) and re.search(r"new|updat|chang", h, re.I)) for h in hits["payment_request"])
        if "secrecy" in hits or (untraceable and ("urgency" in hits or "reward" in hits)):
            add("payment_fraud_pattern", "Payment request with secrecy or untraceable payment method",
                "critical" if ("secrecy" in hits and untraceable) else "high",
                quote("payment_request") + (" + " + quote("secrecy") if "secrecy" in hits else ""),
                "Requests for gift cards, cryptocurrency or quiet bank transfers, especially 'while I am in a meeting', "
                "are the signature of business e-mail compromise and advance-fee fraud.", group="payment")
        elif not all_links_trusted:
            add("payment_request", "Asks for a payment or a change of bank details", "medium" if (untraceable or bank_change) else "low",
                quote("payment_request"),
                "Unexpected fees, overdue invoices and changed bank details are common pretexts. Verify through a "
                "contact you already know, not through details in the message.", group="payment")
    elif "secrecy" in hits and ("urgency" in hits or "call_to_action" in hits) and not links:
        add("pretext_contact", "Vague, secretive request to respond quickly", "low", quote("secrecy"),
            "Short messages that test whether you are available and ask for discretion often open a gift-card or "
            "payment fraud conversation.")
    if "unexpected_charge" in hits and not all_links_trusted:
        phone = re.search(r"\+?\d[\d\s().-]{8,}\d", text)
        wants_call = phone and re.search(r"(?i)\b(call|contact|dial|phone)\b", text) and re.search(r"(?i)\b(cancel|refund|dispute|did not|didn'?t|unauthori[sz]ed|stop)\b", text)
        if wants_call:
            add("callback_scam", "Unexpected charge with a phone number to call", "high",
                quote("unexpected_charge") + f" / call {phone.group(0).strip()[:24]}",
                "Fake renewal and invoice notices that tell you to phone a number to cancel are 'callback phishing': "
                "the operator talks you into granting remote access or paying. Check the charge in your real account instead.",
                group="charge")
        else:
            add("unexpected_charge", "Claims you were (or will be) charged", "medium" if (_RISKY_ATTACH.search(text) or unverified) else "low",
                quote("unexpected_charge"),
                "A surprise charge creates the urge to react. Verify it in your bank or the merchant's real site, not via "
                "the message.", group="charge")
    if "mailbox_lure" in hits and not all_links_trusted and vector:
        add("mailbox_lure", "Claims a mailbox, quota or password problem", "medium", quote("mailbox_lure"),
            "'Mailbox full', 'messages pending' and 'password expires today' notices are the standard pretext for "
            "stealing e-mail passwords. Real mail systems do not ask you to re-validate through a link.", group="mailbox")
    if "reward" in hits and not all_links_trusted:
        wants_details = "credential_request" in hits or "payment_request" in hits or "generic_greeting" in hits or \
            bool(re.search(r"(?i)\breply (with|to)\b|\b(full name|bank details|phone number|copy of your id)\b", text))
        add("reward_lure", "Promises a prize, refund or windfall", "medium" if wants_details else "low", quote("reward"),
            "Unexpected winnings, refunds and inheritances are bait: the next step is a fee or a request for your details.")
    if "delivery_lure" in hits and unverified:
        add("delivery_lure", "Missed-delivery story with a link to an unverified site", "medium", quote("delivery_lure"),
            "Fake parcel notices are among the most common SMS and e-mail scams; couriers link to their own domains.",
            group="pressure2")
    if "generic_greeting" in hits and (unverified or "credential_request" in hits or "payment_request" in hits):
        add("generic_greeting", "Impersonal greeting", "low", quote("generic_greeting"),
            "Organisations you have an account with normally address you by name. Mass phishing cannot.")
    for m in _RISKY_ATTACH.finditer(text):
        window = text[max(m.start() - 90, 0): m.end() + 90]
        if not re.search(r"(?i)\battach|\benclosed\b|\bopen (the|this)\b|\bsee (the|this)\b", window):
            continue
        ext = m.group(1).lower()
        strong_ext = ext in ("html", "htm", "shtml", "svg", "iso", "img", "lnk", "hta", "vbs", "scr", "exe")
        add("risky_attachment", f"Refers to a .{ext} attachment", "medium" if (strong_ext or lure) else "low",
            m.group(0).strip()[:80],
            "HTML, archive, disk-image and script attachments are used to deliver fake sign-in pages and malware "
            "past link scanners.")
        break

    # ---- who the message claims to be vs. where its links go ----
    claimed = _identity_brands(msg.from_name + " " + msg.subject) + [
        b for b in _brands_mentioned(text[:400]) if b not in _identity_brands(msg.from_name + " " + msg.subject)]
    if claimed and unverified and lure:
        for b in claimed:
            if any(l.official_brand == b for l in links):
                continue
            bn = display_name(b)
            add("brand_context_mismatch", f"Speaks as {bn} but links elsewhere", "high",
                f"The message presents itself as {bn}; the link goes to {unverified[0].host}, which is not an official {bn} domain.",
                "When a message speaks in the name of an organisation, its links should lead to that organisation's "
                "own domain.", group="brandctx")
            break
    return out


def _identity_brands(text: str) -> list[str]:
    """Brands named in a sender name / subject line, where even short names are an identity claim."""
    found = _brands_mentioned(text)
    for word in re.findall(r"\b[A-Z][A-Za-z0-9]{2,}\b", text):
        b = brand_for_token(word.lower())
        if b and b not in found and word.lower() not in ("line", "three", "target", "discover", "regions", "citizens", "orange", "wise", "meta", "booking", "notion"):
            found.append(b)
    return found
