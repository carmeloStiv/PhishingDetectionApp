"""Orchestrates rules, ML, reputation, threat intelligence and page analysis
into a single explainable assessment."""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .brands import official_brand
from .config import Settings
from .fetcher import safe_fetch
from .indicators import HEURISTIC, ML, PAGE, REPUTATION, THREAT_INTEL, UNAVAILABLE, Indicator
from .intel import DomainAge, Provider, build_providers
from .ml import url_model_score
from .page_rules import analyse_page
from .reputation import is_established, is_well_known, user_content_platform
from .scoring import (LABELS, LIKELY_PHISHING, LIKELY_SAFE, SUSPICIOUS, SUSPICIOUS_THRESHOLD, UNDETERMINED, Score, classify,
                      compute_score, confidence, ml_severity)
from .text_rules import LinkFacts, analyse_message, parse_message
from .url_rules import analyse_url, embedded_destination, is_shortener
from .urltools import ParsedURL, URLParseError, defang, extract_urls, looks_like_single_url, parse_url

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "positive": 5}


class InputError(ValueError):
    """The submission cannot be analysed at all (shown to the user as a validation error)."""


@dataclass
class URLAssessment:
    parsed: ParsedURL
    indicators: list[Indicator] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    ml_score: float | None = None
    trusted: bool = False
    official: bool = False
    intel_ok: int = 0
    age_days: int | None = None
    page_ok: bool = False
    blocked_reason: str | None = None
    final: ParsedURL | None = None

    @property
    def safe_evidence(self) -> bool:
        if self.trusted:
            return True
        aged = self.age_days is not None and self.age_days >= 180
        return self.intel_ok >= 1 and (aged or self.page_ok)

    @property
    def coverage(self) -> float:
        bonus = 1.5 if self.official else 1.0 if self.trusted else 0.0
        return min((min(self.intel_ok, 1) + (self.age_days is not None) + self.page_ok + bonus) / 3, 1.0)


def _check(name: str, status: str, detail: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail}


class Engine:
    def __init__(self, settings: Settings | None = None, providers: list[Provider] | None = None,
                 age_provider: DomainAge | None = None, fetch=safe_fetch) -> None:
        self.settings = settings or Settings()
        if providers is None or age_provider is None:
            built, age = build_providers(self.settings)
            providers = built if providers is None else providers
            age_provider = age if age_provider is None else age_provider
        self.providers, self.age_provider, self.fetch = providers, age_provider, fetch
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="intel")

    # ------------------------------------------------------------------ public
    def analyse(self, text: str, mode: str = "auto") -> dict:
        text = (text or "").strip()
        if not text:
            raise InputError("Enter a URL or paste a message to analyse.")
        if len(text) > self.settings.max_text_chars:
            raise InputError(f"Submission is too long (limit {self.settings.max_text_chars:,} characters).")
        if mode == "url" or (mode == "auto" and looks_like_single_url(text)):
            try:
                parsed = parse_url(text)
            except URLParseError as exc:
                raise InputError(f"That does not look like a web address: {exc}.") from exc
            return self._url_report(parsed)
        if mode not in ("auto", "message"):
            raise InputError("Unknown analysis mode.")
        return self._message_report(text)

    # --------------------------------------------------------------- URL stage
    def _lexical(self, p: ParsedURL, a: URLAssessment, prefix: str = "") -> None:
        inds = analyse_url(p)
        trusted = (is_established(p) or official_brand(p) is not None) and not user_content_platform(p)
        score = None if is_shortener(p) else url_model_score(p)
        if score is not None:
            top_tier = trusted and (is_well_known(p) or official_brand(p) is not None)
            sev = ml_severity(score, listed=trusted, well_known=top_tier)
            platform = user_content_platform(p)
            if sev and platform:
                # On shared hosting the model saw legitimate *home pages* only. It is allowed to warn
                # (medium at most) about a site root, and counts as weak evidence for deeper links,
                # where it has no legitimate examples to compare against.
                is_root = p.path in ("", "/") and not p.query
                sev = ("medium" if sev == "high" else sev) if is_root else "low"
            if sev is None and ml_severity(score) and trusted:
                inds.append(Indicator(
                    "ml_discounted", "Statistical model score not applied", "info", ML,
                    f"Model score {score:.2f}. Not counted because the domain is long-established or official.",
                    "The model only sees the text of the address. Long sign-in and tracking links on major sites "
                    "resemble phishing links lexically, so the score is not informative for well-known domains."))
            elif sev:
                inds.append(Indicator(
                    "ml_url_model", "Address resembles known phishing links", sev, ML,
                    f"Model score {score:.2f} on a 0-1 scale (bands: 0.75 low, 0.90 medium, 0.97 high"
                    + ("; reduced one band because the domain is in the popularity list)." if trusted else
                       "; limited on shared hosting platforms, where the model is less reliable)." if platform else ")."),
                    "A machine-learning model trained on tens of thousands of phishing and legitimate addresses finds "
                    "this one structurally similar to phishing. This is a statistical resemblance, not proof, and the "
                    "score is not a probability that the site is malicious.", group="ml"))
        if prefix:
            for i in inds:
                i.evidence = prefix + i.evidence
                i.id = "final_" + i.id if i.source != REPUTATION else i.id
        a.indicators.extend(i for i in inds if not (prefix and i.source == REPUTATION))
        if not prefix:
            a.ml_score, a.trusted, a.official = score, trusted, official_brand(p) is not None and trusted

    def _intel(self, p: ParsedURL, a: URLAssessment, label_suffix: str = "") -> None:
        futures = [(prov, self._pool.submit(prov.lookup, p)) for prov in self.providers]
        age_future = self._pool.submit(self.age_provider.lookup, p) if not label_suffix else None
        for prov, fut in futures:
            try:
                res = fut.result(timeout=self.settings.intel_timeout * 3)
            except Exception as exc:  # noqa: BLE001 - a provider must never break the analysis
                a.checks.append(_check(prov.label + label_suffix, "error", f"Lookup failed ({type(exc).__name__})."))
                continue
            a.checks.append(_check(res.provider + label_suffix, res.status, res.detail))
            a.indicators.extend(res.indicators)
            if res.status in ("clean", "match") and not label_suffix:
                a.intel_ok += 1
        if age_future is not None:
            try:
                res = age_future.result(timeout=self.settings.intel_timeout * 3)
                a.checks.append(_check(res.provider, "ok" if res.status == "clean" else res.status, res.detail))
                a.indicators.extend(res.indicators)
                a.age_days = getattr(res, "age_days", None)
            except Exception as exc:  # noqa: BLE001
                a.checks.append(_check(self.age_provider.label, "error", f"Lookup failed ({type(exc).__name__})."))

    def _page(self, p: ParsedURL, a: URLAssessment) -> None:
        name = "Page retrieval and content analysis"
        if not self.settings.enable_live_fetch:
            a.checks.append(_check(name, "not_configured", "Live page retrieval is disabled by the operator."))
            return
        s = self.settings
        fr = self.fetch(p.url, timeout=s.fetch_timeout, max_bytes=s.fetch_max_bytes, max_redirects=s.fetch_max_redirects)
        try:
            final = parse_url(fr.final_url) if fr.final_url else p
        except URLParseError:
            final = p
        if fr.error == "tls_invalid_certificate":
            a.indicators.append(Indicator(
                "invalid_certificate", "Invalid TLS certificate", "medium", PAGE, fr.tls_error[:120],
                "The site's certificate is expired, self-signed or issued for another name, so its identity cannot "
                "be verified at all."))
        if not fr.ok:
            a.checks.append(_check(name, "error", f"Could not retrieve the page: {fr.detail or fr.error}."))
            if fr.error == "dns_failure" and not a.trusted:
                a.blocked_reason = "The host name does not currently resolve, so the site could not be examined."
            return
        if final.registered_domain != p.registered_domain:
            a.final = final
            self._lexical(final, a, prefix=f"Final destination {defang(final.host)}: ")
            if self._network_enabled():
                self._intel(final, a, label_suffix=" (final destination)")
            if is_shortener(p):
                for i in a.indicators:
                    if i.id == "url_shortener":
                        i.severity, i.weight = "info", 0.0
                        i.evidence += f" It was followed safely to {defang(final.host)}."
                final_trusted = (is_established(final) or official_brand(final) is not None) and not user_content_platform(final)
                a.trusted, a.official = final_trusted, official_brand(final) is not None and final_trusted
        if fr.status >= 400:
            a.checks.append(_check(name, "error", f"The server answered HTTP {fr.status}; there was no page content to inspect "
                                                  "(phishing pages are often taken down, or hide from scanners)."))
        else:
            a.indicators.extend(analyse_page(p, final, fr))
            a.page_ok = True
            hops = len(fr.chain) - 1
            a.checks.append(_check(name, "ok", f"Retrieved {defang(final.host)} (HTTP {fr.status}"
                                               + (f", {hops} redirect{'s' if hops != 1 else ''}" if hops else "")
                                               + "). Scripts are never executed, so content generated in the browser is not seen."))

    def _network_enabled(self) -> bool:
        return any(p.configured() for p in self.providers) or self.age_provider.configured()

    def assess_url(self, p: ParsedURL, *, deep: bool) -> URLAssessment:
        a = URLAssessment(parsed=p)
        self._lexical(p, a)
        embedded = embedded_destination(p)
        if embedded is not None and embedded.registered_domain != p.registered_domain:
            # e.g. an open redirect: judge the address the link really leads to as well
            self._lexical(embedded, a, prefix=f"Embedded destination {defang(embedded.host)}: ")
        a.checks.append(_check("URL structure and impersonation rules", "ok", "Always available (no network needed)."))
        a.checks.append(_check("URL machine-learning model", "ok" if a.ml_score is not None else "skipped",
                               f"Model score {a.ml_score:.2f}." if a.ml_score is not None else
                               ("Not applied to link shorteners." if is_shortener(p) else "Model unavailable.")))
        listed = is_established(p)
        a.checks.append(_check("Popularity list (Chrome UX Report)", "ok",
                               "Registered domain is in the top-sites list." if listed else
                               "Not in the top-sites list (true of most small legitimate sites as well)."))
        self._intel(p, a)
        if deep:
            self._page(p, a)
        else:
            a.checks.append(_check("Page retrieval and content analysis", "skipped", "Links inside messages are not fetched."))
        if is_shortener(p) and a.final is None:
            a.blocked_reason = "The link shortener hides the destination, and the destination could not be resolved."
        return a

    # ------------------------------------------------------------------ reports
    def _url_report(self, p: ParsedURL) -> dict:
        a = self.assess_url(p, deep=True)
        score = compute_score(a.indicators)
        cls = classify(score, safe_evidence=a.safe_evidence, blocked_reason=a.blocked_reason)
        conf = confidence(cls, score, a.indicators, a.coverage)
        return self._report("url", p.display, cls, score, conf, a.indicators, a.checks, a.blocked_reason,
                            extra={"final_destination": a.final.display if a.final else None})

    def _message_report(self, text: str) -> dict:
        msg = parse_message(text)
        urls = extract_urls(text if not msg.has_headers else msg.body + "\n" + text)
        assessments: list[URLAssessment] = []
        for raw in urls[: self.settings.max_links_per_message]:
            try:
                assessments.append(self.assess_url(parse_url(raw), deep=False))
            except URLParseError:
                continue
        link_scores = [compute_score(a.indicators) for a in assessments]
        facts = [
            LinkFacts(a.parsed.host, a.parsed.registered_domain, official_brand(a.parsed) if a.trusted else None,
                      a.trusted and s.value < SUSPICIOUS_THRESHOLD, s.value)
            for a, s in zip(assessments, link_scores)
        ]
        indicators = analyse_message(msg, text, facts)
        checks = [_check("Message wording and context rules", "ok",
                         "Sender headers were found and compared." if msg.has_headers else
                         "No e-mail headers were included, so the sender could not be checked.")]
        blocked = None
        links_out = []
        worst = None
        for a, s in zip(assessments, link_scores):
            cls = classify(s, safe_evidence=a.safe_evidence, blocked_reason=a.blocked_reason)
            links_out.append({"url": a.parsed.display, "classification": cls, "label": LABELS[cls], "risk_score": s.value})
            if worst is None or s.value > worst[1].value:
                worst = (a, s)
        if worst is not None:
            a, _ = worst
            host = defang(a.parsed.host)
            text_evidence = any(i.weight > 0 for i in indicators)
            for i in a.indicators:
                if i.source == REPUTATION and len(assessments) > 1:
                    continue
                if i.id == "ml_url_model" and not text_evidence and i.severity in ("high", "medium"):
                    # a statistical resemblance of one link, in a message whose wording is unremarkable
                    i.severity, i.weight = "low", 0.12
                    i.evidence += " Reduced to weak evidence because nothing in the message wording supports it."
                i.evidence = f"Link {host}: {i.evidence}"
                indicators.append(i)
            checks.extend(a.checks)
            blocked = a.blocked_reason
        words = len(re.findall(r"\w+", msg.body))
        if not assessments and words < 5:
            blocked = "The text is too short to assess and contains no links."
        if len(urls) > len(assessments):
            checks.append(_check("Additional links", "skipped", f"{len(urls) - len(assessments)} more link(s) were not analysed."))
        score = compute_score(indicators)
        safe = all(a.safe_evidence for a in assessments)
        unverified = [a for a in assessments if not a.safe_evidence]
        if not blocked and unverified and score.value < SUSPICIOUS_THRESHOLD:
            blocked = (f"The wording shows no phishing traits, but the message links to {defang(unverified[0].parsed.host)}, "
                       "which could not be verified.")
        cls = classify(score, safe_evidence=safe, blocked_reason=blocked)
        coverage = (sum(a.coverage for a in assessments) / len(assessments)) if assessments else 0.3
        conf = confidence(cls, score, indicators, min(coverage + (0.1 if msg.has_headers else 0), 1.0))
        subject = (msg.subject or re.sub(r"\s+", " ", msg.body).strip())[:80]
        return self._report("message", subject, cls, score, conf, indicators, checks, blocked, extra={"links": links_out})

    def _report(self, kind: str, subject: str, cls: str, score: Score, conf: dict, indicators: list[Indicator],
                checks: list[dict], blocked: str | None, extra: dict) -> dict:
        indicators = sorted(indicators, key=lambda i: (_SEV_ORDER[i.severity], -i.weight))
        counted = {c["id"] for c in score.contributions}
        ind_out = []
        for i in indicators:
            d = i.to_dict()
            d["counted"] = i.id in counted
            d.pop("group", None)
            ind_out.append(d)
        missing = [c for c in checks if c["status"] in ("error", "not_configured", "skipped")]
        return {
            "id": uuid.uuid4().hex,
            "engine_version": __version__,
            "analysed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "input_type": kind,
            "subject": subject,
            "classification": cls,
            "label": LABELS[cls],
            "risk_score": score.value,
            "confidence": conf,
            "summary": _summary(kind, cls, score, indicators, blocked),
            "indicators": ind_out,
            "score_breakdown": score.contributions,
            "checks": checks,
            "missing_information": [f"{c['name']}: {c['detail']}" for c in missing],
            "recommendations": _recommendations(kind, cls),
            **extra,
        }


def _summary(kind: str, cls: str, score: Score, indicators: list[Indicator], blocked: str | None) -> str:
    thing = "address" if kind == "url" else "message"
    risk = [i for i in indicators if i.weight > 0]
    top = "; ".join(i.title for i in risk[:3])
    if cls == LIKELY_PHISHING:
        if score.confirmed:
            return f"This {thing} matches a confirmed threat-intelligence listing. Treat it as malicious."
        return f"Several significant indicators point to phishing: {top}."
    if cls == SUSPICIOUS:
        return f"There are warning signs, but not enough evidence for a firm conclusion: {top}."
    if cls == UNDETERMINED:
        base = blocked or ("No phishing indicators were found, but there is no positive evidence that this "
                           f"{thing} is trustworthy either.")
        return base + " Absence of findings is not the same as safe."
    positives = [i for i in indicators if i.severity == "positive"]
    note = f" Supporting evidence: {positives[0].title.lower()}." if positives else ""
    minor = f" Minor observations were noted ({top}) but they are weak on their own." if risk else ""
    return f"No significant phishing indicators were identified.{note}{minor}"


def _recommendations(kind: str, cls: str) -> list[str]:
    if cls == LIKELY_PHISHING:
        rec = ["Do not open the link or enter any information.",
               "If you already entered a password, change it now on the real site and anywhere else you use it, and turn on two-step verification.",
               "If you entered card or bank details, contact your bank immediately.",
               "Report it: use your mail provider's 'Report phishing' button, or forward the message to the impersonated organisation."]
        return rec + (["Delete the message."] if kind == "message" else [])
    if cls == SUSPICIOUS:
        return ["Do not follow the link from the message. Go to the organisation's website by typing its address or using a bookmark.",
                "Do not enter passwords, codes or payment details until you have verified the request through a contact you already trust.",
                "Check each indicator below; if any of it matches a request you did not expect, treat it as phishing."]
    if cls == UNDETERMINED:
        return ["Treat this as unverified: do not enter credentials or payment details.",
                "Confirm the sender or site through an independent channel (official app, known phone number, typed address).",
                "See 'Checks performed' for what could not be examined."]
    return ["No action needed. As always, confirm the address in the browser bar before entering a password.",
            "A legitimate site can still be compromised later; this result describes what could be observed now."]
