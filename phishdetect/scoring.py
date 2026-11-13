"""Transparent risk scoring and classification.

Risk score
    Every risk indicator carries a fixed weight in (0, 1) determined by its
    severity. Indicators that describe the same underlying fact share a group
    and only the strongest in a group counts. The weights are combined as

        score = 100 * (1 - PRODUCT(1 - weight_i))

    so independent pieces of evidence reinforce each other, no single weak
    signal can produce a high score, and the score never exceeds 100.

The score is an *evidence score*, not a probability that the item is malicious.
"""
from __future__ import annotations

from dataclasses import dataclass

from .indicators import ML, THREAT_INTEL, Indicator

LIKELY_PHISHING = "likely_phishing"
SUSPICIOUS = "suspicious"
LIKELY_SAFE = "likely_safe"
UNDETERMINED = "unable_to_determine"

LABELS = {
    LIKELY_PHISHING: "Likely Phishing",
    SUSPICIOUS: "Suspicious",
    LIKELY_SAFE: "Likely Safe",
    UNDETERMINED: "Unable to Determine",
}

PHISHING_THRESHOLD = 65
SUSPICIOUS_THRESHOLD = 30
CONFIRMED_FLOOR = 97

# Model score -> severity band. Chosen on the validation split (docs/EVALUATION.md):
# a statistical resemblance alone can make a URL "Suspicious" but never "Likely Phishing".
ML_BANDS = ((0.97, "high"), (0.90, "medium"), (0.75, "low"))


_DEMOTE = {"high": "medium", "medium": "low", "low": None}


def ml_severity(score: float, *, listed: bool = False, well_known: bool = False) -> str | None:
    """Severity of the model score given the domain's reputation tier.

    well_known (top 100k or an official brand domain): the lexical model is not
    informative, the score is ignored.  listed (top 1M): demoted by one band,
    because such sites are rarely malicious themselves but do get compromised.
    """
    if well_known:
        return None
    for threshold, severity in ML_BANDS:
        if score >= threshold:
            return _DEMOTE[severity] if listed else severity
    return None


@dataclass
class Score:
    value: int
    contributions: list[dict]
    confirmed: bool


def compute_score(indicators: list[Indicator]) -> Score:
    best: dict[str, Indicator] = {}
    for ind in indicators:
        if ind.weight <= 0:
            continue
        key = ind.group or ind.id
        if key not in best or ind.weight > best[key].weight:
            best[key] = ind
    remaining = 1.0
    for ind in best.values():
        remaining *= 1.0 - min(ind.weight, 0.99)
    value = round(100 * (1 - remaining))
    confirmed = any(i.source == THREAT_INTEL and i.severity == "critical" for i in indicators)
    if confirmed:
        value = max(value, CONFIRMED_FLOOR)
    contributions = [
        {"id": i.id, "title": i.title, "source": i.source, "severity": i.severity, "weight": round(i.weight, 2)}
        for i in sorted(best.values(), key=lambda x: -x.weight)
    ]
    return Score(value, contributions, confirmed)


def classify(score: Score, *, safe_evidence: bool, blocked_reason: str | None = None) -> str:
    """Map a score to one of the four classes.

    `safe_evidence`   positive evidence exists (not merely the absence of findings)
    `blocked_reason`  something prevented a meaningful assessment (e.g. an unresolved shortener)
    """
    if score.confirmed or score.value >= PHISHING_THRESHOLD:
        return LIKELY_PHISHING
    if score.value >= SUSPICIOUS_THRESHOLD:
        return SUSPICIOUS
    if blocked_reason or not safe_evidence:
        return UNDETERMINED
    return LIKELY_SAFE


def confidence(classification: str, score: Score, indicators: list[Indicator], coverage: float) -> dict:
    """How much the verdict should be relied on: evidence coverage and margin, not maliciousness.

    coverage: share (0..1) of the independent evidence sources that produced data.
    """
    reasons: list[str] = []
    if classification == UNDETERMINED:
        return {"level": "low", "reasons": ["There is not enough evidence to support any verdict."]}
    if score.confirmed:
        return {"level": "high", "reasons": ["Confirmed by an external threat-intelligence source."]}
    nearest = min(abs(score.value - PHISHING_THRESHOLD), abs(score.value - SUSPICIOUS_THRESHOLD))
    margin = min(nearest / 20, 1.0)
    only_ml = all(c["source"] == ML for c in score.contributions) and bool(score.contributions)
    value = 0.5 * margin + 0.5 * coverage
    if only_ml:
        value = min(value, 0.45)
        reasons.append("The only risk evidence is a statistical model score, with no corroborating rule or intelligence match.")
    if margin < 0.4:
        reasons.append("The score is close to a classification boundary.")
    if coverage < 0.5:
        reasons.append("Several independent checks (threat feeds, domain age, page content) were unavailable.")
    elif coverage >= 0.75:
        reasons.append("Most independent evidence sources were available.")
    strong = [c for c in score.contributions if c["severity"] in ("critical", "high") and c["source"] != ML]
    if classification == LIKELY_PHISHING and len(strong) >= 2:
        value = max(value, 0.7)
        reasons.append("Multiple strong, independent indicators agree.")
    level = "high" if value >= 0.67 else "medium" if value >= 0.4 else "low"
    return {"level": level, "reasons": reasons}
