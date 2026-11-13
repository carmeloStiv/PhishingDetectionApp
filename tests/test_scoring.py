from phishdetect.indicators import HEURISTIC, ML, THREAT_INTEL, Indicator
from phishdetect.scoring import (LIKELY_PHISHING, LIKELY_SAFE, SUSPICIOUS, UNDETERMINED, classify, compute_score,
                                 confidence, ml_severity)


def ind(sev, source=HEURISTIC, id_="x", group=""):
    return Indicator(id_, "t", sev, source, group=group)


def test_noisy_or_combination():
    assert compute_score([]).value == 0
    assert compute_score([ind("low")]).value == 12
    assert compute_score([ind("high", id_="a"), ind("high", id_="b")]).value == 80   # 1 - 0.45^2
    assert compute_score([ind("medium", id_="a"), ind("low", id_="b")]).value == 38


def test_same_group_counts_once():
    s = compute_score([ind("high", id_="a", group="g"), ind("medium", id_="b", group="g")])
    assert s.value == 55 and len(s.contributions) == 1


def test_confirmed_intel_sets_floor_and_class():
    s = compute_score([ind("critical", THREAT_INTEL)])
    assert s.confirmed and s.value >= 97
    assert classify(s, safe_evidence=True) == LIKELY_PHISHING


def test_no_findings_is_not_automatically_safe():
    s = compute_score([])
    assert classify(s, safe_evidence=False) == UNDETERMINED
    assert classify(s, safe_evidence=True) == LIKELY_SAFE
    assert classify(s, safe_evidence=True, blocked_reason="unresolved shortener") == UNDETERMINED


def test_thresholds():
    assert classify(compute_score([ind("medium")]), safe_evidence=True) == SUSPICIOUS
    assert classify(compute_score([ind("high")]), safe_evidence=True) == SUSPICIOUS
    assert classify(compute_score([ind("high", id_="a"), ind("medium", id_="b")]), safe_evidence=True) == LIKELY_PHISHING


def test_ml_alone_can_never_reach_likely_phishing():
    assert ml_severity(1.0) == "high"
    s = compute_score([ind(ml_severity(1.0), ML)])
    assert classify(s, safe_evidence=False) == SUSPICIOUS
    assert confidence(SUSPICIOUS, s, [], coverage=1.0)["level"] != "high"


def test_ml_is_discounted_by_reputation():
    assert ml_severity(0.99, listed=True) == "medium"
    assert ml_severity(0.99, listed=True, well_known=True) is None
    assert ml_severity(0.5) is None


def test_undetermined_is_always_low_confidence():
    assert confidence(UNDETERMINED, compute_score([]), [], coverage=1.0)["level"] == "low"
