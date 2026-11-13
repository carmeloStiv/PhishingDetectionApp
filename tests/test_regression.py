"""Detection-quality floor on the hand-built hard cases (ml/challenge). Offline engine."""
import csv
import json
from pathlib import Path

CH = Path(__file__).parent.parent / "ml" / "challenge"
FLAGGED = {"suspicious", "likely_phishing"}


def test_url_challenge_floor(offline_engine):
    rows = [r for r in csv.DictReader(open(CH / "urls.csv", encoding="utf-8")) if r["label"] != "ambiguous"]
    res = [(r, offline_engine.analyse(r["url"], mode="url")["classification"]) for r in rows]
    phish = [c for r, c in res if r["label"] == "phish"]
    legit = [c for r, c in res if r["label"] == "legit"]
    assert sum(c in FLAGGED for c in phish) / len(phish) >= 0.90
    assert sum(c in FLAGGED for c in legit) / len(legit) <= 0.05
    assert sum(c == "likely_phishing" for c in legit) == 0
    assert sum(c == "likely_safe" for c in phish) == 0


def test_message_challenge_floor(offline_engine):
    rows = [m for m in json.loads((CH / "messages.json").read_text(encoding="utf-8")) if m["label"] != "ambiguous"]
    res = [(m["label"], offline_engine.analyse(m["text"], mode="message")["classification"]) for m in rows]
    phish = [c for l, c in res if l == "phish"]
    legit = [c for l, c in res if l == "legit"]
    assert sum(c in FLAGGED for c in phish) / len(phish) >= 0.90
    assert sum(c in FLAGGED for c in legit) == 0
