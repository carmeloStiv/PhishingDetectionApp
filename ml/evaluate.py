"""Measure the original implementation and the new engine on the same data.

    python -m ml.evaluate            # everything, writes ml/results/evaluation.json
    python -m ml.evaluate --quick    # 2,000-URL sample of the test split
    python -m ml.evaluate --errors   # also print misclassified examples

The new engine runs OFFLINE (rules + ML + bundled reputation; no threat feeds,
no page retrieval, no domain-age lookups), so results are a lower bound that
anyone can reproduce without API keys.

Binary mapping used for precision / recall:
    original app : "Phishing" or "Suspicious"            -> flagged
    new engine   : "Likely Phishing" or "Suspicious"     -> flagged
                   "Likely Safe" / "Unable to Determine" -> not flagged
"Unable to Determine" is additionally reported on its own, because abstaining
is different from calling something safe.
"""
import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

from legacy.baseline import Baseline
from ml.common import binary_metrics, load_split
from phishdetect.config import Settings
from phishdetect.engine import Engine
from phishdetect.reputation import is_established
from phishdetect.urltools import parse_url

HERE = Path(__file__).parent
RAW = HERE / "raw"
FLAGGED_NEW = {"Likely Phishing", "Suspicious"}
FLAGGED_OLD = {"Phishing", "Suspicious"}


def _run(items, engine, baseline, mode):
    """items: list of (text, is_phish, group). Returns metrics for both systems."""
    y, new_pred, old_pred = [], [], []
    dist = {0: Counter(), 1: Counter()}
    old_dist = {0: Counter(), 1: Counter()}
    errors = defaultdict(list)
    for text, label, _group in items:
        res = engine.analyse(text, mode=mode)
        old = baseline.classify(text)
        y.append(label)
        new_pred.append(res["label"] in FLAGGED_NEW)
        old_pred.append(old in FLAGGED_OLD)
        dist[label][res["label"]] += 1
        old_dist[label][old] += 1
        if (res["label"] in FLAGGED_NEW) != bool(label):
            errors[(label, res["label"])].append((text[:160].replace("\n", " "), res["risk_score"],
                                                  [i["id"] for i in res["indicators"] if i["weight"] > 0]))
    out = {"original": binary_metrics(y, old_pred), "new": binary_metrics(y, new_pred)}
    n_ph, n_le = max(sum(dist[1].values()), 1), max(sum(dist[0].values()), 1)
    out["new"]["class_distribution"] = {"phishing": dict(dist[1]), "legitimate": dict(dist[0])}
    out["new"]["phishing_called_likely_safe_rate"] = round(dist[1]["Likely Safe"] / n_ph, 4)
    out["new"]["phishing_called_likely_phishing_rate"] = round(dist[1]["Likely Phishing"] / n_ph, 4)
    out["new"]["legit_called_likely_phishing_rate"] = round(dist[0]["Likely Phishing"] / n_le, 4)
    out["new"]["abstention_rate"] = round((dist[0]["Unable to Determine"] + dist[1]["Unable to Determine"]) / (n_ph + n_le), 4)
    out["original"]["class_distribution"] = {"phishing": dict(old_dist[1]), "legitimate": dict(old_dist[0])}
    return out, errors


def url_items(split, limit=None, seed=7):
    rows = load_split(split)
    if limit:
        random.Random(seed).shuffle(rows)
        rows = rows[:limit]
    return [(r["url"], int(r["label"]), r["source"]) for r in rows]


def challenge_urls():
    with open(HERE / "challenge" / "urls.csv", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def challenge_messages():
    return json.loads((HERE / "challenge" / "messages.json").read_text(encoding="utf-8"))


def email_corpus(part: str, n_phish=700, n_ham_each=350):
    """Nazario phishing vs ham from three corpora. `part` is 'dev' or 'test' (disjoint by content hash)."""
    csv.field_size_limit(10**9)

    def rows(name, want_label):
        out = []
        with open(RAW / f"{name}.csv", newline="", encoding="utf-8", errors="replace") as fh:
            for r in csv.DictReader(fh):
                if r.get("label") != want_label:
                    continue
                body = (r.get("body") or "").strip()
                if len(body) < 40 or "FOLDER INTERNAL DATA" in (r.get("subject") or ""):
                    continue
                head = ""
                if r.get("sender"):
                    head += f"From: {r['sender']}\n"
                head += f"Subject: {r.get('subject') or ''}\n\n"
                text = (head + body)[:20000]
                h = int(hashlib.sha256(body[:2000].encode("utf-8", "replace")).hexdigest(), 16)
                if (h % 2 == 0) == (part == "dev"):
                    out.append((h, text))
        out = sorted(set(out))
        random.Random(11).shuffle(out)
        return [t for _, t in out]

    items = [(t, 1, "nazario_phishing") for t in rows("Nazario", "1")[:n_phish]]
    for name in ("SpamAssasin", "Enron", "CEAS_08"):
        items += [(t, 0, f"{name}_ham") for t in rows(name, "0")[:n_ham_each]]
    return items


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--errors", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--email-part", default="test")
    args = ap.parse_args()
    engine, baseline = Engine(Settings.offline()), Baseline()
    results = {}

    def show(name, out, errors):
        results[name] = out
        o, n = out["original"], out["new"]
        print(f"\n== {name}  (n={n['n']})")
        for k in ("accuracy", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate"):
            print(f"   {k:22s} original {o[k]!s:>7}   new {n[k]!s:>7}")
        print("   new classes :", n["class_distribution"])
        print("   original    :", o["class_distribution"])
        if args.errors:
            for key, ex in errors.items():
                print(f"   -- truth={'phish' if key[0] else 'legit'} predicted={key[1]} ({len(ex)})")
                for e in random.Random(3).sample(ex, min(12, len(ex))):
                    print("      ", e)

    want = lambda n: not args.only or args.only in n  # noqa: E731
    if want("url_test"):
        items = url_items("url_test", 2000 if args.quick else None)
        show("url_test", *_run(items, engine, baseline, "url"))
        listed = [i for i in items if is_established(parse_url(i[0]))]
        unlisted = [i for i in items if not is_established(parse_url(i[0]))]
        show("url_test / domain NOT in popularity list", *_run(unlisted, engine, baseline, "url"))
        show("url_test / domain in popularity list", *_run(listed, engine, baseline, "url"))
    if want("openphish"):
        show("external OpenPhish feed (phishing only)", *_run(url_items("url_external_openphish"), engine, baseline, "url"))
    if want("challenge_urls"):
        ch = challenge_urls()
        items = [(r["url"], int(r["label"] == "phish"), r["category"]) for r in ch if r["label"] != "ambiguous"]
        show("challenge_urls (hand-built hard cases)", *_run(items, engine, baseline, "url"))
        amb = [(r["url"], engine.analyse(r["url"], mode="url")["label"], baseline.classify(r["url"])) for r in ch if r["label"] == "ambiguous"]
        results["challenge_urls_ambiguous"] = amb
        print("   ambiguous:", Counter(a[1] for a in amb))
    if want("challenge_messages"):
        ch = challenge_messages()
        items = [(m["text"], int(m["label"] == "phish"), m["category"]) for m in ch if m["label"] != "ambiguous"]
        show("challenge_messages (hand-built)", *_run(items, engine, baseline, "message"))
        amb = [(m["text"][:60], engine.analyse(m["text"])["label"], baseline.classify(m["text"])) for m in ch if m["label"] == "ambiguous"]
        results["challenge_messages_ambiguous"] = amb
        print("   ambiguous:", amb)
    if want("email") and (RAW / "Nazario.csv").exists():
        items = email_corpus(args.email_part)
        show(f"email_corpus_{args.email_part}", *_run(items, engine, baseline, "message"))
        for src in sorted({i[2] for i in items}):
            sub = [i for i in items if i[2] == src]
            out, _ = _run(sub, engine, baseline, "message")
            key = "recall" if sub[0][1] else "false_positive_rate"
            print(f"   {src:20s} {key}: original {out['original'][key]}  new {out['new'][key]}")
            results[f"email_corpus_{args.email_part}/{src}"] = out
    if not args.only and not args.quick:
        (HERE / "results").mkdir(exist_ok=True)
        (HERE / "results" / "evaluation.json").write_text(json.dumps(results, indent=1))
        print("\nwrote ml/results/evaluation.json")


if __name__ == "__main__":
    sys.exit(main())
