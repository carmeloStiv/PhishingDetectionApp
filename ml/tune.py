"""Choose ML score bands and classification thresholds on the VALIDATION split.

Prints, for a grid of settings, how the offline engine (rules + ML + bundled
reputation, no network) classifies validation URLs. The chosen values live in
phishdetect/scoring.py. The test split is never read here.
"""
import itertools
import pickle
import sys
from pathlib import Path

from ml.common import load_split
from phishdetect import scoring
from phishdetect.config import Settings
from phishdetect.engine import Engine
from phishdetect.indicators import ML
from phishdetect.reputation import is_established, is_well_known
from phishdetect.urltools import parse_url

CACHE = Path(__file__).parent / "raw" / "tune_cache.pkl"


def collect(limit: int):
    if CACHE.exists():
        return pickle.loads(CACHE.read_bytes())
    engine = Engine(Settings.offline())
    rows = load_split("url_val")[:limit]
    out = []
    for r in rows:
        p = parse_url(r["url"])
        a = engine.assess_url(p, deep=False)
        out.append({
            "label": int(r["label"]), "source": r["source"], "ml": a.ml_score,
            "inds": [i for i in a.indicators if i.source != ML], "trusted": a.trusted,
            "listed": is_established(p), "well_known": is_well_known(p), "blocked": a.blocked_reason,
        })
    CACHE.write_bytes(pickle.dumps(out))
    return out


def main() -> None:
    data = collect(int(sys.argv[1]) if len(sys.argv) > 1 else 100000)
    legit = [d for d in data if not d["label"]]
    phish = [d for d in data if d["label"]]
    print(f"validation: {len(phish)} phishing, {len(legit)} legitimate "
          f"({sum(not d['listed'] for d in legit)} legitimate not in the popularity list)")
    print("bands(high,med,low)  susp  phish | legit: LP%  Susp%  | phishing: LP%  Susp%  Safe%  Unable%")
    for bands, susp, lp in itertools.product(
        [(0.97, 0.90, 0.75), (0.95, 0.85, 0.70), (0.97, 0.85, 0.70), (0.98, 0.93, 0.80)], [30, 35], [65, 70]
    ):
        res = {0: {}, 1: {}}
        for d in data:
            inds = list(d["inds"])
            sev = None
            if d["ml"] is not None:
                scoring.ML_BANDS = tuple(zip(bands, ("high", "medium", "low")))
                top = d["trusted"] and (d["well_known"] or any(i.id == "official_brand_domain" for i in inds))
                sev = scoring.ml_severity(d["ml"], listed=d["trusted"], well_known=top)
            if sev:
                from phishdetect.indicators import Indicator
                inds.append(Indicator("ml_url_model", "", sev, ML, group="ml"))
            sc = scoring.compute_score(inds)
            if sc.value >= lp:
                c = "LP"
            elif sc.value >= susp:
                c = "S"
            elif d["blocked"] or not d["trusted"]:
                c = "U"
            else:
                c = "Safe"
            res[d["label"]][c] = res[d["label"]].get(c, 0) + 1
        g = lambda lab, c: 100 * res[lab].get(c, 0) / max(sum(res[lab].values()), 1)  # noqa: E731
        print(f"{bands}  {susp}  {lp}   |  {g(0,'LP'):5.2f} {g(0,'S'):5.2f}  |  {g(1,'LP'):5.1f} {g(1,'S'):5.1f} {g(1,'Safe'):5.1f} {g(1,'U'):5.1f}")


if __name__ == "__main__":
    main()
