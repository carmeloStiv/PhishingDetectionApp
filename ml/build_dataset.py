"""Build leakage-controlled train / validation / test splits for the URL model.

* exact duplicate URLs are removed; URLs that appear with both labels are dropped
* at most MAX_PER_SITE URLs per site, so one phishing kit cannot dominate
* the split is by *registered domain* (by site on shared hosting platforms, where each
  sub-domain has a different owner): every URL of a site lands in exactly one split, so
  the model is always tested on sites it has never seen
* the OpenPhish feed is held out completely as an external test set
"""
import csv
import gzip
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from phishdetect.reputation import user_content_platform
from phishdetect.urltools import URLParseError, parse_url

RAW = Path(__file__).parent / "raw"
OUT = Path(__file__).parent / "splits"
SEED = 20261113
MAX_PER_SITE = 2
MAX_PER_REGISTERED = 150
N_PHISHDB = 60000
N_CRUX = 25000
N_CRUX_PLATFORM = 8000


def _split_of(registered: str) -> str:
    h = int(hashlib.sha256(("split:" + registered).encode()).hexdigest(), 16) % 100
    return "train" if h < 70 else "val" if h < 85 else "test"


def _load(lines, label, source, rows, cap_site=MAX_PER_SITE, cap_reg=MAX_PER_REGISTERED):
    per_site, per_reg = Counter(), Counter()
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("ftp"):
            continue
        try:
            p = parse_url(raw)
        except URLParseError:
            continue
        if per_site[p.site_domain] >= cap_site or per_reg[p.registered_domain] >= cap_reg:
            continue
        per_site[p.site_domain] += 1
        per_reg[p.registered_domain] += 1
        # Split key: the registered domain, except on user-content platforms where every
        # site (sub-domain) has a different owner and is its own unit.
        group = p.site_domain if user_content_platform(p) and p.site_domain != p.registered_domain else p.registered_domain
        rows.append((p.url, label, source, group, p.site_domain))


def main() -> None:
    rnd = random.Random(SEED)
    OUT.mkdir(exist_ok=True)

    external = []
    _load(open(RAW / "openphish_feed.txt", encoding="utf-8", errors="replace"), 1, "openphish", external, cap_site=1)
    external_sites = {r[4] for r in external}

    rows = []
    phishdb = [l for l in open(RAW / "phishdb_active.txt", encoding="utf-8", errors="replace")]
    rnd.shuffle(phishdb)
    tmp = []
    _load(phishdb, 1, "phishing_database", tmp)
    rows += tmp[:N_PHISHDB]
    pdd_p = json.load(open(RAW / "pdd_phish.json"))
    rnd.shuffle(pdd_p)
    tmp = []
    _load(pdd_p, 1, "pdd_phish_2017", tmp)
    rows += tmp[:20000]
    pdd_l = json.load(open(RAW / "pdd_legit.json"))
    rnd.shuffle(pdd_l)
    _load(pdd_l, 0, "pdd_legit", rows, cap_site=4)
    # Legitimate homepages from the Chrome UX Report. Popular sites hosted on free platforms
    # (github.io, blogspot, web.app ...) are sampled separately and generously: without them the
    # model simply learns "free hosting = phishing".
    crux, crux_platform = [], []
    with gzip.open(RAW / "crux.csv.gz", "rt") as fh:
        for row in csv.DictReader(fh):
            try:
                cp = parse_url(row["origin"])
            except URLParseError:
                continue
            if user_content_platform(cp):
                crux_platform.append(row["origin"])
            elif int(row["rank"]) <= 500000:
                crux.append(row["origin"])
    rnd.shuffle(crux)
    rnd.shuffle(crux_platform)
    tmp = []
    _load(crux, 0, "crux_homepage", tmp, cap_site=1)
    rows += tmp[:N_CRUX]
    tmp = []
    _load(crux_platform, 0, "crux_platform_site", tmp, cap_site=1, cap_reg=1500)
    rows += tmp[:N_CRUX_PLATFORM]

    by_url = defaultdict(set)
    for r in rows:
        by_url[r[0]].add(r[1])
    seen, clean = set(), []
    for r in rows:
        if len(by_url[r[0]]) > 1 or r[0] in seen or r[4] in external_sites:
            continue
        seen.add(r[0])
        clean.append(r)

    # A site that appears as phishing (e.g. a compromised site) must not also supply
    # "legitimate" homepage samples.
    phish_sites = {r[4] for r in clean if r[1] == 1}
    clean = [r for r in clean if not (r[2].startswith("crux_") and r[4] in phish_sites)]

    splits = defaultdict(list)
    for r in clean:
        splits[_split_of(r[3])].append(r)
    for name, items in splits.items():
        rnd.shuffle(items)
        with gzip.open(OUT / f"url_{name}.csv.gz", "wt", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["url", "label", "source"])
            w.writerows([r[:3] for r in items])
        print(name, len(items), Counter((r[2], r[1]) for r in items))
    with gzip.open(OUT / "url_external_openphish.csv.gz", "wt", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "source"])
        w.writerows([r[:3] for r in external])
    print("external", len(external))
    # leakage check
    regs = {n: {r[3] for r in items} for n, items in splits.items()}
    assert not (regs["train"] & regs["val"]) and not (regs["train"] & regs["test"]) and not (regs["val"] & regs["test"])
    print("no site is shared between splits")


if __name__ == "__main__":
    main()
