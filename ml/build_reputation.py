"""Build the bundled popularity list from the Chrome UX Report (CrUX) top sites.

Source: https://github.com/zakird/crux-top-lists (cached copy of Google's public
CrUX dataset, CC BY-SA 4.0). Run `python -m ml.fetch_data` first.
"""
import csv
import gzip
from pathlib import Path

from phishdetect.urltools import _extract_private

RAW = Path(__file__).parent / "raw" / "crux.csv.gz"
OUT = Path(__file__).parent.parent / "phishdetect" / "data" / "top_domains.txt.gz"
MAX_RANK = 1_000_000


def main() -> None:
    best: dict[str, int] = {}
    with gzip.open(RAW, "rt", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rank = int(row["rank"])
            if rank > MAX_RANK:
                continue
            host = row["origin"].split("://", 1)[-1].split(":")[0].lower()
            ext = _extract_private(host)  # private suffixes: foo.ru.com / foo.github.io stay distinct
            if not ext.domain or not ext.suffix:
                continue
            dom = f"{ext.domain}.{ext.suffix}"
            if rank < best.get(dom, 10**9):
                best[dom] = rank
    with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as fh:
        for dom, rank in sorted(best.items(), key=lambda kv: (kv[1], kv[0])):
            fh.write(f"{dom},{rank}\n")
    print(f"wrote {len(best)} domains to {OUT}")


if __name__ == "__main__":
    main()
