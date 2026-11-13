"""Download the public datasets used for training and evaluation into ml/raw/.

Sources (all fetched from raw.githubusercontent.com):
  * Phishing.Database active links  - MIT licence, aggregated live phishing URLs
  * OpenPhish community feed        - free for non-commercial use, used as an external test set
  * ebubekirbbr/pdd                 - phishing + legitimate URLs (Sahingoz et al., 2019)
  * zakird/crux-top-lists           - Chrome UX Report popular origins (CC BY-SA 4.0)
  * rokibulroni/Phishing-Email-Dataset - Nazario phishing corpus, SpamAssassin, Enron, CEAS-08

Raw files are not committed. Phishing feeds change daily, so a re-download
produces a different snapshot; `ml/splits/` records the exact URLs used.
"""
import urllib.request
from pathlib import Path

RAW = Path(__file__).parent / "raw"
GH = "https://raw.githubusercontent.com/"
FILES = {
    "phishdb_active.txt": GH + "Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "openphish_feed.txt": GH + "openphish/public_feed/refs/heads/main/feed.txt",
    "pdd_legit.json": GH + "ebubekirbbr/pdd/master/input/data_legitimate_36400.json",
    "pdd_phish.json": GH + "ebubekirbbr/pdd/master/input/data_phishing_37175.json",
    "crux.csv.gz": GH + "zakird/crux-top-lists/main/data/global/current.csv.gz",
    "Nazario.csv": GH + "rokibulroni/Phishing-Email-Dataset/main/Nazario.csv",
    "SpamAssasin.csv": GH + "rokibulroni/Phishing-Email-Dataset/main/SpamAssasin.csv",
    "Enron.csv": GH + "rokibulroni/Phishing-Email-Dataset/main/Enron.csv",
    "CEAS_08.csv": GH + "rokibulroni/Phishing-Email-Dataset/main/CEAS_08.csv",
}


def main() -> None:
    RAW.mkdir(exist_ok=True)
    for name, url in FILES.items():
        dest = RAW / name
        if dest.exists():
            print(f"have  {name}")
            continue
        print(f"fetch {name}")
        urllib.request.urlretrieve(url, dest)  # noqa: S310 - fixed https URLs


if __name__ == "__main__":
    main()
