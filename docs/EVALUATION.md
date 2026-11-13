# Evaluation: original vs rebuilt engine

Reproduce with:

```bash
python -m ml.fetch_data        # downloads the public source data into ml/raw/
python -m ml.evaluate          # writes ml/results/evaluation.json
```

The exact URL splits used are committed in `ml/splits/`, so the URL results below can be
reproduced without re-downloading the (daily-changing) phishing feeds.

## Setup

* **Original** = the decision logic of `legacy/PhishingApp_v1.py`, extracted verbatim.
* **New** = the rebuilt engine run **offline**: rules + ML model + bundled popularity list.
  No threat feeds, no domain-age lookup, no page retrieval. This is the weakest
  configuration and the only one that can be measured reproducibly without API keys.
* Binary mapping: flagged = "Suspicious" or "Likely Phishing" (original: "Suspicious" or
  "Phishing"). "Unable to Determine" counts as *not flagged*, and is reported separately.

### Data

| Set | Content | Role |
|---|---|---|
| URL train / validation / test | 122,363 URLs. Phishing: Phishing.Database active links (MIT) and the 2017 PhishTank-derived list from ebubekirbbr/pdd. Legitimate: pdd search-result pages, Chrome UX Report home pages, and popular sites hosted on free platforms | Train 85,947 / validation 18,159 / **test 18,257** |
| External OpenPhish | 259 URLs from the live OpenPhish community feed on the day of the build | Never used for training or tuning |
| E-mail corpus | Nazario phishing corpus vs ham from SpamAssassin, Enron and CEAS-08; halves split by content hash | Development half for rule work, **test half** reported |
| Hard cases | 131 URLs and 52 messages written by hand (`ml/challenge/`) | Regression suite; **not an unbiased test** (rules were adjusted after looking at failures) |

Leakage controls: exact duplicates removed; URLs with conflicting labels dropped; at most 2
URLs per phishing site; the split is by registered domain (by site on shared hosting), so no
site appears in two splits (asserted in `ml/build_dataset.py`); every site in the OpenPhish
set is excluded from training. Thresholds and score bands were chosen on validation only.

## Results on held-out data

### URLs: test split (10,670 phishing, 7,587 legitimate)

| Metric | Original | New (offline) |
|---|---|---|
| Accuracy | 0.416 | 0.796 |
| Precision | 0 (nothing flagged) | **0.976** |
| Recall | **0.000** | **0.668** |
| F1 | 0.000 | 0.793 |
| False positive rate | 0.000 | 0.023 |
| False negative rate | 1.000 | 0.332 |

The original reports every URL as "Legitimate", so its 0% false-positive rate is the rate
of a system that never flags anything.

How the new engine distributes its four verdicts:

| Truth | Likely Phishing | Suspicious | Unable to Determine | Likely Safe |
|---|---|---|---|---|
| Phishing (10,670) | 19.1% | 47.6% | 32.8% | **0.45%** |
| Legitimate (7,587) | 0.05% | 2.2% | 34.9% | 62.8% |

* A phishing URL is called "Likely Safe" in 0.45% of cases (48), all on domains in the
  popularity list: compromised or mislabelled popular sites.
* A legitimate URL is called "Likely Phishing" in 0.05% of cases (4).
* Most of the remaining errors are abstentions. A third of phishing URLs carry no lexical
  signal at all (for example a bare, newly registered domain), and the engine says
  "Unable to Determine" instead of guessing.
* False positives concentrate on legitimate sites **not** in the popularity list: 6.0% of
  those are flagged "Suspicious", against 0.06% of listed ones.

### URLs: external OpenPhish feed (259 phishing URLs, offline)

| | Original | New (offline) |
|---|---|---|
| Flagged | 0% | 23.6% |
| Unable to Determine | - | 74.1% |
| Called safe | 100% | 2.3% |

This is the weakest result and is reported as such. 79% of the feed is hosted on free
platforms (site builders, cloud storage) under innocuous names, where the address alone
says little. In the default online configuration the same URLs are confirmed by the OpenPhish
feed itself (verified live for a sample URL during development), but that cannot be counted
as a measured detection rate, because the feed would be matching itself.

### Messages: e-mail corpus, test half (700 phishing, 1,050 legitimate)

| Metric | Original | New (offline) |
|---|---|---|
| Accuracy | 0.641 | 0.843 |
| Precision | 0.987 | 0.967 |
| Recall | 0.104 | **0.630** |
| F1 | 0.189 | 0.763 |
| False positive rate | 0.001 | 0.014 |
| False negative rate | 0.896 | 0.370 |

The original model's vocabulary shows it was trained on these same corpora, so its numbers
here are, if anything, flattering. 27% of phishing e-mails are still called "Likely Safe" by
the new engine: this corpus has most links stripped from message bodies, many messages are
not in English, and wording alone is often indistinguishable from a real notice.

## Hard-case regression suites (hand-built, used during development)

| Set | Original recall / FPR | New recall / FPR |
|---|---|---|
| 123 URLs (60 phishing, 63 legitimate) | 0% / 0% | 95% / 1.6% |
| 49 messages (27 phishing, 22 legitimate) | 11% / 0% | 96% / 0% |

These show the engine handles the listed tricks (typosquats, decoy sub-domains, homographs,
sender spoofing, callback scams, long genuine sign-in URLs). They overstate real-world
accuracy, because I wrote them and tuned against them. `tests/test_regression.py` enforces a
floor on them.

## What was not measured

* **Online configuration.** Threat-feed matches, domain age and page-content analysis are
  covered by unit tests with mocked responses, not by an accuracy measurement. Safe Browsing,
  VirusTotal, URLhaus and RDAP were never called for real (no keys; blocked in the sandbox);
  only the OpenPhish feed download was exercised live. Page retrieval was tested against a
  local server only.
* **Real traffic.** Test sets are about 58% phishing; real submissions are not. Precision in
  production depends on the true mix and will differ.
* **Label noise.** Aggregated phishing feeds contain some legitimate or dead URLs, and the
  popular-site lists contain some abusive ones.
* **Age of the legitimate data.** Legitimate pages with paths come from a 2017 crawl and the
  e-mail ham from 2001-2008. Modern legitimate URLs and mail are under-represented.

## Model card (URL model)

Gradient-boosted trees, 48 lexical features, trained on 85,947 URLs. Validation ROC AUC 0.953.
On validation, a score >= 0.97 covers about 51% of phishing at about 0.2% false positives;
>= 0.90 covers about 68% at 1.6%. These bands map to the high / medium severities used by the
engine. Details in `phishdetect/models/url_model_meta.json`.
