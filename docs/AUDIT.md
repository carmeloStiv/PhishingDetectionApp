# Technical audit of the original application (v1)

The original project is preserved unchanged in `legacy/` (`PhishingApp_v1.py`, `model.pkl`,
`vectorizer.pkl`). Its decision logic is extracted verbatim in `legacy/baseline.py` so it can
be measured; the numbers quoted here come from `python -m ml.evaluate` (see
[EVALUATION.md](EVALUATION.md)).

## What existed

| Area | Finding |
|---|---|
| Architecture | One 103-line Streamlit script. UI, pre-processing, model inference and decision rules in one file. No backend API, no database, no authentication, no tests, no deployment config. |
| Model | TF-IDF (word 1-2-grams, 10,000 features) + logistic regression, stored as pickles made with scikit-learn 1.7.2. No training code, no dataset and no evaluation in the repository. |
| Detection inputs | The text of the submission only. No URL parsing, no domain analysis, no threat intelligence, no page inspection. |
| Classes | Phishing (> 0.85), Suspicious (> 0.60), otherwise Legitimate. There is no way to say "not enough information". |
| External services | None. |
| Dependencies | Unpinned; `matplotlib` and `seaborn` listed but unused. The README says `streamlit run app.py`, a file that does not exist. |

## Why it misclassifies

1. **Every URL is erased before the model sees it.** `clean_text` replaces anything starting
   with `http` or `www` by the token `_url_`. `https://www.google.com` and
   `http://paypa1-secure-login.xyz/verify` become the same input and get the same score (0.778).
2. **That score is then discarded.** A result is only "Phishing" or "Suspicious" when at least
   one *phishing-leaning word* remains after removing "neutral" tokens, and the neutral list
   contains `url`. A URL-only submission therefore always has zero indicators and is always
   reported as **"Legitimate (22%)"**. Measured: 0 of 10,670 phishing URLs in the test split
   were flagged, and 0 of 259 from the live OpenPhish feed.
3. **The whitelist is a substring test.** `any(domain in text.lower() ...)` for `linkedin.com`,
   `github.com`, `python.org` means `linkedin.com.evil.ru/login`, or any phishing e-mail that
   merely mentions github.com, is reported as "Legitimate (whitelisted domain)".
4. **Training/serving skew.** The model's vocabulary contains `http`, `www`, `linkedin com`,
   `amazon com`: tokens the serving-time cleaner can never produce. Training used different
   pre-processing from inference, so the learned weights do not apply to what the app feeds it.
5. **The model learned its corpora, not phishing.** Strongest "legitimate" features: `wrote`,
   `enron`, `opensuse`, `vince`, `louise`. Strongest "phishing" features: `josemonkeyorg`,
   `thu`, `aug`, `slashdot`, `viagra`, `microsoft`. These are artefacts of the Enron, mailing-list
   and Nazario (jose@monkey.org) corpora plus 2000s spam, not properties of phishing. The
   classic "account suspended, verify your password" sentence scores 0.41, i.e. Legitimate.
6. **Spam is not phishing.** The training labels evidently mixed general spam with phishing, so
   pharmacy and watch vocabulary dominates.
7. **"Confidence" was the raw model probability**, shown as "Legitimate (99.9%)", which reads as
   a guarantee of safety. Nothing distinguishes "checked and fine" from "nothing recognised".

Measured on the same held-out data as the new engine: the original flags 0% of phishing URLs
and about 10% of phishing e-mails (from corpora it was very likely trained on).

## Other problems

* **Security:** `pickle.load` of model files (code execution if a file is swapped), no input
  size control beyond Streamlit defaults, no rate limiting, version-mismatched pickles
  (scikit-learn warns that results may be invalid).
* **Explainability:** "Key indicators" are the top TF-IDF coefficients, e.g. a red
  "microsoft (phishing indicator)" for any mail mentioning Microsoft.
* **Maintainability:** nothing can be tested without launching Streamlit; nothing is reproducible.

## Verdict

The detection approach is fundamentally unsound for URLs (they are deleted) and unreliable
for messages (corpus artefacts, skewed pre-processing). No part of the detection logic was
worth keeping, so the engine was rebuilt. What was preserved: the product idea (one box for a
URL or a message, a verdict with reasons), the ability to run on Streamlit (`PhishingApp.py`
is now a thin front-end on the new engine), and the original files for baseline measurement.

## What replaced it

| Problem | Replacement |
|---|---|
| URLs erased | Full URL parsing (public-suffix aware), 25+ structural and impersonation rules, a URL model trained on URL features |
| Keyword model for messages | Context rules: who claims to write, what is asked, how much pressure, where the links really go |
| No external evidence | OpenPhish feed, Google Safe Browsing, VirusTotal, URLhaus, RDAP domain age, popularity list, SSRF-safe page inspection |
| 3 classes, probability as confidence | 4 classes incl. "Unable to Determine", transparent evidence score, separate confidence |
| No evaluation | Leakage-controlled splits, baseline vs new comparison, 125 automated tests |
| Streamlit monolith | Engine package + FastAPI API + static front-end; Streamlit kept as an optional thin UI |
