# Architecture and detection methodology

## Architecture

```
browser (server/static: HTML + CSS + vanilla JS, no build step)
   |  POST /api/analyze  {content, mode}
   v
server/app.py      FastAPI: validation, rate limit, security headers, feedback (SQLite)
   |
   v
phishdetect/engine.py          orchestrates one analysis and builds the report
   |- urltools.py              parsing, public-suffix handling, URL extraction, defanging
   |- url_rules.py, brands.py  URL structure + impersonation rules          [Rule]
   |- text_rules.py            message context rules (sender, request, pressure, links)  [Rule]
   |- features.py, ml.py       lexical URL model                             [ML model]
   |- reputation.py            Chrome UX Report popularity, hosting platforms [Reputation]
   |- intel.py                 OpenPhish, Safe Browsing, VirusTotal, URLhaus, RDAP age  [Threat intelligence]
   |- fetcher.py, page_rules.py  SSRF-safe retrieval + static HTML analysis  [Page content]
   `- scoring.py               evidence score, four classes, confidence
ml/                training, threshold tuning and evaluation scripts (not needed at runtime)
legacy/            the original app and model, kept for the baseline comparison
PhishingApp.py     optional Streamlit front-end on the same engine
```

Design decisions:

* **Engine as a plain Python package.** No web framework inside it, so it is unit-testable and
  usable from the API, Streamlit or a script.
* **FastAPI + static front-end instead of Streamlit as the main UI.** Streamlit cannot provide
  rate limiting, security headers, a JSON API or the result layout required. No front-end
  framework or build step: the UI is about 330 lines of JavaScript.
* **No database for analyses.** Reports are returned to the browser and kept there. SQLite
  holds user feedback only. This removes most privacy and storage risk.
* **Synchronous engine with a small thread pool** for provider lookups. Simple, and adequate
  for the expected load; scale by adding processes behind a proxy.

## Why a hybrid, and what each part is for

| Component | Purpose | Strength | Weakness (why it cannot stand alone) |
|---|---|---|---|
| Threat intelligence | Recognise *known* malicious URLs | Near-zero false positives | Blind to anything new; feeds lag by hours |
| Rules | Recognise deliberate deception (look-alikes, decoy sub-domains, sender spoofing) | Precise, explainable | Only catches tricks someone wrote a rule for |
| ML model | Generalise to URLs that merely *look* like phishing | Catches unseen patterns | False positives on unusual legitimate URLs; learns dataset bias |
| Reputation | Positive evidence for well-established sites | Cuts false positives sharply | Popular sites and free hosts can still serve phishing |
| Page content | Confirm what the page actually does | Sees credential forms and exfiltration | No JavaScript execution; cloaking; page may be offline |

### Evaluation of external services

| Service | Decision | Accuracy / reliability | Cost and limits | Privacy | Notes |
|---|---|---|---|---|---|
| OpenPhish community feed | **Integrated, on by default** | Curated active phishing URLs; small (about 300 at a time), refreshed several times a day | Free for non-commercial use; a commercial licence is required otherwise | Matched locally; nothing leaves the server | Verified live in development |
| Google Safe Browsing (Lookup API v4) | **Integrated, needs key** | Very broad coverage, low false positives | Free, quota-limited, **non-commercial use only** (commercial use requires Web Risk) | Full URL sent to Google | Tested against mocked responses only; verify with your key. Google is moving users to v5; the provider class is the one place to change |
| VirusTotal API v3 | **Integrated, needs key** | Aggregates ~90 engines; single-engine hits are noisy, so 3+ engines are required to count as confirmed | Free tier 4 requests/min, 500/day, non-commercial | Full URL sent; only existing reports are read, nothing is submitted for scanning | Mocked tests only |
| URLhaus (abuse.ch) | **Integrated, needs free Auth-Key** | Malware-distribution URLs rather than credential phishing; complements the others | Free | Full URL sent | Mocked tests only |
| RDAP (domain age) | **Integrated, on by default** | Authoritative registry data; not available for every TLD | Free; public bootstrap service `rdap.org` (configurable) | Registered domain sent | Mocked tests only (blocked in the development sandbox) |
| Chrome UX Report top sites | **Bundled** | Real Chrome traffic; more accurate than Alexa/Tranco for popularity | Free, CC BY-SA 4.0; refresh monthly with `python -m ml.build_reputation` | Local | |
| PhishTank | Not integrated | Good data | New API-key registration has been closed for years | - | Its data largely overlaps with the aggregated feeds used for training |
| LLM analysis | **Deliberately not integrated** | Fluent but unverifiable; vulnerable to prompt injection from the very content being analysed | Per-request cost | Would send users' messages to a third party | Explanations are generated from structured evidence instead, so every sentence is traceable to a rule. An LLM could later be added strictly to re-phrase existing evidence |

## URL analysis

Rules (all in `url_rules.py`; each produces evidence text and an explanation):

* **Impersonation** against a curated list of about 220 frequently-phished organisations and
  their official domains: misspellings (edit distance scaled to name length, digit and
  `rn`/`vv` substitutions), look-alike Unicode characters and mixed scripts, a real domain used
  as a sub-domain, brand + keyword domains, brand names on free hosting, brand folders on
  unrelated sites. Short or dictionary-word brands (apple, chase, orange ...) only count with
  sign-in context.
* **Destination hiding:** `user@host` tricks, raw and encoded IP addresses, link shorteners,
  redirect parameters (the embedded destination is analysed too), non-standard ports.
* **Hosting:** about 250 platforms where anyone can publish (site builders, cloud storage,
  dynamic DNS, pseudo-TLDs such as `ru.com`). Their reputation is never inherited.
* **Weak lexical signals:** abused TLDs, deep sub-domain chains, security-sounding words,
  e-mail addresses in the link, kit paths under CMS system folders, executable downloads.
* HTTPS is **never** positive evidence. Plain http with sign-in wording is a weak negative.

ML model (`features.py`, `ml/train_url_model.py`): gradient-boosted trees on 48 hand-built
lexical features. The scheme, `www.` and popularity are excluded on purpose, because in the
available data they reveal which dataset a URL came from, not whether it is phishing.

Reputation tiers decide how much the model is believed: ignored for official domains and
the top 100k sites, reduced one band for the rest of the top million, limited on shared
hosting (where it only has legitimate home pages to learn from), full weight elsewhere.

Page analysis (`page_rules.py`, static HTML only): password or sensitive fields, forms posting
to another domain or to Telegram/Discord/form-relay endpoints, a brand in the title on a domain
that brand does not own, pages built from another site's assets, wallet recovery-phrase
requests, obfuscated loaders, redirect chains, very recent certificates.

## Message analysis

`text_rules.py` reads the opening 3,000 characters and combines:

* **Sender:** display name claims a brand but the address is elsewhere or a free mailbox;
  display name shows a different address or domain; Reply-To on another domain.
* **Request:** credentials, codes, payment, changed bank details, untraceable payment.
* **Pressure:** threat and deadline close together; mailbox/quota/password-expiry pretexts;
  missed deliveries; surprise charges with a phone number (callback scams).
* **Links:** each link (up to 5) goes through the URL pipeline (not fetched). The message is
  judged with its riskiest link. Link text that shows a different site than its target.
* **Mitigation:** when every link leads to an official or established domain, wording such as
  "confirm your account" is recorded as a note, not as risk.

A phrase on its own carries little or no weight; a lure needs an *action vector* (unverified
link, attachment, reply or call request) to count. English only.

There is no text ML model. The audit showed how the available e-mail corpora (Enron,
SpamAssassin, CEAS-08, Nazario) teach a model the corpus rather than phishing, and no
appropriately licensed modern corpus was available to do better.

## Scoring and classification

Weights by severity: critical 0.85, high 0.55, medium 0.30, low 0.12, note/supporting 0.

```
score = 100 x (1 - PRODUCT over counted indicators of (1 - weight))
```

Indicators about the same fact share a group and the strongest counts once. Examples:
one high = 55; high + medium = 69; two highs = 80; medium + low = 38.

| Class | Rule |
|---|---|
| Likely Phishing | confirmed threat-intelligence match (score floor 97), or score >= 65 |
| Suspicious | 30 <= score < 65 |
| Likely Safe | score < 30 **and** positive evidence: official or established domain, or at least one threat feed answered clean together with a registration older than 180 days or a retrieved, unremarkable page; for messages, every link must meet that bar |
| Unable to Determine | score < 30 without positive evidence, an unresolved shortener, a host that does not resolve, or text too short to assess |

Model score bands (high >= 0.97, medium >= 0.90, low >= 0.75) and both thresholds were chosen
on the validation split with `python -m ml.tune`; the test split was not used. Consequence:
the model alone can produce "Suspicious" but never "Likely Phishing".

**Confidence** (high / medium / low) is separate from the score. It combines the distance of
the score from the nearest threshold with how many independent sources answered, is capped
when the only evidence is the model, is always low for "Unable to Determine" and always high
for a confirmed listing. The model score is shown as a score, never as a probability: the
training mix is about 60% phishing, nothing like real traffic.

Every indicator in a report carries its source: threat intelligence, rule, page content, ML
model or reputation. Checks that could not run are listed under "Checks performed" and in
`missing_information`.
