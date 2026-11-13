# Phishing Detector

Checks a web address, e-mail or message for phishing and explains the result. Version 2 is a
rebuild of the original Streamlit prototype: a hybrid engine (rules, machine learning, threat
intelligence, reputation, page inspection) behind a small API and a new web interface.

Each analysis returns one of four verdicts (**Likely Phishing**, **Suspicious**,
**Likely Safe**, **Unable to Determine**), a transparent risk score, a separate confidence
level, the evidence for every indicator labelled by source, the checks that could not be run,
and recommended actions.

## Measured results

Held-out data, new engine running offline (no threat feeds or page retrieval); details and
caveats in [docs/EVALUATION.md](docs/EVALUATION.md).

| Test set | Metric | Original | New |
|---|---|---|---|
| 18,257 URLs | Recall | 0% | 66.8% |
| | Precision | - | 97.6% |
| | False positive rate | 0% (never flags) | 2.3% |
| | Phishing called "safe" | 100% | 0.45% |
| 1,750 e-mails | Recall | 10.4% | 63.0% |
| | False positive rate | 0.1% | 1.4% |

About a third of URLs get "Unable to Determine" offline: the engine abstains instead of
guessing when an address carries no evidence either way.

## Quick start

Requires Python 3.11+ (developed on 3.13).

```bash
pip install -r requirements.txt
```

```bash
uvicorn server.app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. No API keys are needed to start.

Run the tests:

```bash
pip install -r requirements-dev.txt
```

```bash
python -m pytest -q
```

## Configuration

All settings are environment variables; see [.env.example](.env.example). Never commit keys.

| Variable | Default | Purpose |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | unset | Enables Google Safe Browsing lookups (non-commercial use) |
| `VIRUSTOTAL_API_KEY` | unset | Enables VirusTotal URL reports (free tier: 4/min, 500/day) |
| `URLHAUS_AUTH_KEY` | unset | Enables URLhaus lookups (free key from abuse.ch) |
| `ENABLE_OPENPHISH` | `true` | Download and match the OpenPhish community feed (non-commercial licence) |
| `ENABLE_DOMAIN_AGE` | `true` | RDAP registration-date lookups |
| `ENABLE_LIVE_FETCH` | `true` | Retrieve the submitted page for static analysis. Read [docs/SECURITY.md](docs/SECURITY.md) first |
| `RATE_LIMIT_PER_MINUTE` | `20` | Analyses per client per minute |
| `TRUST_PROXY_HEADERS` | `false` | Use `X-Forwarded-For`; only behind your own reverse proxy |
| `DATA_DIR` | `var` | Where the feedback database is written |
| `FEEDBACK_RETENTION_DAYS` | `180` | Automatic deletion of feedback |

To load a `.env` file in a shell: `set -a; . ./.env; set +a` before starting uvicorn.

## Deployment

Docker (recommended):

```bash
docker build -t phishing-detector .
```

```bash
docker run -p 8000:8000 --env-file .env -v phishing-data:/data phishing-detector
```

* Put a TLS-terminating reverse proxy in front and set `TRUST_PROXY_HEADERS=true`.
* Block outbound traffic to private networks and cloud metadata addresses at the network
  level, or set `ENABLE_LIVE_FETCH=false`.
* The rate limiter and lookup cache are per process. Run one worker, or rate-limit at the proxy.
* The image has not been built in the development environment (no Docker there); the same
  commands it runs were tested directly.

Streamlit (the original hosting method still works): `streamlit run PhishingApp.py`. It uses
the same engine but has no rate limiting, history, feedback or security headers. On Streamlit
Community Cloud the page-retrieval caveat above applies; consider `ENABLE_LIVE_FETCH=false`.

## API

`POST /api/analyze` with JSON `{"content": "...", "mode": "auto" | "url" | "message"}` returns
the report. `POST /api/feedback` records a user's judgement of a result. `GET /api/status`
lists enabled evidence sources. `GET /healthz` for health checks.

## Project layout

| Path | Contents |
|---|---|
| `phishdetect/` | Detection engine (no web dependencies) and bundled data / model |
| `server/` | FastAPI app, rate limiter, feedback store, static front-end |
| `ml/` | Dataset building, training, threshold tuning, evaluation, committed splits and hard cases |
| `tests/` | 125 automated tests |
| `legacy/` | Original v1 app and model, used only for the baseline comparison |
| `docs/` | [Audit](docs/AUDIT.md), [methodology](docs/METHODOLOGY.md), [evaluation](docs/EVALUATION.md), [security and privacy](docs/SECURITY.md) |

Retraining: `python -m ml.fetch_data`, `python -m ml.build_dataset`,
`python -m ml.train_url_model`, `python -m ml.tune`, `python -m ml.evaluate`. Refresh the
popularity list monthly with `python -m ml.build_reputation`.

## Known limitations

* Offline, a new phishing site with an innocuous name is "Unable to Determine", not flagged.
  On a fresh external feed only 24% of URLs were flagged from the address alone.
* Pages are read as static HTML. JavaScript-built pages, CAPTCHA walls and cloaking are not seen.
* A compromised legitimate site hosting phishing can look clean from its address.
* Message analysis is English-only and has no text ML model.
* Safe Browsing, VirusTotal, URLhaus and RDAP integrations are tested against mocked responses
  only; verify them with your own keys.
* The brand list (about 220 organisations) is curated by hand and will miss regional brands.
* Legitimate sites on free hosting that use a brand name or sign-in wording are flagged
  "Suspicious" by design.

## Recommended next steps

1. Add API keys and measure the online configuration on a fresh labelled sample.
2. Review collected feedback regularly; add confirmed mistakes to `ml/challenge/`.
3. Retrain monthly: phishing patterns and the popularity list drift.
4. Add a headless-browser sandbox (isolated container) for JavaScript-rendered pages.
5. Obtain a modern, licensed e-mail corpus before considering a text model.
6. Move rate limiting and caching to Redis if you need several workers.

## Data sources and licences

Phishing.Database (MIT), OpenPhish community feed (free for non-commercial use), Chrome UX
Report via zakird/crux-top-lists (CC BY-SA 4.0), ebubekirbbr/pdd URL lists, and for evaluation
only the Nazario, SpamAssassin, Enron and CEAS-08 e-mail corpora. Check the OpenPhish, Safe
Browsing and VirusTotal terms before any commercial use.
