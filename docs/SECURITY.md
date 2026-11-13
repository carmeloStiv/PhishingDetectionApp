# Security and privacy

## Threat model
The service accepts hostile input by design (phishing URLs and messages) and, when live
retrieval is enabled, connects to attacker-controlled servers. The main risks are SSRF,
injection into the UI, abuse of the service or of third-party API quotas, and leakage of
what users submit.

## Review results

| Risk | Status | Control (and where it is tested) |
|---|---|---|
| SSRF via submitted URLs | Mitigated | `phishdetect/fetcher.py`: http/https and ports 80/443 only; DNS resolved once, **every** returned address must be globally routable (loopback, RFC 1918, link-local/metadata 169.254.0.0/16, CGNAT, multicast, IPv6 ULA and IPv4-mapped forms refused); the socket connects to the validated IP so DNS rebinding cannot swap the target; decimal/hex/octal IP encodings are decoded before the check; redirects handled manually and re-validated per hop (max 5); 8 s timeouts, total deadline, 750 KB cap, no cookies, no credentials, no decompression, no script execution; environment proxies ignored. `tests/test_fetcher.py` (27 cases). |
| XSS | Mitigated | The front-end never builds HTML from data (`textContent` only; a test asserts `innerHTML` is not used). CSP `default-src 'none'; script-src 'self'; style-src 'self'`. Submitted URLs are displayed defanged (`hxxp://evil[.]com`) and never as links. |
| CSRF | Not applicable / mitigated | No cookies, sessions or accounts. POST endpoints require `Content-Type: application/json` and no CORS headers are sent, so other origins cannot call them from a browser. |
| SQL injection | Mitigated | One table, parameterised statements only (`server/storage.py`); tested with an injection string. |
| Insecure deserialisation | Reduced | The only pickle loaded is the model shipped in the repository; a version or feature mismatch disables ML instead of loading. The legacy pickles are loaded only by the evaluation script. Do not replace model files with untrusted ones. |
| API key exposure | Mitigated | Keys are read from environment variables on the server, never sent to the browser, never logged (httpx request logging is silenced because Safe Browsing carries the key in the query string). `/api/status` reports only enabled/disabled. `.env` is git-ignored. |
| Abuse / DoS | Mitigated | Per-client sliding-window rate limit (default 20/min, HTTP 429 + Retry-After), 256 KB body cap, 50,000-character input cap, at most 5 links analysed per message, 8 concurrent analyses, provider timeouts, cached lookups. The limiter is in-memory: with several worker processes put a shared limiter (reverse proxy) in front. |
| Sensitive data exposure | Mitigated | Submissions are not stored or logged (logs contain type, class, score, duration). Generic 500 responses; no stack traces. API docs endpoints disabled. `Cache-Control: no-store` on API responses. |
| Clickjacking / sniffing | Mitigated | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. |
| Authentication / authorisation | Not applicable | There are no accounts and no privileged endpoints. Feedback is write-only over the API. |
| File uploads | Not applicable | Not supported. |
| Path traversal | Mitigated | Static files served by Starlette's `StaticFiles` from one directory. |

## Deployment requirements

* **Run the container with an egress policy.** The fetcher's checks are defence in depth, not a
  sandbox. Deploy where outbound traffic to private ranges and cloud metadata endpoints is
  blocked at the network level, with no cloud credentials attached to the instance. If you
  cannot provide that, set `ENABLE_LIVE_FETCH=false`.
* Terminate TLS at a reverse proxy and set `TRUST_PROXY_HEADERS=true` only there; otherwise
  clients can spoof `X-Forwarded-For` and evade the rate limit.
* The page fetcher identifies as a desktop browser and requests each submitted URL once.
  Visiting a personalised phishing link can confirm to the attacker that the address is live;
  the UI tells users that pages may be fetched.

## Privacy: what is collected, why, for how long

| Data | Purpose | Storage and retention |
|---|---|---|
| Submitted URL / message | Produce the report | Memory only, for the duration of the request. Not written to disk or logs. |
| URLs (submitted, or extracted from a message) | Threat-intelligence and registration lookups | Sent to the providers the operator enabled: OpenPhish feed is matched locally (nothing sent); Safe Browsing, VirusTotal and URLhaus receive the full URL; RDAP receives the registered domain. Results cached in memory 15 min (clean) to 6 h (match). **Message text is never sent to third parties.** |
| Client IP address | Rate limiting | Memory only, about one minute. Standard web-server access logs, if you enable them, are your responsibility. |
| Feedback (verdict, score, comment; content only with explicit consent) | Review misclassifications | SQLite file `DATA_DIR/feedback.sqlite3`, deleted automatically after `FEEDBACK_RETENTION_DAYS` (default 180). |
| History | Convenience for the user | The user's own browser (`localStorage`), last 50 reports, cleared by the user. Never on the server. |

No accounts, cookies, analytics or advertising. Operators in the EU/UK should name the enabled
third-party providers in their own privacy notice.

## Not covered
No external penetration test was performed. TLS configuration, host hardening and log
management depend on where you deploy.
