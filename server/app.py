"""HTTP API and static front-end.

    uvicorn server.app:app --host 0.0.0.0 --port 8000

All detection logic and all credentials stay on the server. The browser only
receives the finished report.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishdetect import __version__
from phishdetect.config import Settings
from phishdetect.engine import Engine, InputError
from phishdetect.ml import url_model_info
from phishdetect.scoring import LABELS, PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD

from .ratelimit import RateLimiter
from .storage import FeedbackStore

log = logging.getLogger("phishdetect.server")
STATIC = Path(__file__).parent / "static"
MAX_BODY_BYTES = 256_000
MAX_CONCURRENT_ANALYSES = 8

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=200_000)
    mode: Literal["auto", "url", "message"] = "auto"


class FeedbackRequest(BaseModel):
    analysis_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    input_type: Literal["url", "message"]
    classification: Literal["likely_phishing", "suspicious", "likely_safe", "unable_to_determine"]
    risk_score: int = Field(ge=0, le=100)
    verdict: Literal["correct", "should_be_flagged", "should_not_be_flagged"]
    comment: str = Field(default="", max_length=1000)
    content: str | None = Field(default=None, max_length=50_000)


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = engine or Engine(settings)
    store = FeedbackStore(settings.data_dir, settings.feedback_retention_days)
    analyse_limiter = RateLimiter(settings.rate_limit_per_minute)
    feedback_limiter = RateLimiter(max(settings.rate_limit_per_minute // 2, 1))
    slots = threading.BoundedSemaphore(MAX_CONCURRENT_ANALYSES)
    app = FastAPI(title="Phishing Detection API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    def client_key(request: Request) -> str:
        if settings.trust_proxy_headers:
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                return fwd.split(",")[0].strip()[:64]
        return request.client.host if request.client else "unknown"

    @app.middleware("http")
    async def harden(request: Request, call_next):
        if request.method == "POST":
            # JSON only: a cross-site form cannot send this content type without a CORS
            # pre-flight, and no CORS headers are ever returned (the API also has no cookies).
            if not request.headers.get("content-type", "").lower().startswith("application/json"):
                return JSONResponse({"error": "Content-Type must be application/json."}, status_code=415, headers=SECURITY_HEADERS)
            try:
                if int(request.headers.get("content-length", "0")) > MAX_BODY_BYTES:
                    return JSONResponse({"error": "Request body is too large."}, status_code=413, headers=SECURITY_HEADERS)
            except ValueError:
                return JSONResponse({"error": "Invalid Content-Length."}, status_code=400, headers=SECURITY_HEADERS)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):
        log.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"error": "The analysis failed unexpectedly. Please try again."}, status_code=500)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def invalid(_request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
        return JSONResponse({"error": f"Invalid {field}: {first.get('msg', 'bad value')}."}, status_code=422)

    @app.post("/api/analyze")
    def analyze(body: AnalyzeRequest, request: Request):
        allowed, retry = analyse_limiter.check(client_key(request))
        if not allowed:
            raise HTTPException(429, f"Too many requests. Try again in {retry} seconds.", headers={"Retry-After": str(retry)})
        if not slots.acquire(timeout=10):
            raise HTTPException(503, "The service is busy. Please try again shortly.", headers={"Retry-After": "5"})
        started = time.monotonic()
        try:
            report = engine.analyse(body.content, body.mode)
        except InputError as exc:
            raise HTTPException(422, str(exc)) from exc
        finally:
            slots.release()
        # Operational log: outcome and timing only, never the submitted content.
        log.info("analysis type=%s class=%s score=%s ms=%d", report["input_type"], report["classification"],
                 report["risk_score"], (time.monotonic() - started) * 1000)
        return report

    @app.post("/api/feedback")
    def feedback(body: FeedbackRequest, request: Request):
        allowed, retry = feedback_limiter.check("fb:" + client_key(request))
        if not allowed:
            raise HTTPException(429, f"Too many requests. Try again in {retry} seconds.", headers={"Retry-After": str(retry)})
        store.add(analysis_id=body.analysis_id, input_type=body.input_type, classification=body.classification,
                  risk_score=body.risk_score, verdict=body.verdict, comment=body.comment.strip(), content=body.content)
        return {"stored": True, "retention_days": settings.feedback_retention_days}

    @app.get("/api/status")
    def status():
        model = url_model_info()
        return {
            "version": __version__,
            "thresholds": {"suspicious": SUSPICIOUS_THRESHOLD, "likely_phishing": PHISHING_THRESHOLD},
            "classes": LABELS,
            "limits": {"max_chars": settings.max_text_chars, "requests_per_minute": settings.rate_limit_per_minute},
            "sources": [{"name": p.label, "enabled": p.configured()} for p in engine.providers]
            + [{"name": engine.age_provider.label, "enabled": engine.age_provider.configured()},
               {"name": "Live page retrieval", "enabled": settings.enable_live_fetch}],
            "url_model": {"available": "error" not in model, "trained_at": model.get("trained_at"),
                          "validation_roc_auc": model.get("val_roc_auc")},
            "feedback_retention_days": settings.feedback_retention_days,
        }

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    app.state.store = store
    return app


def _default_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return create_app()


def __getattr__(name: str):   # lazy: `uvicorn server.app:app` builds the app on first access
    if name == "app":
        globals()["app"] = _default_app()
        return globals()["app"]
    raise AttributeError(name)
