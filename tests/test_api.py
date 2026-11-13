import pytest
from fastapi.testclient import TestClient

from phishdetect.config import Settings
from server.app import create_app


@pytest.fixture()
def client(tmp_path, offline_engine):
    s = Settings.offline()
    s.data_dir = tmp_path
    s.rate_limit_per_minute = 5
    app = create_app(s, offline_engine)
    return TestClient(app), app


def test_analyze_and_security_headers(client):
    c, _ = client
    r = c.post("/api/analyze", json={"content": "http://paypa1-secure-login.xyz/verify"})
    assert r.status_code == 200 and r.json()["classification"] == "likely_phishing"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("payload,code", [({"content": ""}, 422), ({"content": "   "}, 422), ({}, 422),
                                          ({"content": "x", "mode": "bogus"}, 422), ({"content": "javascript:alert(1)", "mode": "url"}, 422)])
def test_validation_errors_are_json_messages(client, payload, code):
    c, _ = client
    r = c.post("/api/analyze", json=payload)
    assert r.status_code == code and isinstance(r.json()["error"], str)


def test_non_json_posts_are_rejected(client):
    c, _ = client
    assert c.post("/api/analyze", data={"content": "example.com"}).status_code == 415
    assert c.post("/api/analyze", content="content=example.com", headers={"Content-Type": "text/plain"}).status_code == 415


def test_oversized_body_is_rejected(client):
    c, _ = client
    assert c.post("/api/analyze", json={"content": "a" * 300_000}).status_code in (413, 422)


def test_rate_limit(client):
    c, _ = client
    codes = [c.post("/api/analyze", json={"content": "example.com"}).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    r = c.post("/api/analyze", json={"content": "example.com"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_feedback_is_stored_only_on_request(client):
    c, app = client
    rep = c.post("/api/analyze", json={"content": "example.com"}).json()
    assert app.state.store.count() == 0          # analysing stores nothing
    body = {"analysis_id": rep["id"], "input_type": "url", "classification": rep["classification"],
            "risk_score": rep["risk_score"], "verdict": "correct", "comment": "'); DROP TABLE feedback;--"}
    assert c.post("/api/feedback", json=body).json()["stored"] is True
    assert app.state.store.count() == 1          # parameterised insert, table intact
    assert c.post("/api/feedback", json={**body, "verdict": "nonsense"}).status_code == 422
    assert c.post("/api/feedback", json={**body, "analysis_id": "../../etc"}).status_code == 422


def test_feedback_retention(tmp_path):
    from server.storage import FeedbackStore
    store = FeedbackStore(tmp_path, retention_days=0)
    store.add(analysis_id="a" * 32, input_type="url", classification="suspicious", risk_score=40, verdict="correct", comment="", content=None)
    import time
    time.sleep(1.1)
    assert store.purge() == 1 and store.count() == 0


def test_static_and_status(client):
    c, _ = client
    assert c.get("/").status_code == 200 and "Phishing Detector" in c.get("/").text
    assert c.get("/static/app.js").status_code == 200
    st = c.get("/api/status").json()
    assert st["thresholds"] == {"suspicious": 30, "likely_phishing": 65}
    assert "key" not in str(st).lower()          # no credentials or key material exposed
    assert c.get("/docs").status_code == 404
    assert c.get("/static/../app.py").status_code in (404, 400)


def test_report_text_is_inert_in_frontend():
    # the UI must never build HTML from report data
    js = open("server/static/app.js", encoding="utf-8").read()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js
