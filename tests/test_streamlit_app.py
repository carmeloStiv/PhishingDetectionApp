import pytest

pytest.importorskip("streamlit")


def test_streamlit_front_end_runs(monkeypatch):
    from streamlit.testing.v1 import AppTest

    for name in ("ENABLE_LIVE_FETCH", "ENABLE_DOMAIN_AGE", "ENABLE_OPENPHISH"):
        monkeypatch.setenv(name, "false")
    at = AppTest.from_file("../PhishingApp.py", default_timeout=60).run()
    assert not at.exception
    at.text_area[0].set_value("http://paypa1-secure-login.xyz/verify")
    at.button[0].click().run()
    assert not at.exception
    assert any("Likely Phishing" in e.value for e in at.error)
